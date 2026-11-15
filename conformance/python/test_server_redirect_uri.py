"""CT-08: exact redirect_uri matching in the bundled authorization server (`mcp.server.auth`, mcp 2.3.0).

Model 02 NO_REDIRECT_CHECK (R11; RFC 9700 section 4.1, RFC 6749 sections 3.1.2.3 and 4.1.3).
In-process ASGI (Starlette TestClient): no sockets, no network. IDs are defined in conformance/spec.md.
"""
import base64
import hashlib
import time
from urllib.parse import parse_qs, urlparse

import pytest
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.testclient import TestClient

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.server.auth.routes import create_auth_routes
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

REG = "https://app.example/cb"
LOOP = "http://localhost:3000/cb"
VERIFIER = "v" * 50
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")


class MemProvider:
    """Minimal in-memory AS: records what the SDK hands to the provider."""

    def __init__(self):
        self.clients = {}
        self.codes = {}
        self.authorize_calls = []

    async def get_client(self, client_id):
        return self.clients.get(client_id)

    async def register_client(self, client_info):
        self.clients[client_info.client_id] = client_info

    async def authorize(self, client, params: AuthorizationParams) -> str:
        self.authorize_calls.append(params)
        code = f"code{len(self.codes)}"
        self.codes[code] = AuthorizationCode(code=code, scopes=params.scopes or [], expires_at=time.time() + 60,
                                             client_id=client.client_id, code_challenge=params.code_challenge,
                                             redirect_uri=params.redirect_uri,
                                             redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly)
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

    async def load_authorization_code(self, client, authorization_code):
        return self.codes.get(authorization_code)

    async def exchange_authorization_code(self, client, authorization_code):
        return OAuthToken(access_token="AT", token_type="Bearer", expires_in=60)

    async def load_refresh_token(self, client, refresh_token):
        return None

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        raise NotImplementedError

    async def load_access_token(self, token):
        return None

    async def revoke_token(self, token):
        return None


def make():
    prov = MemProvider()
    for cid, uris in (("pub", [REG]), ("loop", [LOOP]), ("two", [REG, "https://app.example/other"])):
        prov.clients[cid] = OAuthClientInformationFull(client_id=cid, redirect_uris=uris,
                                                       token_endpoint_auth_method="none",
                                                       grant_types=["authorization_code"],
                                                       response_types=["code"])
    app = Starlette(routes=create_auth_routes(prov, issuer_url=AnyHttpUrl("https://as.example")))
    return prov, TestClient(app, base_url="https://as.example", follow_redirects=False)


def authorize(c, client_id="pub", redirect_uri=REG, **extra):
    q = {"client_id": client_id, "response_type": "code", "code_challenge": CHALLENGE,
         "code_challenge_method": "S256", "state": "st"}
    if redirect_uri is not None:
        q["redirect_uri"] = redirect_uri
    q.update(extra)
    return c.get("/authorize", params=q)


def token(c, code, redirect_uri, client_id="pub"):
    data = {"grant_type": "authorization_code", "code": code, "client_id": client_id, "code_verifier": VERIFIER}
    if redirect_uri is not None:
        data["redirect_uri"] = redirect_uri
    return c.post("/token", data=data)


def code_of(resp):
    return parse_qs(urlparse(resp.headers["location"]).query)["code"][0]



# ---------------------------------------------------------------- /authorize
def test_ct08_authorize_exact_match_accepted():
    prov, c = make()
    r = authorize(c)
    assert r.status_code == 302 and r.headers["location"].startswith(REG + "?code=")


@pytest.mark.parametrize("bad", [
    "https://app.example/cb/x",
    "https://app.example/cb/",
    "https://app.example/cb/../cb2",
    "https://app.example/c",
    "https://app.example/cb?a=b",
    "https://app.example:8443/cb",
    "http://app.example/cb",
    "https://app.example.evil.example/cb",
    "https://evil.example/cb",
    "https://app.example@evil.example/cb",
    "https://sub.app.example/cb",
])
def test_ct08_authorize_rejects_inexact_redirect_uri(bad):
    prov, c = make()
    r = authorize(c, redirect_uri=bad)
    assert r.status_code == 400, f"{bad} -> {r.status_code}"
    assert "location" not in r.headers      # never redirects to the unregistered URI
    assert prov.authorize_calls == []       # the provider never sees the request


def test_ct08_authorize_rejects_fragment_in_redirect_uri():
    prov, c = make()
    assert authorize(c, redirect_uri=REG + "#frag").status_code == 400


def test_ct08_authorize_post_form_same_rule():
    prov, c = make()
    r = c.post("/authorize", data={"client_id": "pub", "response_type": "code", "code_challenge": CHALLENGE,
                                   "code_challenge_method": "S256", "redirect_uri": "https://app.example/cb/x"})
    assert r.status_code == 400 and prov.authorize_calls == []


# ---------------------------------------------------------------- /token
def test_ct08_token_accepts_same_redirect_uri():
    prov, c = make()
    code = code_of(authorize(c))
    r = token(c, code, REG)
    assert r.status_code == 200 and r.json()["access_token"] == "AT"


def test_ct08_token_rejects_different_or_missing_redirect_uri():
    for bad in ("https://app.example/other", "https://app.example/cb/x", "https://evil.example/cb", None):
        prov, c = make()
        code = code_of(authorize(c))
        r = token(c, code, bad)
        assert r.status_code == 400, f"{bad} -> {r.status_code}"
        assert r.json()["error"] == "invalid_request"


def test_ct08_token_second_registered_uri_swap_rejected():
    prov, c = make()
    code = code_of(authorize(c, "two", redirect_uri=REG))
    assert token(c, code, "https://app.example/other", "two").status_code == 400
    assert token(c, code, REG, "two").status_code == 200
