"""Conformance checks for MCP authorization, MCP Python SDK (`mcp` 2.3.0).

In-process only: no sockets, no network, no third-party systems.
IDs (CT-xx) are defined in conformance/spec.md.
"""
import anyio
from urllib.parse import parse_qs, urlparse
import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from mcp.client.auth.exceptions import OAuthFlowError
from mcp.client.auth.extensions.client_credentials import (
    PrivateKeyJWTOAuthProvider,
    SignedJWTParameters,
)
from mcp.client.auth.oauth2 import AuthorizationCodeResult, OAuthClientProvider, TokenStorage
from mcp.client.auth.utils import (
    credentials_match_issuer,
    validate_authorization_response_iss,
    validate_metadata_issuer,
)
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend
from mcp.server.auth.provider import AccessToken
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthMetadata

HONEST = "https://as.honest.example"
OTHER = "https://as.other.example"
RS = "https://rs.example/mcp"
OTHER_RS = "https://other-rs.example/mcp"


def meta(issuer, iss_supported=None):
    return OAuthMetadata(
        issuer=issuer,
        authorization_endpoint=f"{issuer}/authorize",
        token_endpoint=f"{issuer}/token",
        authorization_response_iss_parameter_supported=iss_supported,
    )


# CT-01 resource-server audience check (model 02 NO_AUD, R1; GHSA-w4fh-qvv9-3v23, GHSA-rvq5-wwqv-78pq).
# The check is opt-in in mcp 2.3.0 (`validate_token_resource`, off by default per the published
# advisory), so these tests run with it ON: the backend is given the server's own resource URL.
class _Verifier:
    def __init__(self, resource):
        self.resource = resource

    async def verify_token(self, token):
        return AccessToken(token=token, client_id="c", scopes=[], resource=self.resource)


class _Conn:
    headers = {"authorization": "Bearer t"}


def _authenticate(token_resource):
    backend = BearerAuthBackend(_Verifier(token_resource), resource_server_url=RS)
    return anyio.run(backend.authenticate, _Conn())


def test_ct01_token_for_other_resource_rejected():
    assert _authenticate(OTHER_RS) is None


def test_ct01_token_without_resource_claim_rejected():
    assert _authenticate(None) is None


def test_ct01_token_for_this_resource_accepted():
    assert _authenticate(RS) is not None


# CT-02 / CT-03 RFC 9207 handling of `iss` in the authorization response, against validated
# AS metadata (model 02 NO_ISS / ISS_OPTIONAL; R2, R3).
def test_ct02_iss_of_another_as_rejected():
    with pytest.raises(OAuthFlowError):
        validate_authorization_response_iss(OTHER, meta(HONEST))


def test_ct02_matching_iss_accepted():
    validate_authorization_response_iss(HONEST, meta(HONEST, iss_supported=True))


def test_ct03_absent_iss_rejected_when_as_advertises_support():
    with pytest.raises(OAuthFlowError):
        validate_authorization_response_iss(None, meta(HONEST, iss_supported=True))


def test_ct03_absent_iss_accepted_when_as_does_not_advertise_support():
    """RFC 9207 section 2.4 table: no advertisement and no `iss` -> the client proceeds. The MCP
    draft's SHOULD on the AS side is what model 02 ISS_OPTIONAL (R3) is about."""
    validate_authorization_response_iss(None, meta(HONEST, iss_supported=False))


# CT-04 AS metadata `issuer` must equal the issuer it was fetched for (RFC 8414 section 3.3; R0, R8).
def test_ct04_metadata_issuer_mismatch_rejected():
    with pytest.raises(OAuthFlowError):
        validate_metadata_issuer(meta(HONEST), expected_issuer=OTHER)


def test_ct04_metadata_issuer_match_accepted():
    validate_metadata_issuer(meta(HONEST), expected_issuer=HONEST)


# CT-05 client credentials registered at one AS are not reused at another (model 01;
# GHSA-qx49-fqc8-xw99). Applies to records stamped with their issuer, as the SDK's own
# registration flow does.
def test_ct05_stamped_credentials_match_only_their_as():
    info = OAuthClientInformationFull(client_id="c", client_secret="s",
                                      redirect_uris=["http://localhost/cb"], issuer=HONEST)
    assert credentials_match_issuer(info, HONEST, None)
    assert not credentials_match_issuer(info, OTHER, None)


# CT-06: RFC 8707 `resource` is sent on /authorize and /token, value from PRM (model 02 NO_RESOURCE; R4).
class _MemStorage(TokenStorage):
    def __init__(self):
        self._tokens = None

    async def get_tokens(self):
        return self._tokens

    async def set_tokens(self, tokens):
        self._tokens = tokens


def _run_oauth_client(prm_resource=RS):
    requests_log = []
    redirects = []
    saved_state = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests_log.append(request)
        url = str(request.url)
        path = request.url.path

        if url.startswith(RS):
            if "authorization" in request.headers:
                return httpx2.Response(200, json={"ok": True})
            return httpx2.Response(401, headers={"WWW-Authenticate": "Bearer"})

        if path.startswith("/.well-known/oauth-protected-resource"):
            return httpx2.Response(200, json={
                "resource": prm_resource,
                "authorization_servers": [HONEST],
            })

        if path == "/.well-known/oauth-authorization-server":
            return httpx2.Response(200, json={
                "issuer": HONEST,
                "authorization_endpoint": f"{HONEST}/authorize",
                "token_endpoint": f"{HONEST}/token",
                "registration_endpoint": f"{HONEST}/register",
                "response_types_supported": ["code"],
            })

        if path == "/register":
            return httpx2.Response(201, json={
                "client_id": "CID",
                "redirect_uris": ["http://localhost/cb"],
                "token_endpoint_auth_method": "none",
            })

        if path == "/token":
            return httpx2.Response(200, json={
                "access_token": "AT",
                "token_type": "Bearer",
                "expires_in": 3600,
            })

        return httpx2.Response(404)

    async def redirect_handler(auth_url: str):
        redirects.append(auth_url)
        params = parse_qs(urlparse(auth_url).query)
        saved_state["state"] = params.get("state", [""])[0]

    async def callback_handler():
        return AuthorizationCodeResult(code="C", state=saved_state.get("state"), iss=HONEST)

    client_meta = OAuthClientMetadata(
        client_name="test",
        redirect_uris=["http://localhost/cb"],
        grant_types=["authorization_code"],
        response_types=["code"],
    )

    provider = OAuthClientProvider(
        server_url=RS,
        client_metadata=client_meta,
        storage=_MemStorage(),
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )

    async def execute():
        transport = httpx2.MockTransport(handler)
        async with httpx2.AsyncClient(auth=provider, transport=transport) as client:
            resp = await client.get(RS)
            return resp, requests_log, redirects

    return anyio.run(execute)


def test_ct06_resource_sent_on_authorize_and_token():
    resp, log, redirects = _run_oauth_client(RS)
    assert resp.status_code == 200
    assert len(redirects) == 1
    auth_params = parse_qs(urlparse(redirects[0]).query)
    assert auth_params.get("resource") == [RS]

    token_req = next(r for r in log if r.url.path == "/token")
    token_body = parse_qs(token_req.read().decode())
    assert token_body.get("resource") == [RS]


def test_ct06_prm_resource_mismatch_refused_before_redirect():
    with pytest.raises(OAuthFlowError, match="does not match expected"):
        _run_oauth_client(OTHER_RS)


# CT-07: private_key_jwt assertion `aud` is the validated AS issuer, even if the metadata lists
# another AS's token endpoint (model 06 AUD_TOKEN_ENDPOINT; R12).
def test_ct07_assertion_aud_equals_metadata_issuer():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    jwt_params = SignedJWTParameters(
        issuer="cid",
        subject="cid",
        signing_key=pem,
        signing_algorithm="RS256",
    )

    provider = PrivateKeyJWTOAuthProvider(
        server_url=RS,
        storage=_MemStorage(),
        client_id="cid",
        assertion_provider=jwt_params.create_assertion_provider(),
        issuer=OTHER,
    )
    provider.context.oauth_metadata = OAuthMetadata(
        issuer=OTHER,
        authorization_endpoint=f"{OTHER}/authorize",
        token_endpoint=f"{HONEST}/token",
        response_types_supported=["code"],
    )

    token_req = anyio.run(provider._exchange_token_client_credentials)
    assert str(token_req.url) == f"{HONEST}/token"

    data = parse_qs(token_req.read().decode())
    assertion = data["client_assertion"][0]
    payload = jwt.decode(assertion, options={"verify_signature": False})
    assert payload.get("aud") == OTHER


def test_ct07_assertion_provider_receives_validated_issuer():
    recorded_aud = []

    async def assertion_provider(audience: str) -> str:
        recorded_aud.append(audience)
        return "fake-assertion"

    provider = PrivateKeyJWTOAuthProvider(
        server_url=RS,
        storage=_MemStorage(),
        client_id="cid",
        assertion_provider=assertion_provider,
        issuer=OTHER,
    )
    provider.context.oauth_metadata = OAuthMetadata(
        issuer=OTHER,
        authorization_endpoint=f"{OTHER}/authorize",
        token_endpoint=f"{HONEST}/token",
        response_types_supported=["code"],
    )

    anyio.run(provider._exchange_token_client_credentials)
    assert recorded_aud == [OTHER]
