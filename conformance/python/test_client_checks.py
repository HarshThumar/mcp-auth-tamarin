"""Conformance checks for MCP authorization, MCP Python SDK (`mcp` 2.3.0).

In-process only: no sockets, no network, no third-party systems.
IDs (CT-xx) are defined in conformance/spec.md.
"""
import anyio
import pytest

from mcp.client.auth.exceptions import OAuthFlowError
from mcp.client.auth.utils import (
    credentials_match_issuer,
    validate_authorization_response_iss,
    validate_metadata_issuer,
)
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend
from mcp.server.auth.provider import AccessToken
from mcp.shared.auth import OAuthClientInformationFull, OAuthMetadata

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
