# MCP authorization conformance cases (language-agnostic)

Each case is derived from a Tamarin model in this repo (see [../docs/results.md](../docs/results.md)). It checks that an implementation performs the check the *fixed* model assumes. Actors: **Client** (MCP client OAuth code), **RS** (MCP server), **AS** (authorization server). All cases are in-process: mock the HTTP layer, open no sockets.

Spec quotes are paraphrased; see [../docs/verification-mapping.md](../docs/verification-mapping.md) for the exact rule/lemma traceability.

| ID | Target | Check | Model / R | Spec clause |
|---|---|---|---|---|
| CT-01 | RS | Reject tokens not issued for this server | 02 `NO_AUD`, [R1](../docs/results.md) | RFC 8707 §2; MCP Authorization, Token Handling |
| CT-02 | Client | Reject an authorization response whose `iss` is another AS | 02 `NO_ISS`, [R2](../docs/results.md) | RFC 9207 §2.4; RFC 9700 §4.4 |
| CT-03 | Client | `iss` absent: reject if the AS advertised support, accept otherwise | 02 `ISS_OPTIONAL`, [R3](../docs/results.md) | RFC 9207 §2.4 |
| CT-04 | Client | Reject AS metadata whose `issuer` differs from the issuer it was fetched for | 01/03 `NO_META_CHECK`, [R0, R8](../docs/results.md) | RFC 8414 §3.3 |
| CT-05 | Client | Credentials registered at one AS are not used at another | 01, GHSA-qx49-fqc8-xw99 | OAuth 2.1 client credential scope; RFC 9700 §4.4 |
| CT-06 | Client | Send RFC 8707 `resource` on authorize and token requests, from protected-resource metadata; refuse a mismatching one | 02 `NO_RESOURCE`, [R4](../docs/results.md) | RFC 8707 §2; RFC 9728; MCP Authorization, Resource Parameter |
| CT-07 | Client | `private_key_jwt` assertion `aud` is the validated AS issuer, not a token endpoint taken from metadata | 06 `AUD_TOKEN_ENDPOINT`, [R12](../docs/results.md) | RFC 7523 §3; RFC 7521 |
| CT-08 | AS | Match `redirect_uri` exactly at `/authorize`; require the same value at `/token` | 02 `NO_REDIRECT_CHECK`, [R11](../docs/results.md) | RFC 9700 §4.1; RFC 6749 §3.1.2.3, §4.1.3 |

ST-01..ST-03 in [../docs/conformance-test-draft.md](../docs/conformance-test-draft.md) map to CT-01..CT-03. ST-03 as drafted is an AS-side SHOULD (the AS includes `iss`); CT-03 tests the client side of the same RFC 9207 table. The AS-side SHOULD is not an SDK-level check and is not included.

Common fixtures: honest AS `https://as.honest.example`, another AS `https://as.other.example`, MCP server `https://rs.example/mcp`, another MCP server `https://other-rs.example/mcp`.

---

## CT-01 Resource server rejects tokens for another audience
- **Preconditions:** the RS is configured with its own canonical resource URL (opt-in in current SDKs; see README, "Opt-in checks"). A token verifier returns a valid token whose resource/audience is set by the test.
- **Input:** a request with `Authorization: Bearer <token>`.
- **Expected:**
  - (a) token resource = another server: reject (HTTP 401, `invalid_token`); the request does not proceed to the tool handler.
  - (b) token with no resource/audience claim: reject.
  - (c) token resource = this server: accept (a trailing slash difference is tolerated where the SDK documents it).
- **Model:** 02 `-D=NO_AUD`, P2 falsified; fixed variant verified.

## CT-02 Client rejects `iss` of another AS
- **Preconditions:** the client started authorization at the honest AS and holds validated metadata for it.
- **Input:** authorization response `?code=C&state=S&iss=https://as.other.example`.
- **Expected:** (a) validation fails; (b) the code (and PKCE verifier) is never sent to any token endpoint; (c) a response with `iss` equal to the honest issuer completes the flow.
- **Model:** 02 `-D=NO_ISS`, P3 falsified (mix-up despite PKCE).

## CT-03 Client handling of an absent `iss`
- **Preconditions:** as CT-02, with `authorization_response_iss_parameter_supported` set to true or false in the AS metadata.
- **Input:** authorization response with no `iss`.
- **Expected:** supported = true: reject, no token request. Supported = false or unset: proceed (this is what the RFC 9207 §2.4 table requires; the residual risk is the point of R3 and spec gap G1).
- **Model:** 02 `-D=ISS_OPTIONAL`.

## CT-04 AS metadata issuer equals the fetched issuer
- **Input:** a mock server for `https://as.other.example` returns metadata with `issuer = https://as.honest.example`.
- **Expected:** discovery fails with an issuer mismatch; with `issuer` equal to the fetched issuer it succeeds.
- **Model:** 01 `UNVALIDATED_ISSUER`; 03 / 06 `NO_META_CHECK` (R0, R8, R12).

## CT-05 Credentials are bound to the AS they were issued by
- **Preconditions:** a credential record stamped with issuer `https://as.honest.example` (as produced by the SDK's registration flow).
- **Expected:** the record matches the honest issuer and does not match `https://as.other.example`.
- **Model:** 01 `VULNERABLE`, P1 falsified (the abstraction of GHSA-qx49-fqc8-xw99).

## CT-06 `resource` indicator on both requests
- **Preconditions:** mock protected-resource metadata (`resource = https://rs.example/mcp`, `authorization_servers = [honest]`), AS metadata, registration and token endpoints.
- **Expected:** (a) the authorize URL and the token request body both carry `resource=https://rs.example/mcp`; (b) if the metadata's `resource` differs from the server URL the client was pointed at, the flow aborts before any redirect.
- **Model:** 02 `-D=NO_RESOURCE` (a client or AS that drops `resource` allows a broad audience; R4). The spec requires clients to send `resource`; it does not require them to refuse an AS that ignores it, so no such case is included.

## CT-07 Client assertion audience
- **Preconditions:** AS metadata with `issuer = https://as.other.example` and a `token_endpoint` on `https://as.honest.example`.
- **Input:** the client builds a `private_key_jwt` assertion for that token endpoint.
- **Expected:** assertion `aud` = `https://as.other.example` (the validated issuer).
- **Model:** 06 fixed variant; `AUD_TOKEN_ENDPOINT` + `AS_LENIENT` falsifies P7 and P3 (audience injection).

## CT-08 Exact redirect URI matching (AS)
- **Preconditions:** a public client registered with `redirect_uri = https://app.example/cb`; PKCE S256 in use; an in-memory provider that records calls.
- **Input:** `/authorize` with a `redirect_uri` that differs from the registered one by path, trailing slash, `..`, prefix, query, port, scheme, host suffix, other host, userinfo, subdomain, or a fragment; then `/token` with a different or missing `redirect_uri`.
- **Expected:** `/authorize` returns 400 without redirecting and without calling the provider; `/token` rejects a `redirect_uri` that differs from the one `/authorize` saw. The exact registered URI is accepted. A client with two registered URIs cannot redeem a code with the other one.
- **Model:** 02 `-D=NO_REDIRECT_CHECK`, P3 falsified even with PKCE.
