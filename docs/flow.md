# MCP authorization flow (what is being modelled)

This is a summary of the [MCP authorization spec (draft)](https://modelcontextprotocol.io/specification/draft/basic/authorization), written as message steps. It is a working note. **The spec is authoritative**, and every step should be checked against the pinned spec version before a model relies on it.

Parties: **U** user (browser), **C** MCP client, **RS** MCP server (resource server, possibly malicious), **AS** authorization server, **IdP** enterprise identity provider (enterprise flow only).

## 1. Standard flow

| # | From → To | Message | Spec |
|---|---|---|---|
| 1 | C → RS | MCP request without a token | MCP |
| 2 | RS → C | `401` + `WWW-Authenticate` with `resource_metadata` URL (and optional `scope`) | RFC 9728 §5.1 |
| 3 | C → RS | GET Protected Resource Metadata → `resource`, `authorization_servers[]` | RFC 9728 |
| 4 | C → AS | GET AS metadata (`/.well-known/oauth-authorization-server` or OIDC discovery); **check `issuer`** | RFC 8414, OIDC Discovery |
| 5 | C ↔ AS | Client identity: pre-registered, **Client ID Metadata Document** (`client_id` is an HTTPS URL), or Dynamic Client Registration | RFC 7591, CIMD draft |
| 6 | C → U → AS | Authorization request: PKCE `code_challenge` (S256), `resource` = canonical RS URI, `scope`, `state` | OAuth 2.1, RFC 7636, RFC 8707 |
| 7 | AS → U → C | Redirect with `code`, `state`, `iss`; **client checks `iss`** | RFC 9207 |
| 8 | C → AS | Token request: `code`, `code_verifier`, `resource`, client authentication | OAuth 2.1, RFC 8707 |
| 9 | AS → C | Access token with audience = RS | RFC 8707 |
| 10 | C → RS | MCP request with `Authorization: Bearer …`; **RS validates audience** and MUST NOT pass the token through to upstream APIs | MCP |
| 11 | RS → C | Step-up: `403 insufficient_scope` → client re-authorizes for more scope | MCP, RFC 6750 |

**Legacy fallback:** if the RS publishes no protected resource metadata, older behaviour falls back to AS metadata at the RS origin. GHSA-qx49-fqc8-xw99 shows that this path missed the issuer check in SDK 2.0.0–2.1.1.

## 2. Enterprise-Managed Authorization (ID-JAG)

| # | From → To | Message | Spec |
|---|---|---|---|
| E1 | C → IdP | Token exchange (RFC 8693): the user's ID token in, an **ID-JAG** out (audience = MCP AS, `resource` = RS) | RFC 8693, draft-ietf-oauth-identity-assertion-authz-grant |
| E2 | C → AS | JWT bearer grant (RFC 7523) presenting the ID-JAG | RFC 7523 |
| E3 | AS → C | Access token for RS | |

Modelled in model 04 (see [threat-model.md](threat-model.md) for the parameters used).

## 3. Properties (one numbering for all models)

| # | Property | Lemma(s) |
|---|---|---|
| P1 | **Credential binding:** a client credential is only revealed to the AS it belongs to. | 01 `client_credential_secrecy` |
| P2 | **Right resource:** an honest MCP server only accepts a token for user U if U authorized access to *that* server. | 02, 03 `rs_accepts_only_consented`; 04 `rs_accepts_only_authorized` |
| P2' | **Requested resource:** as P2, but "authorized" = some client acting for U set out to use that server (needed when `resource` is optional). | 04 `rs_accepts_only_requested` |
| P3 | **Access-token secrecy (covers mix-up):** a token for an honest user, client and MCP server never reaches the attacker. | 02, 03, 04 `token_secrecy` (03: `token_secrecy_attack` in two variants) |
| P4 | **Refresh-token secrecy (CIMD):** one client identity across ASes does not leak a refresh token issued by AS₁ to AS₂. | 03 `refresh_token_secrecy` (`refresh_token_secrecy_attack` in two variants) |
| P5 | **Enterprise grant agreement:** an honest RAS issues a token for U to client C only on an ID-JAG issued for U, that RAS and C (no cross-RAS replay). | 04 `ras_grant_agreement` |
| P6 | **Session integrity:** if an honest user's client session with an honest AS ends with a token, that AS issued it for that user and client (no code injection / login CSRF). | 02 `session_integrity` |

Helper and sanity lemmas (`*_sources`, `executable*`, `client_key_secret`, `code_single_use`) are not properties; `scripts/prove.sh` counts them separately.
