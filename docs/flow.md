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

Check the exact parameters against the extension text before modelling (planned: model 04).

## 3. Properties to state (draft)

- **P1 credential binding:** a client credential (secret, code, `code_verifier`, signed assertion) is only revealed to the AS it belongs to. → model 01
- **P2 code/token injection:** a code or token issued for RS₁ is never accepted by RS₂ (audience). → model 02
- **P3 mix-up:** C never redeems a code at an AS other than the one that issued it (`iss`). → model 02
- **P4 CIMD:** one client identity across ASes does not let AS₁ act as C at AS₂. → model 03
- **P5 enterprise chain:** an ID-JAG for RS₁/AS₁ cannot be replayed to obtain access at RS₂/AS₂. → model 04
