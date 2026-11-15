# MCP authorization: formal model → SDK implementation check (W4.3)

This document maps the Tamarin models in this repository (`models/01`–`models/09`) to the
observed behaviour of real Model Context Protocol (MCP) SDK implementations. It records where an
implementation's behaviour matches a model's verified property, where it matches a model's
*ablated* (weakened) variant, and where a gap is already covered by a published, fixed advisory.

Wording follows the project standard: findings **rediscover** or **exercise the condition of**
published, already-addressed issues; nothing here is described as "novel" or "first". Where a
client-side finding is still under **coordinated disclosure**, its specifics are withheld until the
relevant maintainer advisory is published (see §4).

---

## 1. Scope and method

Implementations checked:

- **Python SDK** — `mcp` 2.3.0
- **TypeScript client** — `@modelcontextprotocol/client` 2.4.0
- **TypeScript SDK (older line)** — `@modelcontextprotocol/sdk` 1.32.2

Each check below was exercised against **real SDK execution** in a local test harness (not part of
this public repository), covering: metadata `issuer` validation (RFC 8414 §3.3), RFC 9207 `iss`
handling, RFC 8707 `resource`/audience, PKCE (RFC 7636), redirect-URI equality (RFC 6749 §3.1.2 /
RFC 8252 §7.3), refresh-token binding (RFC 6749 §6), and `private_key_jwt` assertion audience
(RFC 7523bis). A loopback end-to-end lab and a cross-SDK differential runner drive each SDK's real
decision path rather than stubbing it.

### Classification

- **(a)** Conforms to specification, or an intentional, documented design choice (e.g. an opt-in
  check that defaults off).
- **(b)** Matches a model's ablated variant, but the behaviour is covered by a **published,
  already-addressed advisory** (GHSA-qx49, GHSA-w4fh, GHSA-rvq5, GHSA-6qxp).
- **(c)** A client-side finding currently **under coordinated disclosure (in triage)** with the SDK
  maintainers — specifics withheld; see §4.

---

## 2. Model → implementation matrix

| Model / check | RFC / clause | Python `mcp` 2.3.0 | TS client 2.4.0 | TS SDK 1.32.2 | Class |
|---|---|---|---|---|---|
| **M01/03** metadata `issuer` == discovery URL (`NO_META_CHECK`) | RFC 8414 §3.3 | Pass — `validate_metadata_issuer` raises on mismatch | Pass — rejects with `IssuerMismatchError` (opt-out: `skipIssuerValidation`) | Older line: keys credentials by discovery URL, not `metadata.issuer` — upgrade recommended | (a)/(b) |
| **M01/03** credential binding to its AS | MCP Auth — AS isolation | Pass — stamped credentials/tokens dropped on AS mismatch | Pass — mismatched credentials discarded | Older line: no issuer binding across AS switches | (b) — GHSA-6qxp |
| **M02** server validates token audience (`NO_AUD`) | RFC 8707 §2 | Pass when `validate_token_resource` set (**opt-in, default off**) | n/a (client package; no server router) | Pass when `expectedResource` set (**opt-in, default off**) | (a)/(b) — GHSA-w4fh / GHSA-rvq5 |
| **M02** client sends RFC 8707 `resource` (`NO_RESOURCE`) | RFC 8707 §2 | Sends `resource`; enforces PRM allow-list | Pass — sends on `/authorize` + `/token`; refuses PRM mismatch | Pass — same | (a) |
| **M02** RFC 9207 `iss` validation (`NO_ISS` / `ISS_OPTIONAL`) | RFC 9207 §2.4 | Pass — `validate_authorization_response_iss` follows the spec table | Pass — `validateAuthorizationResponseIssuer` follows the spec table | Older line predates RFC 9207 support — upgrade recommended | (a) |
| **M06** `private_key_jwt` assertion `aud` = AS issuer (`AUD_TOKEN_ENDPOINT`) | RFC 7523bis §3 | Pass — `aud = metadata.issuer` | Pass — `aud = metadata.issuer` | Pass — `aud = metadata.issuer` (overridable) | (a) |
| **M07** proxy consent bound to `(user, client_id)` (`CONSENT_NOT_CLIENT_BOUND`) | MCP Security BCP — confused deputy | Architectural (proxy responsibility) | Architectural | Architectural | (a) |
| **M08** downstream audience check blocks token passthrough (`PASSTHROUGH`) | RFC 8707 / MCP Security BCP | Pass — client sends resource indicator | Pass — client sends resource indicator | Pass — client sends resource indicator | (a) |
| **M09** consent bound to `(user, resource, scope)` (`CONSENT_NOT_RESOURCE_BOUND`) | RFC 8707 / scope challenge | Step-up scoped per resource | Step-up scoped per resource | Step-up scoped per resource | (a) |
| **M02** redirect URI exact match at `/authorize` (`NO_REDIRECT_CHECK`) | RFC 6749 §3.1.2, RFC 8252 §7.3, RFC 9700 §4.1 | Pass — rejects extra path / query / port / host suffix (21 checks) | n/a (no server router) | Pass — exact match; loopback port relaxed per RFC 8252 | (a) |
| **M02** redirect URI equality at `/token` | RFC 6749 §4.1.3 | Pass — 400 on mismatch | n/a (client package) | Delegated to the provider interface (PKCE remains bound) — hardening note | (a) |

The verified (fixed/strict) variant of every model holds in the current Python SDK and the current
TypeScript client where the relevant code path exists. Where a cell says *opt-in, default off*, the
default configuration corresponds to the model's ablated variant; this is the documented design of
the published advisories named in the Class column.

---

## 3. Rediscovered published advisories

These are already **published and addressed**; the models reproduce the condition they describe.

- **GHSA-qx49-fqc8-xw99** (Python SDK) — credentials not bound to their AS. Abstracted by **model 01**.
- **GHSA-w4fh-qvv9-3v23 / GHSA-rvq5-wwqv-78pq** — server audience validation is opt-in. Matches
  **model 02** `NO_AUD`; the current default-off behaviour is the documented, published design.
- **GHSA-6qxp-vccf-f47h** — cross-AS credential binding, fixed in the 2.x line. Matches the
  **model 01/03** credential-binding property; the older 1.x line predates the fix.

---

## 4. Findings under coordinated disclosure (in triage)

Two **client-side** findings from the differential testing have been **reported privately to the
MCP SDK maintainers and are currently in triage**. In keeping with responsible disclosure, their
specifics — the affected SDKs and versions, the exact code paths, the reproduction, and the
advisory identifiers — are **withheld from this document until the maintainers publish the
corresponding advisories**. This section and the relevant rows of the matrix in §2 will be
completed at that time.

No unfixed exploit detail is published here while the fixes are pending.

---

## 5. General hardening guidance

These are standard, RFC-backed recommendations for any MCP client or authorization server; they do
not describe any unfixed implementation.

1. **Require a verified issuer.** A client should not fall back to a no-op `iss` check when an
   authorization server publishes no metadata; it should require a verified issuer or pin one
   explicitly (RFC 9207, RFC 9700 §4.4).
2. **Invalidate on AS change.** When a protected resource's metadata names a new authorization
   server, previously issued access tokens, refresh tokens, and client credentials should be
   dropped or strictly partitioned by issuer in client storage (RFC 6749 §6).
3. **Scope consent to the resource.** An authorization server serving several MCP servers should
   keep consent records partitioned by `(user, resource, scope)` to prevent scope step-up abuse
   (RFC 8707).
4. **Strict assertion audience.** For `private_key_jwt`, the client assertion `aud` should be the
   authorization server's issuer identifier, and the AS should not accept the token-endpoint URL as
   an alternative (RFC 7523bis).
