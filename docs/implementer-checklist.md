# MCP authorization: checks your client / server / AS must do, machine-checked

*For people building MCP SDKs, clients, MCP servers and authorization servers. Numbers match [results.md](results.md) and [ablation.md](ablation.md) (models last checked 14-15 Nov 2026, Tamarin 1.12.0, 376/376 expectations pass).*

## What was checked, and what it means

Nine Tamarin models ([models/](../models/)) describe MCP authorization (server-chosen authorization server, Client ID Metadata Documents, enterprise ID-JAG, proxy servers, token handling, scope step-up) plus one agent-payment case study. The attacker is Dolev-Yao: it controls the network, runs its own authorization servers, MCP servers, clients and user accounts, and a malicious MCP server may name any AS. Each **check** below is one switchable flag in a model. Every flag subset was run ([ablation.md](ablation.md)); a check is called **necessary** if removing it breaks the property in every model variant tried, and an **either/or pair** if the property holds as long as one of the two is kept.

Limits, please read:
- The models abstract the specs, **not any SDK**. "Skipping a check breaks property P" means a machine-checked attack trace exists in the model, not that a given SDK is vulnerable. The SDK bugs that the models match (GHSA-qx49-fqc8-xw99, GHSA-w4fh-qvv9-3v23, GHSA-rvq5-wwqv-78pq) are published and already fixed; the models rediscover them.
- "Holds" is a proof in the abstraction only. Browser internals (cookies, origins, open redirectors), token expiry, DPoP, refresh rotation and implementation bugs are not modelled ([threat-model.md](threat-model.md)).
- None of the attacks listed is new; each is a known attack class (RFC 9700, audience injection, MCP Security Best Practices). The value here is a check-by-property table that is machine-checked.
- Symbols: ✅ proved, ❌ attack found (steps in brackets), ❌ᵃ attack found with an exists-trace lemma in a **reduced model** (attacker clients left out; the trace is still an attack on the full model, see results.md R8), ✅ʳ proved only in the reduced model (not a proof for the full model, counted as undecided). "Steps" are Tamarin proof steps, a size measure, not protocol messages.
- Property numbers P1-P13b are global ([flow.md](flow.md) §3).

---

## MCP client

| # | Check (do this) | Spec clause | Protects | If you skip it | Alone, or either/or? | How to test |
|---|---|---|---|---|---|---|
| C1 | Take the AS issuer from **validated** metadata: the `issuer` in the document must equal the URL it was fetched for, then record it. | RFC 8414 §3.3; MCP Authorization, Authorization Response Validation ("provides no protection if the expected issuer was obtained from an unvalidated source") | P1 credential secrecy, P3 token secrecy, P4 refresh-token secrecy, P7 client authentication | An attacker-run AS publishes the honest issuer in its metadata. Model 01 `UNVALIDATED_ISSUER`: P1 ❌ (4). Model 03 `NO_META_CHECK`: public client P3, P4 ❌ (8 each); confidential client ❌ᵃ (16 / 9). Model 06 `NO_META_CHECK`: P7 ❌ (7), P3 ❌ (8). R0, R8, R12. | **Necessary** in every model it appears in (01: BIND ∧ META; 03: META; 06: CAUD ∧ META). It also undoes C3 and C7 when missing. | Serve metadata whose `issuer` differs from the fetch URL; the client must refuse. |
| C2 | Store client credentials (pre-registered or from DCR) keyed by the AS `issuer`; send a credential only to the AS it came from. | MCP Client Registration, Authorization Server Binding ("MUST associate ... keyed by the authorization server's `issuer`") | P1 client credential secrecy | A malicious MCP server names its own AS and receives the credential. Model 01 `VULNERABLE`: P1 ❌ (4). Matches GHSA-qx49-fqc8-xw99 (published, fixed). | **Necessary** together with C1 (P1 holds iff BIND ∧ META). | Point the client at an AS other than the one that issued its credential; no credential may be sent. |
| C3 | Compare the `iss` in the authorization response with the recorded issuer **before** sending the code (and PKCE verifier) to any token endpoint; abort on mismatch. | RFC 9207 §2.4; MCP Authorization Response Validation ("MUST apply the validation in RFC9207 Section 2.4 before transmitting the authorization code") | P3 token secrecy | AS mix-up works despite PKCE. Model 02 `NO_ISS`: P3 ❌ (11). Model 03 public `NO_ISS`: P3, P4 ❌ (8 each). R2. | **Necessary** for public clients (03 PUBLIC: ISS ∧ META ∧ RTBIND) and for model 02 (P3 iff ISS ∧ REDIR). **Confidential `private_key_jwt` client: either/or** with the AS checking the assertion `aud` (A5), but the `iss`-only route also needs C1 and C6 (P3 iff (ASAUD ∧ META) ∨ (ISS ∧ META ∧ RTBIND)). Keep checking `iss` anyway (R6). | ST-02: callback with `iss=https://attacker-as.example`; the client must not send `code` or verifier anywhere. |
| C4 | Send an S256 PKCE challenge and send the verifier only to the AS you started the flow with. | RFC 7636; OAuth 2.1; MCP Authorization (PKCE required) | P6 session integrity (no code injection / login CSRF) | Only together with C5 being absent. Model 02 `NO_PKCE` + `NO_STATE`: P6 ❌ (5). R5. | **Either/or with C5**: P6 holds iff PKCE ∨ STATE. `NO_PKCE` alone ✅ (49); `NO_STATE` alone ✅ (61). PKCE does **not** replace the redirect-URI check (A3, R11) or `iss` (C3, R2). | Replay a callback code from another session; the flow must fail (via `state` or via PKCE at the AS). |
| C5 | Generate a secret per-session `state` and verify it on the callback; discard mismatches. | MCP Security Considerations, Open Redirection (SHOULD) | P6 session integrity | See C4. | **Either/or with C4** (P6 iff PKCE ∨ STATE). Spec says SHOULD; the model says one of the two suffices (G7). | Callback with a missing or wrong `state`: the client must discard it. |
| C6 | Send a stored refresh token only to the issuer that issued it, not to whatever AS the current MCP server names. | RFC 6749 §6 and general OAuth practice. **Not stated in the MCP spec** (the AS-binding rule names client credentials only, G3). | P4 refresh-token secrecy; P3 for public clients | Model 03 `RT_UNBOUND`: confidential P4 ❌ (9) (the leaked token is useless alone, P3 stays ✅); public P3, P4 ❌ (8 each); confidential with `AS_NO_ASSERTION_AUD` P3 ❌ᵃ (12). R7. | **Necessary** for P4 (ablation: P4 needs RTBIND) and for public-client P3. | Refresh after the MCP server switches to another AS; the old refresh token must not be sent. |
| C7 | For `private_key_jwt`, set the assertion `aud` to the **validated AS issuer**, not the token-endpoint URL from metadata. | draft-ietf-oauth-rfc7523bis (issuer only); RFC 7523 §3 allows a token-endpoint `aud`. **The MCP draft does not say** which value to use (R12). | P7 client authentication, P3 token secrecy | Audience injection through a client-authenticated revocation request to an attacker AS whose metadata lists the honest token endpoint. Model 06 `AUD_TOKEN_ENDPOINT` + `AS_LENIENT`: P7 ❌ (9), P3 ❌ (10). | **Necessary** with C1 (P7, P3 iff CAUD ∧ META). The client fix **alone suffices** even if the AS still accepts token-endpoint audiences (`AS_LENIENT` ✅, P7 23 / P3 21). `AUD_TOKEN_ENDPOINT` alone is **vacuous** (an AS that accepts only the issuer rejects the honest client). | Check the `aud` of every assertion sent to revocation, token and PAR endpoints. |
| C8 | In the enterprise (ID-JAG) flow, include `resource` in the token exchange so the ID-JAG names the MCP server. | ID-JAG draft-06 (`resource` is **OPTIONAL**); MCP profile ("MUST be audience-restricted to the MCP Server") | P2' token only for the requested server, P3 | If `resource` is absent and the RAS issues a broad audience, a malicious MCP server replays the token at an honest one. Model 04 `NO_RESOURCE_CLAIM`: P2' ❌ (6), P3 ❌ (8). R10. | **Necessary** in model 04 (P2, P2', P3 iff JAGRES). The model has no check at the client that refuses to proceed without it, so this row says what the system needs, not what the spec requires (G9). | Request a token without `resource` and confirm what the RAS returns. |

*Not ablated, assumed by every fixed variant:* the client sends the RFC 8707 `resource` parameter in authorization and token requests, and the user approves only requests for servers they meant (G8). Model 09: a client that carries one scope union across resources (`UNION_ACROSS_RESOURCES`) is harmless on its own (P13 ✅ (70), P13b ✅ (26)); it is dangerous only with an AS consent cache bound to the scope name (A6).

**Client minimum set** (from the minimal sufficient sets; "keep all" is still the safe advice):
1. C1 always (necessary everywhere).
2. C2 for stored credentials; C6 for stored refresh tokens.
3. Public client: C1 + C3 + C6, all three (P3 iff ISS ∧ META ∧ RTBIND).
4. Confidential client: C1 + C6 plus **either** C3 or an AS that checks the assertion `aud` (A5). Do both.
5. C4 or C5 (either one; PKCE is required by the spec, so C5 is the spare).
6. C7 for `private_key_jwt` clients.
7. C8 in the ID-JAG flow.

---

## MCP server (resource server)

| # | Check (do this) | Spec clause | Protects | If you skip it | Alone, or either/or? | How to test |
|---|---|---|---|---|---|---|
| S1 | Reject any access token whose audience is not **your** canonical URI. | RFC 8707 §2; MCP Token Handling ("MUST validate that access tokens were issued specifically for them as the intended audience") | P2 server accepts only consented tokens | A token minted for a malicious server is replayed at yours. Model 02 `NO_AUD`: P2 ❌ (8). Model 08 `S_NO_AUD`: P2 ❌ (6). Model 09 `NO_AUD`: P13 ❌ (7). R1, R15, R16. Matches GHSA-w4fh-qvv9-3v23 / GHSA-rvq5-wwqv-78pq (published, fixed; both fixes are opt-in). | **Necessary**, but not sufficient: P2 iff AUD ∧ RES, so the AS must honour `resource` (A1). A strict check also rejects tokens with no audience. | ST-01: valid token with `aud` of another server; expect 401 `invalid_token`, no tool executed. |
| S2 | Do not pass the client's token on to a downstream API; exchange it for a token whose audience is the downstream API. | MCP Security Best Practices, Token Passthrough ("MUST NOT"); RFC 8693 | P9 downstream is reached only through the server's own decision | Model 08 `PASSTHROUGH` + `D_NO_AUD`: P9 ❌ (6). R15. | P9 iff DAUD ∧ XCHG (both necessary). `PASSTHROUGH` alone is **vacuous**: with a downstream that checks `aud`, a passthrough server cannot work at all. | Intercept the downstream call; its `Authorization` token must differ from the one the client sent. |
| S3 | (Downstream API) check the token audience. | RFC 8707 §2 at the downstream API | P9 | Model 08 `D_NO_AUD`: P9 ❌ (6): a token given to a malicious MCP server is used directly at the downstream API, bypassing the honest server. | **Necessary** for P9 (see S2); separate from S1, which protects P2 only. | Present a token for MCP server A to the downstream API; expect rejection. |

**Server minimum set:** S1 (and an AS that honours `resource`, A1); no passthrough, exchange tokens (S2); downstream API checks `aud` (S3).

---

## Authorization server

| # | Check (do this) | Spec clause | Protects | If you skip it | Alone, or either/or? | How to test |
|---|---|---|---|---|---|---|
| A1 | Honour RFC 8707 `resource`: issue a token whose audience is only the requested resource. | RFC 8707 §2-3; MCP Resource Parameter Implementation (clients MUST send it; the spec does **not** say how a client can tell an AS honours it, G4) | P2 server accepts only consented tokens; P13 | The AS issues a broad audience, so S1 passes for a replayed token. Model 02 `NO_RESOURCE`: P2 ❌ (8). Model 09 `NO_RESOURCE`: P13 ❌ (8). R4, R16. Applies only to an AS whose default audience covers other servers. | **Necessary** with S1 (P2 iff AUD ∧ RES; P13 needs AUD ∧ RES). | Request `resource=A`; the token must not be accepted by server B. (ST-04 was withdrawn: no spec rule or metadata field to key it on.) |
| A2 | Send `iss` in every authorization response and set `authorization_response_iss_parameter_supported` in metadata. | RFC 9207 §2; MCP: **SHOULD** (draft plans MUST); CIMD draft-03 §7: MUST for CIMD clients | P3 token secrecy | Model 02 `ISS_OPTIONAL` (honest AS omits `iss`): P3 ❌ (12), even for a client that implements the table correctly. R3. | **Necessary** for pre-registered / DCR clients while C3 depends on it. For CIMD clients it is already a MUST. | ST-03: redirect must contain `iss`; omission is a warning today, a failure after the planned SHOULD to MUST change. |
| A3 | Match `redirect_uri` exactly against the client's registered (or CIMD) URIs; never accept another one. | OAuth 2.1; RFC 9700 §4.1; MCP Security Considerations | P3 token secrecy | An attacker-built link with its own redirect URI and PKCE challenge gets the code. Model 02 `NO_REDIRECT_CHECK`: P3 ❌ (8). Model 07 `NO_REDIRECT_CHECK`: P3 ❌ (15). R11, R14. | **Necessary** (P3 iff ISS ∧ REDIR in model 02). PKCE does not help here. | Authorization request with a foreign redirect URI; the AS must reject it before any user interaction that issues a code. |
| A4 | Verify the PKCE verifier against the stored challenge at the token endpoint and consume codes once. | RFC 7636 §4.6; OAuth 2.1 | P6 session integrity | Only with `state` absent too: Model 02 `NO_PKCE` + `NO_STATE`: P6 ❌ (5). R5. | **Either/or with client `state`** (C4/C5). | Redeem a code with a wrong verifier, and redeem a code twice; both must fail. |
| A5 | For `private_key_jwt`, check that the assertion `aud` is **your own issuer** (and `verify` the signature). | draft-ietf-oauth-rfc7523bis; RFC 7523 §3. MCP draft silent. | P3, P4 (confidential CIMD clients); P7 | Model 03 `AS_NO_ASSERTION_AUD` alone: ✅ (P3 240 / P4 39). Together with `NO_ISS`: P3 ❌ (15), P4 ❌ (12). R6. | **Either/or with client `iss` check (C3)** for mix-up. In model 06 an AS that also accepts token-endpoint audiences (`AS_LENIENT`) is still safe **if the client uses C7** (P7 ✅ (23)); the model has no variant where only the AS is fixed and the client sends a token-endpoint `aud`, so it does not rank the AS check against the client one beyond that. | Send an assertion whose `aud` is another AS issuer or a token-endpoint URL; expect `invalid_client`. |
| A6 | Show consent per (resource, scope), and do not skip the screen because the same scope **name** was approved for another resource. | RFC 6749 §3.3, §4.1.1; RFC 8707. **Not specified in MCP** (G8; R16 says the consent flags are choices the spec leaves open). | P13b AS issues only intended scope; P13 | Model 09 `CONSENT_NOT_RESOURCE_BOUND`: P13b ❌ (6); with a client that carries the union across resources, P13 ❌ (9). R16. | **Necessary** for P13b. | Approve `admin` for server A; request `admin` for server B; the consent screen must appear again. |
| A7 | (Enterprise RAS) reject an ID-JAG whose `aud` is not your issuer **or** whose `client_id` claim is not the authenticated client. Keep both. | ID-JAG draft-06 §4.4.1 (both MUST) | P5 grant agreement (no cross-RAS replay) | Model 04 `NO_IDJAG_AUD` + `NO_CLIENT_BINDING`: P5 ❌ (10). Each alone ✅ (P5 16 / 15). R9. | **Either/or**: P5 iff JAGCID ∨ JAGAUD. | Replay an ID-JAG issued for another RAS, from an attacker's client; expect `invalid_grant`. |
| A8 | (Enterprise RAS) do not issue a broad-audience token when the ID-JAG has no `resource`; reject it or restrict the audience. | ID-JAG draft-06 / MCP profile: `resource` OPTIONAL, behaviour when absent **unspecified** (G9) | P2', P3 | Model 04 `NO_RESOURCE_CLAIM`: P2' ❌ (6), P3 ❌ (8). R10. | Mirrors A1 and C8; P2' and P3 hold iff `resource` is in the ID-JAG. | Exchange without `resource`; the resulting token must not be accepted by an unrelated server. |

**AS minimum set:** A1 (honour `resource`); A3 (exact redirect URI); A2 (`iss`, always) unless every client is a CIMD client; A4 (PKCE, single-use codes); A5 (assertion `aud`) as the spare for confidential clients; A6 (per-resource consent); for ID-JAG at least one of the two A7 checks, and A8.

---

## Proxy server (MCP server in front of a third-party AS with a static client ID)

| # | Check (do this) | Spec clause | Protects | If you skip it | Alone, or either/or? | How to test |
|---|---|---|---|---|---|---|
| X1 | Record and check consent **per client** (`client_id`), not "this user has consented". | MCP Security Best Practices, Confused Deputy ("MUST"; consent cookies bound to `client_id`) | P8 token only to a consented client | An attacker registers its own client and sends a crafted link; the proxy issues the user's token to it. Model 07 `CONSENT_NOT_CLIENT_BOUND`: P8 ❌ (11). R14. | **Necessary** for P8 (not an either/or with X2). | Register a second client with the same user; the consent screen must appear for it. |
| X2 | Require the exact registered redirect URI for each client. | MCP Security Best Practices ("MUST"); RFC 9700 §4.1 | P3 token secrecy | Per-client consent does not help: the attacker uses a client the user approved, with its own redirect URI and PKCE challenge. Model 07 `NO_REDIRECT_CHECK`: P3 ❌ (15). R14. | **Necessary** for P3; both X1 and X2 are needed (both off: P8 ❌ (11), P3 ❌ (15)). | Authorization request with a foreign redirect URI for an approved client; must be rejected. |

Proxy servers also must not pass tokens through (S2) and must check token audiences (S1).

**Proxy minimum set:** X1 and X2, both.

---

## Payment server and mandate AS (agent-payment case study, model 05)

Case study of an AI agent paying under a mandate ([case-study-upi.md](case-study-upi.md)); anchored on draft-mishra-oauth-agent-grants-02, RFC 9396, RFC 9449 and RFC 7009. It is a modelled abstraction, not a description of any deployed payment system. The mandate has no standard form in the MCP specs.

| # | Check (do this) | Spec clause | Protects | If you skip it | Alone, or either/or? | How to test |
|---|---|---|---|---|---|---|
| M1 | (Mandate AS) issue a mandate only after the principal's approval of exactly that agent, payee and cap. | agent-grants-02 §9.1 (no consent substitution) | P10 every debit stays inside what the principal approved | Model 05 `NO_CONSENT_BINDING`: P10 ❌ (12). R13. | **Necessary** (P10 iff AMOUNT ∧ AUD ∧ CONSENT ∧ PAYEE; no either/or). | Request a mandate the principal did not approve; expect refusal. |
| M2 | (Payment server) check that the mandate names **this** payment server (`aud`). | agent-grants-02 (RS MUSTs); RFC 8707 | P10 | `NO_AUD`: P10 ❌ (12). | **Necessary** for P10. | Present a mandate for another payment server. |
| M3 | (Payment server) check the payee against the mandate. | RFC 9396 `authorization_details` | P10 | `NO_PAYEE_CHECK`: P10 ❌ (12). | **Necessary** for P10. | Pay a payee outside the mandate. |
| M4 | (Payment server) check the amount against the cap. | RFC 9396 | P10 | `NO_AMOUNT_CHECK`: P10 ❌ (12). | **Necessary** for P10. | Pay above the cap. |
| M5 | (Payment server) require proof of possession of the mandate's bound key per payment request. | RFC 9449 (DPoP); agent-grants-02 `cnf` | P12 debit requested by the agent | `NO_SENDER_CONSTRAINT` (bearer use): P12 ❌ (8): a leaked request is re-submitted with a fresh payment id, so a one-time payment-id check does not help. | **Necessary** for P12 only. | Replay a payment request without the agent's signature. |
| M6 | (Payment server) check revocation status online on every payment. | RFC 7009; agent-grants-02 ("when the deployment's risk model requires online state") | P11 no debit after revocation | `NO_REVOCATION_CHECK`: P11 ❌ (14). | **Necessary** for P11 only. The draft makes this optional, so P11 depends on a choice the draft leaves open. | Revoke the mandate, then pay. |

**Payment minimum set:** M1-M4 for P10, M5 for P12, M6 for P11. Each protects a different property; none replaces another. Facts about NPCI UPI Circle rules come from a secondary summary and are not used here.

---

## Counts

| Role | Checks |
|---|---|
| MCP client | 8 (C1-C8) |
| MCP server / RS | 3 (S1-S3) |
| Authorization server | 8 (A1-A8) |
| Proxy server | 2 (X1-X2) |
| Payment server / mandate AS | 6 (M1-M6) |
| **Total** | **27** |

## Where the spec leaves it open

These are questions for review ([spec-gaps.md](spec-gaps.md)), not claims of spec violations.

| Gap | Open point | Checks affected |
|---|---|---|
| G1 | `iss` is a SHOULD for the AS (planned MUST) | A2, C3 |
| G2 | The spec does not say which AS a client should trust for a given MCP server | C1, C3 |
| G3 | AS-binding rule names client credentials, not refresh tokens | C6 |
| G4 | Nothing tells a client whether an AS honours `resource`; broad audiences defeat S1 | A1, S1 |
| G5 | Audience check is a MUST in the spec but opt-in in the patched SDKs until 3.0; no server-side conformance test yet (issue #78) | S1 |
| G6 | One CIMD client identity at many ASes removes the per-AS redirect-URI defence | C3, C7, A5 |
| G7 | `state` is a SHOULD; model shows PKCE or `state` suffices | C4, C5 |
| G8 | Consent screen need not show the resource | A6 |
| G9 | ID-JAG `resource` is OPTIONAL | C8, A8 |

**Not tied to a spec clause (honest list):** C6 (refresh-token binding; standard OAuth practice, MCP names credentials only), C7 and A5 (assertion `aud`; rfc7523bis, MCP draft silent), A6 (per-resource consent; spec silent), A8 and the "send `resource`" half of C8 (spec makes it OPTIONAL), the modelled form of the mandate in M1-M6 (agent-grants-02 has no mandate object), and the unablated assumption that clients send RFC 8707 `resource`. Everything else cites a clause above.

See also [verification-mapping.md](verification-mapping.md) (spec step to model rule), [conformance-test-draft.md](conformance-test-draft.md) (ST-01 to ST-03) and [threat-model.md](threat-model.md) (assumptions).
