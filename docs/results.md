# Results

*Model 01 last checked 9 Nov 2026, model 02 on 13 Nov 2026, models 03 and 04 on 14 Nov 2026: Tamarin 1.12.0, Maude 3.5.1 (local WSL run; CI runs the same script).* `scripts/prove.sh` (and CI) checks these expectations automatically: 159/159 pass, about 17 minutes locally. The full Tamarin output is saved in `results/` and uploaded as a CI artifact.

| Model | Variant | Lemma | Expected | Actual | Notes |
|---|---|---|---|---|---|
| 01 | VULNERABLE | executable | verified | ✅ verified | sanity check |
| 01 | VULNERABLE | client_credential_secrecy | **falsified** | ✅ falsified (attack found) | attack: malicious RS names its own AS |
| 01 | fixed | executable | verified | ✅ verified | |
| 01 | fixed | client_credential_secrecy | verified | ✅ verified | credential bound to its AS |
| 02 | all six | code_sources, token_sources | verified | ✅ verified | helper (`[sources]`) lemmas, proved by induction; they make the main lemmas terminate |
| 02 | NO_AUD | executable | verified | ✅ verified (7 steps) | |
| 02 | NO_AUD | rs_accepts_only_consented | **falsified** | ✅ falsified (8 steps) | R1 below: token replayed from a malicious MCP server to an honest one |
| 02 | NO_AUD | token_secrecy | verified | ✅ verified (19 steps) | |
| 02 | NO_ISS | executable | verified | ✅ verified (7 steps) | |
| 02 | NO_ISS | rs_accepts_only_consented | verified | ✅ verified (32 steps) | |
| 02 | NO_ISS | token_secrecy | **falsified** | ✅ falsified (11 steps) | R2 below: AS mix-up despite PKCE |
| 02 | ISS_OPTIONAL | executable | verified | ✅ verified (7 steps) | |
| 02 | ISS_OPTIONAL | rs_accepts_only_consented | verified | ✅ verified (77 steps) | |
| 02 | ISS_OPTIONAL | token_secrecy | **falsified** | ✅ falsified (13 steps) | R3 below: same mix-up when the honest AS omits `iss` |
| 02 | NO_RESOURCE | executable | verified | ✅ verified (7 steps) | |
| 02 | NO_RESOURCE | rs_accepts_only_consented | **falsified** | ✅ falsified (8 steps) | R4 below: AS ignores `resource`, enabling cross-RS replay |
| 02 | NO_RESOURCE | token_secrecy | verified | ✅ verified (19 steps) | |
| 02 | NO_STATE | executable | verified | ✅ verified (6 steps) | |
| 02 | NO_STATE | rs_accepts_only_consented | verified | ✅ verified (30 steps) | R5 below: P2/P3 do not depend on `state` |
| 02 | NO_STATE | token_secrecy | verified | ✅ verified (19 steps) | |
| 02 | fixed | executable | verified | ✅ verified (7 steps) | |
| 02 | fixed | rs_accepts_only_consented | verified | ✅ verified (30 steps) | audience checked |
| 02 | fixed | token_secrecy | verified | ✅ verified (19 steps) | `iss` always sent and checked |

*Note on lemma count: The 34 individual expectations checked by `scripts/prove.sh` comprise: 4 for Model 01 (2 lemmas × 2 variants) + 30 for Model 02 (5 lemmas × 6 variants: `code_sources`, `token_sources`, `executable`, `rs_accepts_only_consented`, `token_secrecy`).*

### Model 03: one CIMD client identity at many ASes (14 Nov 2026)

P3 = `token_secrecy`, P4 = `refresh_token_secrecy`. In every variant below, the helper lemmas (`client_key_secret`, three `[sources]` lemmas), `executable`, `executable_refresh` and P2 (`rs_accepts_only_consented`) are verified. Numbers are proof steps.

| Client | Checks removed | P3 | P4 | Write-up |
|---|---|---|---|---|
| confidential (`private_key_jwt`) | none | ✅ verified (84) | ✅ verified (22) | combined binding rule holds |
| confidential | `NO_ISS` | ✅ verified (92) | ✅ verified (25) | R6: assertion `aud` alone stops mix-up |
| confidential | `AS_NO_ASSERTION_AUD` | ✅ verified (99) | ✅ verified (22) | `iss` alone stops mix-up |
| confidential | `NO_ISS` + `AS_NO_ASSERTION_AUD` | ❌ falsified (13) | ❌ falsified (11) | R6 |
| confidential | `RT_UNBOUND` | ✅ verified (139) | ❌ falsified (9) | R7: refresh token leaks but is useless |
| confidential | `RT_UNBOUND` + `AS_NO_ASSERTION_AUD` | ❌ falsified (10) | ❌ falsified (9) | R7 |
| confidential | `NO_META_CHECK` | ❌ attack trace found (14) | ❌ attack trace found (9) | R8 |
| public (`none`) | none | ✅ verified (72) | ✅ verified (19) | combined binding rule holds |
| public | `NO_ISS` | ❌ falsified (8) | ❌ falsified (8) | as model 02 R2 |
| public | `NO_META_CHECK` | ❌ falsified (8) | ❌ falsified (8) | R8 |
| public | `RT_UNBOUND` | ❌ falsified (8) | ❌ falsified (8) | R7 |

### Model 04: Enterprise-Managed Authorization / ID-JAG (14 Nov 2026)

P2 = `rs_accepts_only_authorized`, P2' = `rs_accepts_only_requested`, P3 = `token_secrecy`, P4 = `ras_grant_agreement`. `token_sources` and `executable` are verified in every variant.

| Variant | P2 | P2' | P3 | P4 | Write-up |
|---|---|---|---|---|---|
| fixed | ✅ (20) | ✅ (20) | ✅ (16) | ✅ (13) | |
| `NO_IDJAG_AUD` | ✅ | ✅ | ✅ | ✅ | R9: client binding alone suffices |
| `NO_CLIENT_BINDING` | ✅ | ✅ | ✅ | ✅ | R9: ID-JAG `aud` alone suffices |
| `NO_IDJAG_AUD` + `NO_CLIENT_BINDING` | ✅ | ✅ | ✅ | ❌ falsified (10) | R9: cross-RAS ID-JAG replay |
| `NO_RESOURCE_CLAIM` | ❌ (by definition) | ❌ falsified (6) | ❌ falsified (8) | ✅ | R10 |

## Findings and open questions

None of these is a new vulnerability. Each one is the model **rediscovering a published, already-fixed bug or a known attack class** when the relevant check is removed, which shows the abstraction is fine-grained enough to see real bugs.

### R1 (11 Nov 2026): token accepted by the wrong MCP server
- **Model + lemma:** 02 `-D=NO_AUD`, `rs_accepts_only_consented` falsified.
- **What the spec says:** "MCP servers **MUST** validate that access tokens were issued specifically for them as the intended audience, according to RFC 8707 Section 2." ([MCP authorization, Token Handling](https://modelcontextprotocol.io/specification/draft/basic/authorization))
- **What the model shows:** a malicious MCP server names the shared honest AS in its metadata. The user's client gets a token whose audience is the malicious server and sends it there. The malicious server replays the token to an honest MCP server, which accepts it because it does not check the audience. The user never agreed to access that honest server.
- **Is it new?** No. It is the bug in [GHSA-w4fh-qvv9-3v23](https://github.com/advisories/GHSA-w4fh-qvv9-3v23) (Python SDK, CVE-2026-116684) and [GHSA-rvq5-wwqv-78pq](https://github.com/advisories/GHSA-rvq5-wwqv-78pq) (TypeScript SDK, CVE-2026-111771). Both fixes are **opt-in** (`validate_token_resource` / `expectedResource`).
- **Next step:** server-side audience test for the official conformance suite ([issue #78](https://github.com/modelcontextprotocol/conformance/issues/78)), after coordinating with the Conformance WG.

### R2 (11 Nov 2026): AS mix-up despite PKCE
- **Model + lemma:** 02 `-D=NO_ISS`, `token_secrecy` falsified.
- **What the spec says:** clients "**MUST** apply the validation in RFC9207 Section 2.4 before transmitting the authorization code to any token endpoint." (MCP authorization, Authorization Response Validation)
- **What the model shows:** a malicious MCP server names an attacker-run AS. The attacker passes the client's authorization request (with the client's PKCE challenge) on to the honest AS, and the honest AS sends the code to the client. A client that ignores `iss` sends the code **and its PKCE verifier** to the attacker's token endpoint. The attacker redeems both at the honest AS and gets a token for an honest MCP server. PKCE does not help, because the attacker receives the verifier too.
- **Is it new?** No. It is the AS mix-up attack ([RFC 9700 §4.4](https://datatracker.ietf.org/doc/html/rfc9700#section-4.4)), and RFC 9207 is its fix. The MCP-specific twist is how the attacker gets in: the MCP server, not the user, picks the AS.
- **Next step:** client-side `iss` test (check whether the conformance suite already has one).

### R3 (11 Nov 2026): mix-up still possible under the draft's current wording
- **Model + lemma:** 02 `-D=ISS_OPTIONAL`, `token_secrecy` falsified.
- **What the spec says:** "MCP authorization servers **SHOULD** include the `iss` parameter in authorization responses". If metadata does not advertise `authorization_response_iss_parameter_supported` and `iss` is absent, the client action is "Proceed". The draft adds: "A future revision of this specification is expected to upgrade authorization server inclusion of `iss` from **SHOULD** to **MUST**."
- **What the model shows:** if the honest AS follows the SHOULD loosely and omits `iss`, the attacker-run AS also advertises no `iss` support. The client then cannot tell which AS answered, and R2's attack works again even for a client that implements the table correctly. With `iss` always sent and checked (the fixed variant), the property is verified.
- **Is it new?** No. It is a known limitation of RFC 9207 (it only protects when the honest AS sends `iss`), and the MCP draft already plans the upgrade. The model gives machine-checked evidence for that planned change. Note too that with Client ID Metadata Documents the client uses the same `client_id` and redirect URI at every AS, so the older mix-up defence (a distinct redirect URI per AS) is not there by default.
- **Next step:** list it in [spec-gaps.md](spec-gaps.md). Possibly a short supporting comment where the SHOULD→MUST change is discussed.

### R4 (13 Nov 2026): an AS that ignores `resource` and issues broad audiences enables cross-RS token reuse
- **Model + lemma:** 02 `-D=NO_RESOURCE`, `rs_accepts_only_consented` falsified (8 steps).
- **What the spec says:** RFC 8707 binds tokens to audiences "**when the Authorization Server supports the capability**" (MCP Security Considerations, Token Audience Binding). MCP clients "**MUST** send this parameter regardless of whether authorization servers support it" (MCP Authorization, Resource Parameter Implementation). The spec does **not** tell clients to refuse an AS that lacks RFC 8707 support, and there is no standard AS metadata field that advertises it.
- **What the model shows:** the AS ignores the requested `resource` and mints a token whose audience is *some honest MCP server* (`$AnyRS`, chosen freely by the model), i.e. a broad audience that covers the victim. A malicious MCP server receives the token from the client and replays it to that honest server, whose audience check passes. The user only consented to the malicious server.
- **Scope of the result:** the attack needs an AS whose default audience covers other servers (e.g. "all APIs behind this AS"). If an AS that ignores `resource` issues tokens with **no** audience, a strictly checking MCP server rejects them and this trace does not apply. The model has no rule for a client refusing such an AS, so it does not prove that clients must refuse one; it shows that audience checks at the MCP server cannot compensate for an AS that issues broad audiences.
- **Is it new?** No. It formalizes open spec gap G4 from [docs/spec-gaps.md](spec-gaps.md), the documented RFC 8707 caveat.
- **Modelling note:** `token_secrecy` is keyed on the audience the client *requested*, so it stays verified here even though the attacker holds a token that the honest server accepts. P2 is the lemma that catches this variant.
- **Next step:** a question for review: should the spec say how a client can tell whether an AS honours `resource`? Not turned into a conformance test (see [conformance-test-draft.md](conformance-test-draft.md)).

### R5 (13 Nov 2026): P2 and P3 do not depend on the `state` parameter
- **Model + lemma:** 02 `-D=NO_STATE`, all 5 lemmas verified (`executable` in 6 steps, `rs_accepts_only_consented` in 30 steps, `token_secrecy` in 19 steps).
- **What the spec says:** "MCP clients **SHOULD** use and verify state parameters in the authorization code flow and discard any results that do not include or have a mismatch with the original state." (MCP Security Considerations, Open Redirection)
- **What the model shows:** with the client using the public constant `'no_state'`, P2 (`rs_accepts_only_consented`) and P3 (`token_secrecy`) still hold, as long as PKCE is enforced and `iss` is always sent and checked.
- **Limits of this result (read before citing it):**
  1. In **every** variant, `state` travels in the public front-channel authorization request, so the Dolev-Yao attacker always knows it. `state` therefore gives no protection in the fixed variant either, and `NO_STATE` differs from fixed only in that the value is a constant. The result is "P2/P3 never relied on `state`", not "removing `state` was shown safe".
  2. The model has **no dishonest user** and **no session-integrity lemma** (e.g. "the token a client ends up with belongs to the user who started the session"). The attacks `state` is meant to stop (CSRF, injection of the attacker's own code to log the victim into the attacker's account) are therefore **not modelled**, and this result says nothing about them.
- **Is it new?** No. It is consistent with OAuth 2.1 / RFC 9700, which say PKCE can take over `state`'s CSRF role; the model does not test that claim.
- **Next step (open):** add a dishonest user and a session-integrity lemma so G7 becomes a real test of `state` vs PKCE.

### Model 03 summary: one rule that binds a client to its AS
With both client types modelled together, the fixed variant verifies every property once **all** of the following hold:
1. the client validates the metadata `issuer` (RFC 8414 §3.3) and records it;
2. it checks `iss` in the authorization response against that recorded issuer (RFC 9207);
3. it sends a stored refresh token only to the issuer it came from;
4. the MCP server checks the token audience (RFC 8707);
5. for confidential clients, the client assertion's `aud` is the recorded issuer and the AS checks it.

The variant table shows which checks are needed for which client. For a **public** client, removing any one of 1–3 breaks P3. For a **confidential** client, checks 2 and 5 back each other up, so only removing both breaks P3. Check 1 is needed for both client types (R8). This is a modelling result about the spec, not about any implementation.

### R6 (14 Nov 2026): with `private_key_jwt`, the assertion audience stops AS mix-up even without `iss`
- **Model + lemmas:** 03, confidential client. `-D=NO_ISS`: P3 and P4 verified. `-D=NO_ISS -D=AS_NO_ASSERTION_AUD`: P3 falsified (13 steps), P4 falsified (11 steps).
- **What the model shows:** in the R2 mix-up, the client sends the code, the PKCE verifier **and a client assertion** to the attacker's AS. The assertion's `aud` is the attacker AS's issuer, so the honest AS rejects it when the attacker replays it. Mix-up only succeeds if the client skips `iss` **and** the honest AS does not check the assertion audience. Public clients have no assertion, so for them `iss` is the only defence (public `NO_ISS`: falsified in 8 steps, as in R2).
- **Why this is CIMD-specific:** with a CIMD client, the same `client_id` and signing key are used at every AS, including one an untrusted MCP server names. Assertions signed for an attacker-run AS are therefore valid signatures that could be replayed anywhere, and the audience check is what makes them useless elsewhere.
- **Is it new?** No. It is the setting of the audience-injection attacks on `private_key_jwt` (Hosseyni, Küsters, Würtele, 2025) and the fix in draft-ietf-oauth-rfc7523bis (the assertion `aud` is the AS issuer). The model shows how that fix interacts with RFC 9207 in MCP's "server picks the AS" setting.

### R7 (14 Nov 2026): refresh tokens and the AS-binding rule
- **Model + lemmas:** 03 `-D=RT_UNBOUND`. Confidential: P4 falsified (9 steps), P3 verified. Confidential plus `AS_NO_ASSERTION_AUD`: P3 falsified (10 steps). Public: P3 and P4 falsified (8 steps each).
- **What the spec says:** "Clients that use pre-registered credentials, or persist client credentials obtained via Dynamic Client Registration, **MUST** associate those credentials with the specific authorization server that issued them, keyed by the authorization server's `issuer` identifier." (Client Registration, Authorization Server Binding.) The rule names client credentials; refresh tokens are not mentioned. CIMD client IDs are described as "portable across authorization servers".
- **What the model shows:** a client that sends its stored refresh token to whatever AS the current MCP server names leaks it to an attacker-run AS. For a public client that alone gives the attacker access tokens for the honest MCP server. For a confidential client the leaked refresh token is useless on its own, because the honest AS also requires a client assertion addressed to it.
- **Is it new?** No. Not sending a token to the wrong issuer is standard OAuth practice, and the 2026 SDK advisories on credential binding are of the same family. The open question is spec wording: should the AS-binding rule name refresh tokens explicitly (spec gap G3)?

### R8 (14 Nov 2026): an unvalidated metadata `issuer` defeats `iss` and the assertion audience at once
- **Model + lemmas:** 03 `-D=NO_META_CHECK`. Public: P3 and P4 falsified (8 steps each). Confidential: attack traces for P3 (14 steps) and P4 (9 steps).
- **What the spec says:** the client "**MUST** record the `issuer` value from the selected authorization server's validated metadata document … it provides no protection if the expected issuer was obtained from an unvalidated source." (Authorization Response Validation.)
- **What the model shows:** an attacker-run AS publishes metadata whose `issuer` is the honest AS's issuer. A client that records it without the RFC 8414 §3.3 check accepts the honest AS's `iss` while talking to the attacker's endpoints, and (confidential clients) signs its assertions with `aud` = the honest AS. Both defences from R6 then fail together. The refresh-token trace (9 steps) is exactly this: the client refreshes at the attacker's AS, which claims the honest issuer, and leaks the refresh token and an assertion valid at the honest AS.
- **Termination:** for the confidential client the all-traces P3/P4 lemmas did not terminate (10 min each, several heuristics tried). That variant instead states the attacks as `exists-trace` lemmas: `refresh_token_secrecy_attack` (9 steps) and `token_secrecy_attack` (14 steps; it asks for the stolen token to come from a refresh, which narrows the search; the search takes about 11 minutes locally). A found trace is a counterexample to the all-traces lemma, so the result is the same; only the proof style differs.
- **Is it new?** No. The spec already warns about it, and RFC 8414 §3.3 exists for this reason. The model gives a machine-checked trace for the warning.

### R9 (14 Nov 2026): ID-JAG: either RAS check alone stops cross-RAS replay
- **Model + lemma:** 04. `-D=NO_IDJAG_AUD` and `-D=NO_CLIENT_BINDING` alone: all verified. Both together: `ras_grant_agreement` (P4) falsified (10 steps).
- **What the spec says:** the RAS "MUST" check that the ID-JAG `aud` is its own issuer, and "MUST" reject it unless the `client_id` claim identifies the authenticated client (draft-ietf-oauth-identity-assertion-authz-grant-06 §4.4.1).
- **What the model shows:** a malicious MCP server names an attacker-run RAS. The honest client gets an ID-JAG for it and sends it there; the attacker replays it at an honest RAS while authenticating as its own client. With both checks off, the honest RAS issues a token for the user to the attacker's client. Either check alone stops it: the `aud` check rejects the foreign ID-JAG, and client binding rejects it because the attacker cannot authenticate as the honest client (its assertions are bound to the attacker RAS). P3 stays verified because the replayed ID-JAG names the attacker's MCP server as `resource`.
- **Is it new?** No. It is the replay/audience-injection class the draft's checks are written against; the model shows the two checks are redundant with each other in this setting.

### R10 (14 Nov 2026): ID-JAG `resource` is OPTIONAL
- **Model + lemmas:** 04 `-D=NO_RESOURCE_CLAIM`: P2' falsified (6 steps), P3 falsified (8 steps).
- **What the spec says:** `resource` in the token exchange and in the ID-JAG is OPTIONAL. The MCP profile says the access token "MUST be audience-restricted to the MCP Server" identified by the ID-JAG's `resource` claim, but does not say what happens when the claim is absent.
- **What the model shows:** a client talking to a malicious MCP server omits `resource`. If the RAS then issues a broad token whose audience covers an honest MCP server (the same assumption as R4), the malicious server receives it and replays it there.
- **Scope:** as in R4, this needs a RAS that issues broad audiences when `resource` is absent. P2 is falsified by definition here (it asks for an ID-JAG naming the server, which never exists), so P2' is the meaningful lemma.
- **Is it new?** No; it is G4 again, in the enterprise profile. New spec question G9: should the MCP profile make `resource` REQUIRED?

## Modelling notes

- Model 02 needs two `[sources]` lemmas (`code_sources`, `token_sources`), plus tagged codes and tokens (`cd(...)`, `at(...)`). Without them Tamarin loops on "attacker injects a value into the client → client leaks it to a dishonest AS → attacker knows it". The tags have no destructor, so Tamarin's derivation check warns that `code` / `~code` are "not derivable" in the callback and token rules. That warning is expected: those rules deliberately pattern-match on an opaque handle.
