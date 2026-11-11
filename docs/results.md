# Results

*Model 01 last checked 9 Nov 2026 and model 02 on 11 Nov 2026: Tamarin 1.12.0, Maude 3.5.1 (local WSL run; CI runs the same script).* `scripts/prove.sh` (and CI) checks these expectations automatically: 24/24 pass, about 2 minutes in total. The full Tamarin output is saved in `results/` and uploaded as a CI artifact.

| Model | Variant | Lemma | Expected | Actual | Notes |
|---|---|---|---|---|---|
| 01 | VULNERABLE | executable | verified | ✅ verified | sanity check |
| 01 | VULNERABLE | client_credential_secrecy | **falsified** | ✅ falsified (attack found) | attack: malicious RS names its own AS |
| 01 | fixed | executable | verified | ✅ verified | |
| 01 | fixed | client_credential_secrecy | verified | ✅ verified | credential bound to its AS |
| 02 | all four | code_sources, token_sources | verified | ✅ verified | helper (`[sources]`) lemmas, proved by induction; they make the main lemmas terminate |
| 02 | NO_AUD | executable | verified | ✅ verified (7 steps) | |
| 02 | NO_AUD | rs_accepts_only_consented | **falsified** | ✅ falsified (8 steps) | R1 below: token replayed from a malicious MCP server to an honest one |
| 02 | NO_AUD | token_secrecy | verified | ✅ verified (19 steps) | |
| 02 | NO_ISS | executable | verified | ✅ verified (7 steps) | |
| 02 | NO_ISS | rs_accepts_only_consented | verified | ✅ verified (32 steps) | |
| 02 | NO_ISS | token_secrecy | **falsified** | ✅ falsified (11 steps) | R2 below: AS mix-up despite PKCE |
| 02 | ISS_OPTIONAL | executable | verified | ✅ verified (7 steps) | |
| 02 | ISS_OPTIONAL | rs_accepts_only_consented | verified | ✅ verified (77 steps) | |
| 02 | ISS_OPTIONAL | token_secrecy | **falsified** | ✅ falsified (13 steps) | R3 below: same mix-up when the honest AS omits `iss` |
| 02 | fixed | executable | verified | ✅ verified (7 steps) | |
| 02 | fixed | rs_accepts_only_consented | verified | ✅ verified (30 steps) | audience checked |
| 02 | fixed | token_secrecy | verified | ✅ verified (19 steps) | `iss` always sent and checked |

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

## Modelling notes

- Model 02 needs two `[sources]` lemmas (`code_sources`, `token_sources`), plus tagged codes and tokens (`cd(...)`, `at(...)`). Without them Tamarin loops on "attacker injects a value into the client → client leaks it to a dishonest AS → attacker knows it". The tags have no destructor, so Tamarin's derivation check warns that `code` / `~code` are "not derivable" in the callback and token rules. That warning is expected: those rules deliberately pattern-match on an opaque handle.
