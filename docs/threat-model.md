# Threat model and modelling choices

## Attacker

- **Network:** Dolev-Yao. The attacker reads, blocks, modifies and injects all messages on public channels, including every metadata document (protected resource metadata, AS metadata, client metadata documents).
- **Malicious parties:** the attacker can run its own MCP servers and authorization servers (`Compromise_AS` rule), and can register as a client.
- **Honest parties:** an honest AS or honest MCP server follows the spec and talks over TLS. TLS is modelled as a private channel to the named endpoint.
- **Cryptography is perfect** (symbolic model): no hash collisions, no forged signatures without the key.

## What the models leave out (for now)

| Simplification | Why | Revisit |
|---|---|---|
| Credential = one fresh secret | Covers client_secret, code_verifier and signed assertions for P1 | Split them in model 02 |
| No browser model | Tamarin cannot catch browser-level attacks, unlike the Web Infrastructure Model | Note it as a limit in results |
| No time or expiry | Token lifetime is not needed for P1–P3 | DPoP/expiry later |
| DPoP and multi-hop `act` left out | Keep the state space small until the base models work | After model 04 |
| Single spec version | Specs are changing (CIMD, ID-JAG are drafts) | Pin the version in each model's header |

## Validating the models against reality

Each model should **rediscover a known, already-fixed issue** when the fix is removed (`-D=VULNERABLE`), and verify the property when the fix is present. This checks that the abstraction is not too coarse to see real bugs.

| Model | Known issue used as ground truth |
|---|---|
| 01 | [GHSA-qx49-fqc8-xw99](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-qx49-fqc8-xw99): credentials not bound to their AS |
| 02 `NO_AUD` | [GHSA-w4fh-qvv9-3v23](https://github.com/advisories/GHSA-w4fh-qvv9-3v23) (Python SDK, CVE-2026-116684) / [GHSA-rvq5-wwqv-78pq](https://github.com/advisories/GHSA-rvq5-wwqv-78pq) (TypeScript SDK, CVE-2026-111771): server accepts tokens issued for another resource (confirmed 11 Nov 2026) |
| 02 `NO_ISS` | AS mix-up attack ([RFC 9700 §4.4](https://datatracker.ietf.org/doc/html/rfc9700#section-4.4), [RFC 9207](https://datatracker.ietf.org/doc/rfc9207/)): PKCE alone does not stop it |
| 02 `ISS_OPTIONAL` | Not a bug report: checks the MCP draft's current text, where the AS only SHOULD send `iss` and the client proceeds when `iss` is absent and not advertised. This is a known RFC 9207 limitation, and the draft already says a future revision is expected to make `iss` a MUST |
| 02 `NO_RESOURCE` | Spec gap G4: AS ignores RFC 8707 Resource Indicators and issues broad tokens; enables cross-RS token replay (P2 falsified in 8 steps). Proves client MUST refuse an AS lacking RFC 8707 support. |
| 02 `NO_STATE` | Spec gap G7: Client omits session-specific `state` parameter (uses constant atom). All 5 lemmas verified (P2 and P3 hold). Confirms RFC 9700 §4.4.1 / OAuth 2.1 finding that PKCE + RFC 9207 `iss` cryptographically protect against authorization code injection and mix-up. |

### Model 02 modelling choices

- One shared honest AS can serve several MCP servers, and every honest MCP server accepts tokens from every honest AS (the setting the audience advisories describe).
- A malicious MCP server can name any AS in its metadata, including the honest one or an attacker-run one whose metadata it controls (`authorization_response_iss_parameter_supported` true or false).
- Some honest user approves any authorization request for an honest client (the usual mix-up assumption: the user is already signed in at the honest AS). Clients are honest public clients with no secret, as with CIMD, so the same `client_id` and redirect URI are used at every AS.
- Authorization requests travel in the front channel and are public. The attacker can send any callback to the client's redirect URI.
- Under `NO_RESOURCE`, the AS treats `resource` as optional or unsupported, minting tokens with generic audience `'any'`, and honest RS accepts it, enabling cross-RS replay.
- Under `NO_STATE`, the client uses the public constant `'no_state'`, confirming that session binding and CSRF protection in the Dolev-Yao model are handled by PKCE and `iss`.
- In callback rules, un-tilded `state` is used instead of `~state` so that Tamarin's unification engine can match both fresh session names (`~state`) and constant atoms (`'no_state'`) without type mismatch.
- Codes and access tokens are wrapped in constructors with no destructor (`cd(...)`, `at(...)`), and two `[sources]` lemmas say where the client's codes and tokens come from. Both are needed for termination. The tags rule out **type confusion**, for example a value used as an access token in one place and accepted as a PKCE verifier in another. This is a standard assumption for random opaque strings, and it is the only capability they remove: the attacker can still build `cd(x)` / `at(x)` from anything it knows.
- Not modelled yet: code single-use, refresh tokens, scopes / step-up, DPoP.
