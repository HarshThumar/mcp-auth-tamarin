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

### Model 02 modelling choices

- One shared honest AS can serve several MCP servers, and every honest MCP server accepts tokens from every honest AS (the setting the audience advisories describe).
- A malicious MCP server can name any AS in its metadata, including the honest one or an attacker-run one whose metadata it controls (`authorization_response_iss_parameter_supported` true or false).
- Some honest user approves any authorization request for an honest client (the usual mix-up assumption: the user is already signed in at the honest AS). Clients are honest public clients with no secret, as with CIMD, so the same `client_id` and redirect URI are used at every AS.
- Authorization requests travel in the front channel and are public. The attacker can send any callback to the client's redirect URI.
- Not modelled yet: code single-use, refresh tokens, scopes / step-up, DPoP.
