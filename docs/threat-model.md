# Threat model and modelling choices

## Attacker

- **Network:** Dolev-Yao. The attacker reads, blocks, modifies and injects all messages on public channels, including every metadata document (protected resource metadata, AS metadata, client metadata documents).
- **Malicious parties:** the attacker can run its own MCP servers and authorization servers. In models 02–04 it can also register its own clients, which obtain real codes and tokens at honest servers. In models 02 and 04 it also controls some user accounts (`User_Dishonest`). Model 01 has only attacker-run ASes, whose metadata may claim any issuer.
- **Honest parties:** an honest AS or honest MCP server follows the spec and talks over TLS. TLS is modelled as a private channel to the named endpoint.
- **Cryptography is perfect** (symbolic model): no hash collisions, no forged signatures without the key.
- **Well-formedness:** every model passes all of Tamarin's well-formedness checks, including the full message-derivation check (`--derivcheck-timeout=0`). `scripts/prove.sh` fails if any warning appears.

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
| 01 | [GHSA-qx49-fqc8-xw99](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-qx49-fqc8-xw99): credentials not bound to their AS (`VULNERABLE`). `UNVALIDATED_ISSUER` is not a bug report: a binding keyed by an issuer taken from unvalidated metadata (R0) |
| 02 `NO_AUD` | [GHSA-w4fh-qvv9-3v23](https://github.com/advisories/GHSA-w4fh-qvv9-3v23) (Python SDK, CVE-2026-116684) / [GHSA-rvq5-wwqv-78pq](https://github.com/advisories/GHSA-rvq5-wwqv-78pq) (TypeScript SDK, CVE-2026-111771): server accepts tokens issued for another resource (confirmed 11 Nov 2026) |
| 02 `NO_ISS` | AS mix-up attack ([RFC 9700 §4.4](https://datatracker.ietf.org/doc/html/rfc9700#section-4.4), [RFC 9207](https://datatracker.ietf.org/doc/rfc9207/)): PKCE alone does not stop it |
| 02 `ISS_OPTIONAL` | Not a bug report: checks the MCP draft's current text, where the AS only SHOULD send `iss` and the client proceeds when `iss` is absent and not advertised. This is a known RFC 9207 limitation, and the draft already says a future revision is expected to make `iss` a MUST |
| 02 `NO_RESOURCE` | Not a bug report: spec gap G4. The AS ignores RFC 8707 `resource` and issues a token whose audience covers another (honest) MCP server; enables cross-RS token replay (P2 falsified in 8 steps). Holds only for an AS that issues broad audiences; client refusal of such an AS is not modelled. |
| 02 `NO_STATE` / `NO_PKCE` | Not a bug report: spec gap G7. Code injection / login CSRF (RFC 9700 §4.5, §4.7): session integrity (P6) holds with `state` alone or PKCE alone, and fails only when both are removed (results R5). |

Models 03 and 04 are not tied to one advisory. They check spec-level combinations of known defences (RFC 8414 §3.3, RFC 9207, RFC 7523 audience, ID-JAG §4.4.1), and every falsified variant corresponds to a known attack class (results R6–R10).

### Model 02 modelling choices

- One shared honest AS can serve several MCP servers, and every honest MCP server accepts tokens from every honest AS (the setting the audience advisories describe).
- A malicious MCP server can name any AS in its metadata, including the honest one or an attacker-run one whose metadata it controls (`authorization_response_iss_parameter_supported` true or false).
- **Browser channel.** Each client session belongs to one user `U`. The session's authorization request reaches the AS through `U`'s browser over HTTPS, modelled as the private fact `Browser(AS, U, request)`: the network does not see that session's `state` or PKCE challenge. An attacker-run AS receives the request and leaks it (`Dishonest_AS_Leaks_Authz`).
- **Attacker-built requests.** The attacker can also send any authorization request to an honest AS. This stands for a victim's browser that the attacker redirects (as in mix-up): some honest user approves it, and the code goes to the client's redirect URI. The attacker can send any callback to the client's redirect URI (CSRF).
- **Attacker accounts and clients.** Attacker-controlled users (`User_Dishonest`) authorize any client in the attacker's own browser, so the attacker gets genuine codes for its own accounts, bound to a PKCE challenge it chooses. Attacker-run clients get codes and tokens for users who consent to them. Clients are public (no secret), so the attacker can also use an honest client's `client_id` for its own account.
- **PKCE** is the restriction `PkceCheck(challenge, h(verifier))`; `NO_PKCE` removes it. **Codes are single-use**: the AS consumes the code record (lemma `code_single_use`). The attacks found never needed code reuse.
- **Redirect URI.** The honest AS always sends the code to the client's registered redirect URI (`ToClient`). `NO_REDIRECT_CHECK` adds `AS_Authorize_Open_Redirect`: an attacker-built request with the attacker's redirect URI, approved by an honest user, sends the code to the attacker (R11).
- Under `NO_RESOURCE`, the code records the requested resource, but the token endpoint ignores it and mints the token with audience `$AnyRS`, an honest MCP server the model picks freely (not necessarily the requested one). This stands for an AS whose default audience covers other servers. An AS that ignores `resource` but issues tokens with no audience is not modelled.
- Under `NO_STATE`, the client uses the public constant `'no_state'`.
- `rs_accepts_only_consented` (P2) only asks that *some* consent for that user and server exists. It does not require the consent to come before the acceptance or to belong to the same token.
- `token_secrecy` (P3) covers tokens for honest users, honest clients and honest MCP servers. It is keyed on the audience the client requested, so under `NO_RESOURCE` it does not flag a broad token that reaches the attacker (P2 does).
- `session_integrity` (P6): if an honest user's client session with an honest AS ends with a token, that AS issued the token for that user and that client. It does not cover sessions the client starts with an attacker-run AS (those are P3's job).
- Codes and access tokens are tagged (`cd(...)`, `at(...)`) with public destructors (`uncd`, `unat`), so the tags hide nothing. Two `[sources]` lemmas say where the client's codes and tokens come from; both are needed for termination. The tags rule out **type confusion**, for example a value used as an access token in one place and accepted as a PKCE verifier in another. This is a standard assumption for random opaque strings.
- Not modelled: refresh tokens (see model 03), scopes / step-up, DPoP, expiry, browser internals (cookies, origins, open redirectors).

### Model 03 modelling choices (CIMD, client binding)

- AS metadata is a triple: endpoint, claimed `issuer`, `iss` support. An attacker-run AS may claim **any** issuer, including an honest AS's. The client's RFC 8414 §3.3 check is the restriction `MetaIssuer(a, i) ⇒ a = i`.
- Each check is a restriction on one action (`MetaIssuer`, `IssCheck`, `RefreshAt`, `AssertionAud`), so each flag removes exactly one equality and flags combine freely.
- Two client types: confidential CIMD clients use one signing key at every AS (`private_key_jwt`; the assertion is the message `<'cassert', C, aud, jti>` plus its signature, with `aud` = the recorded issuer, and the AS checks it with `verify`); public CIMD clients (`-D=PUBLIC`) send no assertion. The CIMD document is fetched over HTTPS from the client's own URL, so the client's public key is authentic.
- The attacker also runs its own CIMD clients (its own key), which get real codes, tokens and refresh tokens at honest ASes. P3/P4 are stated for honest clients.
- The honest AS always sends and advertises `iss` (model 02 covers the SHOULD). `state`, users and session integrity are left out here; model 02 covers them (R5).
- Refresh: the AS issues a refresh token with every token. Later the client refreshes at some AS whose metadata it has seen (standing for "the AS the current MCP server names"); the binding check compares the recorded issuers. No rotation and no single-use.
- `client_key_secret` (a `[reuse]` lemma) states the client key never leaks. It is proved, not assumed.
- For the confidential client under `NO_META_CHECK`, and under `RT_UNBOUND` + `AS_NO_ASSERTION_AUD`, the all-traces secrecy lemmas do not terminate. Those two variants state the attacks as `exists-trace` lemmas and leave out the attacker-run clients, which the attacks do not use (with them, the search did not finish in 25 min). Removing rules only removes traces, so each attack found is also an attack on the full model (see results R8).
- Codes are single-use (lemma `code_single_use`); tags have public destructors, as in model 02.
- Left out: refresh-token rotation, DPoP, expiry, scopes, the browser, session integrity (see model 02).

### Model 04 modelling choices (ID-JAG)

- One honest IdP whose signing key never leaks, trusted by every honest RAS. SSO (OIDC/SAML and the ID token) is abstracted into the private channel from the client to the IdP, so the IdP's client authentication and its "ID token audience = client" check are built in. Honest users only sign in to honest clients; attacker-controlled users (`User_Dishonest`) also sign in to attacker-run clients, which then hold genuine ID-JAGs. P2' and P4 are stated for honest users.
- Worst-case IdP policy: it issues an ID-JAG for any `audience` and `resource` the honest client asks for.
- Clients are confidential (`private_key_jwt`); the RAS always checks the assertion signature and that its `aud` is the RAS. The attacker may register its own clients. The client sets `resource` to the MCP server it talks to.
- `TokenIssued` records the token's **actual** audience (unlike model 02, where P3 is keyed on the requested one).
- The two RAS checks (`CheckAud`, `CheckClient`) are restrictions switched off by flags.
- Left out: `jti` single-use (no replay cache; leaving it out only strengthens the attacker, so verified results carry over), expiry, refresh tokens, scopes, DPoP / `cnf`, several IdPs, the `act` claim.
