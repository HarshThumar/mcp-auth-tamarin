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
| 02 `NO_RESOURCE` | Not a bug report: spec gap G4. The AS ignores RFC 8707 `resource` and issues a token whose audience covers another (honest) MCP server; enables cross-RS token replay (P2 falsified in 8 steps). Holds only for an AS that issues broad audiences; client refusal of such an AS is not modelled. |
| 02 `NO_STATE` | Not a bug report: spec gap G7. The client uses a constant `state`. All 5 lemmas verified: P2 and P3 do not depend on `state`. `state` is public in every variant and CSRF / session integrity are not modelled, so this says nothing about what `state` protects (see results R5). |

Models 03 and 04 are not tied to one advisory. They check spec-level combinations of known defences (RFC 8414 §3.3, RFC 9207, RFC 7523 audience, ID-JAG §4.4.1), and every falsified variant corresponds to a known attack class (results R6–R10).

### Model 02 modelling choices

- One shared honest AS can serve several MCP servers, and every honest MCP server accepts tokens from every honest AS (the setting the audience advisories describe).
- A malicious MCP server can name any AS in its metadata, including the honest one or an attacker-run one whose metadata it controls (`authorization_response_iss_parameter_supported` true or false).
- Some honest user approves any authorization request for an honest client (the usual mix-up assumption: the user is already signed in at the honest AS). Clients are honest public clients with no secret, as with CIMD, so the same `client_id` and redirect URI are used at every AS.
- Authorization requests travel in the front channel and are public. The attacker can send any callback to the client's redirect URI.
- Under `NO_RESOURCE`, the AS ignores `resource`: the code is stored with the placeholder `'any'`, and the token is minted with audience `$AnyRS`, an honest MCP server the model picks freely (not necessarily the requested one). This stands for an AS whose default audience covers other servers. An AS that ignores `resource` but issues tokens with no audience is not modelled.
- Under `NO_STATE`, the client uses the public constant `'no_state'`. Because `state` is sent in the public authorization request in every variant, the attacker always knows it; and there is no dishonest user or session-integrity lemma. So CSRF / login-CSRF, the attacks `state` targets, are out of scope.
- `rs_accepts_only_consented` (P2) only asks that *some* consent for that user and server exists. It does not require the consent to come before the acceptance or to belong to the same token. All users are honest, and "some user approves any request" is assumed.
- `token_secrecy` (P3) is keyed on the audience the client requested, so under `NO_RESOURCE` it does not flag a broad token that reaches the attacker.
- In callback rules, un-tilded `state` is used instead of `~state` so that Tamarin's unification engine can match both fresh session names (`~state`) and constant atoms (`'no_state'`) without type mismatch.
- Codes and access tokens are wrapped in constructors with no destructor (`cd(...)`, `at(...)`), and two `[sources]` lemmas say where the client's codes and tokens come from. Both are needed for termination. The tags rule out **type confusion**, for example a value used as an access token in one place and accepted as a PKCE verifier in another. This is a standard assumption for random opaque strings, and it is the only capability they remove: the attacker can still build `cd(x)` / `at(x)` from anything it knows.
- Not modelled yet: code single-use, refresh tokens, scopes / step-up, DPoP, dishonest users, session integrity (CSRF).

### Model 03 modelling choices (CIMD, client binding)

- AS metadata is a triple: endpoint, claimed `issuer`, `iss` support. An attacker-run AS may claim **any** issuer, including an honest AS's. The client's RFC 8414 §3.3 check is the restriction `MetaIssuer(a, i) ⇒ a = i`.
- Each check is a restriction on one action (`MetaIssuer`, `IssCheck`, `RefreshAt`, `AssertionAud`), so each flag removes exactly one equality and flags combine freely.
- Two client types: confidential CIMD clients use one signing key at every AS (`private_key_jwt`; the assertion is `sign(<'cassert', C, aud, jti>, sk)` with `aud` = the recorded issuer); public CIMD clients (`-D=PUBLIC`) send no assertion. The CIMD document is fetched over HTTPS from the client's own URL, so the client's public key is authentic. Only honest clients exist.
- The honest AS always sends and advertises `iss` (model 02 covers the SHOULD). `state` is left out (model 02 R5).
- Refresh: the AS issues a refresh token with every token. Later the client refreshes at some AS whose metadata it has seen (standing for "the AS the current MCP server names"); the binding check compares the recorded issuers. No rotation and no single-use.
- `client_key_secret` (a `[reuse]` lemma) states the client key never leaks. It is proved, not assumed.
- For the confidential client under `NO_META_CHECK`, the all-traces secrecy lemmas do not terminate, so that variant states the attacks as `exists-trace` lemmas (see results R8).
- Left out: dishonest clients, dishonest users, code single-use, refresh-token rotation, DPoP, expiry, scopes, the browser.

### Model 04 modelling choices (ID-JAG)

- One honest IdP whose signing key never leaks, trusted by every honest RAS. SSO (OIDC/SAML and the ID token) is abstracted into the private channel from the client to the IdP, so the IdP's client authentication and its "ID token audience = client" check are built in. Users only sign in to honest clients.
- Worst-case IdP policy: it issues an ID-JAG for any `audience` and `resource` the honest client asks for.
- Clients are confidential (`private_key_jwt`); the RAS always checks the assertion signature and that its `aud` is the RAS. The attacker may register its own clients. The client sets `resource` to the MCP server it talks to.
- `TokenIssued` records the token's **actual** audience (unlike model 02, where P3 is keyed on the requested one).
- The two RAS checks (`CheckAud`, `CheckClient`) are restrictions switched off by flags.
- Left out: `jti` single-use, expiry, refresh tokens, scopes, DPoP / `cnf`, several IdPs, the `act` claim.
