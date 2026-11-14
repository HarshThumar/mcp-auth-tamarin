# Verification Mapping: RFC Specifications ↔ Tamarin Formal Model

This document provides the Domain-Driven Design (DDD) traceability matrix between the **Model Context Protocol (MCP) Authorization draft / IETF RFCs** and the exact formal multiset rewriting rules in `models/`.

---

## 1. Ubiquitous Language & Entity Map

| Domain Concept | RFC / Spec Reference | Tamarin Fact / Representation | Semantics |
|---|---|---|---|
| **Client (C)** | OAuth 2.1 / RFC 7591 | `$C` | Public MCP client (e.g. AI agent IDE, desktop client) |
| **Resource Server (RS)** | RFC 9728 / MCP Server | `$RS` | The tool provider endpoint; may be honest or malicious |
| **Authorization Server (AS)** | RFC 8414 / RFC 9207 | `$AS` | Token-issuing authority; may be honest or attacker-run |
| **User (U)** | OAuth 2.1 | `$U` in `Consent($U, $C, $RS, $AS)` | Resource owner approving authorization requests |
| **Protected Resource Metadata (PRM)** | RFC 9728 §5.1 | `!PRM($RS, $AS)` | RS advertising its chosen AS to the client |
| **Client Credential** | RFC 7591 / GHSA-qx49-fqc8-xw99 | `!ClientCred($C, $AS, ~cred)` | Fresh secret bound to a specific AS |
| **Authorization Code** | OAuth 2.1 §4.1.2 | `cd(~code)` | Opaque handle tagged constructor `cd/1` |
| **Code Verifier / Challenge** | RFC 7636 (PKCE) | `~ver`, `h(~ver)` | S256 code challenge |
| **Resource Indicator** | RFC 8707 | `$RS` parameter in auth & token req | Scope/audience target URI |
| **Issuer Parameter** | RFC 9207 §2 | `$AS` in redirect response | AS identity parameter preventing mix-up |
| **Access Token** | OAuth 2.1 §1.4 / RFC 8707 §2 | `at(~tok)` | Bearer token tagged constructor `at/1` |

---

## 2. Protocol Step ↔ Rule Traceability Matrix

### Model 01 (`models/01_as_selection.spthy`)
*Focus: Credential isolation and Authorization Server discovery binding ([GHSA-qx49-fqc8-xw99](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-qx49-fqc8-xw99)).*

| Step # | Protocol Action | RFC / Spec | Exact Tamarin Rule | State Preconditions & Effects |
|---|---|---|---|---|
| S1.1 | AS setup and metadata | RFC 8414 | `Setup_Honest_AS`, `Setup_Dishonest_AS` | Honest AS metadata names itself as `issuer`; attacker-run AS metadata claims any issuer `$I`. |
| S1.2 | Client registers with honest AS | RFC 7591 §3, MCP Client Registration | `Register_Client` | Generates fresh credential `~cred`, stored under the AS issuer: `!ClientCred($C, $A, ~cred)`. |
| S1.3 | Client fetches PRM and AS metadata, sends credential | RFC 9728, RFC 8414 §3.3, GHSA-qx49-fqc8-xw99 | `Client_Token_Request` | Emits `CredLookup($A, $I)` (restriction `credential_bound_to_issuer`, off under `VULNERABLE`) and `MetaIssuer($AS2, $I)` (restriction `metadata_issuer_validated`, off under `VULNERABLE` and `UNVALIDATED_ISSUER`). |
| S1.4 | Honest AS processes credential | OAuth 2.1 | `AS_Accepts` | Verifies credential match and emits `TokenIssued($C, $A)`. |
| S1.6 | Dishonest AS leaks to network | Dolev-Yao | `Dishonest_AS_Leaks` | Leaks raw secret to public channel `Out(m)`. |

---

### Model 02 (`models/02_code_and_audience.spthy`)
*Focus: Token audience validation (RFC 8707), issuer verification (RFC 9207), and AS resource indicators (RFC 8707).*

| Step # | Protocol Action | RFC / Spec | Exact Tamarin Rule | State Preconditions & Effects |
|---|---|---|---|---|
| S2.1 | Setup AS & RS authorities | RFC 9728, RFC 8414 | `Setup_Honest_AS_Iss`, `Setup_Dishonest_AS_Iss`, `Setup_Dishonest_AS_NoIss`, `Setup_Honest_RS`, `Setup_Dishonest_RS` | Configures honest/dishonest servers and PRM metadata. Under `ISS_OPTIONAL`, honest AS uses `Setup_Honest_AS_NoIss`. |
| S2.1b | Clients and users | Threat model | `Setup_Honest_Client`, `Setup_Dishonest_Client`, `Setup_Dishonest_User` | Honest public clients, attacker-run clients, and attacker-controlled user accounts. |
| S2.2 | Client discovers tool & requests auth | RFC 7636 (PKCE), RFC 8707 | `Client_Start_Honest_RS` / `Client_Start_Dishonest_RS` | Session `~sid` of user `$U`: generates verifier `~ver` and state `~state`; sends `authz_request` with PKCE challenge `h(~ver)` through the user's browser (private fact `Browser($AS, $U, ...)`). Under `NO_STATE`, uses public constant `'no_state'` instead of `~state`. |
| S2.3 | AS authorizes & returns code | RFC 9207, OAuth 2.1 | `AS_Authorize_Iss` / `AS_Authorize_NoIss` (user's own request); `AS_Authorize_Iss_Net` / `AS_Authorize_NoIss_Net` (attacker-built request, some honest user approves); `AS_Authorize_Dishonest_User`, `AS_Authorize_Dishonest_Client`, and under `NO_REDIRECT_CHECK` `AS_Authorize_Open_Redirect` (code goes to the attacker) | Emits `Consent($U, $C, $RS, $AS)` and `cd(~code)`; stores the linear (single-use) fact `Code(...)` with the challenge and requested `$RS`. |
| S2.4 | Attacker intercepts or injects callback | Dolev-Yao | `Attacker_Callback_Iss` / `Attacker_Callback_NoIss` | Attacker sends any callback to the client's redirect URI (CSRF / code injection; it must know the session's `state`). |
| S2.5 | Client validates callback & requests token | RFC 9207 §2.4, RFC 8707 §2 | `Client_Callback_Iss` / `Client_Callback_NoIss` | Matches `state`. Under fixed variant: compares callback issuer with expected `$AS`. Under `NO_ISS`: ignores issuer. Sends `token_request` with `~ver` over TLS `ToAS`. |
| S2.6 | AS validates PKCE & issues token | RFC 7636, RFC 8707 §2, OAuth 2.1 | `AS_Token` / `AS_Token_From_Network` | Consumes the code; restriction `pkce_checked` (`PkceCheck(challenge, h(ver))`, removed by `NO_PKCE`); mints `at(~tok)` with audience `$RS`. Under `NO_RESOURCE`: mints token with audience `$AnyRS`, an honest RS chosen freely (broad audience). |
| S2.7 | Dishonest AS intercepts requests | Threat model | `Dishonest_AS_Leaks_Authz`, `Dishonest_AS_Leaks`, `Dishonest_AS_Answers` | Leaks incoming authorization and token requests; answers on behalf of the attacker AS. |
| S2.8 | Client uses token at MCP tool | MCP Auth Spec §Token Handling | `Client_Use_Token` | Sends `at(tok)` as Bearer token over TLS channel `ToRS`. |
| S2.9 | Attacker presents token to RS | Dolev-Yao | `Attacker_To_RS` | Injects any token known to the network into an honest RS. |
| S2.10 | RS validates audience & executes tool | RFC 8707 §2 | `RS_Accepts` | Fixed variant checks `!Token(at(~tok), $AS, $U, $RS)`. Under `NO_AUD`, accepts any audience `aud`. Under `NO_RESOURCE`, the fixed audience check still runs, and passes because the AS stamped this honest RS as the audience (`$AnyRS`). |
| S2.11 | Dishonest RS leaks token | Threat model | `Dishonest_RS_Leaks` | Malicious tool forwards received Bearer token to the public network `Out(m)`. |

---

## 3. Formal Security Properties (Lemmas)

### Model 01 Lemmas

```tamarin
// Executability sanity check: an honest run can issue tokens.
lemma executable:
  exists-trace
  "Ex C A #i. TokenIssued(C, A) @ #i
     & not (Ex X #k. AS_Dishonest(X) @ #k)"

// Secrecy (P1): a credential registered at an honest AS never reaches the attacker.
lemma client_credential_secrecy:
  "All C A cred #i.
     Registered(C, A, cred) @ #i
     ==> not (Ex #j. K(cred) @ #j)"
```

### Model 02 Lemmas

```tamarin
// Induction helper: restricts origins of codes redeemed by the client.
lemma code_sources [sources]:
  "All sid c as code #i.
     ClientRedeems(sid, c, as, code) @ #i
     ==> (Ex #j. CodeIssued(code) @ #j & #j < #i)
       | (Ex #j. KU(code) @ #j & #j < #i)"

// Induction helper: restricts origins of tokens used by the client.
lemma token_sources [sources]:
  "All sid c rs tok #i.
     ClientUsesToken(sid, c, rs, tok) @ #i
     ==> (Ex as u c2 aud #j. TokenIssued(tok, as, u, c2, aud) @ #j & #j < #i)
       | (Ex #j. KU(tok) @ #j & #j < #i)"

// Executability sanity check: an honest client reaches an honest MCP server.
lemma executable:
  exists-trace
  "Ex rs u t #i. RSAccepts(rs, u, rs, t) @ #i
     & not (Ex x #j. AS_Dishonest(x) @ #j)
     & not (Ex x #j. RS_Dishonest(x) @ #j)"

// Authorization Consent (P2): an honest MCP server only accepts a token if user consented to THAT server.
lemma rs_accepts_only_consented:
  "All rs u aud t #i.
     RSAccepts(rs, u, aud, t) @ #i
     ==> Ex c as #j. Consent(u, c, rs, as) @ #j"

// Token Secrecy (P3): tokens minted for an honest user and honest client, for an
// honest MCP server, are never learned by the attacker.
lemma token_secrecy:
  "All t as u c rs #i.
     TokenIssued(t, as, u, c, rs) @ #i
     & not (Ex #j. RS_Dishonest(rs) @ #j)
     & not (Ex #j. Client_Dishonest(c) @ #j)
     & not (Ex #j. User_Dishonest(u) @ #j)
     ==> not (Ex #k. K(t) @ #k)"

// Session integrity (P6): an honest user's session with an honest AS ends with
// a token that AS issued for that user and that client.
lemma session_integrity:
  "All sid c u rs as t #s #i.
     ClientStart(sid, c, u, rs, as) @ #s
     & ClientUsesToken(sid, c, rs, t) @ #i
     & not (Ex #j. User_Dishonest(u) @ #j)
     & not (Ex #j. AS_Dishonest(as) @ #j)
     ==> Ex rs2 #j. TokenIssued(t, as, u, c, rs2) @ #j"

// Sanity: each code is redeemed at most once.
lemma code_single_use:
  "All c #i #j. CodeUsed(c) @ #i & CodeUsed(c) @ #j ==> #i = #j"
```
