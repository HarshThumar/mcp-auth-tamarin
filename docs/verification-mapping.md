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
| **Refresh Token** | RFC 6749 §1.5 | `rt(~r)` | Tagged constructor `rt/1` (model 03) |
| **Client Assertion** | RFC 7523 §2.2, rfc7523bis | `<<'cassert', C, aud, jti>, sign(...)>` | `private_key_jwt`; checked with `verify(...)`; `aud` must be the AS issuer (rfc7523bis) |
| **Token Endpoint URL** | RFC 8414 §2 | `tep($A)` | Public constructor (model 06); an RFC 7523-era acceptable assertion `aud` |
| **Authenticated Endpoint** | RFC 7009, RFC 9126 | `ToEP(owner, m)` | Any endpoint where the client authenticates (model 06: revocation); its owner may be an attacker AS |
| **ID-JAG** | ID-JAG draft-06 | `<'idjag', I, U, A, C, res, jti>` signed by the IdP | Identity Assertion JWT Authorization Grant (model 04) |

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

### Model 03 (`models/03_cimd_client_binding.spthy`)
*Focus: one CIMD client identity and key at many authorization servers; which checks keep codes, access tokens and refresh tokens bound to their AS (R6–R8).*

| Step # | Protocol Action | RFC / Spec | Exact Tamarin Rule | State Preconditions & Effects |
|---|---|---|---|---|
| S3.1 | AS setup and metadata | RFC 8414, RFC 9207 | `Setup_Honest_AS`, `Setup_Dishonest_AS_Iss`, `Setup_Dishonest_AS_NoIss` | Honest AS: metadata `issuer` = itself, always sends `iss`. Attacker AS: metadata claims any issuer `$I`, with or without `iss` support. |
| S3.2 | MCP servers and PRM | RFC 9728 | `Setup_Honest_RS`, `Setup_Dishonest_RS` | Honest RS names an honest AS in `!PRM`; a malicious RS names any AS at run time. |
| S3.3 | CIMD client and its document | CIMD draft-03, RFC 7523 | `Setup_Client`, `Setup_Dishonest_Client` | Confidential client: one signing key, public key in its metadata document (`!CIMD`), used at every AS. `PUBLIC`: no key. Attacker-run CIMD clients (key public). |
| S3.4 | Client discovers AS, records issuer, sends authz request | RFC 9728, RFC 8414 §3.3, RFC 7636 | `Client_Start_Honest_RS`, `Client_Start_Dishonest_RS` | Emits `MetaIssuer($AS, $I)` (restriction `metadata_issuer_validated`, removed by `NO_META_CHECK`); PKCE challenge `h(~ver)`. |
| S3.5 | AS issues code | OAuth 2.1 §4.1.2, RFC 9207 | `AS_Authorize`, `AS_Authorize_Dishonest_Client` | Linear `Code(...)` bound to client, challenge and `$RS`; response carries `iss`. Attacker clients' codes go to the network. |
| S3.6 | Attacker injects a callback | Dolev-Yao | `Attacker_Callback_Iss`, `Attacker_Callback_NoIss` | Any code, with any or no `iss`, to the client's redirect URI. |
| S3.7 | Client checks `iss` | RFC 9207 §2.4 | `Client_Callback_Iss`, `Client_Callback_NoIss` | `IssCheck(recorded, received)` (restriction `iss_checked`, removed by `NO_ISS`); absent `iss` accepted only if metadata does not advertise it. |
| S3.8 | Token request with client assertion | RFC 7523, rfc7523bis | `Client_Token_Request` | Confidential: assertion `<'cassert', C, I, jti>` signed, `aud` = the **recorded** issuer. Public: no client authentication. |
| S3.9 | AS token endpoint | RFC 7636, RFC 7523 §3 | `AS_Token`, `AS_Token_From_Network` | Consumes the code, checks PKCE and `verify(...)`; `AssertionAud($AS, aud)` (restriction `assertion_audience_checked`, removed by `AS_NO_ASSERTION_AUD`); issues `at(~tok)` and `rt(~r)`. |
| S3.10 | Attacker-run AS | Threat model | `Dishonest_AS_Leaks`, `Dishonest_AS_Answers` | Leaks every request (code, verifier, assertion, refresh token) and answers on the connection. |
| S3.11 | Client uses token, stores refresh token | MCP Token Handling | `Client_Use_Token` | Bearer token to the RS; refresh token stored with the recorded issuer. |
| S3.12 | Client refreshes | RFC 6749 §6, MCP Authorization Server Binding | `Client_Refresh` | Sends the stored refresh token to the AS the current MCP server names; `RefreshAt(recorded, current)` (restriction `refresh_token_bound_to_issuer`, removed by `RT_UNBOUND`). |
| S3.13 | AS refresh endpoint | RFC 6749 §6 | `AS_Refresh`, `AS_Refresh_From_Network` | Accepts a refresh token it issued (with a valid assertion for confidential clients) and issues a new access token. |
| S3.14 | MCP server | RFC 8707, Dolev-Yao | `RS_Accepts`, `Attacker_To_RS`, `Dishonest_RS_Leaks` | Audience always checked here; malicious servers leak what they receive. |

### Model 04 (`models/04_id_jag.spthy`)
*Focus: Enterprise-Managed Authorization (ID-JAG): RFC 8693 token exchange at the IdP, then RFC 7523 JWT bearer grant at the MCP authorization server (RAS) (R9–R10).*

| Step # | Protocol Action | RFC / Spec | Exact Tamarin Rule | State Preconditions & Effects |
|---|---|---|---|---|
| S4.1 | IdP, RAS and MCP servers | ID-JAG draft-06, RFC 9728 | `Setup_IdP`, `Setup_Honest_RAS`, `Setup_Dishonest_RAS`, `Setup_Honest_RS`, `Setup_Dishonest_RS` | One IdP with a signing key; honest and attacker-run RASes; honest RS names an honest RAS. |
| S4.2 | Clients and users | Threat model | `Setup_Honest_Client`, `Setup_Dishonest_Client`, `Setup_Dishonest_User` | Honest clients with private keys; attacker clients (key public); attacker-controlled user accounts at the IdP. |
| S4.3 | Client discovers RAS, requests token exchange | RFC 9728, RFC 8693 §2.1 | `Client_Start_Honest_RS`, `Client_Start_Dishonest_RS` | Requests an ID-JAG for audience `$A` and `resource` `$RS`; under `NO_RESOURCE_CLAIM` without `resource`. |
| S4.4 | IdP issues ID-JAG | ID-JAG draft-06 §4.3 | `IdP_Issue_IDJAG`, `IdP_Issue_IDJAG_Dishonest_Client` | Signed `<'idjag', I, U, A, C, res, jti>`; worst-case policy grants any audience/resource. Attacker clients get genuine ID-JAGs only for attacker users. |
| S4.5 | JWT bearer grant | RFC 7523 §2.1, ID-JAG §4.4 | `Client_JWT_Bearer` | Sends the ID-JAG plus a client assertion with `aud` = the RAS. |
| S4.6 | RAS validates and issues token | ID-JAG draft-06 §4.4.1 | `RAS_Token`, `RAS_Token_From_Network`, `RAS_Token_NoRes`, `RAS_Token_NoRes_From_Network` | Verifies both signatures; `CheckAud(aud, $A)` (removed by `NO_IDJAG_AUD`) and `CheckClient(cid, c)` (removed by `NO_CLIENT_BINDING`); token audience = `resource`, or a broad audience `$AnyRS` when `resource` is absent. |
| S4.7 | Attacker-run RAS | Threat model | `Dishonest_RAS_Leaks`, `Dishonest_RAS_Answers` | Leaks the ID-JAG and assertion; answers as it likes. |
| S4.8 | Client uses token; MCP server | RFC 8707, Dolev-Yao | `Client_Use_Token`, `RS_Accepts`, `Attacker_To_RS`, `Dishonest_RS_Leaks` | Audience checked at the honest RS; malicious servers leak. |

### Model 06 (`models/06_audience_injection.spthy`)
*Focus: audience injection (Hosseyni, Küsters, Würtele, S&P 2026) against a CIMD client that uses one key at every AS (R12).*

| Step # | Protocol Action | RFC / Spec | Exact Tamarin Rule | State Preconditions & Effects |
|---|---|---|---|---|
| S6.1 | AS setup and metadata with endpoints | RFC 8414 §2 | `Setup_Honest_AS`, `Setup_Dishonest_AS` | Metadata = (issuer, token endpoint owner, revocation endpoint owner). Attacker AS may list any issuer and any AS's endpoints. |
| S6.2 | CIMD clients | CIMD draft-03, RFC 7523 | `Setup_Client`, `Setup_Dishonest_Client` | One signing key per client, public key in `!CIMD`; attacker clients' keys are public. |
| S6.3 | Client discovers AS, records metadata | RFC 9728, RFC 8414 §3.3 | `Client_Discover` | `MetaIssuer($X, $I)` (restriction `metadata_issuer_validated`, removed by `NO_META_CHECK`). |
| S6.4 | Client-authenticated revocation request | RFC 7009 §2.1, RFC 7523 §3 | `Client_Revoke` | Assertion sent to the metadata's revocation endpoint. `aud` = recorded issuer (fixed, rfc7523bis) or `tep(token endpoint)` (`AUD_TOKEN_ENDPOINT`). |
| S6.5 | Client-credentials token request | RFC 6749 §4.4, RFC 7523 | `Client_CC_Token` | Same assertion rule, sent to the metadata's token endpoint. |
| S6.6 | Honest AS token endpoint | RFC 6749 §4.4, rfc7523bis | `AS_CC_Token`, `AS_CC_Token_From_Network` | `verify(...)` and `AssertionAud($A, aud)`: `aud = $A` (fixed) or `aud ∈ {$A, tep($A)}` (`AUD_TOKEN_ENDPOINT`, `AS_LENIENT`). Issues a token for the client's own resources. |
| S6.7 | Honest AS revocation endpoint | RFC 7009 | `AS_Revoke` | Same assertion checks; no output. |
| S6.8 | Client receives token | RFC 6749 §5.1 | `Client_Receives_Token` | Over the client's TLS connection. |
| S6.9 | Attacker-run endpoints | Threat model | `Dishonest_EP_Leaks` | Any request to an endpoint owned by an attacker AS leaks. |

### Model 05 (`models/05_agent_payment_mandate.spthy`)
*Focus: UPI-style case study. An AI agent pays under a mandate; does every debit stay inside what the principal approved (R13; case study `docs/case-study-upi.md`)?*

| Step # | Protocol Action | RFC / Spec | Exact Tamarin Rule | State Preconditions & Effects |
|---|---|---|---|---|
| S5.1 | AS, payment servers, agents, attacker users | agent-grants-02; NPCI UPI Circle (secondary source) | `Setup_AS`, `Setup_PS`, `Setup_Honest_Agent`, `Setup_Dishonest_Agent`, `Setup_Dishonest_User` | One AS signing key; honest agents keep their key; dishonest agents' keys are public; attacker user accounts approve anything. |
| S5.2 | Principal decides what the agent may pay | RFC 9396 `authorization_details`; UPI Circle caps | `Principal_Intent` | `Intent(user, agent, payee, cap, payment server)`; the task goes to the agent privately. |
| S5.3 | Agent asks for a mandate (PAR) | RFC 9126; agent-grants-02 | `Agent_Request_Mandate` | Request over TLS (`ToAS`). |
| S5.4 | AS issues the mandate after the principal's approval | agent-grants-02 §9.1 (no consent substitution); UPI 2FA at linking | `AS_Issue_From_Agent`, `AS_Issue_From_Network`, `AS_Issue_Dishonest_User` | Fixed: needs `!Intended` matching the request. `NO_CONSENT_BINDING`: issues whatever is asked. Mandate = signed `<mid, user, agent, payee, cap, payment server, cnf>`. |
| S5.5 | Principal revokes (delinks) | RFC 7009; UPI Circle delinking | `Principal_Revoke` | `Revoked(mid)`. |
| S5.6 | Agent pays with proof of possession | RFC 9449 (DPoP `jti`, `ath`); agent-grants-02 `cnf` | `Agent_Pay` | Signs `<payment id, payment server, payee, amount, h(mandate)>`; within its cap; request leaks. |
| S5.7 | Payment server executes | agent-grants-02 (RS MUSTs); RFC 9396; UPI per-payment validation | `PS_Execute` | `verify` mandate; PoP (removed by `NO_SENDER_CONSTRAINT`); `AudCheck` (`NO_AUD`), `PayeeCheck` (`NO_PAYEE_CHECK`), `AmountCheck` (`NO_AMOUNT_CHECK`), `StatusCheck` (`NO_REVOCATION_CHECK`); payment id once. |

### Model 07 (`models/07_confused_deputy_proxy.spthy`)
*Focus: the confused-deputy attack on an MCP proxy server with a static third-party client ID (MCP Security Best Practices; R14).*

| Step # | Protocol Action | RFC / Spec | Exact Tamarin Rule | State Preconditions & Effects |
|---|---|---|---|---|
| S7.1 | Users and redirect endpoints | Threat model | `Setup_User`, `Honest_Redirect_Endpoint`, `Attacker_Redirect_Endpoint` | Each redirect URI is owned by an honest client or by the attacker, never both. |
| S7.2 | Dynamic client registration at the proxy | RFC 7591 | `DCR_Honest_Client`, `DCR_Attacker_Client` | `!Client(client_id, registered redirect URI)`; the attacker registers any redirect URI. |
| S7.3 | Proxy consent screen | MCP Security Best Practices, Confused Deputy: per-client consent | `User_Approves_Client` | An honest user approves only clients it uses (`UserApproves`). |
| S7.4 | Authorization request | RFC 6749 §4.1.1, RFC 7636 | `Client_Start`, `User_Clicks_Link` | Honest client: own state and PKCE challenge. Attacker: any request opened in the user's browser. |
| S7.5 | Proxy authorizes, third-party AS silent (consent cookie) | MCP Security Best Practices, Confused Deputy (vulnerable conditions) | `Proxy_Authorize` | `ConsentCheck` (per client; `CONSENT_NOT_CLIENT_BOUND`: any client), `RedirectCheck` (exact match; `NO_REDIRECT_CHECK`). Issues a single-use code. |
| S7.6 | Redirect delivers the code | RFC 6749 §4.1.2 | `Deliver_To_Honest_Client`, `Deliver_To_Attacker` | Honest redirect URI: private to its client. Attacker endpoint: public. |
| S7.7 | Token request | RFC 6749 §4.1.3, RFC 7636 §4.5 | `Client_Redeem`, `Proxy_Token_Honest_Client`, `Proxy_Token_Network`, `Client_Done` | PKCE verifier checked; token issued for (user, client). |

### Model 08 (`models/08_token_passthrough.spthy`)
*Focus: token passthrough (MCP Security Best Practices, "Token Passthrough"; R15).*

| Step # | Protocol Action | RFC / Spec | Exact Tamarin Rule | State Preconditions & Effects |
|---|---|---|---|---|
| S8.1 | Honest and malicious MCP servers, downstream API | Threat model | `Setup_Honest_Server`, `Setup_Dishonest_Server`, `Setup_Downstream` | Roles unique per name. |
| S8.2 | Client gets an audience-restricted token per MCP server | RFC 8707 §2; MCP Token Handling | `Client_Token_For_Honest_Server`, `Client_Token_For_Dishonest_Server` | `!Token(t, user, aud)`; tokens for malicious servers leak. |
| S8.3 | MCP server validates the token | MCP Token Handling ("MUST validate ... intended audience") | `Server_Receives_From_Client`, `Server_Receives_From_Network` | `ServerAudCheck` (removed by `S_NO_AUD`). |
| S8.4 | MCP server calls the downstream API | RFC 8693; MCP "MUST NOT pass through" | `Server_Calls_Downstream` | `ServerDecides`. Fixed: exchanges for its own `aud` = downstream token. `PASSTHROUGH`: forwards the client's token. |
| S8.5 | Downstream API executes | RFC 8707 §2 at the downstream API | `Downstream_From_Server`, `Downstream_From_Network` | `DownstreamAudCheck` (removed by `D_NO_AUD`). |

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
