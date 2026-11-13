# Verification Mapping: RFC Specifications ↔ Tamarin Formal Model

This document provides the Domain-Driven Design (DDD) traceability matrix between the **Model Context Protocol (MCP) Authorization draft / IETF RFCs** and the formal multiset rewriting rules in `models/`.

---

## 1. Ubiquitous Language & Entity Map

| Domain Concept | RFC / Spec Reference | Tamarin Fact / Representation | Semantics |
|---|---|---|---|
| **Client (C)** | OAuth 2.1 / RFC 7591 | `$C` | Public MCP client (e.g. AI agent IDE, desktop client) |
| **Resource Server (RS)** | RFC 9728 / MCP Server | `$RS` | The tool provider endpoint; may be honest or malicious |
| **Authorization Server (AS)** | RFC 8414 / RFC 9207 | `$AS` | Token-issuing authority; may be honest or attacker-run |
| **User (U)** | OAuth 2.1 | Implicit consent fact | Resource owner approving authorization requests |
| **Protected Resource Metadata (PRM)** | RFC 9728 §5.1 | `Out(<'prm', $RS, $AS>)` | RS advertising its chosen AS to the client |
| **Client Credential** | RFC 7591 / GHSA-qx49-fqc8-xw99 | `!ClientCred($C, $AS, ~cred)` | Fresh secret bound to a specific AS |
| **Authorization Code** | OAuth 2.1 §4.1.2 | `cd(~code)` | Opaque handle tagged constructor `cd/1` |
| **Code Verifier / Challenge** | RFC 7636 (PKCE) | `~cv`, `h(~cv)` | S256 code challenge |
| **Resource Indicator** | RFC 8707 | `$RS` parameter in auth & token req | Scope/audience target URI |
| **Issuer Parameter** | RFC 9207 §2 | `$AS` in redirect response | AS identity parameter preventing mix-up |
| **Access Token** | OAuth 2.1 §1.4 / RFC 8707 §2 | `at(~code)` | Bearer token tagged constructor `at/1` |

---

## 2. Protocol Step ↔ Rule Traceability Matrix

### Model 01 (`models/01_as_selection.spthy`)
*Focus: Credential isolation and Authorization Server discovery binding (GHSA-qx49-fqc8-xw99).*

| Step # | Protocol Action | RFC / Spec | Tamarin Rule | State Preconditions & Effects |
|---|---|---|---|---|
| S1.1 | Client registers with honest AS | RFC 7591 §3 | `Register_Client` | Generates fresh credential `~cred`, records `!ClientCred($C, $AS, ~cred)`. |
| S1.2 | Attacker deploys dishonest AS | Threat model | `Compromise_AS` | Marks endpoint `!Dishonest($X)`. |
| S1.3 | Client fetches PRM & sends credential (Vulnerable) | GHSA-qx49-fqc8-xw99 | `Client_Token_Request_Unbound` | Consumes PRM without checking AS binding; sends `cred` to `$ASnamed`. |
| S1.4 | Client fetches PRM & sends credential (Bound / Fixed) | RFC 9728 + Fix | `Client_Token_Request_Bound` | Validates that `$AS` in metadata matches `!ClientCred($C, $AS, cred)`. |
| S1.5 | Honest AS processes credential | OAuth 2.1 | `AS_Accepts` | Verifies credential match and emits `TokenIssued($C, $AS)`. |
| S1.6 | Dishonest AS leaks to network | Dolev-Yao | `Dishonest_AS_Leaks` | Leaks raw secret to public channel `Out(m)`. |

---

### Model 02 (`models/02_code_and_audience.spthy`)
*Focus: Token audience validation (RFC 8707) and issuer verification (RFC 9207).*

| Step # | Protocol Action | RFC / Spec | Tamarin Rule | State Preconditions & Effects |
|---|---|---|---|---|
| S2.1 | RS publishes metadata pointing to AS | RFC 9728 §5.1 | `Setup_Honest_RS` / `Setup_Dishonest_RS` | Honest RS names honest AS; dishonest RS can name any AS. |
| S2.2 | Client requests authorization | RFC 7636 (PKCE) | `Client_Auth_Request` | Creates fresh verifier `~cv`, sends public request with challenge `h(~cv)` and target `resource`. |
| S2.3 | Honest AS issues code | RFC 9207 / OAuth 2.1 | `Honest_AS_Authorization_Response` | Emits code with `iss` parameter (or omits under `ISS_OPTIONAL`). |
| S2.4 | Client processes redirect callback | RFC 9207 §2.4 | `Client_Callback` | Under fixed variant: checks `iss` matches expected AS before redeeming code. |
| S2.5 | Client redeems code at token endpoint | RFC 8707 §2 | `Client_Token_Request` | Sends code + `~cv` over TLS channel `ToAS` to the recorded AS. |
| S2.6 | AS validates PKCE & issues token | OAuth 2.1 + RFC 8707 | `Honest_AS_Token_Response` | Mints access token `at(code)` bound to the requested resource. |
| S2.7 | Client accesses MCP tool | MCP Auth Spec §Token Handling | `Client_Accesses_RS` | Presents `at(code)` to target RS. |
| S2.8 | RS validates audience & accepts token | RFC 8707 §2 | `Honest_RS_Accepts_Token` | Validates token audience matches RS identity (`rs_accepts_only_consented`). |

---

## 3. Formal Security Properties (Lemmas)

| Lemma | Mathematical Statement | Real-World Guarantee |
|---|---|---|
| `client_credential_secrecy` | $\forall C, A, cred. \text{Registered}(C, A, cred) \implies \neg K(cred) \lor \text{Compromised}(A)$ | Client secrets never reach unauthorized servers unless the home AS itself is compromised. |
| `rs_accepts_only_consented` | $\forall U, RS, token. \text{RS\_Accepted}(RS, token) \implies \text{Consented}(U, RS)$ | An honest tool server never executes an action without explicit user authorization for that specific tool. |
| `token_secrecy` | $\forall AS, RS, token. \text{IssuedFor}(token, AS, RS) \implies \neg K(token)$ | Tokens issued for legitimate servers are never intercepted by network or malicious servers. |
