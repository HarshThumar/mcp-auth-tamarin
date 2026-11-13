# Draft Conformance Test Suite: MCP Authorization (Issue #78)

This document formalizes test cases derived from machine-checked security proofs in `mcp-auth-tamarin`. These tests are designed to be contributed upstream to the official [Model Context Protocol Conformance Suite](https://github.com/modelcontextprotocol/conformance) (addressing [Issue #78: Server-side token validation](https://github.com/modelcontextprotocol/conformance/issues/78)).

---

## Overview of Test Cases

| Test ID | Target Entity | RFC / Spec Clause | Formal Grounding | Attack Prevented |
|---|---|---|---|---|
| **ST-01** | MCP Server (RS) | RFC 8707 §2 / MCP Token Handling | Model 02 (`NO_AUD`, R1) | Cross-RS token replay ([CVE-2026-116684](https://github.com/advisories/GHSA-w4fh-qvv9-3v23)) |
| **ST-02** | MCP Client | RFC 9207 §2.4 | Model 02 (`NO_ISS`, R2) | AS mix-up attack ([RFC 9700 §4.4](https://datatracker.ietf.org/doc/html/rfc9700#section-4.4)) |
| **ST-03** | Auth Server (AS) | MCP Auth Draft §Authorization Response Validation | Model 02 (`ISS_OPTIONAL`, R3) | Mix-up under optional `iss` (evidence for the planned SHOULD → MUST upgrade). **Warning only** under the current draft |

*ST-04 (client refuses an AS without RFC 8707 support) was withdrawn on 13 Nov 2026: the MCP spec has no such requirement (clients MUST send `resource` "regardless of whether authorization servers support it"), and no standard AS metadata field advertises RFC 8707 support, so the test could not be run. R4 / G4 stay open as a spec question.*

---

## Detailed Test Specifications

### Test ST-01: Server-Side Audience Validation (RS)
- **Specification Reference:**
  > "MCP servers **MUST** validate that access tokens were issued specifically for them as the intended audience, according to RFC 8707 Section 2."
  > *(MCP Authorization: Token Handling)*
- **Formal Finding:** Finding R1 (`models/02_code_and_audience.spthy -D=NO_AUD`).
- **Preconditions:**
  1. Test harness mints a cryptographically valid access token signed by a trusted Authorization Server.
  2. The token payload contains `aud: "https://other-tool.example.com/mcp"`.
  3. The target MCP server's canonical identifier is `https://target-server.example.com/mcp`.
- **Action:**
  Client submits a standard JSON-RPC tool-call request over SSE/HTTP containing header:
  ```http
  Authorization: Bearer <token_with_other_audience>
  ```
- **Expected Conformance Assertions:**
  1. The server **MUST** reject the request with HTTP `401 Unauthorized`.
  2. The `WWW-Authenticate` header **MUST** include `error="invalid_token"`.
  3. The server **MUST NOT** execute the underlying tool method or leak internal state.

---

### Test ST-02: Client-Side Issuer Verification (Client)
- **Specification Reference:**
  > "Clients **MUST** apply the validation in RFC9207 Section 2.4 before transmitting the authorization code to any token endpoint."
  > *(MCP Authorization: Authorization Response Validation)*
- **Formal Finding:** Finding R2 (`models/02_code_and_audience.spthy -D=NO_ISS`).
- **Preconditions:**
  1. The client initiates an OAuth authorization session targeted at legitimate Authorization Server `https://auth.legitimate.example`.
  2. The client records PKCE `code_verifier` and expects issuer `https://auth.legitimate.example`.
- **Action:**
  The test harness triggers a redirect callback to the client's `redirect_uri` containing:
  ```http
  GET /callback?code=test_auth_code_1234&state=session_xyz&iss=https://attacker-as.example
  ```
- **Expected Conformance Assertions:**
  1. The client **MUST** compare the `iss` parameter with the recorded expected issuer.
  2. Upon discrepancy, the client **MUST abort** the session immediately.
  3. The client **MUST NOT** transmit the `code` or its associated `code_verifier` to the token endpoint of either server.

---

### Test ST-03: Mandatory AS Issuer Inclusion (Authorization Server)
- **Specification Reference:**
  > "MCP authorization servers **SHOULD** include the `iss` parameter in authorization responses... A future revision is expected to upgrade this to **MUST**."
  > *(MCP Authorization: Authorization Response Validation)*
- **Formal Finding:** Finding R3 (`models/02_code_and_audience.spthy -D=ISS_OPTIONAL`).
- **Preconditions:**
  1. Client sends an OAuth 2.1 authorization request with standard parameters (`client_id`, `redirect_uri`, `code_challenge`, `resource`).
- **Action:**
  User authenticates and consents; Authorization Server issues the redirect response.
- **Expected Conformance Assertions (current draft: SHOULD):**
  1. The redirect **SHOULD** include the `iss` parameter (e.g. `?code=...&state=...&iss=https://as.example`). Omitting it is reported as a **warning**, not a failure.
  2. If the AS includes `iss`, its metadata **MUST** set `authorization_response_iss_parameter_supported` to `true` (this part is already a MUST and can fail).
  3. Once the planned revision makes `iss` a MUST, assertion 1 becomes a failure.
