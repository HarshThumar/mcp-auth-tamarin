# Draft Conformance Test Suite: MCP Authorization (Issue #78)

This document formalizes test cases derived from machine-checked security proofs in `mcp-auth-tamarin`. These tests are designed to be contributed upstream to the official [Model Context Protocol Conformance Suite](https://github.com/modelcontextprotocol/conformance) (addressing [Issue #78: Server-side token validation](https://github.com/modelcontextprotocol/conformance/issues/78)).

---

## Overview of Test Cases

| Test ID | Target Entity | RFC / Spec Clause | Formal Grounding | Attack Prevented |
|---|---|---|---|---|
| **ST-01** | MCP Server (RS) | RFC 8707 §2 / MCP Token Handling | Model 02 (`NO_AUD`, R1) | Cross-RS token replay ([CVE-2026-116684](https://github.com/advisories/GHSA-w4fh-qvv9-3v23)) |
| **ST-02** | MCP Client | RFC 9207 §2.4 | Model 02 (`NO_ISS`, R2) | AS mix-up attack ([RFC 9700 §4.4](https://datatracker.ietf.org/doc/html/rfc9700#section-4.4)) |
| **ST-03** | Auth Server (AS) | MCP Auth Draft §Authorization Response | Model 02 (`ISS_OPTIONAL`, R3) | Mix-up under optional `iss` (proves SHOULD → MUST upgrade) |
| **ST-04** | MCP Client | RFC 8707 §2 / MCP Spec Gap G4 | Model 02 (`NO_RESOURCE`, R4) | Token leakage across tools sharing an unhardened AS |

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
- **Expected Conformance Assertions:**
  1. The redirect URI **MUST** include the `iss` parameter (e.g. `?code=...&state=...&iss=https://as.example`).
  2. Responses omitting the `iss` parameter **FAIL** conformance.

---

### Test ST-04: Client Rejection of AS Without Resource Indicator Support (Client)
- **Specification Reference:**
  > "Clients **SHOULD** refuse an AS that does not support resource indicators."
  > *(MCP Security Considerations & Spec Gap G4)*
- **Formal Finding:** Finding R4 (`models/02_code_and_audience.spthy -D=NO_RESOURCE`).
- **Preconditions:**
  1. MCP server publishes Protected Resource Metadata (`RFC 9728`) naming `https://legacy-as.example`.
  2. `https://legacy-as.example/.well-known/oauth-authorization-server` does NOT advertise `resource_indicators_supported: true` (or omits RFC 8707 capabilities).
- **Action:**
  Client processes the MCP server's 401 challenge and attempts discovery.
- **Expected Conformance Assertions:**
  1. The client **MUST NOT** transmit credentials or initiate authorization requests to an AS that ignores resource scoping.
  2. The client **MUST** report a clear error to the user/runtime stating that the authorization server lacks deterministic resource binding.
