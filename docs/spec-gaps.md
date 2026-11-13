# Assumptions the MCP authorization spec leaves open

*Working list for the IETF 127 Hackathon (goal 3). Checked against the MCP draft [authorization](https://modelcontextprotocol.io/specification/draft/basic/authorization) and [security considerations](https://modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations) pages on 11 Nov 2026.*

Each entry gives what the text says, the gap or open assumption, and how the models treat it. These are questions for review, not claims of vulnerabilities. Where a gap is already known (in RFC 9207, RFC 9700 or the draft itself), the entry says so.

| # | Topic | What the spec says | Open question / gap | Model |
|---|---|---|---|---|
| G1 | `iss` in authorization responses | AS "**SHOULD** include the `iss` parameter". If it is not advertised and absent, the client action is "Proceed". The draft says a future revision "is expected" to make it a MUST. | While it is a SHOULD, a client cannot detect a mix-up when the honest AS omits `iss` (known RFC 9207 limitation). | 02 `ISS_OPTIONAL`: mix-up found. Fixed variant (always sent and checked): verified. |
| G2 | Who picks the AS | The MCP server names its AS in Protected Resource Metadata (RFC 9728). The recorded issuer "provides no protection if the expected issuer was obtained from an unvalidated source." | The spec does not say which AS a client should trust for a given MCP server. A malicious MCP server can always name an attacker-run AS for a **new** interactive sign-in (the TypeScript SDK advisory GHSA-6qxp-vccf-f47h lists this as "not covered by this fix"). Is user judgement the only defence? | 01 and 02 let a malicious MCP server name any AS. |
| G3 | Stored credentials bound to their AS | Not found as an explicit rule on the authorization or security-considerations pages (to re-check in client-registration and the best-practices page). | The 2026 SDK advisories (GHSA-qx49-fqc8-xw99, GHSA-6qxp-vccf-f47h) fixed this in code. Should the spec say "a stored refresh token, client secret or assertion MUST only be sent to the issuer it was obtained from"? | 01: unbound credential leaks; bound credential verified. |
| G4 | Audience binding depends on the AS | RFC 8707 binds tokens to audiences "**when the Authorization Server supports the capability**". MCP servers MUST reject tokens that do not name them in the audience. | If a shared AS ignores `resource`, its tokens carry broad/unbound audience. A rogue tool can replay the token to honest tools even when servers enforce audience checks. Client must refuse an AS without RFC 8707 support. | 02 `NO_RESOURCE`: cross-RS replay attack found (R4); fixed variant (RFC 8707 AS) verified. |
| G5 | Audience check in SDKs is opt-in | MCP servers **MUST** validate the audience. | The patched Python and TypeScript SDKs ship the check **off by default** until 3.0 (GHSA-w4fh-qvv9-3v23, GHSA-rvq5-wwqv-78pq). Spec MUST vs. implementation default; the conformance suite has no server-side audience test yet ([issue #78](https://github.com/modelcontextprotocol/conformance/issues/78)). | 02 `NO_AUD`: attack found. Fixed: verified. |
| G6 | One client identity at many ASes | Client ID Metadata Documents are the preferred registration (SHOULD). The `client_id` is an HTTPS URL. | The same `client_id` and redirect URI are used at every AS, so the older mix-up defence (a distinct redirect URI per AS, RFC 9700 §4.4.2) is not there by default. `iss` (G1) is the only defence left. | 02 assumes one shared `client_id` and redirect URI. Model 03 (CIMD) will look at this in depth. |
| G7 | `state` | Clients **SHOULD** use and verify `state`. | With PKCE, is `state` needed for any property? 02 makes `state` public (front channel), and the properties still hold in the fixed variant, so PKCE + `iss` seem to carry the load. To confirm with a no-`state` variant. | 02: `state` is public. |
| G8 | User consent | The AS "**MUST** clearly display the redirect URI hostname during authorization" (CIMD). | Nothing requires the consent screen to show the **resource** (the MCP server) the token is for. A user signed in at a shared AS may approve a token for a server they did not mean to authorise. | 02 assumes some honest user approves any request for an honest client: the standard, worst-case mix-up assumption. |

## Not modelled yet

Code single-use, refresh-token rotation, scopes and step-up authorization, DPoP, token expiry, and the browser itself. See [threat-model.md](threat-model.md).

## How to help

If any entry misreads the spec, or one of these is already settled somewhere, please open an issue using the "spec gap" template. Corrections are the most useful contribution.
