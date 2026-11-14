# Related work (T60) — DRAFT

*Draft of 14 Nov 2026. Every link below was opened during the review unless marked "(snippet only)" or "(not read)". Where a primary PDF was not read, the claim comes from the abstract page or from a paper or IETF draft that cites it. Re-read the primary sources before citing any of this in a paper.*

## Summary

- We **couldn't find prior work that machine-checks** R6, R8 or R9 in the MCP / CIMD / ID-JAG setting.
- The **mechanisms** behind them are already known informally:
  - The audience-injection work of Hosseyni, Küsters and Würtele, and the drafts that followed it (rfc7523bis, the OAuth Security BCP update), cover R6 and R8.
  - The ID-JAG draft's own security considerations cover R9 and R10.
- The WIM analyses (Fett, Küsters, Schmitz) are the formal basis for mix-up, `iss` and session integrity (R2–R5) in generic OAuth.
- The other MCP security papers found are a ProVerif project page, a measurement study, TLA+ conformance work and a taxonomy. None of them covers AS selection, audience binding, CIMD or ID-JAG at the protocol level.

## Prior work

| Work | Method | What it covers | Overlap with this project |
|---|---|---|---|
| Fett, Küsters, Schmitz, "A Comprehensive Formal Security Analysis of OAuth 2.0", CCS 2016. [arXiv:1601.01229](https://arxiv.org/abs/1601.01229) | Web Infrastructure Model (WIM), manual proofs | OAuth 2.0 grant types; malicious RPs, IdPs and browsers; authorization, authentication, session integrity; mix-up and the `iss` defence | R2–R5 conceptually, in generic OAuth. No MCP, no RS-driven AS discovery. |
| Fett, Küsters, Schmitz, "The Web SSO Standard OpenID Connect: In-Depth Formal Security Analysis and Security Guidelines", CSF 2017. [arXiv:1704.08539](https://arxiv.org/abs/1704.08539) | WIM | OpenID Connect | Background |
| Fett, Hosseyni, Küsters, "An Extensive Formal Security Analysis of the OpenID Financial-grade API", IEEE S&P 2019. [arXiv:1901.11520](https://arxiv.org/abs/1901.11520) | WIM | FAPI 1.0; attacks on authorization and session integrity | Background (same style of result as R2–R5) |
| Hosseyni, Küsters, Würtele, "Formal Security Analysis of the OpenID FAPI 2.0 Family of Protocols", CSF 2024. [ePrint 2024/078](https://eprint.iacr.org/2024/078); full version [ePrint 2024/1540](https://eprint.iacr.org/2024/1540) | WIM, manual proofs | FAPI 2.0, FAPI-CIBA | Per the audience-injection paper (§6.2), this is the only prior formal analysis that considered `private_key_jwt`, and the draft it analysed already used the issuer as `aud`. So the issuer-as-`aud` fix has a pen-and-paper proof for FAPI 2.0 (one AS family, not CIMD/MCP). PDF itself not read. |
| Helmschmidt, Hosseyni, Küsters, Pruiksma, Waldmann, Würtele, "The Grant Negotiation and Authorization Protocol: Attacking, Fixing, and Verifying an Emerging Standard", ESORICS 2023. [ePrint 2023/1325](https://eprint.iacr.org/2023/1325) | WIM | GNAP | None directly |
| Hosseyni, Küsters, Würtele, "Audience Injection Attacks: A New Class of Attacks on Web-Based Authorization and Authentication Standards", IEEE S&P 2026. [ePrint 2025/629](https://eprint.iacr.org/2025/629) (PDF read 14 Nov 2026) | Attack paper: manual analysis and coordinated disclosure; **no formal proof of the fix** | An attacker AS lists an honest AS's endpoint in its configuration document; a client that uses one key at both ASes signs an assertion the honest AS accepts. Fix (§5): issuer identifier as the assertion `aud`; it "cannot be mitigated solely by the AS". Assumes the client validates the configuration document's issuer (§2.1). Mix-up is left to RFC 9207 (§2.3). §7: "a rigorous formal security analysis of these methods [is] a promising avenue for future research." | **Closest prior work for R6 and R8**; related to R9 |
| draft-ietf-oauth-security-topics-update-01, §2.1 "Audience Injection Attacks", §2.2.2. [datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-security-topics-update/01/) | IETF draft (informal) | Attacker AS publishes an honest AS's endpoint in its metadata; fix: issuer as sole `aud`, validated per RFC 8414 §3.3; mix-up defences need a validated issuer | Informally overlaps R6, R8 |
| draft-ietf-oauth-rfc7523bis-10. [datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/10/) | IETF draft | Client-assertion `aud` MUST be the AS issuer as sole value | Spec source for the fix in R6/R8 |
| draft-ietf-oauth-identity-assertion-authz-grant-06 (ID-JAG), 31 Oct 2026. [datatracker](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant) | IETF draft (informal) | §4.4.1 requires both the `aud` and the `client_id` binding checks; §9 informal relay/replay reasoning; `resource` OPTIONAL | Informally overlaps R9, R10 |
| draft-ietf-oauth-client-id-metadata-document-03 (CIMD), 2 Nov 2026. [datatracker](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document) | IETF draft | `private_key_jwt` with keys from the document; §7: "The authorization response MUST include the `iss` parameter" | Subject of model 03; no formal analysis found |
| RFC 9700, OAuth 2.0 Security BCP, Jan 2025. [rfc-editor](https://www.rfc-editor.org/rfc/rfc9700.html) | BCP | §4.1 redirect URIs, §4.4 mix-up, §4.5 code injection, §4.7 CSRF, §4.10.2 audience restriction, §4.14 refresh tokens | Citation anchor for R2–R5, R7, R11 |
| "MCPSec" project page (Zilin Shen), 2026. [project page](https://zilinlin.github.io/projects/3_mcpsec) | ProVerif | Claims a ProVerif model of MCP incl. OAuth 2.1 and multi-server flows; 8 attack scenarios on the MCP Python SDK | **Overlap unknown**: no paper found, OAuth details not given. Re-check before submission. Name clash with Maloyan & Namiot (below). |
| Jiang et al., "A Formal Analysis of Agent Payment Protocols", [arXiv:2609.00060](https://arxiv.org/abs/2609.00060), Aug 2026 | Tamarin | x402, MPP, ACP, AP2 | No MCP authorization; none of R0–R11 |
| Zhou et al. (Fudan), "A First Measurement Study on Authentication Security in Real-World Remote MCP Servers", [arXiv:2605.22333](https://arxiv.org/abs/2605.22333), May 2026 | Measurement | 7,973 remote MCP servers; OAuth flaws in deployed servers; 9 CVEs | Empirical complement; no protocol-level formal analysis |
| Zheng, Zhang, "AgentRFC: Security Design Principles and Conformance Testing for Agent Protocols", [arXiv:2603.23801](https://arxiv.org/abs/2603.23801), Mar 2026 | TLA+ + SDK replay | MCP, A2A, ANP, ACP; design-principle invariants | Different level; no audience / mix-up / CIMD invariants found (HTML skimmed) |
| Acharya, Gupta, "A Formal Security Framework for MCP-Based AI Agents" (MCPShield), [arXiv:2604.05969](https://arxiv.org/abs/2604.05969), Apr 2026 | Labelled transition system, taxonomy | 23 threat vectors | None found (abstract only) |
| Maloyan, Namiot, "Breaking the Protocol…", arXiv:2601.17549, Jan 2026 (snippet only) | Analysis + protocol extension (also named "MCPSec") | Prompt injection, message authentication | None |
| Gaire et al., "Systematization of Knowledge: Security and Safety in the MCP Ecosystem", [arXiv:2512.08290](https://arxiv.org/abs/2512.08290), Dec 2025 | Survey | MCP security landscape | Motivation |
| Primbs et al., "Streamlining Plug-and-Charge Authorization for EVs with OAuth2 and OIDC", IEEE Access 2025. [arXiv:2501.14397](https://arxiv.org/abs/2501.14397) | Tamarin | OAuth device grant + RAR | Tamarin-on-OAuth precedent only |

## The candidate results

**R6: with `private_key_jwt`, the client-assertion `aud` check alone stops AS mix-up even without `iss`.**
- **Partly covered** by the audience-injection work and rfc7523bis. They establish that the assertion `aud` must be the validated issuer, and that fix is the check R6 relies on.
- We couldn't find prior work that states or machine-checks R6 itself: that the `aud` check can replace `iss` against mix-up, for a CIMD client using one key at many ASes.
- The S&P 2026 paper (read 14 Nov 2026) does not discuss it: it treats mix-up as solved by RFC 9207 and client authentication as a separate goal.
- The BCP update (§2.1, §2.2.2) treats audience injection and mix-up as separate problems. It still lists RFC 9207 `iss` (or an issuer in the redirect URI) as a condition for mix-up protection and does not offer the assertion `aud` as a substitute. R6 should therefore be read as "in this model, for confidential clients, the two defences overlap", not as advice to skip `iss`.

**R8: an unvalidated metadata `issuer` defeats both `iss` and the assertion `aud` at once.**
- **Partly covered** by the audience-injection work and the BCP update. They identify the root cause (trusting unvalidated metadata) and the fix (validate the issuer per RFC 8414 §3.3).
- We couldn't find prior work showing that one unvalidated value neutralises both defences together, or any analysis in the CIMD/MCP setting.
- The audience-injection paper *assumes* the client validates the configuration document's issuer (§2.1); its attacker keeps its own issuer and only lies about endpoints. R8 is the case that assumption excludes: the attacker claims the honest issuer, and the issuer-as-`aud` fix then fails along with `iss`. That dependency is implicit in the paper and explicit (machine-checked) in model 03.

**R9: in ID-JAG, either the RAS `aud` check or its client binding check alone stops cross-RAS replay.**
- **Partly covered** by the ID-JAG draft's own informal reasoning: it requires both checks and gives the audience-injection rationale.
- We couldn't find any formal analysis of ID-JAG, RFC 8693 token exchange or identity chaining.
- The full text of -06 was not read; check whether it already says the two checks are redundant.

**R10** (optional `resource` leads to broad-token replay) is described informally in the ID-JAG draft's security considerations, so it is partly covered at the informal level.

## Corrections this review triggered

- **CIMD requires `iss`.** CIMD draft-03 §7 says the authorization response "MUST include the `iss` parameter" (verified 14 Nov 2026). The MCP draft's "SHOULD" (R3, G1) therefore applies to ASes serving pre-registered or DCR clients. An AS that follows CIMD must send `iss` to CIMD clients. Model 03 already assumes honest ASes always send `iss`. R3 and G1 have been annotated.

## Not found / could not verify

- **MCPSec (ProVerif):** only a project page; no paper, venue or code link found. Its OAuth coverage is unknown. **This is the main open risk for the "couldn't find prior work" claims about MCP authorization.**
- **Primary PDF not read:** FAPI 2.0 (ePrint 2024/078). The audience-injection paper was read on 14 Nov 2026.
- **Not found:** any formal analysis of CIMD, ID-JAG, RFC 8693 token exchange, or refresh-token-to-issuer binding. This is absence of search hits, not proof of absence.
- **Snippet only (not opened):** the OIDF `private_key_jwt` disclosure notice, the ETH Tamarin OIDC thesis (Hofmeier 2019), a 2026 Tamarin analysis of OIDC CSRF (TechScience CMC), and CVE-2026-26390.

## How to reproduce the search

Web searches run on 14 Nov 2026 (14 queries), among them:
- `MCPSec ProVerif OAuth 2.1 Model Context Protocol formal analysis`
- `Hosseyni Küsters Würtele audience injection private_key_jwt client assertion formal analysis`
- `formal verification Model Context Protocol authorization Tamarin OR ProVerif OAuth MCP`
- `formal analysis "identity assertion authorization grant" OR "ID-JAG" OR "enterprise-managed authorization" …`
- `"Client ID Metadata Document" OAuth security analysis formal OR attack …`
- `Tamarin ProVerif formal model OAuth mix-up attack RFC 9207 issuer identification verified`
- `formal analysis OAuth 2.0 Token Exchange RFC 8693 OR "identity chaining" OR "refresh token" binding verification symbolic`

Before submission: repeat the search; read the FAPI 2.0 PDF; contact the MCPSec author for the paper.
