# Related work (T60)

*Systematic review, 15 Nov 2026 (first draft 14 Nov). Status: **draft for Harsh's review; re-read the primary sources before citing anything in the paper.** Every link was opened during the review unless marked "(snippet only)" or "(not read)". Where a primary PDF was not read, the claim comes from the abstract page or from a paper or IETF draft that cites it. "Couldn't find prior work" means: not found by the searches logged in the last section, which is absence of search hits, not proof of absence. This is not the final T60 sign-off (due 9 May 2027): the search must be repeated before submission.*

## Summary

- **No result in R0–R16 is a new attack.** Every attack is a published one (SDK advisories, RFC 9700, MCP Security Best Practices, the audience-injection paper) or a textbook consequence of removing one check.
- What we **couldn't find prior work on** is the *machine-checked, check-by-check* statement in MCP's setting. Specifically: R6, R9, R13, R16 and the ablation lattice as a method applied to OAuth/MCP.
- The closest formal work is the Stuttgart group's WIM analyses (manual proofs). FAPI 2.0 (CSF 2024) proves the profile secure with every check on, and its client-impersonation attack has the same root cause as R8. The audience-injection paper (S&P 2026) has no formal proof of its fix and says so (§7).
- We couldn't find a formal analysis (Tamarin, ProVerif, WIM or otherwise) of CIMD, ID-JAG, RFC 8693 token exchange, MCP proxy confused deputy, token passthrough, MCP scope step-up or UPI-style agent mandates. The only MCP-related formal item that mentions OAuth is the **MCPSec** project page (ProVerif, no paper); its overlap is unknown and it is the main open risk.
- The newest agent-payment formal paper (arXiv 2609.00060, Tamarin) covers x402, MPP, ACP and AP2 only, not OAuth, MCP or UPI.

## Claims table

Verdicts (exactly one per row): **K** = confirmation of known attack/fix; **P** = known in prose, machine-checked here in the MCP setting; **N** = couldn't find prior work (as of 15 Nov 2026). Where a row is N, the note says what part is *not* new.

| Result | Closest prior work | Verdict | Note |
|---|---|---|---|
| **R0** binding keyed by an unvalidated issuer is no binding (model 01) | RFC 8414 §3.3; MCP authorization spec (issuer from validated metadata); [GHSA-qx49-fqc8-xw99](https://github.com/advisories/GHSA-qx49-fqc8-xw99) | **K** | Same failure as R8. |
| **R1** token accepted by the wrong MCP server (`NO_AUD`) | [GHSA-w4fh-qvv9-3v23](https://github.com/advisories/GHSA-w4fh-qvv9-3v23), [GHSA-rvq5-wwqv-78pq](https://github.com/advisories/GHSA-rvq5-wwqv-78pq); RFC 8707; RFC 9700 §4.10.2 | **K** | The models rediscovered published, already-fixed SDK bugs. |
| **R2** AS mix-up despite PKCE (`NO_ISS`) | Fett, Küsters, Schmitz, CCS 2016 ([arXiv:1601.01229](https://arxiv.org/abs/1601.01229)); RFC 9207; RFC 9700 §4.4 | **K** | Formal proof of `iss` as the fix exists (cited by RFC 9207). MCP twist: the server picks the AS. |
| **R3** mix-up under SHOULD `iss` (`ISS_OPTIONAL`) | RFC 9207 (protects only if the AS sends `iss`); MCP draft ("future revision … MUST"); CIMD draft-03 §7 (MUST) | **P** | Limitation known in prose; applies to non-CIMD clients only. |
| **R4** AS ignoring `resource` enables cross-RS reuse (`NO_RESOURCE`) | RFC 8707 ("when the AS supports it"); MCP spec; [spec-gaps.md](spec-gaps.md) G4 | **P** | Scope condition: AS must issue broad audiences. |
| **R5** `state` or PKCE alone keeps session integrity | RFC 9700 §4.5, §4.7; Fett et al. 2016 (session integrity); [arXiv:1901.11520](https://arxiv.org/abs/1901.11520) (FAPI, PKCE) | **K** | Matches OAuth 2.1 / RFC 9700. |
| **R6** with `private_key_jwt`, assertion `aud` alone stops mix-up without `iss` (and `iss` alone suffices without assertion `aud`) | Audience-injection paper (ePrint 2025/629); draft-ietf-oauth-rfc7523bis-10; FAPI 2.0 (ePrint 2024/1540) proves both on | **N** | Not new: the issuer-as-`aud` fix. We couldn't find a statement or proof that the two defences are redundant against mix-up, for one key at many ASes. FAPI proofs (186 pp.) only skimmed: **unverified** whether its proof uses only one of them. BCP update still lists `iss` for mix-up. Not advice to skip `iss`. |
| **R7** refresh token must be bound to its issuer (`RT_UNBOUND`) | RFC 9700 §4.14; MCP "Authorization Server Binding" (names client credentials, not refresh tokens); [spec-gaps.md](spec-gaps.md) G3 | **P** | Standard OAuth practice; machine-checked consequence for CIMD/confidential vs public. |
| **R8** unvalidated metadata `issuer` defeats `iss` and assertion `aud` together (`NO_META_CHECK`) | FAPI 2.0 §3.2 "Client Impersonation" (same root cause, fix: use AS metadata); audience-injection paper §2.1 (assumes issuer validated); BCP update §2.2.2; RFC 8414 §3.3 | **P** | Largely covered in mechanism. Left: the machine-checked trace in MCP's "server names the AS" setting. |
| **R9** ID-JAG: either RAS check (`aud`, client binding) alone stops cross-RAS replay | ID-JAG draft-06 §4.4.1 (both MUST), §9.4, §9.5 | **N** | Replay class is known. Draft §9 lists checks as layered and does not say either suffices (read 15 Nov; -06 §§4.3–4.4 and 9 read). Not found: any formal analysis of ID-JAG. |
| **R10** ID-JAG `resource` optional leads to broad-token replay | ID-JAG draft-06 §4.3.3 (ID-JAG without `resource` "is not restricted to a specific protected resource"), §9.5 (defence depends on the client including `resource`) | **P** | The draft states the absence of restriction but does not state the replay consequence. Same assumption as R4 (broad-audience RAS). |
| **R11** exact redirect URI matching needed; PKCE does not replace it | RFC 9700 §4.1; Fett et al. 2016; Bansal et al., CSF 2012 / JCS 2014 | **K** | |
| **R12** audience injection against a CIMD client; client-side issuer-as-`aud` fix suffices | Hosseyni, Küsters, Würtele, S&P 2026 (ePrint 2025/629; no formal proof, §7 calls for one); rfc7523bis-10; BCP update §2.1 | **P** | Machine-checked in the CIMD setting; only one second phase (client-credentials) modelled. |
| **R13** agent payment mandate (model 05): which check stops which loss | arXiv 2609.00060 (Tamarin: x402, MPP, ACP, AP2); arXiv 2602.06345 (runtime verification of AP2 mandates); arXiv 2608.23858 (informal AP2); draft-mishra-oauth-agent-grants-02; Malladi 2021 (UPI, no delegation) | **N** | No new attack. Not found: a formal analysis of UPI-style delegated or agent mandates, nor of Visa TAP / Mastercard Verifiable Intent (searched 15 Nov). NPCI rules known only from a secondary summary. |
| **R14** proxy confused deputy: per-client consent and exact redirect URI each stop a different attack | MCP Security Best Practices, "Confused Deputy Problem" (prescribes both) | **K** | Machine-checked necessity per mitigation. No formal prior work found. |
| **R15** token passthrough: downstream audience check is what stops circumvention | MCP Security Best Practices ("Token Passthrough", "Security Control Circumvention"); MCP Token Handling | **K** | |
| **R16** scope step-up: audience binding plus per-resource consent; union across resources alone is harmless | MCP spec (step-up, union); RFC 8707; R14 and model 02 mechanisms | **N** | Nothing new on the attack side (only path is broken audience binding or consent not bound to the resource). The consent-record finding (`CONSENT_NOT_RESOURCE_BOUND`) and "union alone is harmless" are not stated in anything we found; the spec leaves consent recording open. Only practitioner blogs on scope step-up found. |
| **Ablation lattice** (every flag subset per model; consistency and monotonicity checks) | FAPI/WIM analyses prove one fixed profile; Cremers and Dehnel-Wild, NDSS 2019 (Tamarin; which unstated assumptions 5G-AKA relies on); arXiv 2609.00060 ("minimally strengthened reference models") | **N** | Closest in spirit: component-based Tamarin analyses that expose which assumptions a protocol silently needs. We couldn't find a systematic "every subset of checks, which are necessary and which sufficient" analysis of OAuth or MCP. A 802.11 4-way handshake Tamarin paper on property adequacy surfaced only as a search snippet and was **not identified or read (unverified)**. Part of the novelty is method, not result. |

**Results marked N:** R6, R9, R13, R16, ablation lattice. Even these come with the caveats in their notes; none may be described as "first".

## Prior work

| Work | Method | What it covers | Overlap with this project |
|---|---|---|---|
| Fett, Küsters, Schmitz, "A Comprehensive Formal Security Analysis of OAuth 2.0", CCS 2016. [arXiv:1601.01229](https://arxiv.org/abs/1601.01229) | Web Infrastructure Model (WIM), manual proofs | OAuth 2.0 grant types; malicious RPs, IdPs and browsers; authorization, authentication, session integrity; mix-up and the `iss` defence | R2–R5, R11 conceptually, generic OAuth. No MCP, no RS-driven AS discovery. |
| Fett, Küsters, Schmitz, "The Web SSO Standard OpenID Connect: In-Depth Formal Security Analysis and Security Guidelines", CSF 2017. [arXiv:1704.08539](https://arxiv.org/abs/1704.08539) | WIM | OpenID Connect | Background |
| Fett, Hosseyni, Küsters, "An Extensive Formal Security Analysis of the OpenID Financial-grade API", IEEE S&P 2019. [arXiv:1901.11520](https://arxiv.org/abs/1901.11520) | WIM | FAPI 1.0; JWS client assertions; PKCE; four attacks found | Background (same style as R2–R5) |
| Hosseyni, Küsters, Würtele, "Formal Security Analysis of the OpenID FAPI 2.0 Family of Protocols", CSF 2024. [ePrint 2024/078](https://eprint.iacr.org/2024/078); full version [ePrint 2024/1540](https://eprint.iacr.org/2024/1540) | WIM, manual proofs | FAPI 2.0, FAPI-CIBA (full version §§2–4 read 14 Nov 2026) | Says it is the first formal analysis of JWT client authentication (§4). Many ASes, some corrupted; client gets the issuer by configuration and checks metadata `issuer` (§2.2), always checks `iss`, assertion carries the issuer as `aud`. §3.2 "Client Impersonation": client tricked into an attacker token endpoint leaks assertions valid at the honest AS; fix adopted by the FAPI WG: clients MUST use AS metadata. Lemma 12: an honest client's assertion for an honest AS never leaks. All checks on together; no ablation. **Closest formal work for R6 and R8.** |
| Helmschmidt, Hosseyni, Küsters, Pruiksma, Waldmann, Würtele, "The Grant Negotiation and Authorization Protocol: Attacking, Fixing, and Verifying an Emerging Standard", ESORICS 2023. [ePrint 2023/1325](https://eprint.iacr.org/2023/1325) | WIM | GNAP | None directly |
| Hosseyni, Küsters, Würtele, "Audience Injection Attacks: A New Class of Attacks on Web-Based Authorization and Authentication Standards", IEEE S&P 2026. [ePrint 2025/629](https://eprint.iacr.org/2025/629) (PDF read 14 Nov 2026; ePrint revised 2 Dec 2025 per the listing) | Attack paper: manual analysis, coordinated disclosure; **no formal proof of the fix** | An attacker AS lists an honest AS's endpoint in its configuration document; a client that uses one key at both ASes signs an assertion the honest AS accepts. Fix (§5): issuer identifier as the assertion `aud`; "cannot be mitigated solely by the AS". Assumes the client validates the configuration document's issuer (§2.1). Mix-up is left to RFC 9207 (§2.3). §7: "a rigorous formal security analysis of these methods [is] a promising avenue for future research." | **Closest prior work for R6, R8, R12**; related to R9 |
| Bansal, Bhargavan, Delignat-Lavaud, Maffeis, "Discovering concrete attacks on website authorization by formal analysis", CSF 2012 / J. Computer Security 2014. [JCS PDF](https://microsoft.com/en-us/research/wp-content/uploads/2017/07/jcs14.pdf) (snippet only) | ProVerif (WebSpi) | OAuth 2.0 and other web authorization protocols | Earlier ProVerif-on-OAuth precedent; no MCP, CIMD, ID-JAG. |
| draft-ietf-oauth-security-topics-update-01, §2.1 "Audience Injection Attacks", §2.2.2. [datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-security-topics-update/01/) | IETF draft (informal) | Attacker AS publishes an honest AS's endpoint in its metadata; fix: issuer as sole `aud`, validated per RFC 8414 §3.3; mix-up defences need a validated issuer | Informally overlaps R6, R8, R12 |
| draft-ietf-oauth-rfc7523bis-10. [datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/10/) | IETF draft | Client-assertion `aud` MUST be the AS issuer as sole value | Spec source for the fix in R6/R8/R12 |
| draft-ietf-oauth-identity-assertion-authz-grant-06 (ID-JAG), 31 Oct 2026. [datatracker](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant) (§§4.3–4.4, 9 read 15 Nov 2026) | IETF draft (informal) | §4.4.1 two separate MUST checks (`aud`, `client_id`), "prevents audience injection attacks"; §4.3.3 ID-JAG without `resource` is not restricted to a resource; §9.4 no reuse at a different RAS; §9.5 client-side issuer check is "the primary defense", relay defeated by sender constraint; `resource` RECOMMENDED | Informally overlaps R9, R10. Does not say either check suffices. |
| draft-ietf-oauth-client-id-metadata-document-03 (CIMD), 2 Nov 2026. [datatracker](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document) | IETF draft | `private_key_jwt` with keys from the document; §7: "The authorization response MUST include the `iss` parameter" | Subject of model 03; no formal analysis found |
| RFC 9700, OAuth 2.0 Security BCP, Jan 2025. [rfc-editor](https://www.rfc-editor.org/rfc/rfc9700.html) | BCP | §4.1 redirect URIs, §4.4 mix-up, §4.5 code injection, §4.7 CSRF, §4.10.2 audience restriction, §4.14 refresh tokens | Citation anchor for R2–R5, R7, R11 |
| RFC 9207, OAuth 2.0 Authorization Server Issuer Identification. [rfc-editor](https://www.rfc-editor.org/rfc/rfc9207) | RFC | `iss` response parameter; cites the CCS 2016 formal proof of its effectiveness | Fix for R2, R3 |
| "MCPSec" project page (Zilin Shen), 2026. [project page](https://zilinlin.github.io/projects/3_mcpsec) | ProVerif | Page (re-checked 14 Nov 2026): ProVerif models of MCP initialization, tool discovery, sampling, OAuth 2.1 and multi-server setups, against four threat models: prompt injection, tool poisoning, data leakage, privilege escalation. 8 attack scenarios on the MCP Python SDK; defences re-verified. No paper, venue or public code. | **Overlap unknown, probably partial.** Threat models are application-layer, but OAuth 2.1 and multi-server flows are in scope. Ask the author. Name clash with Maloyan & Namiot (below). |
| Jiang et al., "A Formal Analysis of Agent Payment Protocols", [arXiv:2609.00060](https://arxiv.org/abs/2609.00060), 30 Aug 2026 (abstract page read 15 Nov 2026) | Tamarin | x402, MPP, ACP, AP2; 86 cases, 46 known or calibration, 40 new "formal-consistency findings"; 18 shared principles; "minimally strengthened reference models"; main conclusion: delegated authorization must stay consistent with its economic and service effects | No OAuth, MCP or UPI. Closest to R13 and, loosely, to the ablation idea. Full text not read. |
| Lan et al., [arXiv:2602.06345](https://arxiv.org/abs/2602.06345) (not re-read) | Runtime verification | Replay and context-binding failures in AP2 mandates | Adjacent to R13 |
| "Beyond the Mandate", arXiv:2608.23858 (not re-read) | Informal analysis | AP2 | Adjacent to R13 |
| Zhou et al. (Fudan), "A First Measurement Study on Authentication Security in Real-World Remote MCP Servers", [arXiv:2605.22333](https://arxiv.org/abs/2605.22333), 21 May 2026 (abstract page read 15 Nov 2026) | Measurement | 7,973 remote MCP servers; 119 testable OAuth servers, 325 flaws, 9 CVEs; 4 categories, 9 flaw types; dynamic client registration flaws in 96.6 % | Empirical complement; no formal analysis; abstract does not name mix-up, audience, issuer or CIMD, so whether the taxonomy covers them is **unverified** |
| Zheng, Zhang, "AgentRFC: Security Design Principles and Conformance Testing for Agent Protocols", [arXiv:2603.23801](https://arxiv.org/abs/2603.23801), 25 Mar 2026 (abstract page read 15 Nov 2026) | TLA+ + SDK replay | MCP, A2A, ANP, ACP; 11 principles as TLA+ invariants; AgentConform; preliminary findings on credential lifecycle, consent enforcement, audit, composition; some under disclosure | Different level. Abstract mentions no OAuth, audience, mix-up or CIMD. Full evaluation deferred to a later version: re-check. |
| Acharya, Gupta, "A Formal Security Framework for MCP-Based AI Agents" (MCPSHIELD), [arXiv:2604.05969](https://arxiv.org/abs/2604.05969), 7 Apr 2026 (abstract page read 15 Nov 2026) | Labelled transition systems, taxonomy | 7 categories, 23 attack vectors, 12 defences compared, reference architecture | No OAuth, authorization server, audience or token binding in the abstract. Not a protocol-level verification. |
| Maloyan, Namiot, "Breaking the Protocol…", arXiv:2601.17549, Jan 2026 (snippet only) | Analysis + protocol extension (also named "MCPSec") | Prompt injection, message authentication | None |
| Gaire et al., "Systematization of Knowledge: Security and Safety in the MCP Ecosystem", [arXiv:2512.08290](https://arxiv.org/abs/2512.08290), Dec 2025 | Survey | MCP security landscape | Motivation |
| arXiv:2603.07473, Mar 2026 (search snippet only; title not read) | Empirical | Caller-identity confusion; 8 of 87 MCP-related projects with authentication issues | Adjacent; **unverified** |
| Primbs et al., "Streamlining Plug-and-Charge Authorization for EVs with OAuth2 and OIDC", IEEE Access 2025. [arXiv:2501.14397](https://arxiv.org/abs/2501.14397) | Tamarin | OAuth device grant + RAR | Tamarin-on-OAuth precedent only |
| Hermenius, Strömbäck Olofsson, Chalmers master's thesis on mAuth, 2026. [PDF](https://odr.chalmers.se/bitstreams/6a478ad7-2825-4b5f-8044-92d7760287eb/download) (search snippet / table of contents only) | Tamarin | mAuth native-app authorization against OAuth-based standards; CIBA, FIDO2, ROPC variants; token binding and discovery/registration sections | Tamarin-on-OAuth precedent; no MCP, CIMD, ID-JAG found; lemmas **not read** |
| Cremers, Dehnel-Wild, "Component-Based Formal Analysis of 5G-AKA: Channel Assumptions and Session Confusion", NDSS 2019. [NDSS page](https://www.ndss-symposium.org/ndss-paper/component-based-formal-analysis-of-5g-aka-channel-assumptions-and-session-confusion/) (snippet only) | Tamarin | Which unstated channel assumptions 5G-AKA relies on | Methodological neighbour of the ablation lattice (assumption-by-assumption analysis), different domain |
| Kumar, Kishore, Lu, Prakash, "Security Analysis of Unified Payments Interface and Payment Apps in India", USENIX Security 2020. [USENIX page](https://www.usenix.org/conference/usenixsecurity20/presentation/kumar) | Empirical reverse-engineering | Multi-factor authentication flaws in UPI 1.0 specifications and apps | Adjacent to R13; no delegation |
| Malladi, "Towards Formal Modeling and Analysis of UPI Protocols", 2021. [CPS-VO](https://archive.cps-vo.org/node/82178) (snippet only; page fetch failed) | Modelling for Tamarin/ProVerif | UPI | Adjacent to R13; whether it models delegation **unverified** (earlier review: no delegation) |
| Tudorache, Kurtev, van den Brand, "Bridging Theory and Practice: An Executable Taxonomy of Security Properties for ProVerif and Tamarin", [arXiv:2605.29465](https://arxiv.org/abs/2605.29465), May 2026 (abstract read) | Literature review, patterns | Property taxonomy from 53 studies | Useful for property-naming; not OAuth, not ablation |
| Davliatshin, ProVerif analysis of attenuation chains, [draft report](https://datatracker.ietf.org/doc/draft-davliatshin-oauth-attenuation-chains-report/) (not re-read) | ProVerif | Delegation attenuation chains | Not MCP, not RFC 8693 |

## Per-area survey

**Formal OAuth/OIDC/FAPI.** Strong, mostly Stuttgart WIM work with manual proofs (CCS 2016, CSF 2017, S&P 2019, ESORICS 2023, CSF 2024). Earlier ProVerif (Bansal et al.) and a few Tamarin case studies (EV charging, mAuth thesis, SOAP) exist. All analyse a fixed profile with all checks on. None covers MCP's setting where an untrusted resource server names the AS, CIMD (one client identity at many ASes), or ID-JAG.

**Audience injection and client assertions.** The S&P 2026 paper plus rfc7523bis and the BCP update give the attack, the fix and the informal reasoning; no formal proof of the fix. FAPI 2.0 gives a formal proof of the profile with issuer-as-`aud` and `iss` both on. R6, R8, R12 sit directly here.

**MCP security (formal or semi-formal).** MCPSec (ProVerif, page only), AgentRFC (TLA+ invariants over MCP, A2A, ANP, ACP), MCPSHIELD (taxonomy plus transition systems). Measurement: Fudan 2605.22333. Nothing found that models AS selection, audience binding, CIMD, proxy confused deputy, passthrough or step-up in a symbolic prover. Practitioner and CSA material on these (secondary, partly AI-assisted per its own disclaimer) is not formal.

**CIMD, ID-JAG, token exchange.** Spec drafts only (CIMD-03, ID-JAG-06, RFC 8693). Search for formal analyses of RFC 8693, identity chaining and RFC 8707 audience restriction returned only specs and practitioner blogs. ID-JAG §9 gives layered informal defences.

**Agent payments and UPI.** 2609.00060 (Tamarin, four protocols), 2602.06345 (runtime verification), 2608.23858 (informal). Visa TAP and Mastercard Verifiable Intent: only vendor and press material found. UPI: reverse-engineering (Kumar 2020) and Malladi 2021; nothing on UPI Circle or agent delegation.

**Ablation and minimal-sufficient-check analyses.** Component-based and assumption-minimising Tamarin analyses exist in other domains (5G-AKA; 802.11 handshake snippet unverified). 2609.00060 builds "minimally strengthened reference models". We couldn't find a systematic subset-lattice over protocol checks for OAuth.

**Known attacks (for the K/P rows).** RFC 9700 covers redirect manipulation, mix-up, code injection, CSRF, audience restriction and refresh tokens. MCP Security Best Practices cover confused deputy, passthrough and scope handling. Public SDK advisories GHSA-qx49-fqc8-xw99, GHSA-w4fh-qvv9-3v23 and GHSA-rvq5-wwqv-78pq cover R0 and R1.

## Corrections this review triggered

- **CIMD requires `iss`.** CIMD draft-03 §7 says the authorization response "MUST include the `iss` parameter" (verified 14 Nov 2026). The MCP draft's "SHOULD" (R3, G1) therefore applies to ASes serving pre-registered or DCR clients. R3 and G1 have been annotated.
- **R10 wording (15 Nov).** The earlier draft of this file said the ID-JAG security considerations describe R10. Reading -06 §9 shows they do not address an ID-JAG issued without `resource`; only §4.3.3 states that such an ID-JAG is not restricted to a resource. R10 is therefore marked P, and the replay consequence is not in the draft.
- **R9 wording (15 Nov).** -06 §§4.4.1 and 9 present the two checks as layered and do not say either one suffices, so the redundancy statement is marked N (the replay class itself is known). The earlier note "check whether -06 already says the two checks are redundant" is resolved.
- **R16 and the ablation lattice** were not covered by the 14 Nov draft and are classified above.

## Not found / could not verify

- **MCPSec (ProVerif):** only a project page; no paper, venue or public code found (web, arXiv and GitHub, 14 Nov and again 15 Nov). OAuth 2.1 and multi-server flows are in scope, so some overlap with models 01–02 is possible. **Main open risk for "couldn't find prior work" claims about MCP authorization.** Also not formal models despite similar names: MCPSecBench (arXiv 2508.13220, benchmark), MCP-SafetyBench (arXiv 2512.15163), a Gopher Security blog post.
- Audience-injection paper and FAPI 2.0 full version were read 14 Nov (§§2–4 of the latter); the FAPI appendices with the formal model and proofs (186 pp.) were only skimmed. **Whether FAPI's proofs use only one of `iss` and issuer-as-`aud` is unverified**, which matters for R6.
- **Not found:** any formal analysis of CIMD, ID-JAG, RFC 8693 token exchange, refresh-token-to-issuer binding, MCP proxy confused deputy, token passthrough, scope step-up, Visa TAP, Mastercard Verifiable Intent, or UPI-style delegation.
- **Unverified / snippet only:** Bansal et al. JCS 2014, mAuth thesis lemmas, Cremers–Dehnel-Wild framing, Malladi 2021 content (fetch failed), arXiv 2603.07473, a 802.11 4-way handshake property-adequacy paper, the OIDF `private_key_jwt` disclosure notice, the ETH Tamarin OIDC thesis (Hofmeier 2019), a 2026 Tamarin analysis of OIDC CSRF (TechScience CMC), CVE-2026-26390, and CSA research notes (9 Nov and 30 Sep 2026; secondary, AI-assisted).
- AgentRFC says full evaluation is deferred; its later version may overlap with consent or credential-lifecycle results. Re-check before submission.
- Search engine was US-only and returns summaries, not full text. Venue proceedings (CSF, S&P, CCS, USENIX Security, EuroS&P, NDSS 2024–2026) were not browsed directly: a manual sweep of their programmes is still to do.

## Searches performed

Run 14 Nov 2026 (14 queries) and 15 Nov 2026 (the queries below plus fetches). Each query was run once with the web search tool; US-only, summaries.

14 Nov (among others):
- `MCPSec ProVerif OAuth 2.1 Model Context Protocol formal analysis`
- `Hosseyni Küsters Würtele audience injection private_key_jwt client assertion formal analysis`
- `formal verification Model Context Protocol authorization Tamarin OR ProVerif OAuth MCP`
- `formal analysis "identity assertion authorization grant" OR "ID-JAG" OR "enterprise-managed authorization" …`
- `"Client ID Metadata Document" OAuth security analysis formal OR attack …`
- `Tamarin ProVerif formal model OAuth mix-up attack RFC 9207 issuer identification verified`
- `formal analysis OAuth 2.0 Token Exchange RFC 8693 OR "identity chaining" OR "refresh token" binding verification symbolic`

15 Nov:
1. `formal analysis Model Context Protocol authorization OAuth Tamarin OR ProVerif`
2. `formal verification OAuth mix-up attack RFC 9207 issuer identification Tamarin ProVerif`
3. `formal analysis "Client ID Metadata Document" OR "identity assertion authorization grant" OAuth security`
4. `formal analysis agent payment protocols AP2 Visa Trusted Agent Protocol Mastercard Verifiable Intent symbolic verification`
5. `formal analysis UPI protocol Tamarin OR ProVerif delegated payments`
6. `MCP confused deputy proxy token passthrough OAuth scope step-up formal model verification`
7. `formal security analysis OAuth PKCE code injection Tamarin OR ProVerif OR "web infrastructure model" 2024 2025`
8. `formal analysis OAuth token exchange RFC 8693 delegation chaining symbolic model audience restriction RFC 8707`
9. `protocol verification which security checks are necessary ablation minimal sufficient set of checks Tamarin removing one check each attack`
10. `arXiv 2026 MCP authorization security analysis OAuth Model Context Protocol attack authorization server mix-up SDK`
11. `Tamarin OAuth 2.0 formal model refresh token binding authorization server malicious dynamic client registration`
12. `formal analysis agent delegation OAuth AI agents authorization on-behalf-of formal verification 2026`
13. `Cremers Dehnel-Wild component-based formal analysis of 5G-AKA minimal assumptions NDSS 2019`
14. `Hosseyni Küsters Würtele 2026 OAuth formal analysis new paper ePrint`
15. `draft-ietf-oauth-identity-assertion-authz-grant security considerations replay cross-domain formal`
16. `"Trusted Agent Protocol" OR "Verifiable Intent" OR "Agent Pay" formal verification Tamarin ProVerif analysis paper`
17. `mAuth Chalmers thesis Tamarin OAuth CIBA FIDO2 native app authorization`
18. `ProVerif OR Tamarin OAuth 2.1 OR OpenID Connect formal analysis 2025 2026 audience restriction client authentication JWT assertion`

Pages fetched 15 Nov: arXiv 2609.00060, 2603.23801, 2604.05969, 2605.29465, 2605.22333 (abstract pages); ID-JAG draft-06 full text (§§4.3–4.4, 9; datatracker). Failed fetch: CPS-VO page for Malladi 2021 (connection reset).

Before submission: repeat all queries; sweep CSF/S&P/CCS/USENIX/EuroS&P/NDSS 2024–2027 programmes and arXiv cs.CR by hand; re-read the primary PDFs behind every P and N row; contact the MCPSec author for the paper.
