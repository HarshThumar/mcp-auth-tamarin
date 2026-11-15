# References

## MCP
- Authorization spec (draft): https://modelcontextprotocol.io/specification/draft/basic/authorization
- Security best practices: https://modelcontextprotocol.io/specification/draft/basic/security_best_practices
- Conformance suite: https://github.com/modelcontextprotocol/conformance (audience-validation tests: issue #78)
- SDK tiers: https://modelcontextprotocol.io/community/sdk-tiers
- Python SDK advisories: https://github.com/modelcontextprotocol/python-sdk/security/advisories
- TypeScript SDK advisories: https://github.com/modelcontextprotocol/typescript-sdk/security/advisories

## IETF
- RFC 9728 OAuth 2.0 Protected Resource Metadata: https://datatracker.ietf.org/doc/rfc9728/
- RFC 8414 OAuth 2.0 Authorization Server Metadata: https://datatracker.ietf.org/doc/rfc8414/
- RFC 8707 Resource Indicators: https://datatracker.ietf.org/doc/rfc8707/
- RFC 9207 Authorization Server Issuer Identification: https://datatracker.ietf.org/doc/rfc9207/
- RFC 7636 PKCE: https://datatracker.ietf.org/doc/rfc7636/
- RFC 7591 Dynamic Client Registration: https://datatracker.ietf.org/doc/rfc7591/
- RFC 8693 Token Exchange: https://datatracker.ietf.org/doc/rfc8693/
- RFC 7523 JWT Bearer grant: https://datatracker.ietf.org/doc/rfc7523/
- RFC 9700 OAuth 2.0 Security Best Current Practice: https://datatracker.ietf.org/doc/rfc9700/
- Identity Assertion Authorization Grant (ID-JAG): https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/

## Formal methods
- Tamarin prover manual: https://tamarin-prover.com/manual/
- Fett, Küsters, Schmitz: "A Comprehensive Formal Security Analysis of OAuth 2.0" (CCS 2016): https://arxiv.org/abs/1601.01229
- Stuttgart group (FAPI 2.0, audience injection): https://www.sec.uni-stuttgart.de/institute/team/Hosseyni/
- MCPSec (ProVerif models of MCP): https://zilinlin.github.io/projects/3_mcpsec
- Fett, Hosseyni, Küsters: FAPI 1.0 analysis (S&P 2019): https://arxiv.org/abs/1901.11520
- Fett, Küsters, Schmitz: OpenID Connect analysis (CSF 2017): https://arxiv.org/abs/1704.08539
- Hosseyni, Küsters, Würtele: FAPI 2.0 (CSF 2024): https://eprint.iacr.org/2024/078 (full version https://eprint.iacr.org/2024/1540)
- Hosseyni, Küsters, Würtele: Audience Injection Attacks (S&P 2026): https://eprint.iacr.org/2025/629
- Helmschmidt et al.: GNAP analysis (ESORICS 2023): https://eprint.iacr.org/2023/1325
- Bansal, Bhargavan, Delignat-Lavaud, Maffeis: ProVerif/WebSpi OAuth analysis (JCS 2014): https://microsoft.com/en-us/research/wp-content/uploads/2017/07/jcs14.pdf
- Jiang et al.: A Formal Analysis of Agent Payment Protocols (Tamarin; x402, MPP, ACP, AP2): https://arxiv.org/abs/2609.00060
- Zhou et al.: Remote MCP server authentication measurement: https://arxiv.org/abs/2605.22333
- Zheng, Zhang: AgentRFC (TLA+): https://arxiv.org/abs/2603.23801
- Acharya, Gupta: MCPSHIELD (taxonomy, transition systems): https://arxiv.org/abs/2604.05969
- Lan et al.: runtime verification of AP2 mandates: https://arxiv.org/abs/2602.06345
- Cremers, Dehnel-Wild: Component-based analysis of 5G-AKA (NDSS 2019, ablation-style neighbour): https://www.ndss-symposium.org/ndss-paper/component-based-formal-analysis-of-5g-aka-channel-assumptions-and-session-confusion/
- Tudorache et al.: executable taxonomy of properties for ProVerif/Tamarin: https://arxiv.org/abs/2605.29465
- Chalmers master's thesis on mAuth (Tamarin, OAuth-based; lemmas not read): https://odr.chalmers.se/bitstreams/6a478ad7-2825-4b5f-8044-92d7760287eb/download
- Kumar, Kishore, Lu, Prakash: "Security Analysis of Unified Payments Interface and Payment Apps in India" (USENIX Security 2020): https://www.usenix.org/conference/usenixsecurity20/presentation/kumar
- Malladi: Towards Formal Modeling and Analysis of UPI Protocols (2021): https://archive.cps-vo.org/node/82178
- Related-work review with all claims and the search log: [related-work.md](related-work.md)
- ProVerif analysis of attenuation chains (not MCP or RFC 8693): https://datatracker.ietf.org/doc/draft-davliatshin-oauth-attenuation-chains-report/
