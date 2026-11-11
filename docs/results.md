# Results

*Model 01 last checked 9 Nov 2026: Tamarin 1.12.0, Maude 3.5.1 (CI). Model 02 drafted 11 Nov 2026, not run yet.* `scripts/prove.sh` (and CI) checks these expectations automatically. The full Tamarin output is saved in `results/` and uploaded as a CI artifact.

| Model | Variant | Lemma | Expected | Actual | Notes |
|---|---|---|---|---|---|
| 01 | VULNERABLE | executable | verified | ✅ verified | sanity check |
| 01 | VULNERABLE | client_credential_secrecy | **falsified** | ✅ falsified (attack found) | attack: malicious RS names its own AS |
| 01 | fixed | executable | verified | ✅ verified | |
| 01 | fixed | client_credential_secrecy | verified | ✅ verified | credential bound to its AS |
| 02 | NO_AUD | executable | verified | ⏳ not run yet | |
| 02 | NO_AUD | rs_accepts_only_consented | **falsified** | ⏳ | expected attack: token for a malicious MCP server replayed to an honest one (GHSA-w4fh-qvv9-3v23 / GHSA-rvq5-wwqv-78pq) |
| 02 | NO_AUD | token_secrecy | verified | ⏳ | |
| 02 | NO_ISS | executable | verified | ⏳ | |
| 02 | NO_ISS | rs_accepts_only_consented | verified | ⏳ | |
| 02 | NO_ISS | token_secrecy | **falsified** | ⏳ | expected attack: AS mix-up despite PKCE (RFC 9700 §4.4) |
| 02 | ISS_OPTIONAL | executable | verified | ⏳ | |
| 02 | ISS_OPTIONAL | rs_accepts_only_consented | verified | ⏳ | |
| 02 | ISS_OPTIONAL | token_secrecy | **falsified** | ⏳ | expected: mix-up still possible when the honest AS omits `iss` (allowed today: "SHOULD") |
| 02 | fixed | executable | verified | ⏳ | |
| 02 | fixed | rs_accepts_only_consented | verified | ⏳ | audience checked |
| 02 | fixed | token_secrecy | verified | ⏳ | `iss` always sent and checked |

## Findings and open questions

Use one entry per finding, in this format:

- **ID / date:**
- **Model + lemma:**
- **What the spec says** (quote + link):
- **What the model shows:**
- **Is it new?** (check advisories, MCP security best practices, OAuth list archive)
- **Next step:** conformance test / spec issue / private disclosure
