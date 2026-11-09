# Results

*Last checked 9 Nov 2026: Tamarin 1.12.0, Maude 3.5.1 (CI).* `scripts/prove.sh` (and CI) checks these expectations automatically. The full Tamarin output is saved in `results/` and uploaded as a CI artifact.

| Model | Variant | Lemma | Expected | Actual | Notes |
|---|---|---|---|---|---|
| 01 | VULNERABLE | executable | verified | ✅ verified | sanity check |
| 01 | VULNERABLE | client_credential_secrecy | **falsified** | ✅ falsified (attack found) | attack: malicious RS names its own AS |
| 01 | fixed | executable | verified | ✅ verified | |
| 01 | fixed | client_credential_secrecy | verified | ✅ verified | credential bound to its AS |

## Findings and open questions

Use one entry per finding, in this format:

- **ID / date:**
- **Model + lemma:**
- **What the spec says** (quote + link):
- **What the model shows:**
- **Is it new?** (check advisories, MCP security best practices, OAuth list archive)
- **Next step:** conformance test / spec issue / private disclosure
