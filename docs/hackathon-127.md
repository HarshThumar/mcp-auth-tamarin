# IETF 127 Hackathon (14–15 Nov 2026, remote)

Wiki: https://wiki.ietf.org/en/meeting/127/hackathon · Champion: Harsh Thumar (remote, India UTC+5:30)

## Goals for the weekend

1. ✅ Model 01 runs in CI. The `VULNERABLE` variant finds the attack, and the fixed variant verifies.
2. ✅ Model 02 (done early, 11 Nov): discovery + PKCE + RFC 8707 audience + RFC 9207 `iss`. Attacks found in `NO_AUD`, `NO_ISS` and `ISS_OPTIONAL`; the fixed variant verifies. See [results.md](results.md).
3. ✅ Modeled open item G4 (AS ignores resource indicator) as `NO_RESOURCE` variant in Model 02. Cross-RS token replay attack found in 8 steps; fixed variant verified. See [results.md](results.md) §R4.
4. ✅ Modeled open item G7 (omitting `state` parameter) as `NO_STATE` variant in Model 02. Formally proved that PKCE + RFC 9207 `iss` suffice against code injection and mix-up in the cryptographic model; all 5 lemmas verified (34/34 total lemmas green in CI). See [results.md](results.md) §R5.
5. A short written results summary prepared for the wiki and hackathon channels.

## Hours (IST)

| Hackathon (PST) | IST |
|---|---|
| Sat 14 Nov 10:00–20:30 | Sat 23:30 → Sun 10:00 |
| Sun 15 Nov 09:30–13:30 | Sun 23:00 → Mon 03:00 |
| Results presentations Sun 14:00 | Mon 16 Nov 03:30 (results posted in writing) |

## Afterwards

- IETF 127 OAuth sessions on 18, 19 (joint with WIMSE) and 20 Nov: share the model and ask for a review of the assumptions.
- Dec 2026 – Feb 2027: models 03–04, upstream conformance tests, write-up.
