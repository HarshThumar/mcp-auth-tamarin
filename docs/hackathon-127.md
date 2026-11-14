# IETF 127 Hackathon (14–15 Nov 2026, remote)

Wiki: https://wiki.ietf.org/en/meeting/127/hackathon · Champion: Harsh Thumar (remote, India UTC+5:30)

## Goals for the weekend

1. ✅ Model 01 runs in CI. The `VULNERABLE` variant finds the attack, and the fixed variant verifies.
2. ✅ Model 02 (done early, 11 Nov): discovery + PKCE + RFC 8707 audience + RFC 9207 `iss`. Attacks found in `NO_AUD`, `NO_ISS` and `ISS_OPTIONAL`; the fixed variant verifies. See [results.md](results.md).
3. ✅ Modeled open item G4 (AS ignores resource indicator) as `NO_RESOURCE` variant in Model 02. Cross-RS token replay found in 8 steps when the AS issues a broad audience; fixed variant verified. See [results.md](results.md) §R4.
4. ✅ Modeled open item G7 (`state` vs PKCE) in Model 02, with attacker-controlled user accounts and a session-integrity lemma: `state` alone or PKCE alone keeps session integrity; removing both allows code injection / login CSRF. See [results.md](results.md) §R5.
5. ✅ Model 03 (CIMD: one client identity at many ASes) and Model 04 (ID-JAG), done early (14 Nov). Model 03 checks together the metadata `issuer` check, `iss`, refresh-token binding and the client assertion audience, for public and confidential clients. See [results.md](results.md) R6–R10.
6. A short written results summary prepared for the wiki and hackathon channels.

## Hours (IST)

| Hackathon (PST) | IST |
|---|---|
| Sat 14 Nov 10:00–20:30 | Sat 23:30 → Sun 10:00 |
| Sun 15 Nov 09:30–13:30 | Sun 23:00 → Mon 03:00 |
| Results presentations Sun 14:00 | Mon 16 Nov 03:30 (results posted in writing) |

## Afterwards

- IETF 127 OAuth sessions on 18, 19 (joint with WIMSE) and 20 Nov: share the model and ask for a review of the assumptions.
- Upstream conformance tests (coordinate on issue #78 first), write-up.
