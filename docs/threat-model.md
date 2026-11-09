# Threat model and modelling choices

## Attacker

- **Network:** Dolev-Yao. The attacker reads, blocks, modifies and injects all messages on public channels, including every metadata document (protected resource metadata, AS metadata, client metadata documents).
- **Malicious parties:** the attacker can run its own MCP servers and authorization servers (`Compromise_AS` rule), and can register as a client.
- **Honest parties:** an honest AS or honest MCP server follows the spec and talks over TLS. TLS is modelled as a private channel to the named endpoint.
- **Cryptography is perfect** (symbolic model): no hash collisions, no forged signatures without the key.

## What the models leave out (for now)

| Simplification | Why | Revisit |
|---|---|---|
| Credential = one fresh secret | Covers client_secret, code_verifier and signed assertions for P1 | Split them in model 02 |
| No browser model | Tamarin cannot catch browser-level attacks, unlike the Web Infrastructure Model | Note it as a limit in results |
| No time or expiry | Token lifetime is not needed for P1–P3 | DPoP/expiry later |
| DPoP and multi-hop `act` left out | Keep the state space small until the base models work | After model 04 |
| Single spec version | Specs are changing (CIMD, ID-JAG are drafts) | Pin the version in each model's header |

## Validating the models against reality

Each model should **rediscover a known, already-fixed issue** when the fix is removed (`-D=VULNERABLE`), and verify the property when the fix is present. This checks that the abstraction is not too coarse to see real bugs.

| Model | Known issue used as ground truth |
|---|---|
| 01 | [GHSA-qx49-fqc8-xw99](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-qx49-fqc8-xw99): credentials not bound to their AS |
| 02 | [GHSA-w4fh-qvv9-3v23](https://github.com/modelcontextprotocol/python-sdk/security/advisories) / [GHSA-rvq5-wwqv-78pq](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories): server accepts tokens issued for another resource (to confirm) |
