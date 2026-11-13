# mcp-auth-tamarin

**A formal model of MCP authorization in the [Tamarin prover](https://tamarin-prover.com): untrusted servers, authorization-server discovery and enterprise token exchange.**

[![tamarin](https://github.com/HarshThumar/mcp-auth-tamarin/actions/workflows/tamarin.yml/badge.svg)](https://github.com/HarshThumar/mcp-auth-tamarin/actions/workflows/tamarin.yml)

> Status: **work in progress**, started for the [IETF 127 Hackathon](https://wiki.ietf.org/en/meeting/127/hackathon) (14–15 Nov 2026, remote).

## Why

In the [Model Context Protocol](https://modelcontextprotocol.io/specification/draft/basic/authorization), the server a client connects to tells the client which authorization server to use ([RFC 9728](https://datatracker.ietf.org/doc/rfc9728/) Protected Resource Metadata). That server may be untrusted. A single client identity can also be reused across many authorization servers (Client ID Metadata Documents), and the Enterprise-Managed Authorization extension chains an [RFC 8693](https://datatracker.ietf.org/doc/rfc8693/) token exchange at the identity provider with an [RFC 7523](https://datatracker.ietf.org/doc/rfc7523/) JWT bearer grant at the MCP authorization server.

Classic formal analyses of OAuth do not cover this exact setup. Real bugs show it matters. For example, [GHSA-qx49-fqc8-xw99](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-qx49-fqc8-xw99) (MCP Python SDK, Sep 2026) let a malicious MCP server receive OAuth credentials meant for the user's real authorization server.

**Goal:** find attacks or prove which client-side checks (issuer, resource, credential-to-AS binding) are sufficient, and turn each result into a conformance test or a spec clarification.

**Motivating use case:** AI agents that start payments. One example is India's UPI agentic-payment pilots, where the payment network has said authentication "must follow deterministic auditable rules".

## Models

| # | Model | What it checks | Variants | Status |
|---|---|---|---|---|
| 01 | [`01_as_selection.spthy`](models/01_as_selection.spthy) | Does a client credential reach only the AS it belongs to? | `VULNERABLE` (unbound credential) / fixed (bound) | ✅ falsified / verified (CI) |
| 02 | [`02_code_and_audience.spthy`](models/02_code_and_audience.spthy) | Does a code / token reach only the intended AS and MCP server? (PKCE + RFC 8707 audience + RFC 9207 `iss`) | `NO_AUD` / `NO_ISS` / `ISS_OPTIONAL` / `NO_RESOURCE` / `NO_STATE` / fixed | ✅ attacks found in weakened variants; fixed and NO_STATE verified (34/34 lemmas in CI) |
| 03 | [`03_cimd_client_binding.spthy`](models/03_cimd_client_binding.spthy) | One CIMD client identity at many ASes: which checks (metadata `issuer`, `iss`, refresh-token binding, assertion `aud`) keep codes, tokens and refresh tokens bound to their AS? | confidential / `PUBLIC` × `NO_META_CHECK` / `NO_ISS` / `RT_UNBOUND` / `AS_NO_ASSERTION_AUD` | ✅ fixed verified for both client types; attacks in weakened variants (CI) |
| 04 | [`04_id_jag.spthy`](models/04_id_jag.spthy) | Enterprise-Managed Authorization (ID-JAG): RFC 8693 at the IdP + RFC 7523 at the MCP AS | `NO_IDJAG_AUD` / `NO_CLIENT_BINDING` / both / `NO_RESOURCE_CLAIM` / fixed | ✅ fixed verified; replay needs both RAS checks off (CI) |

Results are tracked in [docs/results.md](docs/results.md). Each modelling choice is listed in [docs/threat-model.md](docs/threat-model.md).

## Run it

Requirements: [Tamarin prover](https://tamarin-prover.com/manual/master/book/002_installation.html) (1.12+) and [Maude](https://github.com/maude-lang/Maude/releases) (3.x). On Windows, use WSL.

```bash
# Linux / WSL / macOS
scripts/prove.sh                          # runs every variant and checks expected results

# or one model at a time
tamarin-prover --prove models/01_as_selection.spthy -D=VULNERABLE
tamarin-prover --prove models/01_as_selection.spthy
tamarin-prover interactive models/        # web UI at http://127.0.0.1:3001 (needs GraphViz)
```

CI (GitHub Actions) runs `scripts/prove.sh` on every push.

## Repository layout

```
models/        Tamarin theories (.spthy), one file per question
scripts/       prove.sh: runs all models, compares with expected results
docs/          flow.md (MCP auth flow), threat-model.md, results.md, spec-gaps.md, references.md, hackathon-127.md
results/       Tamarin output (generated, not committed)
```

## Related documents

- MCP: [authorization spec](https://modelcontextprotocol.io/specification/draft/basic/authorization), [security best practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices), [conformance suite](https://github.com/modelcontextprotocol/conformance)
- IETF: [RFC 9728](https://datatracker.ietf.org/doc/rfc9728/), [RFC 8707](https://datatracker.ietf.org/doc/rfc8707/), [RFC 9207](https://datatracker.ietf.org/doc/rfc9207/), [RFC 8693](https://datatracker.ietf.org/doc/rfc8693/), [RFC 7523](https://datatracker.ietf.org/doc/rfc7523/), [RFC 9700](https://datatracker.ietf.org/doc/rfc9700/), [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)

The full list is in [docs/references.md](docs/references.md).

## Contributing and disclosure

Reviews of the model's assumptions are the most useful contribution; see [CONTRIBUTING.md](CONTRIBUTING.md). If the model points to a **new** weakness in a real implementation, it is reported privately to the maintainers first; see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Harsh Thumar
