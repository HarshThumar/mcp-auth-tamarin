# MCP authorization conformance kit

Portable, in-process tests for MCP SDK maintainers. Each test checks that an SDK performs a check that the machine-checked Tamarin models in this repo assume. They are derived from the models; they are not a complete test suite for MCP authorization.

- [spec.md](spec.md): language-agnostic cases CT-01..CT-08 (preconditions, input, expected behaviour, spec clause, model).
- [python/](python): pytest, against `mcp` 2.3.0.
- [typescript/](typescript): Node test runner, against `@modelcontextprotocol/client` 2.4.0 and `@modelcontextprotocol/sdk` 1.32.2.

No sockets, no network, no third-party systems: HTTP is mocked (fake `fetch`, Starlette `TestClient`, fake request/response objects).

## What is covered

| ID | Check | Model / write-up | Python | TypeScript |
|---|---|---|---|---|
| CT-01 | RS rejects tokens for another audience (opt-in check ON) | 02 `NO_AUD`, [R1](../docs/results.md) | 3 | 3 (sdk 1.32.2 server) |
| CT-02 | Client rejects `iss` of another AS | 02 `NO_ISS`, [R2](../docs/results.md) | 2 | 4 |
| CT-03 | Absent `iss`: reject if advertised, accept if not | 02 `ISS_OPTIONAL`, [R3](../docs/results.md) | 2 | 3 |
| CT-04 | AS metadata `issuer` equals fetched issuer | 01/03 `NO_META_CHECK`, [R0, R8](../docs/results.md) | 2 | 2 |
| CT-05 | Credentials bound to their AS | 01, GHSA-qx49-fqc8-xw99 | 1 | 2 |
| CT-06 | RFC 8707 `resource` on authorize and token; PRM mismatch refused | 02 `NO_RESOURCE`, [R4](../docs/results.md) | 2 | 2 |
| CT-07 | Assertion `aud` = validated AS issuer | 06, [R12](../docs/results.md) | 2 | 2 |
| CT-08 | Exact `redirect_uri` match at `/authorize` and `/token` | 02 `NO_REDIRECT_CHECK`, [R11](../docs/results.md) | 17 | not ported (no server auth router in the 2.4.0 packages) |

Test names start with the case ID (`test_ct01_...`, `'CT-01 ...'`), so a failure points straight at [spec.md](spec.md).

## Opt-in checks

The resource-server audience check (CT-01) is off by default in both SDKs (Python `validate_token_resource`, TypeScript `expectedResource`), as described in the published advisories GHSA-w4fh-qvv9-3v23 and GHSA-rvq5-wwqv-78pq. The tests turn it ON. A server that does not turn it on is exposed to the cross-server token replay of model 02 `NO_AUD`.

## Run

Python (3.10+):

```
cd conformance/python
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m pytest -q
```

TypeScript (Node 20+; developed on Node 22):

```
cd conformance/typescript
npm install
npm test
```

Versions are pinned (`mcp==2.3.0`; client 2.4.0; sdk 1.32.2). To test another version, change the pin and re-run; a failure means the SDK no longer performs the check on that path, or its API moved (the tests call a few SDK helpers directly, for example `validate_authorization_response_iss` and `validateAuthorizationResponseIssuer`).

Result on the pinned versions (15 Nov 2026): Python 31 passed; TypeScript 18 passed.

## Port to another SDK

1. Pick a case from [spec.md](spec.md). Each lists the mock world it needs and one assertion per behaviour.
2. Mock the transport, not the SDK: a fake HTTP client for client-side cases, an in-process ASGI/handler call for server-side cases.
3. Keep both directions: a negative input that must be rejected and a matching input that must be accepted, so a blanket "reject everything" does not pass.
4. Assert on observable effects, such as "no request reached the token endpoint" and "the provider was never called", rather than on error text.
5. Where a check is opt-in in the SDK, turn it on in the test and say so in a comment.

## Scope and honesty notes

- The cases check behaviour of published SDK code. A model result such as "falsified without this check" is a statement about the model, not about an SDK.
- Several attacks the models find are already known (RFC 9700 §4.1, §4.4); the models reproduce them and the SDK tests confirm the corresponding check exists.
- Spec quotes are paraphrased. The spec clauses to cite are in [../docs/verification-mapping.md](../docs/verification-mapping.md).
- Related: [../docs/conformance-test-draft.md](../docs/conformance-test-draft.md) (proposals for the upstream conformance suite, Issue #78).
