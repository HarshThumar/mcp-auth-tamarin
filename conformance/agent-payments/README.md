<!-- Reference implementation for conformance testing only. NOT security-audited. NOT for production use. No warranty. -->

# Agent-Payments Mandate Conformance Kit

> ⚠️ **Reference implementation for conformance testing only. NOT security-audited. NOT for production use. No warranty.** This kit checks *policy decisions*; it is a test harness, not a payment-security library.

![Node](https://img.shields.io/badge/node-%E2%89%A518-informational) ![deps](https://img.shields.io/badge/dependencies-none-success) ![network](https://img.shields.io/badge/network-none-success) ![license](https://img.shields.io/badge/license-MIT-blue)

A portable, dependency-free test suite that lets an engineer building AI-agent payments check their **own** payment-mandate validator against six concrete attacks and get an automated, per-control PASS/FAIL — backed by a machine-checked formal proof ([Tamarin Model 05](../../models/05_agent_payment_mandate.spthy), [result R13](../../docs/results.md)).

The attacks here are **well-understood, textbook** failure modes. What the model adds is proof that each of the six controls is *strictly necessary* and that together they are *sufficient* — none is redundant, none is missing.

---

## TL;DR

```bash
git clone https://github.com/HarshThumar/mcp-auth-tamarin.git
cd mcp-auth-tamarin/conformance/agent-payments

node run_conformance.mjs                 # reference validator → 13/13 PASS, exit 0
node run_conformance.mjs --demo-weak     # a broken validator → payee + revocation FAIL, exit 1
node run_conformance.mjs --adapter ./my-adapter.mjs   # test YOUR validator
```

Requires **Node ≥ 18**. No `npm install`, no network, no configuration.

---

## Contents

- [What it tests](#1-what-it-tests) · the six controls and the three proven properties
- [Standards](#2-standards) · the generic OAuth building blocks it uses
- [Test your validator](#3-test-your-validator) · the 4-step loop
- [Reading the output](#4-reading-the-output) · table, defense map, exit codes
- [Use it in CI](#5-use-it-in-ci)
- [Scope and limitations](#6-scope-and-limitations) · **read before relying on it**
- [File manifest](#7-file-manifest) · [Citation](#8-citation) · [License](#license)

---

## 1. What it tests

When an AI agent pays on a user's behalf under a mandate, every debit must stay strictly inside what the user approved. Model 05 proves the necessary-and-sufficient controls for three properties:

- **P10 — money stays inside approval** (`debit_within_intent`): every debit goes to the approved payee, at the intended payment server, within the approved cap.
- **P11 — nothing paid after revocation** (`no_debit_after_revocation`): no debit occurs once the user has cancelled the mandate.
- **P12 — an honest agent's request can't be forged** (`debit_requested_by_agent`): a leaked request can't be replayed or rewritten under a fresh payment ID.

Drop any single control and one textbook attack opens up:

| Property | Necessary & sufficient controls | Attack when the control is dropped |
|---|---|---|
| **P10** | `consent_binding` **AND** `payee_check` **AND** `amount_cap_check` **AND** `audience_check` | **1.** consent off → consent substitution (mandate the user never approved)<br>**2.** payee off → payee redirection (funds to an unapproved merchant)<br>**3.** amount cap off → over-debit (more than the user allowed)<br>**4.** audience off → cross-server replay (a mandate for server A used at server B) |
| **P11** | `revocation_check` (online, at payment time) | **5.** revocation off → post-revocation debit (payments continue after cancel) |
| **P12** | `sender_constraint` (agent proof-of-possession matching `cnf`) | **6.** sender-constraint off → bearer replay (anyone who sees one request replays it) |

The full rule statements, with the exact mandate and request shapes, are in **[SPEC.md](SPEC.md)**.

---

## 2. Standards

Generic, open internet standards only — no proprietary or scheme-specific message formats:

| Building block | Standard | Role in the mandate |
|---|---|---|
| Rich authorization request | **RFC 9396** | the mandate as `authorization_details` (payee, amount cap, audience, `cnf`, consent) |
| Audience restriction | **RFC 8707** / **RFC 7519** | the mandate is valid at one payment server only |
| Proof-of-possession | **RFC 9449** (DPoP) / **RFC 7800** (`cnf`) | the agent signs each request with its bound key |
| Revocation | **RFC 7009** | online check at payment time |
| Agent delegation profile | **draft-mishra-oauth-agent-grants-02** | consent and delegation safeguards |

The validator evaluates **policy only**. Cryptographic verification (`verifyProofOfPossession`) and external state (`revocationLookup`) are **injected as dependencies** — the kit never ships its own crypto, so there is no in-band crypto to get wrong.

---

## 3. Test your validator

**Step 1 — implement the adapter.** One function that hands a mandate + request to your validator and returns a verdict:

```javascript
/**
 * @param {Object}   p
 * @param {Object}   p.mandate  - RFC 9396 mandate (see SPEC.md §2)
 * @param {Object}   p.request  - payment request (see SPEC.md §3)
 * @param {Object}   p.deps     - { verifyProofOfPossession(request, cnf), revocationLookup(mandateId) }
 * @returns {Promise<{ allow: boolean, reason: string }>}
 */
export async function decide({ mandate, request, deps }) {
  const ok = await myValidator.check(mandate, request, deps);   // ← your code
  return { allow: ok, reason: ok ? 'authorized' : 'policy check failed' };
}
```

See **[adapter.example.mjs](adapter.example.mjs)** for a working wiring.

**Step 2 — run it** against your adapter:

```bash
node run_conformance.mjs --adapter ./my-adapter.mjs
```

**Step 3 — read the per-control table** (next section).

**Step 4 — fix any `FAIL`.** Each row names the control, the property it protects, and the attack it missed; the **defense map** footer and **[SPEC.md](SPEC.md)** give the rule to implement.

---

## 4. Reading the output

Each control has a negative vector (the attack — your validator must `deny`) and a positive one (the legitimate version — must `allow`), plus a happy-path baseline:

```text
Control             | Prop   | Attack / Scenario                    | Expect | Got    | Result
all                 | P10    | Baseline legitimate payment ...      | allow  | allow  | PASS
payee_check         | P10    | Payee redirection attack: ...        | deny   | deny   | PASS
revocation_check    | P11    | Post-revocation debit attack: ...    | deny   | deny   | PASS
...
Summary: 13 passed, 0 failed (out of 13 vectors)
```

A **defense map** then prints `control → property → attack → guard → RFC clause → model`, so a `FAIL` points straight at the standard and the lemma behind it.

**Exit codes** (so the kit scripts cleanly):

| Command | Meaning | Exit |
|---|---|---|
| `run_conformance.mjs [--adapter …]` | all vectors matched their expectation | `0` |
| `run_conformance.mjs [--adapter …]` | one or more vectors failed | non-zero |
| `run_conformance.mjs --demo-weak` | demonstration of the intentionally-weak validator (payee + revocation `FAIL` **on purpose**) | non-zero |

`--demo-weak` runs the deliberately incomplete [`reference/weak-validator.mjs`](reference/weak-validator.mjs) so you can see the harness actually catch a gap — its non-zero exit is expected, not a suite failure.

---

## 5. Use it in CI

The runner exits non-zero on any mismatch, so one line gates a build:

```yaml
# GitHub Actions
- uses: actions/setup-node@v4
  with: { node-version: 20 }
- run: node conformance/agent-payments/run_conformance.mjs --adapter ./path/to/your-adapter.mjs
```

Treat a new `FAIL` as a regression in your mandate validator.

---

## 6. Scope and limitations

**Please read this before relying on the kit.**

- **It is a reference / conformance test, not production security code.** Every file carries that banner. Do not drop `reference/validator.mjs` into a real payment path.
- **It tests policy, not cryptography.** PoP verification and revocation lookups are injected stubs. A `PASS` says your *policy logic* matches the proven controls — it says nothing about the strength of your signatures, key storage, or revocation backend.
- **The vectors are illustrative, not exhaustive.** They cover the six controls Model 05 proves. They are not a full attack corpus; passing is necessary, not a guarantee of security.
- **The model abstracts.** Model 05 does not model wall-clock time (e.g. mandate expiry timing) and the search is not exhaustive over all real-world message formats. See [`docs/threat-model.md`](../../docs/threat-model.md) for every assumption.
- **Examples are generic.** Identifiers, amounts and payees are invented placeholders; no real scheme message formats, banks, or operators are used or implied.

Found a gap in the kit or the model? See [CONTRIBUTING.md](../../CONTRIBUTING.md); for a weakness in a real implementation, [SECURITY.md](../../SECURITY.md) (private disclosure first).

---

## 7. File manifest

| File | What |
|---|---|
| [`README.md`](README.md) | this guide |
| [`SPEC.md`](SPEC.md) | mandate + request shapes and the 6 policy rules (→ control / property / attack / RFC) |
| [`adapter.example.mjs`](adapter.example.mjs) | the adapter interface + a working example |
| [`vectors.mjs`](vectors.mjs) | all test vectors (attack + positive control per control, plus baseline) |
| [`reference/validator.mjs`](reference/validator.mjs) | reference validator — all 6 checks, policy only; passes every vector |
| [`reference/weak-validator.mjs`](reference/weak-validator.mjs) | deliberately incomplete validator for `--demo-weak` |
| [`run_conformance.mjs`](run_conformance.mjs) | the CLI runner |

**Formal foundation:** [Model 05](../../models/05_agent_payment_mandate.spthy) · [result R13](../../docs/results.md) · [case study](../../docs/case-study-upi.md) · [whitepaper](../../whitepaper/agent-payments-india.md) · [ablation lattice](../../docs/ablation.md)

---

## 8. Citation

> Harsh Thumar (remote participant, IETF 127; independent researcher). *Agent-Payments Mandate Conformance Kit*, `mcp-auth-tamarin`, 2026. https://github.com/HarshThumar/mcp-auth-tamarin

---

## License

[MIT](../../LICENSE) © 2026 Harsh Thumar
