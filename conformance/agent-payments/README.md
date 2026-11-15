<!-- Reference implementation for conformance testing only. NOT security-audited. NOT for production use. No warranty. -->

# Agent-Payments Mandate Conformance Kit

> **Reference implementation for conformance testing only. NOT security-audited. NOT for production use. No warranty.**

A portable, executable test suite for mandate validators used in autonomous AI agent payment systems. This kit enables an engineer building agentic payment systems to test their own mandate validator against 6 concrete attack vectors and receive an automated per-control PASS/FAIL verification backed by machine-checked formal proofs.

Formal foundation:
- **Tamarin Model 05:** [`models/05_agent_payment_mandate.spthy`](../../models/05_agent_payment_mandate.spthy)
- **Formal Verification Results:** [Result R13 in `docs/results.md`](../../docs/results.md#r13-14-nov-2026-agent-payment-mandate-case-study-which-check-stops-which-loss)
- **Case Study:** [UPI-style Agent Mandate Case Study (`docs/case-study-upi.md`)](../../docs/case-study-upi.md)
- **Whitepaper:** [Agent Authorization for Indian Payments (`whitepaper/agent-payments-india.md`)](../../whitepaper/agent-payments-india.md)
- **Specification:** [SPEC.md](SPEC.md)

*Researcher:* Harsh Thumar (remote participant, IETF 127; independent researcher).

---

## 1. What This Kit Tests

When an AI agent pays on behalf of a human user under an authorization mandate, every payment must remain strictly inside what the human approved. In Model 05, Tamarin proved the exact necessary and sufficient controls governing three fundamental properties:

1. **P10 (Money stays inside approval / `debit_within_intent`):** Every debit is made to the approved payee, at the intended payment server, and for an amount within the approved cap.
2. **P11 (No payment after revocation / `no_debit_after_revocation`):** No debit occurs under a mandate after the user has revoked or cancelled it.
3. **P12 (Honest agent requests cannot be forged / `debit_requested_by_agent`):** Leaked payment requests cannot be replayed or rewritten under a fresh payment ID.

Omitting any single control exposes the payment flow to a textbook failure mode:

### Necessary and Sufficient Controls Table

| Property | Necessary & Sufficient Controls | Attack When Control is Dropped |
|---|---|---|
| **P10** | `consent_binding` **AND** `payee_check` **AND** `amount_cap_check` **AND** `audience_check` (all 4 required) | **1. Consent binding dropped:** Consent substitution (mandate issued without user approval).<br>**2. Payee check dropped:** Payee redirection (funds diverted to unapproved merchant).<br>**3. Amount cap check dropped:** Over-debit (payment exceeding authorized cap).<br>**4. Audience check dropped:** Cross-server token replay (mandate for bank A presented to bank B). |
| **P11** | `revocation_check` (online check at payment time) | **5. Revocation check dropped:** Post-revocation debit (payments continue after user cancels mandate). |
| **P12** | `sender_constraint` (agent cryptographic proof of possession matching `cnf`) | **6. Sender constraint dropped:** Bearer replay (attacker replays leaked request with a fresh transaction ID). |

> **Context on attacks:** These attacks represent well-understood, textbook consequences of missing security checks. What Model 05 provides is machine-checked proof that every check is strictly necessary and that none is redundant.

---

## 2. Standards-Based Design

This kit is built strictly on generic, open internet standards:
- **RFC 9396** (OAuth 2.0 Rich Authorization Requests): Mandates are modeled as `authorization_details` of type `"payment_mandate"`.
- **RFC 8707** / **RFC 7519**: Audience restriction (`aud`) targeting the specific payment server.
- **RFC 9449** / **RFC 7800**: Confirmation keys (`cnf`) and DPoP-style proof-of-possession tokens.
- **draft-mishra-oauth-agent-grants-02**: Agent delegation profile and consent safeguards.

The validator logic evaluates **policy rules only**. Cryptographic operations (signature verification) and external state queries (revocation lookups) are injected as dependencies (`deps`), avoiding flawed in-band cryptography.

---

## 3. Four-Step "How to Test Your Validator"

### Step 1: Implement the Adapter Interface

Create an adapter module (e.g. `my-adapter.mjs`) exporting a `decide` function:

```javascript
/**
 * @param {Object} params
 * @param {Object} params.mandate - RFC 9396 mandate object
 * @param {Object} params.request - Payment request object
 * @param {Object} params.deps - Injected dependencies (verifyProofOfPossession, revocationLookup)
 * @returns {Promise<{ allow: boolean, reason: string }>}
 */
export async function decide({ mandate, request, deps }) {
  // Call your mandate validator implementation here:
  const isAuthorized = await myValidator.check(mandate, request, deps);
  return {
    allow: isAuthorized,
    reason: isAuthorized ? 'Authorized' : 'Policy validation failed'
  };
}
```

See [`adapter.example.mjs`](adapter.example.mjs) for a reference implementation.

### Step 2: Run the Conformance Test Suite

Run the conformance CLI harness with plain Node.js (>= 18, zero dependencies):

```bash
node conformance/agent-payments/run_conformance.mjs --adapter ./my-adapter.mjs
```

### Step 3: Read the Per-Control PASS/FAIL Table

The runner outputs an aligned table reporting the decision on every attack vector and legitimate positive control:

```text
--------------------------------------------------------------------------------------------------------------
Control             | Prop   | Attack / Scenario                              | Expect   | Got      | Result  
--------------------------------------------------------------------------------------------------------------
all                 | P10    | Baseline legitimate payment request satisfy... | allow    | allow    | PASS    
consent_binding     | P10    | Consent substitution attack: mandate issued... | deny     | deny     | PASS    
consent_binding     | P10    | Consent binding verified: mandate carries a... | allow    | allow    | PASS    
payee_check         | P10    | Payee redirection attack: agent attempts de... | deny     | deny     | PASS    
payee_check         | P10    | Payee check verified: requested payee exact... | allow    | allow    | PASS    
amount_cap_check    | P10    | Over-debit attack: requested amount exceeds... | deny     | deny     | PASS    
amount_cap_check    | P10    | Amount cap check verified: requested amount... | allow    | allow    | PASS    
audience_check      | P10    | Cross-server replay attack: mandate present... | deny     | deny     | PASS    
audience_check      | P10    | Audience check verified: requested audience... | allow    | allow    | PASS    
sender_constraint   | P12    | Bearer replay attack: leaked payment reques... | deny     | deny     | PASS    
sender_constraint   | P12    | Sender constraint verified: valid cryptogra... | allow    | allow    | PASS    
revocation_check    | P11    | Post-revocation debit attack: payment attem... | deny     | deny     | PASS    
revocation_check    | P11    | Revocation check verified: mandate confirme... | allow    | allow    | PASS    
--------------------------------------------------------------------------------------------------------------
```

### Step 4: Fix Any Failing Controls

If any test fails, consult the **Defense Map** printed at the bottom of the test run and review the rule specifications in [`SPEC.md`](SPEC.md).

---

## 4. Demonstrating the Test Harness

### Running the Reference Validator
To run the full suite against the included reference validator ([`reference/validator.mjs`](reference/validator.mjs)):

```bash
node conformance/agent-payments/run_conformance.mjs
```
*(All 13 vectors PASS; exit code 0)*

### Running the Demonstration Weak Validator
To demonstrate that the test harness actively catches missing controls, run the deliberately incomplete validator ([`reference/weak-validator.mjs`](reference/weak-validator.mjs)):

```bash
node conformance/agent-payments/run_conformance.mjs --demo-weak
```
*(Catches missing `payee_check` and `revocation_check` controls; exits non-zero)*

---

## 5. File Manifest

- [`README.md`](README.md): This documentation and quick-start guide.
- [`SPEC.md`](SPEC.md): Mandate schema, payment request format, and the 6 formal policy rules.
- [`adapter.example.mjs`](adapter.example.mjs): Reference adapter interface and example wiring.
- [`vectors.mjs`](vectors.mjs): Complete set of test vectors (attack cases + positive controls).
- [`reference/validator.mjs`](reference/validator.mjs): Reference validator implementing all 6 policy checks.
- [`reference/weak-validator.mjs`](reference/weak-validator.mjs): Deliberately incomplete validator demonstrating failure detection.
- [`run_conformance.mjs`](run_conformance.mjs): Conformance test runner CLI harness.
