<!-- Reference implementation for conformance testing only. NOT security-audited. NOT for production use. No warranty. -->

# Specification: Agent-Payment Mandate and Conformance Policy Rules

> **Reference implementation for conformance testing only. NOT security-audited. NOT for production use. No warranty.**

## 1. Overview

This specification establishes a standards-based, generic profile for delegating payment authorization to autonomous AI agents. The profile uses standard OAuth 2.0 building blocks:
- **RFC 9396** (Rich Authorization Requests, `authorization_details`) for defining payment scope, payee, and amount caps.
- **RFC 8707** (Resource Indicators for OAuth 2.0) and **RFC 7519** (`aud`) for strict payment server audience binding.
- **RFC 9449** (OAuth 2.0 Demonstrating Proof of Possession / DPoP) and **RFC 7800** (`cnf`) for agent key confirmation.
- **draft-mishra-oauth-agent-grants-02** ("OAuth Profile for Delegated AI Agent Authorization") for agent delegation architecture.

The policy verification rules specified herein correspond directly to the formal security properties proved in Tamarin Model 05 (`models/05_agent_payment_mandate.spthy`) and results R13 (`docs/results.md`).

Anything marked with `[design]` represents an operational or schema design choice extending the formal abstraction to executable data structures.

---

## 2. Necessary and Sufficient Controls (Formal Proof Mapping)

Tamarin Model 05 formally models an AI agent paying under a mandate token issued by an Authorization Server (AS) and executed at a Payment Server (PS). A complete state ablation across all 64 check permutations proved the exact necessary and sufficient controls for three core security properties:

| Formal Property | Definition | Necessary & Sufficient Controls | Attack When Control is Dropped |
|---|---|---|---|
| **P10** (`debit_within_intent`) | Money stays strictly within the human principal's approval (correct payee, correct payment server, amount <= cap). | `consent_binding` **AND** `payee_check` **AND** `amount_cap_check` **AND** `audience_check` (all four required) | **1.** `consent_binding` dropped: Consent substitution (mandate issued without user approval).<br>**2.** `payee_check` dropped: Payee redirection (funds diverted to an unapproved recipient).<br>**3.** `amount_cap_check` dropped: Over-debit (payment exceeding authorized cap).<br>**4.** `audience_check` dropped: Cross-server replay (mandate intended for bank A presented to bank B). |
| **P11** (`no_debit_after_revocation`) | No debit can execute under a mandate after the principal has revoked it. | `revocation_check` (online status verification at payment time) | **5.** `revocation_check` dropped: Post-revocation payment (debits continue despite explicit user cancellation). |
| **P12** (`debit_requested_by_agent`) | An honest agent's payment request cannot be forged, replayed, or altered. | `sender_constraint` (cryptographic proof of possession of the agent's key) | **6.** `sender_constraint` dropped: Request replay (an attacker replaying a leaked payment request under a fresh payment ID). |

> **Note on security findings:** These attacks are well-understood, textbook consequences of omitting standard access controls. The formal model provides machine-checked verification that every one of the six controls is strictly necessary, and none is redundant.

---

## 3. Data Structures

Neutral, standard identifiers are used throughout this specification (e.g., `https://bank.example.com/pay`, `merchant-utility@merchant.example`).

### 3.1. Mandate Structure (`authorization_details`)

A mandate represents the authorization granted by the principal to the agent. In standard OAuth 2.0 terminology, it is structured as an RFC 9396 `authorization_details` entry of type `"payment_mandate"`:

```json
{
  "type": "payment_mandate",
  "mandate_id": "urn:mandate:example:m-2026-11-001",
  "payee": "merchant-utility@merchant.example",
  "amount_cap": {
    "class": "small",
    "value": 1000,
    "currency": "USD"
  },
  "audience": "https://bank.example.com/pay",
  "cnf": {
    "jkt": "agent-key-thumbprint-k7d8f9"
  },
  "consent_evidence": {
    "approved_by_user": true,
    "user_id": "user-alice@user.example",
    "intent_id": "intent-2026-901",
    "timestamp": "2026-11-15T10:00:00Z"
  }
}
```

#### Field Specifications:
- `mandate_id` *(string, MUST)*: Unique identifier for the mandate token.
- `payee` *(string, MUST)*: Unique identifier of the single authorized payee.
- `amount_cap` *(object, MUST)*:
  - `class` *(string, MUST)*: `"small"` or `"large"` (abstract amount classification matching Tamarin Model 05).
  - `value` *(number, MUST) [design]*: Maximum allowable amount for an individual transaction.
  - `currency` *(string, OPTIONAL) [design]*: ISO 4217 currency code (e.g., `"USD"`).
- `audience` *(string, MUST)*: RFC 8707 / RFC 7519 target Payment Server URI (e.g., `https://bank.example.com/pay`).
- `cnf` *(object, MUST)*: RFC 9449 / RFC 7800 confirmation key thumbprint (`jkt`) binding the mandate to the agent's asymmetric key.
- `consent_evidence` *(object, MUST) [design]*: Attestation details verifying that the authorization server obtained explicit approval from the principal (`approved_by_user: true`).

---

### 3.2. Payment Request Structure

When an agent initiates a payment, it submits a payment request to the payment server referencing the mandate:

```json
{
  "payment_id": "pay-req-2026-11-9001",
  "mandate_id": "urn:mandate:example:m-2026-11-001",
  "payee": "merchant-utility@merchant.example",
  "amount": {
    "class": "small",
    "value": 250,
    "currency": "USD"
  },
  "audience": "https://bank.example.com/pay",
  "pop": {
    "proof_type": "dpop_proof",
    "agent_key_id": "agent-key-001",
    "payload": {
      "payment_id": "pay-req-2026-11-9001",
      "mandate_id": "urn:mandate:example:m-2026-11-001",
      "audience": "https://bank.example.com/pay",
      "payee": "merchant-utility@merchant.example",
      "amount": {
        "class": "small",
        "value": 250
      }
    }
  }
}
```

#### Field Specifications:
- `payment_id` *(string, MUST)*: Unique per-transaction identifier (nonce) generated by the agent.
- `mandate_id` *(string, MUST)*: Reference identifier to the authorizing mandate.
- `payee` *(string, MUST)*: Target payee for this transaction.
- `amount` *(object, MUST)*:
  - `class` *(string, MUST)*: `"small"` or `"large"`.
  - `value` *(number, MUST) [design]*: Transaction amount.
  - `currency` *(string, OPTIONAL) [design]*: Currency identifier.
- `audience` *(string, MUST)*: Target payment server URI receiving the request.
- `pop` *(object, MUST) [design]*: Proof-of-possession artifact demonstrating that the caller possesses the private key corresponding to `mandate.cnf`.

---

## 4. Conformance Policy Verification Rules

A compliant payment mandate validator MUST enforce all six of the following rules. If any check fails, the validator MUST reject the payment with `allow: false` and a descriptive reason.

### Rule 1: Consent Binding Check (`consent_binding`)
- **Protected Property:** P10 (`debit_within_intent`)
- **Attack Mitigated:** Consent substitution (mandate issued without authentic principal approval).
- **Standards Anchor:** RFC 9396 §2, draft-mishra-oauth-agent-grants-02 §9.1 ("Automated policy decisions MUST NOT replace the Principal's authenticated approval").
- **Verification Logic:**
  1. Inspect `mandate.consent_evidence`.
  2. Verify that `mandate.consent_evidence.approved_by_user === true`.
  3. If missing or false, MUST reject with code `CONSENT_NOT_BOUND`.

### Rule 2: Payee Match Check (`payee_check`)
- **Protected Property:** P10 (`debit_within_intent`)
- **Attack Mitigated:** Payee redirection (funds diverted to an unauthorized payee).
- **Standards Anchor:** RFC 9396 §2.2 (`authorization_details` field matching).
- **Verification Logic:**
  1. Compare `request.payee` with `mandate.payee`.
  2. The values MUST match identically.
  3. If mismatched, MUST reject with code `PAYEE_MISMATCH`.

### Rule 3: Amount Cap Check (`amount_cap_check`)
- **Protected Property:** P10 (`debit_within_intent`)
- **Attack Mitigated:** Over-debit (payment exceeding authorized cap).
- **Standards Anchor:** RFC 9396 §2.2.
- **Verification Logic:**
  1. *Class validation (Model 05 formal rule):* If `mandate.amount_cap.class === 'small'`, then `request.amount.class` MUST be `'small'`. (`'large'` mandate cap permits both `'small'` and `'large'`).
  2. *Numeric validation [design]:* `request.amount.value` MUST be less than or equal to `mandate.amount_cap.value`.
  3. If either constraint is violated, MUST reject with code `AMOUNT_CAP_EXCEEDED`.

### Rule 4: Audience Check (`audience_check`)
- **Protected Property:** P10 (`debit_within_intent`)
- **Attack Mitigated:** Cross-server token replay (mandate intended for payment server A presented to payment server B).
- **Standards Anchor:** RFC 8707 §3, RFC 7519 §4.1.3, draft-mishra-oauth-agent-grants-02 §6 ("The resource server MUST reject tokens without the expected audience").
- **Verification Logic:**
  1. Compare `mandate.audience` with the receiving payment server's identity (`request.audience`).
  2. The values MUST match identically.
  3. If mismatched, MUST reject with code `AUDIENCE_MISMATCH`.

### Rule 5: Sender Constraint Check (`sender_constraint`)
- **Protected Property:** P12 (`debit_requested_by_agent`)
- **Attack Mitigated:** Leaked request replay and parameter rewriting under a fresh payment ID.
- **Standards Anchor:** RFC 9449 §5, draft-mishra-oauth-agent-grants-02 §6 ("The resource server MUST validate the cnf sender constraint").
- **Verification Logic:**
  1. Validate that `mandate.cnf` is present.
  2. Invoke injected dependency `deps.verifyProofOfPossession(request, mandate.cnf)`.
  3. If the cryptographic proof is invalid or absent, MUST reject with code `SENDER_CONSTRAINT_FAILED`.

### Rule 6: Online Revocation Check (`revocation_check`)
- **Protected Property:** P11 (`no_debit_after_revocation`)
- **Attack Mitigated:** Post-revocation payment (debited after principal cancellation).
- **Standards Anchor:** RFC 7009, draft-mishra-oauth-agent-grants-02 §7.
- **Verification Logic:**
  1. Invoke injected dependency `deps.revocationLookup(mandate.mandate_id)`.
  2. Inspect returned status `{ revoked: boolean }`.
  3. If `revoked === true`, MUST reject with code `MANDATE_REVOKED`.

---

## 5. Injected Dependency Interface

To ensure portability and avoid embedding insecure cryptographic code, validators MUST decouple cryptographic verification and state lookups via injected dependency functions:

```typescript
interface InjectedDependencies {
  /**
   * Verifies that request.pop proves possession of the key identified by mandate.cnf.
   */
  verifyProofOfPossession(request: PaymentRequest, cnf: ConfirmationClaim): Promise<boolean> | boolean;

  /**
   * Queries online revocation authority for the current status of mandateId.
   */
  revocationLookup(mandateId: string): Promise<{ revoked: boolean }> | { revoked: boolean };
}
```
