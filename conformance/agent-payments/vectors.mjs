/**
 * Reference implementation for conformance testing only. NOT security-audited. NOT for production use. No warranty.
 */

/**
 * Standard test fixtures representing legitimate mandate, request, and stub dependencies.
 */
const baseMandate = Object.freeze({
  type: 'payment_mandate',
  mandate_id: 'urn:mandate:example:m-2026-11-001',
  payee: 'merchant-utility@merchant.example',
  amount_cap: Object.freeze({
    class: 'small',
    value: 1000,
    currency: 'USD'
  }),
  audience: 'https://bank.example.com/pay',
  cnf: Object.freeze({
    jkt: 'agent-key-thumbprint-k7d8f9'
  }),
  consent_evidence: Object.freeze({
    approved_by_user: true,
    user_id: 'user-alice@user.example',
    intent_id: 'intent-2026-901',
    timestamp: '2026-11-15T10:00:00Z'
  })
});

const baseRequest = Object.freeze({
  payment_id: 'pay-req-2026-11-9001',
  mandate_id: 'urn:mandate:example:m-2026-11-001',
  payee: 'merchant-utility@merchant.example',
  amount: Object.freeze({
    class: 'small',
    value: 250,
    currency: 'USD'
  }),
  audience: 'https://bank.example.com/pay',
  pop: Object.freeze({
    proof_type: 'dpop_proof',
    agent_key_id: 'agent-key-001',
    signature: 'mock-valid-signature'
  })
});

/**
 * Default stub dependencies where cryptographic PoP is valid and mandate is active.
 */
function createValidDeps() {
  return {
    verifyProofOfPossession: async (_req, _cnf) => true,
    revocationLookup: async (_mandateId) => ({ revoked: false })
  };
}

/**
 * Test vectors covering the 6 controls and 3 formal properties (P10, P11, P12)
 * from Tamarin Model 05 and RFC standards.
 */
export const vectors = [
  // --------------------------------------------------------------------------
  // Baseline: Happy Path (All 6 controls satisfied)
  // --------------------------------------------------------------------------
  {
    id: 'VEC-00-HAPPY-PATH',
    control: 'all',
    property: 'P10, P11, P12',
    expect: 'allow',
    mandate: { ...baseMandate },
    request: { ...baseRequest },
    deps: createValidDeps(),
    note: 'Baseline legitimate payment request satisfying all 6 policy checks'
  },

  // --------------------------------------------------------------------------
  // Control 1: consent_binding (P10)
  // --------------------------------------------------------------------------
  {
    id: 'VEC-01-CONSENT-DENY',
    control: 'consent_binding',
    property: 'P10',
    expect: 'deny',
    mandate: {
      ...baseMandate,
      consent_evidence: {
        approved_by_user: false,
        reason: 'unapproved_auto_grant'
      }
    },
    request: { ...baseRequest },
    deps: createValidDeps(),
    note: 'Consent substitution attack: mandate issued without authentic user approval (Model 05 NO_CONSENT_BINDING)'
  },
  {
    id: 'VEC-01-CONSENT-ALLOW',
    control: 'consent_binding',
    property: 'P10',
    expect: 'allow',
    mandate: {
      ...baseMandate,
      consent_evidence: {
        approved_by_user: true,
        user_id: 'user-alice@user.example',
        intent_id: 'intent-2026-901',
        timestamp: '2026-11-15T10:00:00Z'
      }
    },
    request: { ...baseRequest },
    deps: createValidDeps(),
    note: 'Consent binding verified: mandate carries authentic user approval evidence'
  },

  // --------------------------------------------------------------------------
  // Control 2: payee_check (P10)
  // --------------------------------------------------------------------------
  {
    id: 'VEC-02-PAYEE-DENY',
    control: 'payee_check',
    property: 'P10',
    expect: 'deny',
    mandate: { ...baseMandate },
    request: {
      ...baseRequest,
      payee: 'attacker-store@merchant.example'
    },
    deps: createValidDeps(),
    note: 'Payee redirection attack: agent attempts debit to an unapproved merchant (Model 05 NO_PAYEE_CHECK)'
  },
  {
    id: 'VEC-02-PAYEE-ALLOW',
    control: 'payee_check',
    property: 'P10',
    expect: 'allow',
    mandate: { ...baseMandate },
    request: {
      ...baseRequest,
      payee: 'merchant-utility@merchant.example'
    },
    deps: createValidDeps(),
    note: 'Payee check verified: requested payee exactly matches mandate payee'
  },

  // --------------------------------------------------------------------------
  // Control 3: amount_cap_check (P10)
  // --------------------------------------------------------------------------
  {
    id: 'VEC-03-AMOUNT-DENY',
    control: 'amount_cap_check',
    property: 'P10',
    expect: 'deny',
    mandate: { ...baseMandate },
    request: {
      ...baseRequest,
      amount: {
        class: 'large',
        value: 5000,
        currency: 'USD'
      }
    },
    deps: createValidDeps(),
    note: 'Over-debit attack: requested amount exceeds authorized mandate cap (Model 05 NO_AMOUNT_CHECK)'
  },
  {
    id: 'VEC-03-AMOUNT-ALLOW',
    control: 'amount_cap_check',
    property: 'P10',
    expect: 'allow',
    mandate: { ...baseMandate },
    request: {
      ...baseRequest,
      amount: {
        class: 'small',
        value: 1000,
        currency: 'USD'
      }
    },
    deps: createValidDeps(),
    note: 'Amount cap check verified: requested amount within authorized cap boundary'
  },

  // --------------------------------------------------------------------------
  // Control 4: audience_check (P10)
  // --------------------------------------------------------------------------
  {
    id: 'VEC-04-AUDIENCE-DENY',
    control: 'audience_check',
    property: 'P10',
    expect: 'deny',
    mandate: { ...baseMandate },
    request: {
      ...baseRequest,
      audience: 'https://other-bank.example.com/pay'
    },
    deps: createValidDeps(),
    note: 'Cross-server replay attack: mandate presented to unauthorized payment server (Model 05 NO_AUD)'
  },
  {
    id: 'VEC-04-AUDIENCE-ALLOW',
    control: 'audience_check',
    property: 'P10',
    expect: 'allow',
    mandate: { ...baseMandate },
    request: {
      ...baseRequest,
      audience: 'https://bank.example.com/pay'
    },
    deps: createValidDeps(),
    note: 'Audience check verified: requested audience matches mandate audience'
  },

  // --------------------------------------------------------------------------
  // Control 5: sender_constraint (P12)
  // --------------------------------------------------------------------------
  {
    id: 'VEC-05-SENDER-DENY',
    control: 'sender_constraint',
    property: 'P12',
    expect: 'deny',
    mandate: { ...baseMandate },
    request: {
      ...baseRequest,
      payment_id: 'pay-req-stolen-replayed-002',
      pop: {
        proof_type: 'dpop_proof',
        signature: 'invalid-or-forged-signature'
      }
    },
    deps: {
      verifyProofOfPossession: async (_req, _cnf) => false,
      revocationLookup: async (_mandateId) => ({ revoked: false })
    },
    note: 'Bearer replay attack: leaked payment request replayed without agent key proof of possession (Model 05 NO_SENDER_CONSTRAINT)'
  },
  {
    id: 'VEC-05-SENDER-ALLOW',
    control: 'sender_constraint',
    property: 'P12',
    expect: 'allow',
    mandate: { ...baseMandate },
    request: { ...baseRequest },
    deps: {
      verifyProofOfPossession: async (_req, _cnf) => true,
      revocationLookup: async (_mandateId) => ({ revoked: false })
    },
    note: 'Sender constraint verified: valid cryptographic proof of possession of agent key'
  },

  // --------------------------------------------------------------------------
  // Control 6: revocation_check (P11)
  // --------------------------------------------------------------------------
  {
    id: 'VEC-06-REVOCATION-DENY',
    control: 'revocation_check',
    property: 'P11',
    expect: 'deny',
    mandate: { ...baseMandate },
    request: { ...baseRequest },
    deps: {
      verifyProofOfPossession: async (_req, _cnf) => true,
      revocationLookup: async (_mandateId) => ({
        revoked: true,
        revoked_at: '2026-11-15T09:00:00Z'
      })
    },
    note: 'Post-revocation debit attack: payment attempted after mandate cancellation (Model 05 NO_REVOCATION_CHECK)'
  },
  {
    id: 'VEC-06-REVOCATION-ALLOW',
    control: 'revocation_check',
    property: 'P11',
    expect: 'allow',
    mandate: { ...baseMandate },
    request: { ...baseRequest },
    deps: {
      verifyProofOfPossession: async (_req, _cnf) => true,
      revocationLookup: async (_mandateId) => ({ revoked: false })
    },
    note: 'Revocation check verified: mandate confirmed active via online lookup'
  }
];
