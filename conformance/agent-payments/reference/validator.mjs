/**
 * Reference implementation for conformance testing only. NOT security-audited. NOT for production use. No warranty.
 */

/**
 * Validates an agent payment request against an authorized mandate token.
 *
 * Implements the 6 policy checks established by Tamarin Model 05 and RFC standards:
 *  1. consent_binding (P10)
 *  2. audience_check (P10)
 *  3. payee_check (P10)
 *  4. amount_cap_check (P10)
 *  5. sender_constraint (P12)
 *  6. revocation_check (P11)
 *
 * @param {Object} params
 * @param {Object} params.mandate - RFC 9396-style authorization details and mandate claims
 * @param {Object} params.request - Payment request object
 * @param {Object} params.deps - Injected external crypto/lookup dependencies
 * @param {(req: any, cnf: any) => Promise<boolean>|boolean} params.deps.verifyProofOfPossession
 * @param {(mandateId: string) => Promise<{ revoked: boolean }>|{ revoked: boolean }} params.deps.revocationLookup
 * @returns {Promise<{ allow: boolean, reason: string, control?: string, property?: string }>}
 */
export async function validatePayment({ mandate, request, deps }) {
  if (!mandate || typeof mandate !== 'object') {
    return {
      allow: false,
      control: 'mandate_structure',
      property: 'P10',
      reason: 'INVALID_MANDATE: Mandate object is missing or invalid'
    };
  }

  if (!request || typeof request !== 'object') {
    return {
      allow: false,
      control: 'request_structure',
      property: 'P10',
      reason: 'INVALID_REQUEST: Payment request object is missing or invalid'
    };
  }

  // 1. Consent Binding Check (P10)
  // Ensures the mandate was authorized with explicit principal approval
  if (!mandate.consent_evidence || mandate.consent_evidence.approved_by_user !== true) {
    return {
      allow: false,
      control: 'consent_binding',
      property: 'P10',
      reason: 'CONSENT_NOT_BOUND: Mandate lacks verified principal approval'
    };
  }

  // 2. Audience Check (P10)
  // Ensures the mandate is presented to the payment server it was issued for (RFC 8707)
  if (!mandate.audience || !request.audience || mandate.audience !== request.audience) {
    return {
      allow: false,
      control: 'audience_check',
      property: 'P10',
      reason: `AUDIENCE_MISMATCH: Mandate audience '${mandate.audience}' does not match request audience '${request.audience}'`
    };
  }

  // 3. Payee Match Check (P10)
  // Ensures the payment goes only to the merchant named in the mandate
  if (!mandate.payee || !request.payee || mandate.payee !== request.payee) {
    return {
      allow: false,
      control: 'payee_check',
      property: 'P10',
      reason: `PAYEE_MISMATCH: Request payee '${request.payee}' does not match mandate payee '${mandate.payee}'`
    };
  }

  // 4. Amount Cap Check (P10)
  // Ensures payment amount is within the authorized cap (class and numeric limits)
  const reqClass = request.amount?.class;
  const capClass = mandate.amount_cap?.class;
  const reqVal = request.amount?.value;
  const capVal = mandate.amount_cap?.value;

  // Model 05 formal class check: 'large' allows both 'small' and 'large'; 'small' allows only 'small'
  if (capClass === 'small' && reqClass === 'large') {
    return {
      allow: false,
      control: 'amount_cap_check',
      property: 'P10',
      reason: `AMOUNT_CAP_EXCEEDED: Requested amount class '${reqClass}' exceeds authorized cap class '${capClass}'`
    };
  }

  // Numeric limit check [design]
  if (typeof reqVal === 'number' && typeof capVal === 'number' && reqVal > capVal) {
    return {
      allow: false,
      control: 'amount_cap_check',
      property: 'P10',
      reason: `AMOUNT_CAP_EXCEEDED: Requested amount value ${reqVal} exceeds authorized cap value ${capVal}`
    };
  }

  // 5. Sender Constraint Check (P12)
  // Ensures payment request was signed by the agent possessing the mandate's cnf key
  if (!mandate.cnf) {
    return {
      allow: false,
      control: 'sender_constraint',
      property: 'P12',
      reason: 'SENDER_CONSTRAINT_FAILED: Mandate does not declare confirmation key (cnf)'
    };
  }

  if (!deps || typeof deps.verifyProofOfPossession !== 'function') {
    return {
      allow: false,
      control: 'sender_constraint',
      property: 'P12',
      reason: 'SENDER_CONSTRAINT_FAILED: Missing verifyProofOfPossession dependency'
    };
  }

  const popValid = await deps.verifyProofOfPossession(request, mandate.cnf);
  if (!popValid) {
    return {
      allow: false,
      control: 'sender_constraint',
      property: 'P12',
      reason: 'SENDER_CONSTRAINT_FAILED: Proof of possession of agent key is invalid or absent'
    };
  }

  // 6. Online Revocation Check (P11)
  // Ensures mandate has not been cancelled/revoked prior to debit execution
  if (!mandate.mandate_id) {
    return {
      allow: false,
      control: 'revocation_check',
      property: 'P11',
      reason: 'REVOCATION_CHECK_FAILED: Mandate missing unique mandate_id'
    };
  }

  if (!deps || typeof deps.revocationLookup !== 'function') {
    return {
      allow: false,
      control: 'revocation_check',
      property: 'P11',
      reason: 'REVOCATION_CHECK_FAILED: Missing revocationLookup dependency'
    };
  }

  const status = await deps.revocationLookup(mandate.mandate_id);
  if (status && status.revoked === true) {
    return {
      allow: false,
      control: 'revocation_check',
      property: 'P11',
      reason: `MANDATE_REVOKED: Mandate '${mandate.mandate_id}' has been revoked by principal`
    };
  }

  // All 6 checks satisfied
  return {
    allow: true,
    reason: 'AUTHORIZED: All 6 mandate policy controls satisfied'
  };
}

export { validatePayment as decide };
