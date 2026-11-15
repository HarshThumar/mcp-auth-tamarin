/**
 * Reference implementation for conformance testing only. NOT security-audited. NOT for production use. No warranty.
 *
 * INTENTIONALLY BROKEN DEMONSTRATION VALIDATOR:
 * This validator is deliberately incomplete and used strictly for demonstrating
 * that the conformance test suite detects gaps in security controls.
 * It intentionally omits:
 *   - payee_check (allowing arbitrary payee redirection)
 *   - revocation_check (allowing payments on revoked mandates)
 */

/**
 * Validates an agent payment request against an authorized mandate token,
 * but intentionally omits payee and revocation checks for demonstration.
 *
 * @param {Object} params
 * @param {Object} params.mandate - RFC 9396-style authorization details and mandate claims
 * @param {Object} params.request - Payment request object
 * @param {Object} params.deps - Injected external crypto/lookup dependencies
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
  if (!mandate.consent_evidence || mandate.consent_evidence.approved_by_user !== true) {
    return {
      allow: false,
      control: 'consent_binding',
      property: 'P10',
      reason: 'CONSENT_NOT_BOUND: Mandate lacks verified principal approval'
    };
  }

  // 2. Audience Check (P10)
  if (!mandate.audience || !request.audience || mandate.audience !== request.audience) {
    return {
      allow: false,
      control: 'audience_check',
      property: 'P10',
      reason: `AUDIENCE_MISMATCH: Mandate audience '${mandate.audience}' does not match request audience '${request.audience}'`
    };
  }

  // 3. Payee Match Check (P10) - INTENTIONALLY OMITTED
  // A secure validator must verify request.payee === mandate.payee.
  // This weak validator skips this check to demonstrate vulnerability to payee redirection.

  // 4. Amount Cap Check (P10)
  const reqClass = request.amount?.class;
  const capClass = mandate.amount_cap?.class;
  const reqVal = request.amount?.value;
  const capVal = mandate.amount_cap?.value;

  if (capClass === 'small' && reqClass === 'large') {
    return {
      allow: false,
      control: 'amount_cap_check',
      property: 'P10',
      reason: `AMOUNT_CAP_EXCEEDED: Requested amount class '${reqClass}' exceeds authorized cap class '${capClass}'`
    };
  }

  if (typeof reqVal === 'number' && typeof capVal === 'number' && reqVal > capVal) {
    return {
      allow: false,
      control: 'amount_cap_check',
      property: 'P10',
      reason: `AMOUNT_CAP_EXCEEDED: Requested amount value ${reqVal} exceeds authorized cap value ${capVal}`
    };
  }

  // 5. Sender Constraint Check (P12)
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

  // 6. Online Revocation Check (P11) - INTENTIONALLY OMITTED
  // A secure validator must query deps.revocationLookup(mandate.mandate_id).
  // This weak validator skips this check to demonstrate vulnerability to post-revocation debit.

  return {
    allow: true,
    reason: 'AUTHORIZED (Weak validator: skipped payee and revocation checks)'
  };
}

export { validatePayment as decide };
