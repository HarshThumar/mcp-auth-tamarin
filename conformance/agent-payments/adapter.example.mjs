/**
 * Reference implementation for conformance testing only. NOT security-audited. NOT for production use. No warranty.
 */

import { validatePayment } from './reference/validator.mjs';

/**
 * Adapter interface for validating agent payment mandates.
 *
 * An engineer testing their own mandate validator should implement this
 * interface in a custom adapter file (e.g., `my-adapter.mjs`) and invoke:
 *   node run_conformance.mjs --adapter ./my-adapter.mjs
 *
 * @typedef {Object} ValidationDecision
 * @property {boolean} allow - true if the payment request is authorized under the mandate; false otherwise.
 * @property {string} reason - description of the policy evaluation result or denial cause.
 * @property {string} [control] - optional identifier of the specific failing control if denied.
 * @property {string} [property] - optional formal property (P10, P11, P12) protected by the failing control.
 *
 * @typedef {Object} InjectedDependencies
 * @property {(request: any, cnf: any) => Promise<boolean>|boolean} verifyProofOfPossession - verifies agent key possession.
 * @property {(mandateId: string) => Promise<{ revoked: boolean }>|{ revoked: boolean }} revocationLookup - queries mandate revocation status.
 *
 * @param {Object} params
 * @param {Object} params.mandate - RFC 9396-style authorization details and mandate claims.
 * @param {Object} params.request - Payment request object.
 * @param {InjectedDependencies} params.deps - Injected external crypto/lookup dependencies.
 * @returns {Promise<ValidationDecision>}
 */
export async function decide({ mandate, request, deps }) {
  // Example wiring: delegates directly to the reference policy validator
  return await validatePayment({ mandate, request, deps });
}
