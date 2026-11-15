# Case study: an AI agent that pays under a UPI-style mandate

*Model 05, [`models/05_agent_payment_mandate.spthy`](../models/05_agent_payment_mandate.spthy). Checked 14 Nov 2026 with Tamarin 1.12.0. Results R13 in [results.md](results.md). Every combination of removed checks is in [ablation.md](ablation.md).*
*Companion overview: [engineering blog post](../blog/2026-11-ietf127-mcp-authorization.md) · Model → SDK verification: [implementation-check.md](implementation-check.md) · Test your own validator: [agent-payments conformance kit](../conformance/agent-payments/).*

This page has three parts for three kinds of reader. Read only the part you need.

---

## 1. In one minute

AI agents are starting to pay for things on people's behalf. In India, NPCI's UPI Circle already lets a person delegate payments to another device or app, within limits. The question this case study asks is simple:

> If an agent pays under a mandate, does every payment stay inside what the person actually approved?

We built a formal model of that flow and had a theorem prover (Tamarin) check it. With all six checks on, the prover **proves** three things for every possible run of the model, including runs where an attacker controls the network, runs malicious agents and has its own accounts:

1. money only goes to the payee, the bank and up to the amount the person approved (P10);
2. nothing is paid after the person revokes the mandate (P11);
3. an honest agent's payments cannot be replayed or rewritten (P12).

Then we switched off one check at a time. Every check turned out to matter, and the prover found the exact attack each time:

| Check switched off | What goes wrong |
|---|---|
| The person approves the mandate | The agent gets a mandate the person never agreed to. |
| The bank checks the payee | Money goes to a payee the person never named. |
| The bank checks the amount cap | More money moves than the person allowed. |
| The bank checks the mandate is meant for it | A mandate for one bank is used at another. |
| The agent proves it holds its key | Someone who sees one payment request replays it as a new payment. |
| The bank checks for revocation | Payments continue after the person cancels. |

None of these attacks is new. Each follows from dropping that check. What the model adds is a machine-checked table of which check protects what, for a kind of system that is being designed right now.

---

## 2. For IETF and MCP people

**What is modelled.** A principal (user) tells an AS what an AI agent may pay: payee, amount class, payment server. The agent gets a signed mandate token through a pushed authorization request. The token is RFC 9396-style: payee and cap in `authorization_details`, an audience, and a `cnf` key binding. The agent pays with a DPoP-style proof of possession over the payment id, the payment server, the payee, the amount and the mandate's hash. The payment server checks:

- the AS signature;
- the proof of possession;
- the audience;
- the payee;
- the cap;
- the revocation status;
- that the payment id is new.

**Spec anchors.** draft-mishra-oauth-agent-grants-02 ("OAuth Profile for Delegated AI Agent Authorization") is the closest current draft. It is a generic delegation profile: PAR, PKCE, sender-constrained tokens, `aud`, and no consent substitution. It has **no mandate object**. For financial limits it points to RFC 9396. Two points from the model are relevant to it:

- **Revocation.** P11 depends on an online status check at the payment server. The draft makes revocation-status checking conditional on "the deployment's risk model". For payment mandates the model suggests making it unconditional.
- **Proof of possession is not a nice-to-have for payments.** A one-time payment-id cache alone does not stop replay: the attacker re-submits a leaked request with a fresh id (P12 falsified in 8 steps without `cnf`).

**What is not modelled.**

- Monthly totals and per-transaction rupee limits (Tamarin has no arithmetic; amounts are two classes).
- The UPI cooling period and clocks.
- Device-ID binding as a separate factor.
- The real NPCI message formats.

The NPCI UPI Circle rules (delegation, caps, per-payment validation, delinking) are known to us **only from a secondary summary**, not from NPCI's circulars (OC 201, 13 Aug 2024; OC 201-B, 8 Oct 2025): the PDFs could not be retrieved on 15 Nov 2026. We found no NPCI circular on AI-agent payments, only press reports. They motivate the checks; the model does not claim to be UPI.

**How industry agent-payment schemes compare** (published specs and docs, read 15 Nov 2026; not exhaustive):

| Check in the model | Visa Intelligent Commerce / Trusted Agent Protocol | Mastercard Agent Pay / Verifiable Intent (draft v0.1) | NPCI UPI Circle, delegated payments (secondary source) |
|---|---|---|---|
| Principal's approval | Passkey-authenticated instruction | Cardholder mandate (L2) signed by the user's device key | 2FA consent at linking |
| Payee | Merchant name checked against the mandate | `allowed_payees` / `allowed_merchants`, exact match MUST | Person-to-merchant only; no payee binding found |
| Amount cap | `declineThreshold`, aggregated per instruction | `amount_range` and cumulative `budget` | Per-transaction and monthly caps |
| Payment-server audience | Not as an audience claim (TAP signs `@authority`) | Not found in the parts read | Not found |
| Proof of possession | Fresh `agentSignature` per call; TAP: RFC 9421 HTTP signatures with nonce and expiry checks | Agent key bound with `cnf` (RFC 7800); the agent signs the final order | Device ID and user ID validated on each payment |
| Online revocation check | Token can be revoked by the issuer, "no callback or notification"; no per-payment check stated | Not defined; short expiry instead | Delinking in the app; no per-payment check stated |

What the comparison shows:
- None of the three defines a per-payment revocation check. They rely on expiry, token revocation or delinking instead. In the model, the online status check is the only thing that protects P11.
- None binds the mandate to one payment server, in the way an OAuth `aud` would. In the model, dropping that check lets a mandate for one payment server be used at another, which falsifies P10.
- Whether their other checks (merchant routing, issuer or network controls) close those gaps in practice is outside the model.

Sources:
- [Visa Intelligent Commerce concepts](https://developer.visa.com/docs/visa-intelligent-commerce/concepts)
- [Trusted Agent Protocol specification](https://developer.visa.com/docs/trusted-agent-protocol/trusted-agent-protocol-specifications)
- [Mastercard Verifiable Intent, draft v0.1](https://github.com/agent-intent/verifiable-intent): README and `spec/constraints.md` only
- NPCI OC 201 (13 Aug 2024) and OC 201-B (8 Oct 2025): their PDFs could not be retrieved, so the NPCI column still rests on a law-firm summary.

**Prior work.** arXiv 2609.00060 has Tamarin models of x402, MPP, ACP and AP2. It covers neither UPI nor MCP authorization. arXiv 2608.23858 analyses AP2 informally. We couldn't find prior formal work on UPI-style agent mandates. Details are in [related-work.md](related-work.md).

---

## 3. For reviewers

- **Roles.** One honest AS (signing key). Honest payment servers. Honest agents (keys secret) and malicious agents (keys public). Honest principals and attacker-controlled user accounts. Payees are arbitrary names. The network is Dolev-Yao.
- **Checks, one flag each.** `NO_CONSENT_BINDING`, `NO_PAYEE_CHECK`, `NO_AMOUNT_CHECK`, `NO_AUD`, `NO_SENDER_CONSTRAINT` and `NO_REVOCATION_CHECK` each remove exactly one restriction or one `verify` equality. Signature verification and the payment-id cache are always on.
- **Properties.**
  - P10 `debit_within_intent`: for honest principals, a debit implies a matching earlier `Intent` with a compatible cap.
  - P11 `no_debit_after_revocation`: every debit precedes the revocation.
  - P12 `debit_requested_by_agent`: for an honest principal and an honest agent, every debit is preceded by `AgentPays` with the same mandate, payee, amount and payment server.
- **Results.** Fixed: P10–P12 verified. Single-flag variants: see R13. The full lattice of 64 combinations, with the minimal sufficient check sets per property and the monotonicity test, is generated in [ablation.md](ablation.md).
- **Abstractions to challenge.**
  - Payment requests leak, modelling leaked request logs as in the FAPI 2.0 attacker model.
  - Revocation is an event ordering, with the status check as a restriction.
  - Consent means the AS issues only on a matching `Intent`.

  Each is listed in [threat-model.md](threat-model.md), "Model 05 modelling choices".
