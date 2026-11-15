---
title: "Agent authorization for Indian payments, formally"
subtitle: "What a UPI-style mandate must bind when an AI agent pays, and which checks protect what"
author: "Harsh Thumar (remote participant, IETF; independent researcher)"
date: "Draft, 15 November 2026"
---

*Public draft for comment. Not legal advice, not a regulatory interpretation, and not endorsed by NPCI, RBI, CERT-In or any standards body. Items marked **[verify]** could not be confirmed against a primary source when this draft was written.*

# 1. Executive summary

AI agents are starting to pay for things on a person's behalf. India already has a delegation idea in UPI: NPCI's UPI Circle lets a person authorise another person or device to pay within limits. Public reporting suggests NPCI is exploring something similar for AI agents (see section 5; unverified). The security question for engineers is simple:

> If an agent pays under a mandate, does every payment stay inside what the person actually approved?

We wrote a formal model of such a flow (a payer, an authorization server, an agent, a payment server, an attacker who controls the network) and had a theorem prover, Tamarin, check it. The model uses OAuth building blocks (RFC 9396 rich authorization requests, sender-constrained tokens, audience restriction), anchored on a current IETF individual draft for delegated agent authorization. It is not UPI and uses no NPCI message formats.

With all six checks on, the prover proves three properties for every run of the model:

- **P10, money stays inside the approval.** A debit happens only to the payee, at the payment server, and up to the cap that the person approved.
- **P11, nothing is paid after revocation.**
- **P12, an honest agent's payment cannot be forged, replayed or rewritten.**

We then switched checks off, one subset at a time (all 64 combinations). The result is a table of which check protects which property:

| Property | Holds if and only if the following checks are on (in this model) |
|---|---|
| P10 | person's consent, payee check, amount-cap check and audience check, all four |
| P11 | online revocation check at the payment server |
| P12 | proof that the agent holds its key |

Each missing check enables a concrete, already well-understood attack (section 4). None of these attacks is new. What the model adds is a machine-checked statement that no check in the list is redundant and none protects more than the table says. We couldn't find prior formal work on UPI-style agent mandates (see the related-work file in the repository; the search is not exhaustive).

Practical takeaways: bind the mandate to the payee, the cap, the one payment server and the agent's key; make the revocation check a per-payment online lookup rather than relying on expiry; require the agent to sign each payment request; and log the evidence needed to show what the person approved. A checklist is in section 7.

Everything is reproducible with one Docker command (section 9).

# 2. The problem: agents paying under mandates

A human payment has a natural safeguard: the person sees the amount and payee and authenticates. An agent payment removes that moment. The person approves something earlier, in general terms ("pay the electricity bill up to a cap", "buy groceries from these merchants"), and an agent, possibly an LLM-driven one that can be misled by untrusted text, makes the actual payment later.

So the mandate, not the person, becomes the thing the payment system checks. Three things can then go wrong:

1. **The mandate says less than the person meant**, or was issued without a real approval.
2. **A payment goes beyond the mandate.** Wrong payee, larger amount, a different bank or payment app than the mandate was meant for.
3. **The mandate outlives the person's intent.** The person cancelled, but payments continue. Or someone who has seen one payment request resubmits it.

An LLM agent adds one more concern: it may be tricked into asking for something the mandate does not allow. This is why the checks have to be enforced by the payment side with deterministic rules, not by the agent's own judgement. That echoes NPCI's reported preference for narrow, deterministic controls (section 5).

# 3. What a mandate must bind, in plain words

| Binding | Plain meaning | Why |
|---|---|---|
| **Payer consent** | The person actually approved this mandate, on a channel the agent cannot fake. | Otherwise anyone can obtain a mandate in someone's name. |
| **Payee** | Money may go only to the named payee(s). | Stops redirecting money to an attacker's account. |
| **Cap** | An upper limit on what can be paid. | Stops over-spending. The real world has per-payment and monthly caps; the model only has two amount classes. |
| **Expiry** | The mandate stops working at a set time. | Limits the damage of a leaked or forgotten mandate. (Time is not modelled; see limitations.) |
| **Revocation** | The person can cancel, and cancellation is checked at payment time. | Expiry alone leaves a window. |
| **Audience** | The mandate names the one payment server (bank or payment app) it is for. | Stops a mandate for one bank being used at another. |
| **Agent key** | The mandate is tied to the agent's key, and each payment request is signed with it. | Stops anyone else, including someone who saw a request, from making payments. |

# 4. What the formal model proves, and the attack each missing check enables

**Model in one paragraph.** One honest authorization server (signs mandates), honest payment servers, honest agents (key secret) and malicious agents (key known to the attacker), honest payers and attacker-controlled accounts, arbitrary payee names, and a network the attacker controls (the standard Dolev-Yao attacker). Payment requests are assumed to leak, as in the FAPI 2.0 attacker model, for instance through logs. Signature verification and a one-time payment-id cache are always on. Checks:

| Check (flag that removes it) | What goes wrong without it | Property lost |
|---|---|---|
| Person approves the mandate (`NO_CONSENT_BINDING`) | The authorization server issues a mandate the person never agreed to, and the agent debits with it. | P10 |
| Payment server checks the payee (`NO_PAYEE_CHECK`) | Money goes to a payee the person never named. | P10 |
| Payment server checks the amount cap (`NO_AMOUNT_CHECK`) | More money moves than the person allowed. | P10 |
| Payment server checks the mandate names it (`NO_AUD`) | A mandate meant for one payment server is used at another. | P10 |
| Agent proves it holds its key (`NO_SENDER_CONSTRAINT`) | The mandate acts as a bearer token. An attacker who sees one payment request resubmits it as a new payment; the one-time payment-id cache does not help because the attacker uses a fresh id. | P12 |
| Payment server checks revocation online (`NO_REVOCATION_CHECK`) | Payments continue after the person cancels. | P11 |

**Which check is necessary for which property** (from the 64-combination ablation, repository file `docs/ablation.md`):

- **P10** is falsified whenever any one of consent, payee, amount or audience is off, whatever else is on. It holds when all four are on, independently of the other two checks.
- **P11** is falsified exactly when the revocation check is off.
- **P12** is falsified exactly when proof of possession is off.

The three properties are independent: removing the revocation check does not break P10 or P12, and removing proof of possession does not break P10 or P11. So you cannot trade one control for another. A strong key-binding does not make up for a missing revocation lookup, and a good revocation lookup does not make up for a missing amount check.

**What this is not.** None of the attacks is new. Each one follows from dropping a check that OAuth practice (RFC 9700, RFC 8707, RFC 9449) or payment practice already asks for. The contribution is the machine-checked, check-by-check statement for this kind of flow. The Tamarin runs proved the "all checks on" model and found attack traces for each variant with a check removed; the proof is relative to the model's assumptions (section 8).

**Spec anchor and one design suggestion.** The closest current IETF draft we found is draft-mishra-oauth-agent-grants-02, "OAuth Profile for Delegated AI Agent Authorization" (Sanjeev Kumar, Orchestrum Technologies LLP; reference implementation Grantex). It profiles PAR, PKCE, sender-constrained tokens and audience, and for financial limits points to RFC 9396. It has no mandate object. It makes revocation checking conditional on "the deployment's risk model". For payment mandates, the model suggests making the per-payment revocation check unconditional, since P11 depends on it alone.

# 5. How industry schemes and NPCI's approach compare

Read from public specifications and documentation on 15 November 2026. Not exhaustive; whether other controls (merchant routing, issuer or network rules) close the gaps in practice is outside the model.

| Check in the model | Visa Intelligent Commerce / Trusted Agent Protocol | Mastercard Agent Pay / Verifiable Intent (draft v0.1) | NPCI UPI Circle (as publicly reported; **[verify]** against NPCI circulars) |
|---|---|---|---|
| Principal's approval | Passkey-authenticated instruction | Cardholder mandate signed by the user's device key | Consent at linking |
| Payee | Merchant name checked against the mandate | `allowed_payees` / `allowed_merchants` exact match | Person-to-merchant delegation reported; no payee binding found |
| Cap | `declineThreshold`, aggregated per instruction | `amount_range` and cumulative `budget` | Per-transaction and monthly caps reported |
| Audience (one payment server) | Not found as an audience claim | Not found in the parts read | Not found |
| Proof of possession | Fresh `agentSignature` per call; TAP uses RFC 9421 HTTP signatures | Agent key bound with `cnf` (RFC 7800); agent signs the final order | Device and user ID reported as validated per payment |
| Online revocation check | Issuer-side token revocation; no per-payment check stated | Not defined; short expiry instead | Delinking in the app; no per-payment check stated |

What the comparison suggests, with the caveat that it rests on the documents we read:

- None of the three, as far as we found, states a per-payment revocation check. They rely on expiry, token revocation or delinking. In the model, only the online status check protects P11.
- None, as far as we found, binds the mandate to one payment server the way an OAuth `aud` claim would. In the model, dropping that check lets a mandate for one payment server work at another.

**NPCI.** We did not retrieve NPCI's own circulars on UPI Circle (OC 201 of 13 August 2024 and OC 201-B of 8 October 2025; **[verify]**). The UPI Circle column therefore rests on secondary reporting and should be treated as unverified. Press reports (not an NPCI specification; **[verify]**) describe a proposed NPCI protocol for AI agents that would verify and register agents, check their scope of authority and transaction limits, and build on UPI Circle. The NPCI chief executive is reported to favour narrow, "as deterministic as possible" AI models, with systems that can trace the instructions and consent a user gave. Status is reported inconsistently, and we found no NPCI circular on AI-agent payments. This paper does not claim that UPI works as modelled.

# 6. Mapping to Indian frameworks

This section is a reading aid, not compliance advice. It says where each check plausibly supports a stated aim; it does not say a framework requires it.

| Framework | What it is | How the checks relate | Primary source |
|---|---|---|---|
| **RBI FREE-AI** (Framework for Responsible and Ethical Enablement of AI), committee report, 13 Aug 2025 | Report to RBI proposing seven "sutras" (including Trust, Accountability, Explainability, Resilience) and 26 recommendations across six pillars (infrastructure, policy, capacity, governance, protection, assurance). It is a committee report with recommendations. | Per-payment deterministic checks and recorded consent support accountability and explainability; the revocation check and the audience check are resilience controls against misuse. | RBI press release: <https://rbi.org.in/Scripts/BS_PressReleaseDisplay.aspx?prid=61018>; RBI publication page: <https://rbi.org.in/scripts/PublicationReportDetails.aspx?ID=1306> (both appeared in web search; opening them for exact wording is **[verify]**) |
| **CERT-In AI security guidance** | CERT-In's Technical Guidelines on SBOM, QBOM, CBOM, AIBOM and HBOM (Version 2.0, 9 July 2025) include an AI bill of materials. Law-firm summaries also describe a 2026 CERT-In "AI cybersecurity blueprint", reported as non-binding. | A bill of materials helps you know which agent, model and libraries sit behind a mandate holder. It does not replace the protocol checks here. | A copy of the BOM guidelines PDF is hosted at <https://fsd.delhi.gov.in/sites/default/files/FS/circulars-orders/6technicalguidelines_on_bom.pdf> (copy on a Delhi government site; the CERT-In original URL is **[verify]**). The 2026 blueprint: no primary text found, **[verify]** on cert-in.org.in. |
| **DPDP Act 2023** (Act 22 of 2023; Rules notified 2025, per a PIB release, **[verify]**) | Consent-based personal data protection law. | Consent must be specific and withdrawable. The consent-binding and revocation checks are the payment-side counterparts for what the person approved and later withdraws; mandate logs themselves contain personal data and fall under the Act. Whether a payment mandate is "consent" under the Act is a legal question outside this paper. | India Code copy: <https://www.indiacode.nic.in/bitstream/123456789/22037/2/a2023-22.pdf> (appeared in web search; **[verify]** that the file opens and is current) |
| **NPCI "deterministic auditable rules"** | Reported stance of NPCI leadership on agentic payments (section 5). | The mandate checks are exactly rule checks the payment server can run without any AI. The recorded consent, mandate and signed request are the audit evidence. | No NPCI primary source found: **[verify]**. Reported via press and an interview; do not treat as policy. |

# 7. Checklist for implementers

**Mandate issuance**

1. Issue a mandate only after the person approves it on a channel the agent cannot control. Record what was shown (payee, cap, expiry, payment server).
2. Put the payee, cap, expiry, the payment server (audience) and the agent's public key in the mandate. Sign it.
3. Make the mandate short-lived, and make a new approval, not silent renewal, the way to extend it.

**At each payment (payment server)**

4. Verify the mandate signature and expiry.
5. Check the mandate names *this* payment server (audience).
6. Check the payee equals a payee in the mandate (exact match, not prefix or display name).
7. Check the amount, and any running total, against the cap.
8. Require a fresh signature by the agent's key over the payment request, including payment id, payee, amount, payment server and the mandate's hash. Reject unsigned or replayed requests. A payment-id cache alone is not enough.
9. Look up revocation online for every payment. Do not depend on expiry or on cached status beyond a very short window.
10. Accept each payment id once.

**Agent and operations**

11. Keep the agent's key in hardware or a managed key store; rotate on suspicion.
12. Treat everything the agent reads as untrusted. The payment-side checks are the safety net if the agent is misled.
13. Log mandate id, request, decision and evidence for audit, protecting the logs as personal data. Treat logged payment requests as leakable (the model assumes they leak).
14. Test each check separately: a payment that is wrong in exactly one way (other payee, over cap, other server, bad signature, after revocation) must be rejected by the check designed for it.

# 8. Limitations

- **Abstract model.** Amounts are two classes, not rupees. There are no monthly totals, clocks, cooling periods, expiry dynamics, device binding as a separate factor, or real NPCI message formats. Several checks the checklist asks for (expiry, running totals) are therefore argued, not proved.
- **Symbolic, Dolev-Yao.** Cryptography is assumed perfect, so this says nothing about implementation bugs, side channels or weak keys. Attackers who control the network, malicious agents and attacker-run accounts are covered; the model assumes honest authorization and payment servers.
- **Modelling choices matter.** Consent is modelled as the authorization server issuing only on a matching approval; revocation is an event ordering with the status check as a restriction; payment requests are assumed to leak. These are listed in the repository's threat-model file and should be challenged.
- **Necessity is relative to the model.** "Holds if and only if" means within these rules and this attacker.
- **Anchor spec.** The draft used for the anchor is an individual IETF submission, not a standard.
- **Unverified inputs.** NPCI rules (secondary sources only), press reports on NPCI's agent plans, and framework details marked **[verify]**.
- **Not legal advice.** Nothing here interprets the DPDP Act, RBI directions or NPCI rules.
- **Prior work.** Related work was searched on 15 November 2026 with a search engine that returns summaries; absence of hits is not absence of work. Neighbouring work includes formal analyses of other agent-payment protocols and of OAuth and FAPI; see the related-work file.

# 9. How to reproduce

The models, proofs and the ablation table are in the public repository (<https://github.com/HarshThumar/mcp-auth-tamarin>). Model 05 is `models/05_agent_payment_mandate.spthy`; the case study is `docs/case-study-upi.md`; the results write-up (R13) is `docs/results.md`; the 64-combination table is `docs/ablation.md`.

With Docker installed, from the repository root:

```
scripts/reproduce.sh                              # full run, about 60 minutes, 9-10 GB RAM
ONLY=05 TIMEOUT=600 JOBS=1 scripts/reproduce.sh   # model 05 only (ONLY is a regex; see scripts/prove.sh)
```

The script builds the image, runs every Tamarin variant, checks each lemma against its expected result and exits non-zero on any difference. Tamarin 1.12.0 and Maude 3.5.1 are pinned.

*Comments and corrections are welcome as GitHub issues on the repository.*

# Sources

- RBI FREE-AI committee report press release: <https://rbi.org.in/Scripts/BS_PressReleaseDisplay.aspx?prid=61018>
- CERT-In BOM technical guidelines v2.0 (copy): <https://fsd.delhi.gov.in/sites/default/files/FS/circulars-orders/6technicalguidelines_on_bom.pdf>
- DPDP Act 2023 (India Code): <https://www.indiacode.nic.in/bitstream/123456789/22037/2/a2023-22.pdf>
- Visa Intelligent Commerce: <https://developer.visa.com/docs/visa-intelligent-commerce/concepts>; Trusted Agent Protocol: <https://developer.visa.com/docs/trusted-agent-protocol/trusted-agent-protocol-specifications>
- Mastercard Verifiable Intent, draft v0.1: <https://github.com/agent-intent/verifiable-intent>
- RFC 9396 (rich authorization requests), RFC 8707 (resource indicators), RFC 9449 (DPoP), RFC 9700 (OAuth security BCP), RFC 7800 (proof-of-possession keys), RFC 9421 (HTTP message signatures)
- draft-mishra-oauth-agent-grants-02, IETF datatracker
