#!/usr/bin/env python3
"""Ablation report and tests (W2).

Reads results/ablation.json (from scripts/ablate.py) and scripts/prove.sh, then
  1. CONSISTENCY: every prove.sh row that names the same model, context and
     removed checks as an ablation cell must agree with it;
  2. MONOTONICITY: removing more checks never turns an attack back into a
     proof (if P fails with checks S removed, it fails for every superset);
  3. computes, per property, the minimal sets of checks that are enough
     (kept checks of every verified cell, minimised) and the checks that are
     necessary (in every sufficient set), as a Boolean formula;
and writes docs/ablation.md. Exit code 1 if test 1 or 2 fails.

Usage: python3 scripts/ablation_report.py
"""
import itertools
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ablate import MODELS  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JSON = os.path.join(ROOT, "results", "ablation.json")
DOC = os.path.join(ROOT, "docs", "ablation.md")

PROP_NO = {  # global property numbers (docs/flow.md §3)
    "client_credential_secrecy": "P1", "rs_accepts_only_consented": "P2",
    "rs_accepts_only_authorized": "P2", "rs_accepts_only_requested": "P2'",
    "token_secrecy": "P3", "refresh_token_secrecy": "P4",
    "ras_grant_agreement": "P5", "session_integrity": "P6",
    "client_authentication": "P7", "token_only_to_consented_client": "P8",
    "downstream_only_via_server": "P9", "server_accepts_only_own_tokens": "P2",
    "debit_within_intent": "P10", "no_debit_after_revocation": "P11",
    "debit_requested_by_agent": "P12",
}
CHECK_NAME = {  # flag -> the check it removes (ubiquitous language)
    "NO_BINDING": "issuer binding", "UNVALIDATED_ISSUER": "metadata issuer check",
    "NO_AUD": "RS audience check", "NO_ISS": "`iss` check", "NO_RESOURCE": "AS honours `resource`",
    "NO_STATE": "`state`", "NO_PKCE": "PKCE", "NO_REDIRECT_CHECK": "exact redirect URI",
    "NO_META_CHECK": "metadata issuer check", "RT_UNBOUND": "refresh-token binding",
    "AS_NO_ASSERTION_AUD": "AS checks assertion `aud`",
    "NO_IDJAG_AUD": "RAS checks ID-JAG `aud`", "NO_CLIENT_BINDING": "RAS checks ID-JAG `client_id`",
    "NO_RESOURCE_CLAIM": "`resource` in ID-JAG",
    "AUD_TOKEN_ENDPOINT": "client: `aud` = issuer", "AS_LENIENT": "AS: `aud` = issuer only",
    "NO_CONSENT_BINDING": "principal's approval", "NO_PAYEE_CHECK": "payee check",
    "NO_AMOUNT_CHECK": "amount cap check", "NO_SENDER_CONSTRAINT": "proof of possession",
    "NO_REVOCATION_CHECK": "revocation check",
    "CONSENT_NOT_CLIENT_BOUND": "per-client consent",
    "S_NO_AUD": "MCP server checks `aud`", "PASSTHROUGH": "server exchanges the token (not a check: a design choice)",
    "D_NO_AUD": "downstream API checks `aud`",
}
SHORT = {  # flag -> short symbol for formulas
    "NO_BINDING": "BIND", "UNVALIDATED_ISSUER": "META", "NO_AUD": "AUD", "NO_ISS": "ISS",
    "NO_RESOURCE": "RES", "NO_STATE": "STATE", "NO_PKCE": "PKCE", "NO_REDIRECT_CHECK": "REDIR",
    "NO_META_CHECK": "META", "RT_UNBOUND": "RTBIND", "AS_NO_ASSERTION_AUD": "ASAUD",
    "NO_IDJAG_AUD": "JAGAUD", "NO_CLIENT_BINDING": "JAGCID", "NO_RESOURCE_CLAIM": "JAGRES",
    "AUD_TOKEN_ENDPOINT": "CAUD", "AS_LENIENT": "ASAUD",
    "NO_CONSENT_BINDING": "CONSENT", "NO_PAYEE_CHECK": "PAYEE", "NO_AMOUNT_CHECK": "AMOUNT",
    "NO_SENDER_CONSTRAINT": "POP", "NO_REVOCATION_CHECK": "REVOKE",
    "CONSENT_NOT_CLIENT_BOUND": "CCONSENT",
    "S_NO_AUD": "SAUD", "PASSTHROUGH": "XCHG", "D_NO_AUD": "DAUD",
}
FAILS = {"F", "A"}


def load_prove_rows():
    rows = []
    with open(os.path.join(ROOT, "scripts", "prove.sh"), encoding="utf-8") as fh:
        for line in fh:
            mt = re.match(r'^\s*"(models/[^|]+)\|([^|]*)\|([^|]+)\|(verified|falsified)"', line)
            if mt:
                rows.append(mt.groups())
    return rows


def main():
    with open(JSON, encoding="utf-8") as fh:
        cells = json.load(fh)
    # A run that states some property as an exists-trace attack lemma uses a
    # REDUCED model (attacker rules left out; see models/03 ATTACK_LEMMAS).
    # Its all-traces proofs hold only for that reduced model, so they are
    # marked R: not a proof for the full model, counted as undecided.
    for c in cells:
        st = c["status"]
        if any(v in ("A", "N") for v in st.values()):
            for k, v in list(st.items()):
                if v == "V" and k != "executable":
                    st[k] = "R"
    idx = {(c["model"], tuple(c["context"]), frozenset(c["removed"])): c for c in cells}
    problems = []

    # 1. consistency with prove.sh
    agree = 0
    for model_file, flags, lemma, expected in load_prove_rows():
        key = os.path.basename(model_file)[:2]
        if key not in MODELS:
            continue
        m = MODELS[key]
        fl = [] if flags == "-" else flags.split(",")
        ctx = tuple(f for f in fl if any(f in c for c in m["contexts"]))
        rem = frozenset(f for f in fl if f not in ctx)
        if not rem <= set(m["flags"]):
            continue  # legacy alias flags (VULNERABLE, ISS_OPTIONAL)
        cell = idx.get((key, ctx, rem))
        if cell is None:
            continue
        base = lemma[:-7] if lemma.endswith("_attack") else lemma
        if base not in cell["status"] and lemma != "executable":
            continue
        got = cell["status"].get("executable" if lemma == "executable" else base)
        if got == "R":
            got = "V"  # same run as prove.sh (reduced model there too)
        if lemma.endswith("_attack"):
            want = "A" if expected == "verified" else "N"
        elif lemma == "executable":
            want = "V" if expected == "verified" else "F"
        else:
            want = "V" if expected == "verified" else "F"
        if got in ("T", "?"):
            continue
        if (want in FAILS) != (got in FAILS) or (want == "N") != (got == "N"):
            problems.append(f"CONSISTENCY {key} ctx={ctx} removed={sorted(rem)} {lemma}: prove.sh={expected}, ablation={got}")
        else:
            agree += 1

    # 2. monotonicity
    mono_checked = 0
    vacuous_skipped = set()
    for c in cells:
        for d in cells:
            if c["model"] != d["model"] or c["context"] != d["context"]:
                continue
            if not set(c["removed"]) < set(d["removed"]):
                continue
            # A vacuous cell (honest protocol cannot run) proves nothing, so it
            # cannot contradict an attack. Counted and reported, not tested.
            if d["status"].get("executable") == "F":
                vacuous_skipped.add(d["name"])
                continue
            for p in MODELS[c["model"]]["props"]:
                a, b = c["status"].get(p), d["status"].get(p)
                if a in FAILS and b in ("V",):
                    problems.append(f"MONOTONICITY {c['model']} {p}: fails with {c['removed']} removed but holds with {d['removed']} removed")
                if a in FAILS and b in FAILS | {"V"}:
                    mono_checked += 1

    # 3. sufficient / necessary checks, and the report
    out = ["# Ablation: which checks each property needs",
           "",
           "*Generated by `scripts/ablation_report.py` from `results/ablation.json` (`scripts/ablate.py`). Do not edit by hand.*",
           "",
           "Each model is run once for **every subset of its removable checks** (one flag = one check). "
           "A cell is the result of a property with that subset removed: ✅ proved, ❌ attack found, "
           "❌ᵃ attack found with an exists-trace attack lemma (reduced model, see results.md R8), "
           "∅ no attack in the reduced model (not a proof), ✅ʳ proved only in the reduced model (attacker clients left out; not a proof for the full model, counted as undecided), ⏱ timeout (no result; the cap is stated), ? missing. "
           "A row marked **vacuous** is one where the honest protocol cannot run (`executable` fails), so a ✅ there means nothing.",
           "",
           f"**Tests:** {agree} cells agree with `scripts/prove.sh`; {mono_checked} subset pairs checked for monotonicity; "
           f"{len(problems)} problem(s). {len(vacuous_skipped)} vacuous cell(s) left out of the monotonicity test "
           "(a flag that changes behaviour, rather than removing a check, can make the honest run impossible).",
           "",
           "COVERAGE_PLACEHOLDER",
           ""]
    sym = {"V": "✅", "F": "❌", "A": "❌ᵃ", "N": "∅", "R": "✅ʳ", "T": "⏱", "?": "?"}
    decided = total = 0
    for key, m in MODELS.items():
        for ctx in m["contexts"]:
            flags = [f for f in m["flags"] if (ctx, f) not in m.get("exclude", [])]
            mc = [c for c in cells if c["model"] == key and tuple(c["context"]) == ctx]
            if not mc:
                continue
            title = f"## Model {key}" + (f" ({', '.join(ctx)})" if ctx else "")
            out += [title, "", "Checks: " + ", ".join(f"{SHORT[f]} = {CHECK_NAME[f]} (`{f}` removes it)" for f in flags), ""]
            props = m["props"]
            out.append("| Removed checks | " + " | ".join(f"{PROP_NO.get(p, '')} `{p}`" for p in props) + " | s |")
            out.append("|---|" + "---|" * len(props) + "---|")
            for c in sorted(mc, key=lambda c: (len(c["removed"]), c["removed"])):
                rem = ", ".join(SHORT[f] for f in c["removed"]) or "none (all checks on)"
                vac = " **vacuous**" if c["status"].get("executable") == "F" else ""
                out.append(f"| {rem}{vac} | " + " | ".join(sym[c["status"].get(p, "?")] for p in props) + f" | {c['seconds']} |")
                for p in props:
                    total += 1
                    decided += c["status"].get(p) in ("V", "F", "A")
            out.append("")
            out.append("**What is enough** (minimal sets of kept checks that make the property hold; non-vacuous proved cells only):")
            out.append("")
            for p in props:
                suff = []
                undecided = 0
                for c in mc:
                    st = c["status"].get(p)
                    if st in ("T", "?", "N", "R"):
                        undecided += 1
                    if st == "V" and c["status"].get("executable") != "F":
                        suff.append(frozenset(f for f in flags if f not in c["removed"]))
                minimal = sorted({s for s in suff if not any(t < s for t in suff)}, key=lambda s: (len(s), sorted(s)))
                if not minimal:
                    formula = "never holds in this model (an attack exists even with every check on)" if suff == [] and any(
                        c["status"].get(p) in FAILS and not c["removed"] for c in mc) else "no proved cell"
                else:
                    terms = [" ∧ ".join(SHORT[f] for f in sorted(s)) or "⊤ (no check needed)" for s in minimal]
                    formula = " ∨ ".join(f"({t})" if len(minimal) > 1 and " ∧ " in t else t for t in terms)
                necessary = set.intersection(*[set(s) for s in minimal]) if minimal else set()
                note = f"; {undecided} cell(s) undecided, so this is a lower bound" if undecided else ""
                nec = ", ".join(SHORT[f] for f in sorted(necessary)) or "none"
                out.append(f"- {PROP_NO.get(p, '')} `{p}` holds iff **{formula}** (necessary: {nec}{note})")
            out.append("")
    out[out.index("COVERAGE_PLACEHOLDER")] = (
        f"**Coverage:** {decided} of {total} property cells decided ({100 * decided // max(total, 1)} %).")
    if problems:
        out += ["## Problems", ""] + [f"- {x}" for x in problems] + [""]
    with open(DOC, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out))
    for x in problems:
        print(x)
    print(f"agree={agree} mono_pairs={mono_checked} decided={decided}/{total} problems={len(problems)}; wrote {DOC}")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
