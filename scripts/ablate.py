#!/usr/bin/env python3
"""Ablation lattice (W2): run every subset of removable checks for each model.

For each model, every subset S of its check flags is run once (one Tamarin
run per subset, plus "context" flags such as PUBLIC that pick a protocol
variant rather than remove a check). The result of every property lemma is
written to results/ablation.json; scripts/ablation_report.py turns it into
docs/ablation.md and runs the consistency and monotonicity tests.

Usage (needs tamarin-prover and maude on PATH):
    JOBS=5 TIMEOUT=1800 python3 scripts/ablate.py            # all models
    JOBS=5 python3 scripts/ablate.py 02 03                   # some models
Runs are resumable: a finished output file is not run again.
"""
import itertools
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "results", "ablation")
JSON = os.path.join(ROOT, "results", "ablation.json")
TIMEOUT = int(os.environ.get("TIMEOUT", "1800"))
JOBS = int(os.environ.get("JOBS", "4"))

# One entry per model. flags: removable checks (one flag = one check).
# contexts: protocol variants the lattice is computed for separately.
# exclude: (context, flag) pairs that make no sense together.
MODELS = {
    "01": dict(file="models/01_as_selection.spthy", contexts=[()],
               flags=["NO_BINDING", "UNVALIDATED_ISSUER"],
               props=["client_credential_secrecy"]),
    "02": dict(file="models/02_code_and_audience.spthy", contexts=[()],
               flags=["NO_AUD", "NO_ISS", "NO_RESOURCE", "NO_STATE", "NO_PKCE", "NO_REDIRECT_CHECK"],
               props=["rs_accepts_only_consented", "token_secrecy", "session_integrity"]),
    "03": dict(file="models/03_cimd_client_binding.spthy", contexts=[(), ("PUBLIC",)],
               flags=["NO_META_CHECK", "NO_ISS", "RT_UNBOUND", "AS_NO_ASSERTION_AUD"],
               exclude=[(("PUBLIC",), "AS_NO_ASSERTION_AUD")],
               props=["rs_accepts_only_consented", "token_secrecy", "refresh_token_secrecy"]),
    "04": dict(file="models/04_id_jag.spthy", contexts=[()],
               flags=["NO_IDJAG_AUD", "NO_CLIENT_BINDING", "NO_RESOURCE_CLAIM"],
               props=["rs_accepts_only_authorized", "rs_accepts_only_requested",
                      "token_secrecy", "ras_grant_agreement"]),
    "06": dict(file="models/06_audience_injection.spthy", contexts=[()],
               flags=["AUD_TOKEN_ENDPOINT", "AS_LENIENT", "NO_META_CHECK"],
               props=["client_authentication", "token_secrecy"]),
    "05": dict(file="models/05_agent_payment_mandate.spthy", contexts=[()],
               flags=["NO_CONSENT_BINDING", "NO_PAYEE_CHECK", "NO_AMOUNT_CHECK", "NO_AUD",
                      "NO_SENDER_CONSTRAINT", "NO_REVOCATION_CHECK"],
               props=["debit_within_intent", "no_debit_after_revocation", "debit_requested_by_agent"]),
    "07": dict(file="models/07_confused_deputy_proxy.spthy", contexts=[()],
               flags=["CONSENT_NOT_CLIENT_BOUND", "NO_REDIRECT_CHECK"],
               props=["token_only_to_consented_client", "token_secrecy"]),
    "08": dict(file="models/08_token_passthrough.spthy", contexts=[()],
               flags=["S_NO_AUD", "PASSTHROUGH", "D_NO_AUD"],
               props=["downstream_only_via_server", "server_accepts_only_own_tokens"]),
}

LINE = re.compile(r"^\s*([A-Za-z0-9_]+) \((all-traces|exists-trace)\): (.*)$")


def runs_for(key):
    m = MODELS[key]
    for ctx in m["contexts"]:
        flags = [f for f in m["flags"] if (ctx, f) not in m.get("exclude", [])]
        for k in range(len(flags) + 1):
            for removed in itertools.combinations(flags, k):
                yield key, ctx, removed


def name_of(key, ctx, removed):
    c = "+".join(ctx) or "default"
    r = "+".join(removed) or "none"
    return f"{key}.{c}.{r}".lower()


def parse(text, props):
    """Map each property to V/F (proved/attack), A (attack via *_attack
    exists-trace lemma), N (no attack in the reduced attack-lemma model),
    or ? (no result line)."""
    res = {}
    for line in text.splitlines():
        mt = LINE.match(line)
        if mt:
            res[mt.group(1)] = (mt.group(2), mt.group(3))
    out = {}
    for p in props:
        if p in res:
            out[p] = "V" if res[p][1].startswith("verified") else "F"
        elif p + "_attack" in res:
            out[p] = "A" if res[p + "_attack"][1].startswith("verified") else "N"
        else:
            out[p] = "?"
    ex = res.get("executable", ("", ""))[1]
    out["executable"] = "V" if ex.startswith("verified") else ("F" if ex else "?")
    return out


def run(job):
    key, ctx, removed = job
    m = MODELS[key]
    name = name_of(key, ctx, removed)
    path = os.path.join(OUT, name + ".txt")
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        if "summary of summaries" in text or "ABLATE_TIMEOUT" in text:
            return finish(key, ctx, removed, name, text, None)
    args = ["timeout", "-s", "KILL", str(TIMEOUT), "tamarin-prover", "--prove",
            "--derivcheck-timeout=0", m["file"]] + [f"-D={f}" for f in (*ctx, *removed)]
    t0 = time.time()
    p = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, errors="replace")
    secs = int(time.time() - t0)
    text = p.stdout + p.stderr
    if p.returncode in (124, 137):
        text += f"\nABLATE_TIMEOUT after {TIMEOUT}s\n"
    text += f"\nABLATE_SECONDS {secs}\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return finish(key, ctx, removed, name, text, secs)


def finish(key, ctx, removed, name, text, secs):
    props = MODELS[key]["props"]
    status = parse(text, props)
    timeout = "ABLATE_TIMEOUT" in text
    if timeout:
        status = {k: ("T" if v == "?" else v) for k, v in status.items()}
    if secs is None:
        mt = re.search(r"ABLATE_SECONDS (\d+)", text)
        secs = int(mt.group(1)) if mt else -1
    warn = bool(re.search(r"WARNING:.*wellformedness", text))
    rec = dict(model=key, context=list(ctx), removed=list(removed), name=name,
               seconds=secs, timeout=timeout, wellformedness_warning=warn, status=status)
    print(f"{name:60s} {secs:>6}s {' '.join(f'{k}={v}' for k, v in status.items())}", flush=True)
    return rec


def main():
    keys = sys.argv[1:] or list(MODELS)
    os.makedirs(OUT, exist_ok=True)
    jobs = [j for k in keys for j in runs_for(k)]
    print(f"{len(jobs)} runs, JOBS={JOBS}, TIMEOUT={TIMEOUT}s", flush=True)
    old = []
    if os.path.exists(JSON):
        with open(JSON, encoding="utf-8") as fh:
            old = [r for r in json.load(fh) if r["model"] not in keys]
    with ThreadPoolExecutor(max_workers=JOBS) as ex:
        recs = list(ex.map(run, jobs))
    with open(JSON, "w", encoding="utf-8") as fh:
        json.dump(old + recs, fh, indent=1)
    print(f"wrote {JSON}")


if __name__ == "__main__":
    main()
