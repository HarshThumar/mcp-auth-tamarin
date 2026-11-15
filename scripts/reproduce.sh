#!/usr/bin/env bash
# One-command reproduction in Docker.
#   scripts/reproduce.sh                      full run (about 60 min, JOBS=4, 9-10 GB RAM)
#   ONLY=01 TIMEOUT=600 JOBS=1 scripts/reproduce.sh   smoke test
# ONLY / TIMEOUT / JOBS are passed to scripts/prove.sh. Exit code is nonzero on any failure.
set -uo pipefail
cd "$(dirname "$0")/.."
IMAGE="${IMAGE:-mcp-auth-tamarin}"
log="$(mktemp)"; trap 'rm -f "$log"' EXIT

docker build -t "$IMAGE" . || { echo "FAIL  docker build"; exit 1; }

env_args=(-e "JOBS=${JOBS:-4}")
[[ -n "${ONLY:-}" ]] && env_args+=(-e "ONLY=${ONLY}")
[[ -n "${TIMEOUT:-}" ]] && env_args+=(-e "TIMEOUT=${TIMEOUT}")

docker run --rm "${env_args[@]}" "$IMAGE" 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}

echo
grep -E "^Checked [0-9]+ lemma results" "$log" || echo "No 'Checked N lemma results' line found."
if [[ $rc -ne 0 ]] || grep -q "^FAIL" "$log"; then echo "REPRODUCE: FAILED (exit $rc)"; exit $(( rc != 0 ? rc : 1 )); fi
echo "REPRODUCE: OK"
