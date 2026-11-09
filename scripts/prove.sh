#!/usr/bin/env bash
# Run every model variant and check each lemma against its expected result.
# Usage: scripts/prove.sh            (needs tamarin-prover and maude on PATH)
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p results
fail=0

# model | preprocessor flag ("-" for none) | lemma | expected (verified|falsified)
expectations=(
  "models/01_as_selection.spthy|VULNERABLE|executable|verified"
  "models/01_as_selection.spthy|VULNERABLE|client_credential_secrecy|falsified"
  "models/01_as_selection.spthy|-|executable|verified"
  "models/01_as_selection.spthy|-|client_credential_secrecy|verified"
)

declare -A ran=()
for row in "${expectations[@]}"; do
  IFS='|' read -r model flag lemma expected <<<"$row"
  name="$(basename "$model" .spthy)"
  [[ "$flag" == "-" ]] && variant="fixed" || variant="${flag,,}"
  out="results/${name}.${variant}.txt"

  if [[ -z "${ran[$out]:-}" ]]; then
    args=(--prove "$model")
    [[ "$flag" != "-" ]] && args+=("-D=$flag")
    echo "== tamarin-prover ${args[*]}"
    tamarin-prover "${args[@]}" >"$out" 2>&1 || true
    ran[$out]=1
  fi

  line="$(grep -E "^[[:space:]]*${lemma} \((all-traces|exists-trace)\): " "$out" | tail -1 || true)"
  if [[ "$line" == *": ${expected} "* || "$line" == *": ${expected}" ]]; then
    echo "PASS  ${name} [${variant}] ${lemma}: ${expected}"
  else
    echo "FAIL  ${name} [${variant}] ${lemma}: expected ${expected}, got: ${line:-<no result line; see $out>}"
    fail=1
  fi
done

exit "$fail"
