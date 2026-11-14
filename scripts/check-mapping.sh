#!/usr/bin/env bash
# Traceability linter: every rule in models/NN_*.spthy must be named (in
# backticks) in the "### Model NN" section of docs/verification-mapping.md,
# which maps it to the spec clause it models.
# Usage: scripts/check-mapping.sh
set -euo pipefail

cd "$(dirname "$0")/.."
doc=docs/verification-mapping.md
fail=0

for model in models/*.spthy; do
  nn="$(basename "$model" | cut -c1-2)"
  # this model's section: from "### Model NN" up to the next "### " or "## " heading
  section="$(awk -v h="### Model ${nn} " 'index($0,h)==1{on=1;next} on&&/^##/{exit} on' "$doc")"
  if [[ -z "$section" ]]; then
    echo "UNMAPPED  $(basename "$model"): no '### Model ${nn} ' section in $doc"
    fail=1
    continue
  fi
  # rule names, including ones inside #ifdef branches
  while read -r rule; do
    if ! grep -q "\`${rule}\`" <<<"$section"; then
      echo "UNMAPPED  $(basename "$model"): rule ${rule}"
      fail=1
    fi
  done < <(grep -oE '^[[:space:]]*rule[[:space:]]+[A-Za-z0-9_]+' "$model" | awk '{print $2}' | sort -u)
done

if [[ $fail -eq 0 ]]; then echo "OK  every rule is mapped in $doc"; fi
exit "$fail"
