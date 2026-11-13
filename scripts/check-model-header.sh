#!/usr/bin/env bash
# Every .spthy model must declare which spec version it was written against.
# This prevents forgetting to pin the spec version when drafts change.
set -euo pipefail

fail=0
for f in models/*.spthy; do
  if ! grep -q "Spec pinned" "$f"; then
    echo "FAIL: $f is missing 'Spec pinned:' in its header"
    fail=1
  fi
done

if [[ $fail -eq 0 ]]; then
  echo "OK: all models have pinned spec versions"
fi
exit "$fail"
