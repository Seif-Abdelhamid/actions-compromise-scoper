#!/bin/sh
# Build the local tag-repointing lab and scope it end to end. Local git only, canary values only.
set -eu
cd "$(dirname "$0")/.."
OUT="${1:-lab-out}"
PY="${PY:-.venv/bin/python}"
SCOPE="${SCOPE:-.venv/bin/actions-scope}"
echo "== 1. build lab (stand-in action repo, consumer repo, runs export, logs) =="
"$PY" lab/build_lab.py "$OUT" > "$OUT.summary.json"
"$PY" -c "import json,sys; m=json.load(open(sys.argv[1]))['mechanism']; print('tag v44 before:', m['tag_v44_before'][:12], '-> after:', m['tag_v44_after'][:12], '| tag pin followed move:', m['tag_pin_followed_move'], '| SHA pin unchanged:', m['sha_pin_unchanged'])" "$OUT.summary.json"
echo "== 2. scope the runs =="
set +e
"$SCOPE" scope --runs "$OUT/runs.json" --repo "$OUT/app" --logs "$OUT/logs" --out "$OUT/report.md"
code=$?
set -e
sed -n '1,40p' "$OUT/report.md"
echo "== exit code: $code (1 = exposed runs found) =="
if grep -q LABCANARY "$OUT/report.md"; then echo "FAIL: a canary value was printed"; exit 1; fi
echo "OK: no canary value appears in the report"
