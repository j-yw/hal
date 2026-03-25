#!/bin/bash
set -euo pipefail
SKILL="/home/v/.agents/skills/markshare/SKILL.md"
[ -f "$SKILL" ] || { echo "FAIL: SKILL.md missing"; exit 1; }
grep -q "PHASE 1: Get API Key" "$SKILL" || { echo "FAIL: Phase 1 missing"; exit 1; }
grep -q "PHASE 4: Report Result" "$SKILL" || { echo "FAIL: Phase 4 missing"; exit 1; }
python3 -m py_compile /home/v/.agents/skills/markshare/autoresearch-markshare/run_markshare_eval.py || { echo "FAIL: eval harness broken"; exit 1; }
echo "OK"
