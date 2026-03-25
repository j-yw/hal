#!/bin/bash
set -euo pipefail

# Quick sanity: SKILL.md must still exist and contain key sections
SKILL="/home/v/.agents/skills/markshare/SKILL.md"
[ -f "$SKILL" ] || { echo "FAIL: SKILL.md missing"; exit 1; }
grep -q "PHASE 1: Get API Key" "$SKILL" || { echo "FAIL: Phase 1 missing"; exit 1; }
grep -q "PHASE 2: Find Files" "$SKILL" || { echo "FAIL: Phase 2 missing"; exit 1; }
grep -q "PHASE 3: Upload" "$SKILL" || { echo "FAIL: Phase 3 missing"; exit 1; }
grep -q "PHASE 4: Report Result" "$SKILL" || { echo "FAIL: Phase 4 missing"; exit 1; }
grep -q "OUTPUT RULES" "$SKILL" || { echo "FAIL: Output Rules missing"; exit 1; }

# Eval harness must compile
python3 -m py_compile /home/v/.agents/skills/markshare/autoresearch-markshare/run_markshare_eval.py || { echo "FAIL: eval harness broken"; exit 1; }

echo "OK: all structural checks pass"
