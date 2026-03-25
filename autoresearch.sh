#!/bin/bash
set -euo pipefail

# Markshare skill autoresearch eval
EXPERIMENT_ID="${MARKSHARE_EXPERIMENT_ID:-99}"
WORKDIR="/home/v/.agents/skills/markshare/autoresearch-markshare"
TIMEOUT="${MARKSHARE_TIMEOUT:-90}"
RUNS="${MARKSHARE_RUNS:-5}"

exec python3 "$WORKDIR/run_markshare_eval.py" \
  --workdir "$WORKDIR" \
  --experiment-id "$EXPERIMENT_ID" \
  --runs "$RUNS" \
  --timeout "$TIMEOUT"
