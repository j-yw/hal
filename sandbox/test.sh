#!/usr/bin/env bash
# =============================================================================
# Smoke-test that the sandbox image has all required tools.
# Run inside the container:  /test.sh
# Or from host:              docker run --rm hal-sandbox /test.sh
# =============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

# Use (( ... )) || true to prevent set -e from aborting when count is 0
inc_pass() { (( PASS++ )) || true; }
inc_fail() { (( FAIL++ )) || true; }

check() {
  local label="$1"
  shift
  if output=$("$@" 2>&1); then
    echo -e "  ${GREEN}✓${NC} ${label}: ${output%%$'\n'*}"
    inc_pass
  else
    echo -e "  ${RED}✗${NC} ${label}: FAILED"
    inc_fail
  fi
}

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Hal Sandbox — Tool Verification"
echo "═══════════════════════════════════════════════════════"
echo ""

echo "── System ──────────────────────────────────────────────"
check "git"       git --version
check "make"      make --version
check "curl"      curl --version
check "jq"        jq --version
check "ssh"       ssh -V

echo ""
echo "── Languages & Runtimes ──────────────────────────────"
check "node"      node --version
check "npm"       npm --version
check "go"        go version

echo ""
echo "── Dev Tools ─────────────────────────────────────────"
check "gh"        gh --version
check "claude"    claude --version
check "pi"        pi --version
check "codex"     codex --version
check "hal"       hal version

check "tailscale" tailscale version

echo ""
echo "── Claude Code Config ────────────────────────────────"
if [ -f /root/.claude/settings.json ]; then
  echo -e "  ${GREEN}✓${NC} settings.json exists"
  inc_pass
else
  echo -e "  ${RED}✗${NC} settings.json missing"
  inc_fail
fi

AGENT_COUNT=$(find /root/.claude/agents -type f -name '*.md' 2>/dev/null | wc -l)
if [ "$AGENT_COUNT" -gt 0 ]; then
  echo -e "  ${GREEN}✓${NC} agents: ${AGENT_COUNT} agent files"
  inc_pass
else
  echo -e "  ${YELLOW}⚠${NC} agents: none found"
  inc_fail
fi

SKILL_COUNT=$(find /root/.claude/skills -type f -iname '*.md' 2>/dev/null | wc -l)
if [ "$SKILL_COUNT" -gt 0 ]; then
  echo -e "  ${GREEN}✓${NC} skills: ${SKILL_COUNT} skill files"
  inc_pass
else
  echo -e "  ${YELLOW}⚠${NC} skills: none found"
  inc_fail
fi

echo ""
echo "── Runtime Config ────────────────────────────────────"
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  echo -e "  ${GREEN}✓${NC} ANTHROPIC_API_KEY is set"
  inc_pass
else
  echo -e "  ${YELLOW}⚠${NC} ANTHROPIC_API_KEY not set (claude won't work)"
fi

if [ -n "${OPENAI_API_KEY:-}" ]; then
  echo -e "  ${GREEN}✓${NC} OPENAI_API_KEY is set"
  inc_pass
else
  echo -e "  ${YELLOW}⚠${NC} OPENAI_API_KEY not set (codex won't work)"
fi

if [ -n "${GITHUB_TOKEN:-}" ]; then
  echo -e "  ${GREEN}✓${NC} GITHUB_TOKEN is set"
  inc_pass
else
  echo -e "  ${YELLOW}⚠${NC} GITHUB_TOKEN not set (gh won't be authenticated)"
fi

GIT_NAME=$(git config --global user.name 2>/dev/null || true)
if [ -n "$GIT_NAME" ]; then
  echo -e "  ${GREEN}✓${NC} git user.name: ${GIT_NAME}"
  inc_pass
else
  echo -e "  ${YELLOW}⚠${NC} git user.name not configured"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "═══════════════════════════════════════════════════════"
echo ""

exit "$FAIL"
