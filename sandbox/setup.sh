#!/usr/bin/env bash
# =============================================================================
# Universal Dev Sandbox Bootstrap
# =============================================================================
# Installs all dev tools on any fresh Ubuntu/Debian machine.
# Idempotent — safe to run multiple times.
#
# Usage (remote):
#   curl -fsSL https://raw.githubusercontent.com/jywlabs/hal/main/sandbox/setup.sh | bash
#
# Usage (local):
#   ./sandbox/setup.sh
#
# Usage (with env file):
#   export $(grep -v '^#' sandbox/.env | xargs) && ./sandbox/setup.sh
#
# The script also works inside Docker (called by the Dockerfile).
# =============================================================================
set -euo pipefail

# ── Version pins (single source of truth) ────────────────────────────────────
GO_VERSION="${GO_VERSION:-1.25.7}"
NODE_MAJOR="${NODE_MAJOR:-22}"
CLAUDE_CODE_VERSION="${CLAUDE_CODE_VERSION:-2.1.42}"
PI_CODING_AGENT_VERSION="${PI_CODING_AGENT_VERSION:-0.52.10}"
CODEX_VERSION="${CODEX_VERSION:-0.101.0}"

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

step()  { echo -e "\n${CYAN}${BOLD}── $1 ──${NC}"; }
ok()    { echo -e "  ${GREEN}✓${NC} $1"; }
fail()  { echo -e "  ${RED}✗${NC} $1"; }

# ── Detect environment ───────────────────────────────────────────────────────
IN_DOCKER="${IN_DOCKER:-false}"
if [ -f /.dockerenv ]; then
  IN_DOCKER="true"
fi

ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
HOME_DIR="${HOME:-/root}"

# ── System packages ─────────────────────────────────────────────────────────
step "System packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
  build-essential \
  ca-certificates \
  curl \
  git \
  gnupg \
  jq \
  make \
  openssh-client \
  openssh-server \
  sudo \
  unzip \
  wget \
  tmux \
  vim \
  ripgrep \
  htop \
  2>&1 | tail -1
rm -rf /var/lib/apt/lists/*
ok "System packages installed"

# ── SSH server (VPS only — skip in Docker) ───────────────────────────────────
if [ "$IN_DOCKER" = "false" ]; then
  step "SSH server"
  mkdir -p /run/sshd
  # Enable password auth (can be disabled later once keys are set up)
  sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null || true
  sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null || true
  # Restart sshd if running
  systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || true
  ok "SSH server configured"
fi

# ── GitHub CLI ───────────────────────────────────────────────────────────────
step "GitHub CLI"
if command -v gh &>/dev/null; then
  ok "gh already installed: $(gh --version | head -1)"
else
  curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg 2>/dev/null
  echo "deb [arch=${ARCH} signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    | tee /etc/apt/sources.list.d/github-cli.list > /dev/null
  apt-get update -qq
  apt-get install -y --no-install-recommends gh 2>&1 | tail -1
  rm -rf /var/lib/apt/lists/*
  ok "gh installed: $(gh --version | head -1)"
fi

# ── Node.js ──────────────────────────────────────────────────────────────────
step "Node.js ${NODE_MAJOR}.x"
if command -v node &>/dev/null && node --version | grep -q "v${NODE_MAJOR}\."; then
  ok "Node.js already installed: $(node --version)"
else
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash - 2>&1 | tail -1
  apt-get install -y --no-install-recommends nodejs 2>&1 | tail -1
  rm -rf /var/lib/apt/lists/*
  ok "Node.js installed: $(node --version)"
fi

# ── Go ───────────────────────────────────────────────────────────────────────
step "Go ${GO_VERSION}"
if command -v go &>/dev/null && go version | grep -q "go${GO_VERSION}"; then
  ok "Go already installed: $(go version)"
else
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" \
    | tar -C /usr/local -xzf -
  ok "Go installed: $(/usr/local/go/bin/go version)"
fi

# Ensure Go is on PATH for the rest of this script and future sessions
export PATH="/usr/local/go/bin:${HOME_DIR}/go/bin:${PATH}"
export GOPATH="${HOME_DIR}/go"

# Persist Go PATH for interactive shells
PROFILE="${HOME_DIR}/.profile"
if ! grep -q '/usr/local/go/bin' "$PROFILE" 2>/dev/null; then
  cat >> "$PROFILE" <<'GOPATH_EOF'

# Go + local bin
export PATH="/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin:$PATH"
export GOPATH="$HOME/go"
GOPATH_EOF
  ok "Go PATH added to .profile"
fi
mkdir -p "${HOME_DIR}/.local/bin"

# ── npm global tools ────────────────────────────────────────────────────────
step "Claude Code, Pi, Codex (npm)"
npm install -g \
  "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
  "@mariozechner/pi-coding-agent@${PI_CODING_AGENT_VERSION}" \
  "@openai/codex@${CODEX_VERSION}" \
  2>&1 | tail -3
ok "npm tools installed"

# ── hal (from source) ───────────────────────────────────────────────────────
# In Docker, hal is built separately via COPY + make build (see Dockerfile).
# On VPS, we clone and build from GitHub.
if [ "$IN_DOCKER" = "true" ]; then
  step "hal (skipped — built separately in Docker)"
elif command -v hal &>/dev/null; then
  step "hal"
  ok "hal already installed: $(hal version 2>&1 | head -1)"
else
  step "hal (build from source)"
  HAL_BUILD_DIR="/tmp/hal-build"
  if [ -f "$(pwd)/go.mod" ] && grep -q "jywlabs/hal" "$(pwd)/go.mod" 2>/dev/null; then
    # We're inside the hal repo — build in place
    HAL_BUILD_DIR="$(pwd)"
  else
    rm -rf "$HAL_BUILD_DIR"
    git clone --depth 1 https://github.com/jywlabs/hal.git "$HAL_BUILD_DIR"
  fi
  cd "$HAL_BUILD_DIR"
  go mod download
  make build 2>&1 | tail -1
  cp hal /usr/local/bin/hal
  if [ "$HAL_BUILD_DIR" = "/tmp/hal-build" ]; then
    rm -rf "$HAL_BUILD_DIR"
  fi
  ok "hal built and installed"
fi

# ── Tailscale ────────────────────────────────────────────────────────────────
step "Tailscale"
if command -v tailscale &>/dev/null; then
  ok "Tailscale already installed: $(tailscale version | head -1)"
else
  curl -fsSL https://tailscale.com/install.sh | sh 2>&1 | tail -3
  ok "Tailscale installed: $(tailscale version | head -1)"
fi

# ── Git defaults ─────────────────────────────────────────────────────────────
step "Git config"
git config --global init.defaultBranch main
git config --global pull.rebase false
ok "Git defaults set"

# ── Configure runtime (git identity, gh auth) ───────────────────────────────
if [ -n "${GIT_USER_NAME:-}" ]; then
  git config --global user.name "$GIT_USER_NAME"
  ok "git user.name = $GIT_USER_NAME"
fi
if [ -n "${GIT_USER_EMAIL:-}" ]; then
  git config --global user.email "$GIT_USER_EMAIL"
  ok "git user.email = $GIT_USER_EMAIL"
fi

if [ -n "${GITHUB_TOKEN:-}" ]; then
  echo "$GITHUB_TOKEN" | gh auth login --with-token 2>/dev/null || true
  gh auth setup-git 2>/dev/null || true
  ok "gh authenticated"
fi

# ── Claude Code config ──────────────────────────────────────────────────────
step "Claude Code config"
# SCRIPT_DIR can be overridden (e.g. in Docker) to point at the config source
if [ -z "${SCRIPT_DIR:-}" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
CLAUDE_DIR="${HOME_DIR}/.claude"
mkdir -p "${CLAUDE_DIR}/skills" "${CLAUDE_DIR}/agents"

# Copy configs from the sandbox/claude directory if available
if [ -d "${SCRIPT_DIR}/claude" ]; then
  if [ -f "${SCRIPT_DIR}/claude/settings.json" ]; then
    cp "${SCRIPT_DIR}/claude/settings.json" "${CLAUDE_DIR}/settings.json"
    ok "settings.json"
  fi
  if [ -d "${SCRIPT_DIR}/claude/agents" ] && [ "$(ls -A "${SCRIPT_DIR}/claude/agents" 2>/dev/null)" ]; then
    cp -r "${SCRIPT_DIR}/claude/agents/"* "${CLAUDE_DIR}/agents/"
    AGENT_COUNT=$(find "${CLAUDE_DIR}/agents" -type f -name '*.md' | wc -l)
    ok "agents: ${AGENT_COUNT} files"
  fi
  if [ -d "${SCRIPT_DIR}/claude/skills" ] && [ "$(ls -A "${SCRIPT_DIR}/claude/skills" 2>/dev/null)" ]; then
    cp -r "${SCRIPT_DIR}/claude/skills/"* "${CLAUDE_DIR}/skills/"
    SKILL_COUNT=$(find "${CLAUDE_DIR}/skills" -type f -name '*.md' | wc -l)
    ok "skills: ${SKILL_COUNT} files"
  fi
else
  # Remote install — fetch configs from GitHub
  if command -v git &>/dev/null; then
    TEMP_CONF="/tmp/hal-config"
    rm -rf "$TEMP_CONF"
    git clone --depth 1 --filter=blob:none --sparse https://github.com/jywlabs/hal.git "$TEMP_CONF" 2>/dev/null
    cd "$TEMP_CONF"
    git sparse-checkout set sandbox/claude 2>/dev/null
    if [ -d sandbox/claude ]; then
      cp -r sandbox/claude/* "${CLAUDE_DIR}/" 2>/dev/null || true
      ok "Configs fetched from GitHub"
    fi
    rm -rf "$TEMP_CONF"
  fi
fi

# ── API keys reminder ───────────────────────────────────────────────────────
step "API keys"
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  ok "ANTHROPIC_API_KEY is set"
  # Persist to profile for future sessions (VPS only — never bake into Docker images)
  if [ "$IN_DOCKER" = "false" ] && ! grep -q 'ANTHROPIC_API_KEY' "$PROFILE" 2>/dev/null; then
    echo "export ANTHROPIC_API_KEY=\"${ANTHROPIC_API_KEY}\"" >> "$PROFILE"
  fi
else
  echo -e "  ${RED}⚠${NC}  ANTHROPIC_API_KEY not set — export it or add to ~/.profile"
fi
if [ -n "${OPENAI_API_KEY:-}" ]; then
  ok "OPENAI_API_KEY is set"
  if [ "$IN_DOCKER" = "false" ] && ! grep -q 'OPENAI_API_KEY' "$PROFILE" 2>/dev/null; then
    echo "export OPENAI_API_KEY=\"${OPENAI_API_KEY}\"" >> "$PROFILE"
  fi
else
  echo -e "  ${RED}⚠${NC}  OPENAI_API_KEY not set — export it or add to ~/.profile"
fi

# ── Workspace ────────────────────────────────────────────────────────────────
step "Workspace"
WORKSPACE="${HOME_DIR}/workspace"
mkdir -p "$WORKSPACE"
ok "Workspace at $WORKSPACE"

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Dev sandbox ready!${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "  Tools: go, node, gh, claude, pi, codex, hal"
echo "  Workspace: ${WORKSPACE}"
echo ""
if [ -z "${GIT_USER_NAME:-}" ]; then
  echo "  Next steps:"
  echo "    1. Set git identity:  git config --global user.name 'You'"
  echo "    2. Set API keys:      export ANTHROPIC_API_KEY=sk-ant-..."
  echo "    3. Auth GitHub:       gh auth login"
  echo ""
fi
