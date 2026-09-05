#!/usr/bin/env bash
# =============================================================================
# Universal Dev Sandbox Bootstrap
# =============================================================================
# Installs all dev tools on any fresh Ubuntu/Debian machine.
# Idempotent — safe to run multiple times.
#
# Usage (remote):
#   curl -fsSL https://raw.githubusercontent.com/ReScienceLab/hal/main/sandbox/setup.sh | bash
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
CLAUDE_CODE_VERSION="${CLAUDE_CODE_VERSION:-2.1.207}"
PI_CODING_AGENT_VERSION="${PI_CODING_AGENT_VERSION:-0.80.6}"
CODEX_VERSION="${CODEX_VERSION:-0.144.1}"

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

step()  { echo -e "\n${CYAN}${BOLD}── $1 ──${NC}"; }
ok()    { echo -e "  ${GREEN}✓${NC} $1"; }
fail()  { echo -e "  ${RED}✗${NC} $1"; }

curl_retry() {
  curl --retry 5 --retry-delay 2 --retry-all-errors --connect-timeout 30 "$@"
}

download_retry() {
  local url="$1"
  local destination="$2"
  if curl_retry -fsSL "$url" -o "$destination"; then
    return 0
  fi
  rm -f "$destination"
  echo "  curl download failed; retrying with wget" >&2
  wget --tries=5 --timeout=30 --retry-connrefused -qO "$destination" "$url"
}

install_github_cli_repo() {
  local keyring_tmp
  keyring_tmp="$(mktemp)"
  if ! download_retry https://cli.github.com/packages/githubcli-archive-keyring.gpg "$keyring_tmp"; then
    rm -f "$keyring_tmp"
    return 1
  fi
  install -m 0644 "$keyring_tmp" /usr/share/keyrings/githubcli-archive-keyring.gpg
  rm -f "$keyring_tmp"
  echo "deb [arch=${ARCH} signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    > /etc/apt/sources.list.d/github-cli.list
  if apt-get update -qq && apt-get install -y --no-install-recommends gh 2>&1 | tail -1; then
    rm -rf /var/lib/apt/lists/*
    return 0
  fi
  rm -f /etc/apt/sources.list.d/github-cli.list
  rm -f /usr/share/keyrings/githubcli-archive-keyring.gpg
  return 1
}

install_github_cli_distro() {
  rm -f /etc/apt/sources.list.d/github-cli.list
  apt-get update -qq
  apt-get install -y --no-install-recommends gh 2>&1 | tail -1
  rm -rf /var/lib/apt/lists/*
}

install_nodesource_node() {
  local setup_tmp
  setup_tmp="$(mktemp)"
  if ! download_retry "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" "$setup_tmp"; then
    rm -f "$setup_tmp"
    return 1
  fi
  if ! bash "$setup_tmp"; then
    rm -f "$setup_tmp"
    return 1
  fi
  rm -f "$setup_tmp"
  if ! apt-get install -y --no-install-recommends nodejs 2>&1 | tail -1; then
    return 1
  fi
  rm -rf /var/lib/apt/lists/*
  node --version | grep -q "^v${NODE_MAJOR}\."
}

install_nodejs_archive() {
  local node_arch archive archive_dir checksums checksum_line
  case "$ARCH" in
    amd64) node_arch=x64 ;;
    arm64) node_arch=arm64 ;;
    *)
      echo "unsupported Node.js archive architecture: $ARCH" >&2
      return 1
      ;;
  esac
  rm -f /etc/apt/sources.list.d/nodesource.list
  rm -f /usr/share/keyrings/nodesource.gpg /etc/apt/keyrings/nodesource.gpg
  archive_dir="$(mktemp -d)"
  checksums="$archive_dir/SHASUMS256.txt"
  if ! download_retry "https://nodejs.org/dist/latest-v${NODE_MAJOR}.x/SHASUMS256.txt" "$checksums"; then
    rm -rf "$archive_dir"
    return 1
  fi
  archive="$(awk -v suffix="linux-${node_arch}.tar.gz" '$2 ~ suffix "$" { print $2; exit }' "$checksums")"
  if [ -z "$archive" ]; then
    echo "Node.js checksum manifest has no linux-${node_arch} archive" >&2
    rm -rf "$archive_dir"
    return 1
  fi
  if ! download_retry "https://nodejs.org/dist/latest-v${NODE_MAJOR}.x/${archive}" "$archive_dir/$archive"; then
    rm -rf "$archive_dir"
    return 1
  fi
  checksum_line="$(grep -F "  $archive" "$checksums")"
  if [ -z "$checksum_line" ] || ! (cd "$archive_dir" && printf '%s\n' "$checksum_line" | sha256sum -c -); then
    rm -rf "$archive_dir"
    return 1
  fi
  tar -C /usr/local --strip-components=1 -xzf "$archive_dir/$archive"
  rm -rf "$archive_dir"
}

install_agent_clis() {
  local attempt
  for attempt in 1 2 3; do
    if npm install -g --no-audit --no-fund \
      --fetch-retries=5 \
      --fetch-retry-factor=2 \
      --fetch-retry-mintimeout=10000 \
      --fetch-retry-maxtimeout=60000 \
      "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
      "@earendil-works/pi-coding-agent@${PI_CODING_AGENT_VERSION}" \
      "@openai/codex@${CODEX_VERSION}"; then
      return 0
    fi
    if [ "$attempt" -lt 3 ]; then
      echo "  npm agent CLI install failed; retrying ($attempt/3)" >&2
      sleep $((attempt * 5))
    fi
  done
  return 1
}

install_tailscale_repo() {
  local distro_id distro_codename repo_base repo_tmp key_tmp
  distro_id="$(. /etc/os-release && printf '%s' "$ID")"
  distro_codename="$(. /etc/os-release && printf '%s' "$VERSION_CODENAME")"
  if [ -z "$distro_id" ] || [ -z "$distro_codename" ]; then
    echo "cannot determine distribution for Tailscale repository" >&2
    return 1
  fi
  repo_base="https://pkgs.tailscale.com/stable/${distro_id}/${distro_codename}"
  key_tmp="$(mktemp)"
  repo_tmp="$(mktemp)"
  if ! download_retry "${repo_base}.noarmor.gpg" "$key_tmp" || \
     ! download_retry "${repo_base}.tailscale-keyring.list" "$repo_tmp"; then
    rm -f "$key_tmp" "$repo_tmp"
    return 1
  fi
  install -m 0644 "$key_tmp" /usr/share/keyrings/tailscale-archive-keyring.gpg
  install -m 0644 "$repo_tmp" /etc/apt/sources.list.d/tailscale.list
  rm -f "$key_tmp" "$repo_tmp"
  apt-get update -qq
  apt-get install -y --no-install-recommends tailscale 2>&1 | tail -1
  rm -rf /var/lib/apt/lists/*
}

HAL_REPO="${HAL_REPO:-ReScienceLab/hal}"
HAL_REPO_REF="${HAL_REPO_REF:-}"
HAL_REPO_URL_EXPLICIT="${HAL_REPO_URL+x}"
HAL_REPO_URL="${HAL_REPO_URL:-https://github.com/${HAL_REPO}.git}"

github_token() {
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    printf '%s' "$GITHUB_TOKEN"
  elif [ -n "${GH_TOKEN:-}" ]; then
    printf '%s' "$GH_TOKEN"
  fi
}

ensure_git_instead_of() {
  local base="$1"
  local value="$2"
  if ! git config --global --get-all "url.${base}.insteadOf" 2>/dev/null | grep -Fx "$value" >/dev/null; then
    git config --global --add "url.${base}.insteadOf" "$value"
  fi
}

configure_github_auth() {
  local token
  token="$(github_token)"
  if [ -z "$token" ]; then
    return 0
  fi

  if command -v gh &>/dev/null; then
    if ! printf '%s' "$token" | env -u GITHUB_TOKEN -u GH_TOKEN gh auth login --with-token 2>/dev/null; then
      env -u GITHUB_TOKEN -u GH_TOKEN gh auth status >/dev/null 2>&1 || true
    fi
    env -u GITHUB_TOKEN -u GH_TOKEN gh auth status >/dev/null 2>&1 && env -u GITHUB_TOKEN -u GH_TOKEN gh auth setup-git 2>/dev/null || true
  fi

  # Factory bootstrap may clone SSH-style GitHub remotes. Rewrite those to
  # HTTPS so gh's credential helper can provide the token non-interactively.
  ensure_git_instead_of "https://github.com/" "git@github.com:"
  ensure_git_instead_of "https://github.com/" "ssh://git@github.com/"
}

is_github_https_repo_url() {
  case "$1" in
    https://github.com/*|https://www.github.com/*) return 0 ;;
    *) return 1 ;;
  esac
}

clone_hal_repo() {
  local dest="$1"
  shift || true
  local clone_args=("$@")
  if [ -n "$HAL_REPO_REF" ]; then
    clone_args+=(--branch "$HAL_REPO_REF")
  fi
  local token
  token="$(github_token)"

  if [ -n "$token" ]; then
    configure_github_auth

    if [ -z "$HAL_REPO_URL_EXPLICIT" ] && command -v gh &>/dev/null; then
      if gh repo clone "$HAL_REPO" "$dest" -- "${clone_args[@]}" 2>/dev/null; then
        return 0
      fi
    fi

    if ! is_github_https_repo_url "$HAL_REPO_URL"; then
      git clone "${clone_args[@]}" "$HAL_REPO_URL" "$dest"
      return $?
    fi

    local askpass status
    askpass="$(mktemp)"
    chmod 700 "$askpass"
    cat > "$askpass" <<'EOF'
#!/usr/bin/env sh
case "$1" in
  *Username*) printf '%s\n' 'x-access-token' ;;
  *) printf '%s\n' "$GITHUB_TOKEN" ;;
esac
EOF
    if GITHUB_TOKEN="$token" GIT_ASKPASS="$askpass" GIT_TERMINAL_PROMPT=0 git clone "${clone_args[@]}" "$HAL_REPO_URL" "$dest"; then
      status=0
    else
      status=$?
    fi
    rm -f "$askpass"
    return "$status"
  fi

  git clone "${clone_args[@]}" "$HAL_REPO_URL" "$dest"
}

# ── Detect environment ───────────────────────────────────────────────────────
IN_DOCKER="${IN_DOCKER:-false}"
if [ -f /.dockerenv ]; then
  IN_DOCKER="true"
fi

ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
export HOME="${HOME:-/root}"
HOME_DIR="$HOME"
# SCRIPT_DIR can be overridden (e.g. in Docker) to point at the config source.
# Resolve it before any cd so relative local invocations keep pointing at this repo.
if [ -z "${SCRIPT_DIR:-}" ]; then
  if [ -n "${BASH_SOURCE[0]:-}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  else
    SCRIPT_DIR="$(pwd)"
  fi
fi

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
  if ! install_github_cli_repo; then
    echo "  GitHub CLI repository unavailable; falling back to the distro package" >&2
    install_github_cli_distro
  fi
  ok "gh installed: $(gh --version | head -1)"
fi

# ── Node.js ──────────────────────────────────────────────────────────────────
step "Node.js ${NODE_MAJOR}.x"
if command -v node &>/dev/null && node --version | grep -q "v${NODE_MAJOR}\."; then
  ok "Node.js already installed: $(node --version)"
else
  if ! install_nodesource_node; then
    echo "  NodeSource unavailable; falling back to the verified official Node.js archive" >&2
    install_nodejs_archive
  fi
  ok "Node.js installed: $(node --version)"
fi

# ── Go ───────────────────────────────────────────────────────────────────────
step "Go ${GO_VERSION}"
if command -v go &>/dev/null && go version | grep -q "go${GO_VERSION}"; then
  ok "Go already installed: $(go version)"
else
  GO_ARCHIVE="$(mktemp)"
  download_retry "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" "$GO_ARCHIVE"
  tar -C /usr/local -xzf "$GO_ARCHIVE"
  rm -f "$GO_ARCHIVE"
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
install_agent_clis
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
    clone_hal_repo "$HAL_BUILD_DIR" --depth 1
  fi
  cd "$HAL_BUILD_DIR"
  go mod download
  make build 2>&1 | tail -1
  cp hal /usr/local/bin/hal
  cd "$HOME_DIR"
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
  install_tailscale_repo
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
  configure_github_auth
  ok "gh authenticated"
elif [ -n "${GH_TOKEN:-}" ]; then
  configure_github_auth
  ok "gh authenticated"
fi

# ── Claude Code config ──────────────────────────────────────────────────────
step "Claude Code config"
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
    clone_hal_repo "$TEMP_CONF" --depth 1 --filter=blob:none --sparse
    cd "$TEMP_CONF"
    git sparse-checkout set sandbox/claude 2>/dev/null
    if [ -d sandbox/claude ]; then
      cp -r sandbox/claude/* "${CLAUDE_DIR}/" 2>/dev/null || true
      ok "Configs fetched from GitHub"
    fi
    cd "$HOME_DIR"
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
