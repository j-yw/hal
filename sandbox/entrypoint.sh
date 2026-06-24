#!/usr/bin/env bash
set -euo pipefail

export HOME="${HOME:-/root}"

# ── Git identity (from env vars) ─────────────────────────────────────────────
if [ -n "${GIT_USER_NAME:-}" ]; then
  git config --global user.name "$GIT_USER_NAME"
fi
if [ -n "${GIT_USER_EMAIL:-}" ]; then
  git config --global user.email "$GIT_USER_EMAIL"
fi

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

# ── GitHub CLI auth (from GITHUB_TOKEN/GH_TOKEN env var) ─────────────────────
TOKEN="$(github_token)"
if [ -n "$TOKEN" ]; then
  if ! printf '%s' "$TOKEN" | env -u GITHUB_TOKEN -u GH_TOKEN gh auth login --with-token 2>/dev/null; then
    env -u GITHUB_TOKEN -u GH_TOKEN gh auth status >/dev/null 2>&1 || true
  fi
  env -u GITHUB_TOKEN -u GH_TOKEN gh auth status >/dev/null 2>&1 && env -u GITHUB_TOKEN -u GH_TOKEN gh auth setup-git 2>/dev/null || true
  ensure_git_instead_of "https://github.com/" "git@github.com:"
  ensure_git_instead_of "https://github.com/" "ssh://git@github.com/"
fi
unset TOKEN

# ── SSH agent (if keys are mounted) ──────────────────────────────────────────
if [ -d /root/.ssh ] && ls /root/.ssh/id_* 1>/dev/null 2>&1; then
  eval "$(ssh-agent -s)" > /dev/null 2>&1
  ssh-add /root/.ssh/id_* 2>/dev/null || true
fi

# ── Tailscale (connect to your tailnet for SSH from phone) ───────────────────
if command -v tailscaled &>/dev/null && [ -n "${TAILSCALE_AUTHKEY:-}" ]; then
  # Start tailscaled in userspace mode (works in containers without TUN device)
  tailscaled --tun=userspace-networking --statedir=/var/lib/tailscale &>/dev/null &
  sleep 2
  # Connect with SSH enabled — the authkey auto-authenticates
  tailscale up --authkey="$TAILSCALE_AUTHKEY" --ssh --hostname="${TAILSCALE_HOSTNAME:-hal-sandbox}" 2>/dev/null || true
  TS_IP=$(tailscale ip -4 2>/dev/null || true)
  if [ -n "$TS_IP" ]; then
    echo "Tailscale connected: $TS_IP (ssh root@$TS_IP)"
  fi
fi

# ── Pass through to CMD ─────────────────────────────────────────────────────
exec "$@"
