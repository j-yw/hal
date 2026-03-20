#!/usr/bin/env bash
set -euo pipefail

# ── Git identity (from env vars) ─────────────────────────────────────────────
if [ -n "${GIT_USER_NAME:-}" ]; then
  git config --global user.name "$GIT_USER_NAME"
fi
if [ -n "${GIT_USER_EMAIL:-}" ]; then
  git config --global user.email "$GIT_USER_EMAIL"
fi

# ── GitHub CLI auth (from GITHUB_TOKEN env var) ──────────────────────────────
if [ -n "${GITHUB_TOKEN:-}" ]; then
  echo "$GITHUB_TOKEN" | gh auth login --with-token 2>/dev/null || true
  gh auth setup-git 2>/dev/null || true
fi

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
