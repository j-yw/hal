# Dev Sandbox

Portable dev environment you can run on Hetzner, DigitalOcean, AWS Lightsail,
a registered worker host, local Podman, Docker, or GitHub Codespaces.

## What's included

| Tool | Version | Purpose |
|------|---------|---------|
| **Go** | 1.25.7 | Build hal and Go projects |
| **Node.js** | 22.x | Runtime for JS-based CLI tools |
| **gh** | repository-selected (distro fallback) | GitHub CLI (authenticated via GITHUB_TOKEN) |
| **Claude Code** | 2.1.207 | AI coding assistant |
| **Pi** | 0.85.0 | Coding agent harness |
| **Codex** | 0.144.1 | OpenAI Codex CLI |
| **hal** | built from source | This project |
| **tmux** | distro package | Terminal multiplexer (keep sessions alive) |
| **ripgrep** | distro package | Fast search |
| **vim** | distro package | Editor |
| Claude agents & skills | from sandbox/claude/ | Pre-configured Claude Code agents |

## Quick Start

### Option 1: Cloud VPS (Hetzner, DigitalOcean, or AWS Lightsail)

SSH into a fresh Ubuntu 22.04+ machine and run:

```bash
curl -fsSL https://raw.githubusercontent.com/ReScienceLab/hal/main/sandbox/setup.sh | bash
```

With environment variables (recommended):

```bash
export GIT_USER_NAME="j-yw"
export GIT_USER_EMAIL="32629001+j-yw@users.noreply.github.com"
export GITHUB_TOKEN="ghp_..."
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
curl -fsSL https://raw.githubusercontent.com/ReScienceLab/hal/main/sandbox/setup.sh | bash
```

### Option 2: Rootless Podman lab

Linux uses native rootless Podman with isolated lab storage. macOS and explicit
`HAL_SANDBOX_LAB_PODMAN_MODE=machine` runs use a named Podman machine.

```bash
make sandbox-lab-prepare
make sandbox-lab-start
./sandbox/podman-lab.sh run -- hal sandbox host status hal-lab-worker --live
make sandbox-lab-destroy
```

See [TESTING.md](TESTING.md) for the contained lab workflow and cleanup rules.

### Option 3: Docker (local testing)

```bash
# Build
docker build -f sandbox/Dockerfile -t hal-sandbox .

# Run smoke tests
docker run --rm hal-sandbox /test.sh

# Interactive shell
docker run --rm -it --env-file sandbox/.env hal-sandbox
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GIT_USER_NAME` | Yes | Git commit author name |
| `GIT_USER_EMAIL` | Yes | Git commit author email |
| `GITHUB_TOKEN` | For gh | GitHub personal access token |
| `ANTHROPIC_API_KEY` | For Claude | Anthropic API key |
| `OPENAI_API_KEY` | For Codex | OpenAI API key |

For VPS: set these before running `setup.sh` — they'll be persisted to `~/.profile`.

For Docker: pass values via `--env-file sandbox/.env` or `-e KEY=VALUE`.
For the contained Podman lab, use `sandbox/podman-lab.sh seed-auth` so copied
credentials stay inside the disposable lab root.

```bash
cp sandbox/.env.example sandbox/.env
# Edit sandbox/.env with your values
```

## SSH from Phone

1. **Create a supported cloud VPS** or register a worker host
2. **Add your phone's SSH key** to `~/.ssh/authorized_keys` on the machine
3. **Use a mobile SSH client**:
   - **iOS**: [Blink Shell](https://blink.sh) or [Termius](https://termius.com)
   - **Android**: [Termux](https://termux.dev) or [JuiceSSH](https://juicessh.com)
4. **Use tmux** so sessions survive disconnects:
   ```bash
   tmux new -s work     # start
   tmux a -t work       # reattach after reconnect
   ```

## Version Defaults

AI CLI tools use the exact versions in the table above, not the latest npm release.
Pi 0.85.0 matches the host version exercised in the native Linux rootless game
smoke, including its xAI OAuth provider. Other agent pins are unchanged. Override
versions explicitly with environment variables for direct bootstrap:

```bash
PI_CODING_AGENT_VERSION=0.85.0 ./sandbox/setup.sh
```

For image builds, use `--build-arg PI_CODING_AGENT_VERSION=0.85.0` (or the
corresponding variable for another tool). The Dockerfile passes its build-argument
defaults to `setup.sh`; deterministic Go tests keep both sets of defaults aligned.
Node is pinned only to major 22, and OS packages are repository-selected, so the
complete image is not a fully locked dependency snapshot. `/test.sh` reports tool
versions and smoke-tests availability; it does not enforce exact version pins.

## Updating Tools

1. For VPS: re-run `setup.sh` to install the selected defaults, or pass explicit version environment variables.
2. For Docker or Podman: rebuild with explicit build arguments, or update the defaults in both `setup.sh` and `Dockerfile` and their regression test.

## Updating Claude Agents & Skills

```bash
cp -r ~/.claude/agents/* sandbox/claude/agents/
cp -r ~/.claude/skills/* sandbox/claude/skills/
cp ~/.claude/settings.json sandbox/claude/settings.json
```

Then re-run `setup.sh` or rebuild the Docker image.

## Architecture

```
setup.sh          ← Universal bootstrap (the ONE script)
  ↑ used by
Dockerfile        ← Portable Docker/Podman image
entrypoint.sh     ← Runtime config (git identity, gh auth, SSH agent)
test.sh           ← Smoke tests (verify all tools present)
claude/           ← Claude Code settings, agents, skills
.env.example      ← Secrets template
```

`setup.sh` owns the shared installation logic. The Dockerfile calls it internally
with matching version defaults; container and VPS runtime setup still differ.
