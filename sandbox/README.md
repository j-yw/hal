# Dev Sandbox

Portable dev environment you can spin up anywhere — Daytona, any VPS, GitHub Codespaces — and SSH into from your phone.

## What's included

| Tool | Version | Purpose |
|------|---------|---------|
| **Go** | 1.25.7 | Build hal and Go projects |
| **Node.js** | 22.x | Runtime for JS-based CLI tools |
| **gh** | latest | GitHub CLI (authenticated via GITHUB_TOKEN) |
| **Claude Code** | 2.1.42 | AI coding assistant |
| **Pi** | 0.52.10 | Coding agent harness |
| **Codex** | 0.101.0 | OpenAI Codex CLI |
| **hal** | built from source | This project |
| **tmux** | latest | Terminal multiplexer (keep sessions alive) |
| **ripgrep** | latest | Fast search |
| **vim** | latest | Editor |
| Claude agents & skills | from sandbox/claude/ | Pre-configured Claude Code agents |

## Quick Start

### Option 1: Any VPS (DigitalOcean, Hetzner, AWS, etc.)

SSH into a fresh Ubuntu 22.04+ machine and run:

```bash
curl -fsSL https://raw.githubusercontent.com/jywlabs/hal/main/sandbox/setup.sh | bash
```

With environment variables (recommended):

```bash
export GIT_USER_NAME="j-yw"
export GIT_USER_EMAIL="32629001+j-yw@users.noreply.github.com"
export GITHUB_TOKEN="ghp_..."
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
curl -fsSL https://raw.githubusercontent.com/jywlabs/hal/main/sandbox/setup.sh | bash
```

### Option 2: Daytona (pre-baked snapshot)

```bash
# First time — create the snapshot
hal sandbox snapshot create

# Spin up a sandbox
hal sandbox start -n my-dev

# SSH in
daytona ssh my-dev
```

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

For Docker/Daytona: pass via `--env-file sandbox/.env` or `-e KEY=VALUE`.

```bash
cp sandbox/.env.example sandbox/.env
# Edit sandbox/.env with your values
```

## SSH from Phone

1. **Create a VPS** or Daytona sandbox
2. **Add your phone's SSH key** to `~/.ssh/authorized_keys` on the machine
3. **Use a mobile SSH client**:
   - **iOS**: [Blink Shell](https://blink.sh) or [Termius](https://termius.com)
   - **Android**: [Termux](https://termux.dev) or [JuiceSSH](https://juicessh.com)
4. **Use tmux** so sessions survive disconnects:
   ```bash
   tmux new -s work     # start
   tmux a -t work       # reattach after reconnect
   ```

### Daytona SSH shortcut

```bash
# From any machine with daytona CLI installed
daytona ssh my-dev
```

## Version Pinning

Tool versions are pinned in `setup.sh` and can be overridden via env vars:

```bash
GO_VERSION=1.25.7 NODE_MAJOR=22 ./sandbox/setup.sh
```

The Dockerfile passes these as build args but delegates installation to `setup.sh` — **one source of truth**.

## Updating Tools

1. Edit the version pins at the top of `sandbox/setup.sh`
2. For VPS: re-run `setup.sh` (it's idempotent)
3. For Daytona: rebuild the snapshot:
   ```bash
   hal sandbox snapshot delete --id <old-id>
   hal sandbox snapshot create
   ```

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
Dockerfile        ← Pre-baked image (for Daytona snapshots / Docker)
entrypoint.sh     ← Runtime config (git identity, gh auth, SSH agent)
test.sh           ← Smoke tests (verify all tools present)
claude/           ← Claude Code settings, agents, skills
.env.example      ← Secrets template
```

`setup.sh` is the single source of truth. The Dockerfile calls it internally.
Both paths produce the exact same environment.
