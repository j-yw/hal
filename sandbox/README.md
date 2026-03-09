# Hal Dev Sandbox

Docker image that mirrors the local dev environment used to build the `hal` Daytona template snapshot (`hal sandbox snapshot create`).

## What's included

| Tool | Version | Purpose |
|------|---------|---------|
| **Go** | 1.25.7 | Build hal and Go projects |
| **Node.js** | 22.x | Runtime for JS-based CLI tools |
| **gh** | 2.86.0+ | GitHub CLI |
| **Claude Code** | latest | AI coding assistant |
| **Pi** | 0.52.10 | Coding agent harness |
| **Codex** | latest | OpenAI Codex CLI |
| **hal** | built from source | This project |
| **Claude agents & skills** | from ~/.claude | Pre-configured Claude Code agents |

## Quick Start

### 1. Build the image

```bash
# From project root (native platform)
docker build -f sandbox/Dockerfile -t hal-sandbox .

# For Daytona (must be amd64)
docker build --platform=linux/amd64 -f sandbox/Dockerfile -t hal-sandbox .
```

### 2. Configure environment

```bash
cp sandbox/.env.example sandbox/.env
# Edit sandbox/.env with your API keys and git identity
```

### 3. Run & test

```bash
# Run the smoke test
docker run --rm --env-file sandbox/.env hal-sandbox /test.sh

# Interactive shell
docker run --rm -it --env-file sandbox/.env hal-sandbox

# Mount a project
docker run --rm -it --env-file sandbox/.env \
  -v $(pwd):/root/workspace \
  hal-sandbox
```

### 4. Create the template snapshot with hal

```bash
# Initialize .hal once per repo
hal init

# Configure Daytona credentials
hal sandbox setup

# Create or reuse template snapshot "hal" from sandbox/Dockerfile
hal sandbox snapshot create

# Start a sandbox from the template snapshot
hal sandbox start -n my-box
```

If you update `sandbox/Dockerfile`, refresh the template snapshot:

```bash
hal sandbox snapshot list
hal sandbox snapshot delete --id <hal-snapshot-id>
hal sandbox snapshot create
```

## Runtime Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GIT_USER_NAME` | Yes | Git commit author name |
| `GIT_USER_EMAIL` | Yes | Git commit author email |
| `ANTHROPIC_API_KEY` | For Claude | Anthropic API key |
| `OPENAI_API_KEY` | For Codex | OpenAI API key |
| `GITHUB_TOKEN` | For gh | GitHub personal access token |

These are injected at runtime via `--env-file` or `-e` flags — **never baked into the image**.

## SSH Keys (optional)

Mount your SSH keys for git operations over SSH:

```bash
docker run --rm -it \
  --env-file sandbox/.env \
  -v ~/.ssh:/root/.ssh:ro \
  hal-sandbox
```

## Updating

When tools change version, update the `ARG` lines in `sandbox/Dockerfile` and rebuild:

```dockerfile
ARG GO_VERSION=1.25.7      # ← update Go version
ARG NODE_MAJOR=22           # ← update Node major version
```

To update Claude agents/skills, re-copy from your home directory:

```bash
cp -r ~/.claude/agents/* sandbox/claude/agents/
cp -r ~/.claude/skills/* sandbox/claude/skills/
cp ~/.claude/settings.json sandbox/claude/settings.json
```
