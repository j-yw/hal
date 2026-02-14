# =============================================================================
# Hal Dev Sandbox — mirrors the local dev environment for Daytona snapshots
# =============================================================================
# Build (local/native):  docker build -f sandbox/Dockerfile -t hal-sandbox .
# Build (Daytona/amd64): docker build --platform=linux/amd64 -f sandbox/Dockerfile -t hal-sandbox .
# Run:                    docker run --rm -it --env-file sandbox/.env hal-sandbox
# =============================================================================

FROM ubuntu:22.04

# -- Build args (pin versions to match local machine) ------------------------
ARG GO_VERSION=1.25.7
ARG NODE_MAJOR=22

ENV DEBIAN_FRONTEND=noninteractive

# -- System packages ----------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    gnupg \
    jq \
    make \
    openssh-client \
    sudo \
    unzip \
    wget \
    && rm -rf /var/lib/apt/lists/*

# -- GitHub CLI ---------------------------------------------------------------
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
      | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

# -- Node.js (v22.x via NodeSource) ------------------------------------------
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# -- Go (from official tarball) -----------------------------------------------
RUN ARCH=$(dpkg --print-architecture) \
    && curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" \
       | tar -C /usr/local -xzf -
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# -- npm global tools: Claude Code, Pi, Codex --------------------------------
RUN npm install -g \
    @anthropic-ai/claude-code@latest \
    @mariozechner/pi-coding-agent@0.52.10 \
    @openai/codex@latest

# -- Build hal from source ----------------------------------------------------
WORKDIR /tmp/hal-build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make build \
    && cp hal /usr/local/bin/hal

# -- Claude Code configuration ------------------------------------------------
# Copy from build context (not /tmp/hal-build) — done before cleanup
RUN mkdir -p /root/.claude/skills /root/.claude/agents
COPY sandbox/claude/settings.json /root/.claude/settings.json
COPY sandbox/claude/agents/        /root/.claude/agents/
# Skills dir may be empty; use a wildcard to avoid COPY failure
COPY sandbox/claude/skill[s]/ /root/.claude/skills/

# -- Cleanup build tree -------------------------------------------------------
RUN rm -rf /tmp/hal-build

# -- Git defaults (user.name & user.email set at runtime via entrypoint) ------
RUN git config --global init.defaultBranch main \
    && git config --global pull.rebase false

# -- Workspace ----------------------------------------------------------------
WORKDIR /root/workspace

# -- Test & entrypoint scripts ------------------------------------------------
COPY sandbox/test.sh /test.sh
COPY sandbox/entrypoint.sh /entrypoint.sh
RUN chmod +x /test.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]
