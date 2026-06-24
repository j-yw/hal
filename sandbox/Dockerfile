# =============================================================================
# Hal Dev Sandbox — mirrors the local dev environment for Daytona snapshots
# =============================================================================
# Build (local/native):  docker build -f sandbox/Dockerfile -t hal-sandbox .
# Build (Daytona/amd64): docker build --platform=linux/amd64 -f sandbox/Dockerfile -t hal-sandbox .
# Run:                    docker run --rm -it --env-file sandbox/.env hal-sandbox
# =============================================================================

FROM ubuntu:22.04

# -- Build args (override version pins from setup.sh if needed) ---------------
ARG GO_VERSION=1.25.7
ARG NODE_MAJOR=22
ARG CLAUDE_CODE_VERSION=2.1.42
ARG PI_CODING_AGENT_VERSION=0.52.10
ARG CODEX_VERSION=0.101.0
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

ENV DEBIAN_FRONTEND=noninteractive
ENV IN_DOCKER=true

# -- Copy setup script and configs first (for layer caching) ------------------
COPY sandbox/setup.sh /setup.sh
COPY sandbox/claude/  /tmp/sandbox/claude/
RUN chmod +x /setup.sh

# -- Run the universal bootstrap (installs everything except hal) -------------
ENV GO_VERSION=${GO_VERSION}
ENV NODE_MAJOR=${NODE_MAJOR}
ENV CLAUDE_CODE_VERSION=${CLAUDE_CODE_VERSION}
ENV PI_CODING_AGENT_VERSION=${PI_CODING_AGENT_VERSION}
ENV CODEX_VERSION=${CODEX_VERSION}
# Point setup.sh at the copied configs (SCRIPT_DIR tells it where claude/ lives)
RUN SCRIPT_DIR=/tmp/sandbox /setup.sh

# -- Build hal from source (Docker-specific — uses COPY context) --------------
# Go was installed by setup.sh — set PATH so subsequent RUN steps find it
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"
WORKDIR /tmp/hal-build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make build VERSION="${VERSION}" COMMIT="${COMMIT}" BUILD_DATE="${BUILD_DATE}" \
    && cp hal /usr/local/bin/hal

# -- Cleanup build tree -------------------------------------------------------
RUN rm -rf /tmp/hal-build /tmp/sandbox

# -- Workspace ----------------------------------------------------------------
WORKDIR /root/workspace

# -- Test & entrypoint scripts ------------------------------------------------
COPY sandbox/test.sh /test.sh
COPY sandbox/entrypoint.sh /entrypoint.sh
RUN chmod +x /test.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]
