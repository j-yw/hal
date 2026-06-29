# Next-Generation Sandbox Architecture for Cloud Coding Agents

**Status**: Proposed
**Date**: 2026-06-29
**Scope**: Architecture proposal only. This document does not change runtime behavior, command behavior, storage formats, or machine-readable CLI contracts.

## Executive Summary

Hal should not add Docker as just another `internal/sandbox.Provider`.
The current provider interface models one sandbox as one remotely managed
machine, and it combines infrastructure provisioning, runtime lifecycle,
execution, copy, and status into one boundary. That model works for Daytona
and one-VPS-per-sandbox providers, but it does not describe the architecture Hal
needs next: one or more self-hosted sandbox hosts running many isolated agent
sandboxes through Docker, Podman, gVisor, Kata, Firecracker, or equivalent
runtimes.

The recommended architecture is a layered model:

1. `HostProvider`: provisions or registers sandbox hosts, such as local host,
   SSH host, Hetzner, DigitalOcean, Lightsail, or future bare-metal pools.
2. `RuntimeProvider`: creates execution environments on a host, such as legacy
   SSH machine, Docker container, Podman container, gVisor sandboxed container,
   Kata container, Firecracker microVM, or an optional Docker `sbx`-compatible
   runtime.
3. `ExecutionTransport`: executes commands and streams output in an environment.
   Examples: SSH exec, Docker exec, Podman exec, `nsenter`, Firecracker agent
   exec, or a small Hal runtime agent over SSH.
4. `WorkspaceSyncer`: moves repository state in and changes out. Examples:
   remote clone, existing `BootstrapWorkspace`, git bundle sync, tar copy,
   patch/diff extraction, or read-only mount plus in-sandbox clone.
5. `SandboxScheduler`: assigns factory runs to sandbox hosts using capacity,
   labels, runtime support, policy, leases, TTL, and cleanup constraints.

Existing VPS sandboxes remain supported by adapting each current cloud provider
to `HostProvider + SSHMachineRuntime`. New Docker/Podman support should be
implemented as `RuntimeProvider` running on a selected host, not as a peer of
Hetzner or DigitalOcean. This lets Hal preserve current user workflows while
making shared sandbox hosts, stronger isolation, and future control-plane
scheduling possible.

## Research Sources

Local Hal sources reviewed:

- `internal/sandbox/*`
- `cmd/sandbox*.go`
- `cmd/factory_sandbox_executor.go`
- `internal/factory/bootstrap*.go`
- `internal/factory/policy*.go`
- `internal/factory/secrets.go`
- `internal/factory/sandbox_artifacts.go`
- `docs/design/multi-sandbox.md`
- `docs/adr/0001-hal-future-team-organization-factory-control-plane.md`
- `docs/contracts/sandbox-list-v1.md`
- `docs/contracts/factory-run-v1.md`
- `docs/contracts/factory-status-v1.md`

External references:

- Sandcastle repository: <https://github.com/mattpocock/sandcastle>
  - Local checkout reviewed at `73f15d1`, matching `origin/main` after fetch.
- Sandcastle provider and sync files:
  - <https://github.com/mattpocock/sandcastle/blob/main/src/SandboxProvider.ts>
  - <https://github.com/mattpocock/sandcastle/blob/main/src/DockerLifecycle.ts>
  - <https://github.com/mattpocock/sandcastle/blob/main/src/sandboxes/docker.ts>
  - <https://github.com/mattpocock/sandcastle/blob/main/src/sandboxes/vercel.ts>
  - <https://github.com/mattpocock/sandcastle/blob/main/src/startSandbox.ts>
  - <https://github.com/mattpocock/sandcastle/blob/main/src/SandboxFactory.ts>
  - <https://github.com/mattpocock/sandcastle/blob/main/src/syncIn.ts>
  - <https://github.com/mattpocock/sandcastle/blob/main/src/syncOut.ts>
- Docker Sandboxes documentation:
  - <https://docs.docker.com/ai/sandboxes/>
  - <https://docs.docker.com/ai/sandboxes/architecture/>
  - <https://docs.docker.com/ai/sandboxes/security/>
  - <https://docs.docker.com/ai/sandboxes/security/defaults/>
  - <https://docs.docker.com/ai/sandboxes/security/isolation/>
  - <https://docs.docker.com/ai/sandboxes/security/credentials/>
  - <https://docs.docker.com/ai/sandboxes/governance/local/>
  - <https://docs.docker.com/ai/sandboxes/governance/org/>
  - <https://docs.docker.com/ai/sandboxes/agents/>
  - <https://docs.docker.com/ai/sandboxes/workflows/>
  - <https://docs.docker.com/ai/sandboxes/usage/>
  - <https://docs.docker.com/ai/sandboxes/customize/kits/>
  - <https://docs.docker.com/ai/sandboxes/customize/templates/>

Docker Sandboxes and Vercel are used here as architectural references, not as
required dependencies.

## 1. Current State of Hal Sandbox and Factory Architecture

### Sandbox Model

Hal currently has a single sandbox provider abstraction in
`internal/sandbox/provider.go`:

- `Create(ctx, name, env, out)` provisions a sandbox and streams provider output.
- `Start`, `Stop`, `Delete`, and `Status` manage lifecycle.
- `SSH(info)` and `Exec(info, args)` return executable commands for interactive
  shell or non-interactive command execution.
- `ProviderFromConfig` chooses between `daytona`, `hetzner`, `digitalocean`, and
  `lightsail`.

The abstraction treats the sandbox as a machine-like target. Provider
implementations shell out to provider CLIs such as `daytona`, `hcloud`,
`doctl`, and `aws lightsail`, then use SSH for most non-Daytona execution. This
keeps dependencies small and testable but means one interface owns too many
responsibilities: cloud provisioning, machine lifecycle, network addressing,
remote command transport, and copy-adjacent behavior.

Sandbox state is persisted as JSON:

- Project legacy state: `.hal/sandbox.json`
- Global registry: `$HAL_CONFIG_HOME/sandboxes/<name>.json`,
  `$XDG_CONFIG_HOME/hal/sandboxes/<name>.json`, or
  `$HOME/.config/hal/sandboxes/<name>.json`

`SandboxState` currently contains:

- Identity: `id`, `name`
- Provider: `provider`, `workspaceId`
- Network: `ip`, `tailscaleIp`, `tailscaleHostname`, `tailscaleLockdown`
- Lifecycle: `status`, `createdAt`, `stoppedAt`
- Config and cost hints: `autoShutdown`, `idleHours`, `size`
- Labels: `repo`, `snapshotId`

The global registry supports multiple sandboxes, default resolution, staged
delete recovery, atomic file writes, and per-file JSON state. Human output
redacts raw IPs by default; JSON contracts intentionally expose raw network
fields when present.

### Sandbox CLI

`cmd/sandbox*.go` implements:

- `hal sandbox setup` for global provider config and env values.
- `hal sandbox create` for provisioning one or many sandboxes, injecting env
  and auto-shutdown configuration.
- `hal sandbox list --json` using `sandbox-list-v1`.
- `hal sandbox start`, `stop`, `status`, `delete`, `ssh`, `auth`, and migration
  helpers.

The CLI already has several patterns that should be preserved:

- Global sandbox config wins over legacy project-local config.
- Runtime side effects are behind injectable dependencies in tests.
- Human output redacts addresses by default.
- JSON contract changes are additive and documented in `docs/contracts/`.

### Factory Sandbox Execution

Factory run state lives under the global factory store, not in project `.hal/`:

- `runs/<run-id>.json`
- `timelines/<run-id>.json`
- `logs/<run-id>.json`
- `artifacts/<run-id>/...`
- `queue.json` plus `queue.lock`

`factory.RunRecord` captures status, executor mode, engine, source, repo,
branch, policy snapshot, sandbox metadata, artifacts, verification, telemetry,
failure, and run-secret metadata. The current executor modes are `local` and
`sandbox`.

`cmd/factory_sandbox_executor.go` is the current remote execution path. It:

1. Opens the factory store and saves a run record with `executorMode=sandbox`.
2. Resolves or provisions a sandbox using the existing sandbox registry and
   provider.
3. Starts a stopped sandbox if needed.
4. Records redaction-safe sandbox metadata and timeline events.
5. Runs `factory.BootstrapWorkspace` remotely through the provider `Exec`
   boundary. Bootstrap clones or refreshes the repository, checks out the base
   and run branches, refreshes Hal templates, verifies tooling, and runs final
   checks.
6. Syncs selected agent auth files, currently Codex and Pi-style files, from the
   local machine into remote home paths.
7. Copies local PRD/report inputs to the remote workspace when needed.
8. Runs remote `hal auto` with attempt policy env values and run-scoped secrets.
9. Streams remote output into user output, timeline events, and log chunks with
   run-secret redaction.
10. Applies cleanup behavior from factory policy.

This path is useful and should remain, but it assumes the sandbox target is the
same unit as the execution environment. For a container inside a shared host,
that is no longer true.

### Policy, Secrets, Artifacts, and Queue

Factory policy currently covers:

- `sandboxRequired`
- allowed engines
- max run/review/CI attempts
- verification, PR, and merge gates
- cleanup behavior: `preserve`, `on_success`, `always`

Run secrets are resolved through explicit sources, currently env only. Raw
secret values stay in memory and durable records store only metadata:
`name`, `source`, `required`, and `present`. Redactors sanitize run records,
timeline entries, output logs, and artifact metadata.

Sandbox artifact collection goes through `factory.SandboxArtifactCopier`.
Collectors copy remote payloads into local temp storage, persist them under the
factory store, omit raw remote source paths from JSON surfaces, and preserve
optional-missing artifacts as warning-only partial records.

The queue is local and file-backed. `Store.ClaimNextQueueEntry` claims one FIFO
entry under a local lock and records local process metadata. This is a good
local queue, but it is not a host-capacity scheduler and not a distributed
lease system.

### Existing Directional Docs

`docs/design/multi-sandbox.md` moved Hal from one project-local sandbox to a
global multi-sandbox registry. It also introduced the `ConnectInfo` boundary
that keeps providers from reading state files.

`docs/adr/0001-hal-future-team-organization-factory-control-plane.md` states
that future shared factory coordination should use queue items, runs, leases,
heartbeats, cancellation, stale lease recovery, shared artifact retention, and
authorization. The next sandbox architecture should align with that direction
without requiring a hosted control plane in the first phase.

## 2. Lessons from Sandcastle

Sandcastle's provider model is relevant because it separates sandbox shape from
workflow lifecycle more explicitly than Hal does today.

### Provider Types Must Describe Filesystem Semantics

Sandcastle distinguishes:

- `bind-mount` providers: the host worktree is mounted into the sandbox and no
  sync is needed. Docker and Podman are examples.
- `isolated` providers: the sandbox has its own filesystem, so code must be
  copied or synced in and changes must be extracted out. Vercel's Firecracker
  provider is an example.
- `none`: the agent runs directly on the host.

This distinction is more important than the provider brand. A Docker container
on the same host and a Firecracker microVM on another host may both be
"sandboxes", but they have different workspace, copy, and cleanup semantics.
Hal should encode those semantics as runtime and workspace modes rather than
hiding them behind one provider enum.

### Streaming Exec Is a Contract, Not an Optimization

Sandcastle requires provider `exec` implementations to stream output
line-by-line. It uses live output for display and idle timeouts. Hal's factory
sandbox executor has reached the same conclusion through timeline and log
capture. Any new `ExecutionTransport` must require streaming output and
bounded capture, with deterministic redaction before persistence.

### Isolated Sync Needs Recovery Artifacts

Sandcastle's isolated provider sync path uses:

- `syncIn`: create a git bundle from the host repo, copy it into the sandbox,
  clone from it, and verify HEAD.
- `syncOut`: save committed patches, uncommitted diff, and untracked files to a
  recovery directory before applying them to the host. It tracks a
  sandbox-owned `refs/sandcastle/sync-base` ref so repeated sync-outs do not
  lose commits after `git am` rewrites SHAs.

Hal already has `BootstrapWorkspace` for remote clone-based factory runs, but
container-in-host runtimes need a first-class `WorkspaceSyncer` contract so the
copy strategy can vary by runtime and policy. The important lesson is not "copy
Sandcastle's implementation"; it is that sync must be explicit, testable, and
recoverable before cleanup can run.

### Worktree and Branch Lifecycles Are Separate from Runtime Lifecycles

Sandcastle creates or reuses worktrees, locks them to prevent concurrent branch
collisions, starts a sandbox under scoped cleanup, and removes or preserves the
worktree based on whether changes remain. Hal factory runs already have branch,
artifact, and handoff concepts, but current sandbox execution pushes most
workspace setup into a remote `BootstrapWorkspace` call.

The next architecture should keep these concerns distinct:

- Branch/checkout lifecycle: what code state should the agent work on?
- Runtime lifecycle: where does the agent execute?
- Sync lifecycle: how does code get in and changes get out?
- Handoff lifecycle: how does a user inspect or resume?

### UID/GID and Provider-Owned State Should Be Decided Early

Sandcastle's Docker ADRs reject runtime `chown -R` in favor of build-time UID
alignment or runtime namespace mapping. The lesson for Hal is to avoid starting
containers and then mutating large mounted trees to repair ownership. For bind
mounts, align UID/GID or use user namespaces before start. For remote containers,
prefer non-bind sync modes when the host filesystem ownership is not safe.

Sandcastle's agent-session ADR also pushes provider-specific session storage
behind the provider that owns it. Hal should apply the same rule to agent auth:
generic runtime layers should not learn the internal path layout of each agent
unless an agent-auth adapter owns that transfer.

## 3. Lessons from Docker AI Sandboxes

Docker AI Sandboxes are not an acceptable required dependency for Hal's
open-source architecture, but the docs are a useful reference design.

### MicroVM Boundary and Private Docker Daemon

Docker's reference architecture gives each sandbox its own microVM, Linux
kernel, filesystem, network, and Docker Engine. Agents can run `docker build`
and Compose inside the sandbox without seeing the host Docker daemon. This is a
critical distinction from a naive container that bind-mounts `/var/run/docker.sock`.

Hal should treat "agent needs Docker" as a runtime requirement and satisfy it
with one of:

- private Docker/Podman daemon inside a stronger boundary such as microVM, Kata,
  Firecracker, or a dedicated nested VM;
- rootless BuildKit/Podman inside the container where suitable;
- an explicit policy exception for trusted manual sandboxes only.

The default factory path must not mount the host Docker socket into an
agent-controlled container.

### Direct Mount Is Convenient, Clone Mode Is Safer for Parallel Agents

Docker Sandboxes direct-mount the workspace by default so changes are immediate.
They also support a clone mode where the host repository is mounted read-only,
the agent works in a private in-sandbox clone, and the sandbox exposes that
clone as a Git remote for fetching changes.

For Hal, the safer default for cloud factory execution should be remote clone
or git bundle sync, not broad bind mount. Bind mounts are acceptable for local
manual development or trusted hosts, but shared cloud hosts should prefer
private per-run workspaces.

### Credential Proxy Is Better Than Copying Secrets

Docker Sandboxes keep real credentials on the host. A host-side proxy injects
credentials into outbound HTTP headers and exposes only sentinel values inside
the sandbox. Hal's existing run-scoped secret model is already compatible with
this direction: raw values remain in memory, durable state stores metadata, and
redaction is centralized.

Hal should eventually add a `SecretBroker` that can inject secrets by:

- process env for short-lived bootstrap or agent commands;
- file materialization into tmpfs with cleanup;
- SSH agent forwarding for Git signing or private repo access;
- proxy-managed HTTP credential injection where available.

The proxy model is the best long-term target for model-provider and GitHub API
credentials because it prevents the agent from reading raw tokens.

Docker's docs also distinguish proxy-injected model credentials from registry
credentials that may need to be written into the sandbox's Docker config when
the agent must pull or push images. Hal should preserve that distinction:
service/API credentials should move toward brokered or proxy-mediated access,
while explicitly in-sandbox credentials should require policy opt-in, narrow
scope, and durable metadata that records the exception without storing values.

### Deny-by-Default Network Governance

Docker's default posture blocks outbound traffic unless a policy allows it,
blocks raw TCP/UDP/ICMP by default, blocks host localhost and private ranges,
and supports local and organization-level rules. Hal does not need to duplicate
Docker's exact policy engine, but it should adopt the same product posture for
factory-run sandboxes:

- start from deny-by-default egress;
- allow only required domains for the selected engine, Git provider, package
  registries, CI provider, and project-specific needs;
- log denied destinations for debugging;
- prevent traffic to host metadata services, RFC1918/private networks, link
  local addresses, and host loopback unless explicitly approved;
- record effective policy in run metadata.

Docker's governance docs also make policy precedence explicit: when an
organization policy is active, local rules are inactive rather than merged. Hal
should copy that clarity even before it has an organization control plane.
Policy evaluation should produce one effective policy snapshot with provenance
such as `local`, `project`, `host`, or future `organization`, and the runtime
should enforce that snapshot instead of trying to merge mutable rules after a
run has started.

### Templates and Kits Suggest a Declarative Setup Layer

Docker templates and kits package an agent image, install commands, env,
credentials, network rules, files, startup commands, and agent context. Hal
should not depend on Docker kits, but it should have a similar concept for
self-hosted sandbox hosts:

- base image or runtime profile;
- required host capabilities;
- bootstrap commands;
- expected agent auth adapters;
- network policy additions;
- resource defaults;
- test probes.

This can begin as config and tests, not a full packaging ecosystem.

The supported-agent and workflow docs are also useful product signals. Docker
ships agent-specific authentication/configuration pages and documents workflow
patterns for direct mode, clone mode, host worktrees, commit signing,
authenticated CLIs, and CI/headless use. Hal should keep runtime profiles
separate from agent adapters: a runtime profile defines the image, workspace,
network, and transport; an agent adapter defines auth/session handling,
commands, and resume or handoff capabilities.

## 4. Recommended Architecture for Hal

### Recommendation

Implement a layered sandbox system and keep the current provider interface as a
compatibility adapter.

Do not implement `docker` as a new `internal/sandbox.Provider` beside
`hetzner` and `digitalocean`. Docker is not an infrastructure provider in this
model; it is a runtime provider that runs inside or on top of a host. A Docker
container might run on the local machine, on a manually registered SSH host, or
on a Hetzner/DigitalOcean/Lightsail host provisioned by Hal. Treating Docker as
the same abstraction as Hetzner would make it difficult to represent the host,
capacity, host cleanup, per-container cleanup, nested networking, and
container-specific transport.

The first production-worthy version should support:

- legacy `SSHMachineRuntime` backed by current providers;
- `DockerRuntime` on a registered SSH sandbox host;
- remote clone plus `BootstrapWorkspace` as the default workspace mode for
  factory runs;
- run-scoped env secrets with existing metadata and redaction;
- per-run container cleanup with TTL and lease records;
- additive JSON metadata for host/runtime/lease without changing existing
  required fields.

After that, add:

- local Docker/Podman runtime for manual development and CI;
- rootless Podman support where available;
- gVisor/Kata runtime class support;
- stronger per-host egress enforcement;
- a credential proxy or secret broker;
- distributed leases if/when the control plane becomes shared.

### Layer Diagram

```text
Hal CLI / factory queue / future control plane
        |
        v
SandboxScheduler
        |
        +-- HostRegistry ---- HostProvider
        |       |              local, ssh, hetzner, digitalocean, lightsail
        |       v
        |   SandboxHost
        |
        +-- RuntimeProvider
        |       ssh-machine, docker, podman, gvisor, kata, firecracker
        |
        +-- WorkspaceSyncer
        |       remote-clone, bootstrap-workspace, git-bundle, tar-copy, clone-remote
        |
        +-- ExecutionTransport
        |       ssh exec, docker exec, podman exec, runtime-agent exec
        |
        +-- SecretBroker / NetworkPolicy / ArtifactCollector
```

### Why This Fits Hal

- It preserves current user workflows through the SSH machine adapter.
- It allows one VPS host to run many per-run sandboxes.
- It keeps cloud provider limits and costs at the host pool layer.
- It lets runtime security differ by host capability.
- It makes network, secret, and workspace policies explicit and testable.
- It aligns with the future control-plane ADR's lease and run concepts.
- It keeps JSON contract changes additive.

### Scheduling and Operational Policy

Factory scheduling should be a two-step operation: claim queue work, then
reserve host capacity. The queue claim says "this worker owns the run"; the
host lease says "this run owns CPU, memory, disk, concurrency, and runtime
slots on a host." They must remain separate so a worker crash can release
capacity without rewriting queue semantics.

Initial scheduling should be deterministic and conservative:

- filter unhealthy hosts, incompatible runtime providers, wrong labels, and
  policy-incompatible hosts;
- sort by explicit preference, available capacity, and oldest successful use;
- create a lease before runtime creation;
- heartbeat the lease during bootstrap, agent execution, artifact collection,
  and cleanup;
- mark stale leases expired with a recovery reason instead of silently deleting
  runtime state.

Cleanup should operate at runtime scope first and host scope second. Per-run
containers get TTL labels and lease records. Preserved failure containers expire
after a configurable TTL once artifacts are collected. Manual sandboxes can use
idle shutdown, but factory runs should use explicit `perRunTTL` plus cleanup
policy because "idle" is ambiguous while an agent is waiting on network,
package install, CI, or review.

Cost tracking starts at the host. Host records should store provider size,
hourly estimate, and billing scope. Factory telemetry can add an estimated
allocated cost by prorating host cost across runtime wall time and reserved
resources. That estimate should be optional and explicitly labeled as estimated
because cloud billing details vary by provider.

Artifact collection and handoff must happen before destructive cleanup. Every
runtime provider should expose enough copy/inspect behavior for the factory to
persist logs, patches, verification output, and handoff hints. A preserved
runtime should record a bounded, redacted handoff command; a deleted runtime
should record artifact locations and the cleanup result.

## 5. Abstraction Model

### `HostProvider`

Responsible for host lifecycle, not agent execution.

Responsibilities:

- provision, register, start, stop, and delete hosts;
- report host identity, status, labels, resource capacity, runtime support, and
  connection info;
- bootstrap host-level prerequisites such as Docker/Podman, runtime shims,
  firewall/proxy, Hal runtime agent, and monitoring;
- expose an admin transport to the host, usually SSH;
- never own per-run container state.

Initial implementations:

- `ExistingMachineHostProvider`: adapter for current `daytona`, `hetzner`,
  `digitalocean`, `lightsail` behavior.
- `SSHHostProvider`: register an already existing machine.
- `LocalHostProvider`: current machine for local Docker/Podman experiments.
- Existing cloud-specific providers can later produce hosts instead of direct
  sandboxes.

### `SandboxHost`

Persistent host state, stored separately from sandbox instances.

Suggested fields:

- `id`, `name`, `provider`, `workspaceId`
- `status`, `createdAt`, `updatedAt`, `lastHeartbeatAt`
- `connection`: public/Tailscale/admin addresses, redacted in human output
- `labels`: region, architecture, trust tier, team/project labels
- `capacity`: CPU, memory, disk, max concurrent sandboxes
- `availableCapacity`: optional live status
- `runtimes`: supported runtime names and versions
- `cost`: provider size, hourly estimate, billing scope
- `policy`: allowed runtime classes, network policy defaults, workspace modes

### `RuntimeProvider`

Responsible for creating one execution environment on one host.

Responsibilities:

- create, start, stop, inspect, and delete runtime instances;
- report runtime ID, image/profile, resource limits, workspace path, network ID,
  and status;
- return or construct an `ExecutionTransport`;
- enforce runtime-specific restrictions: user, capabilities, mounts, network,
  seccomp/AppArmor/SELinux, rootless mode, TTL labels.

Initial runtimes:

- `SSHMachineRuntime`: compatibility mode where the host itself is the sandbox.
- `DockerRuntime`: per-run or manual container on a host.
- `PodmanRuntime`: rootless preferred where possible.

Later runtimes:

- `DockerRuntime` with gVisor (`runsc`) runtime class.
- `KataRuntime`.
- `FirecrackerRuntime` through an open-source jailer/agent stack.
- optional `SbxCompatibleRuntime` if Docker publishes a suitable local API and
  Hal treats it as optional.

### `ExecutionTransport`

Responsible for command execution and streaming output.

Responsibilities:

- run commands with cwd, env, stdin, timeout, and user;
- stream stdout/stderr line-by-line for timeline/log capture;
- return exit status and bounded output summaries;
- copy files or directories if supported, or delegate to `ArtifactTransport`;
- never store raw secrets in command summaries or durable state.

Initial transports:

- `SSHTransport`: current provider `Exec` behavior.
- `DockerExecTransport`: `docker exec`, `docker cp`, and tar streaming over SSH
  to the host.
- `PodmanExecTransport`: equivalent for Podman.

### `WorkspaceSyncer`

Responsible for repository materialization and change extraction.

Workspace modes:

- `remote_clone`: clone/fetch repository inside environment. This is the
  default for factory runs with a remote URL.
- `bootstrap_workspace`: current `factory.BootstrapWorkspace` flow, kept as the
  implementation of `remote_clone` for SSH-like environments.
- `git_bundle`: create a bundle from local state, copy it in, and clone inside
  environment. Use when unpushed local commits or private local state must be
  included.
- `patch_extract`: extract commits/diffs/untracked files out as durable
  artifacts before applying or handing off.
- `bind_mount`: mount host workspace directly. Allowed only for local/manual
  trusted use or explicitly approved host policies.
- `readonly_mount_clone`: mount host repo read-only and create an in-environment
  clone, similar to Docker clone mode.

Recommended sync defaults:

| Mode | Best use | Main risk |
| --- | --- | --- |
| `remote_clone` | Cloud factory runs where commits are pushed or the repo is reachable from the sandbox. | Does not include unpushed local work unless Hal first publishes or bundles it. |
| `bootstrap_workspace` | Compatibility path for current SSH/VPS factory runs. | Too tied to SSH-machine assumptions unless wrapped behind `WorkspaceSyncer`. |
| `git_bundle` | Local commits, private local state, or air-gapped handoff into an isolated runtime. | Requires explicit sync-out and recovery artifacts. |
| `patch_extract` | Failure recovery, review, and handoff from isolated runtimes. | Patch application can fail after rebase or generated-file churn. |
| `bind_mount` | Local trusted manual work where instant file updates matter. | Exposes host filesystem and creates ownership/concurrency problems. |
| `readonly_mount_clone` | Shared hosts where host repo access is useful but the agent needs a private worktree. | More moving pieces than direct clone and still depends on safe mount policy. |

### `SandboxScheduler`

Responsible for assigning a requested sandbox/run to a host and runtime.

Responsibilities:

- filter hosts by health, labels, runtime support, trust tier, region, and
  policy;
- reserve capacity through a lease before creating an environment;
- create per-run runtime instances;
- heartbeat active leases;
- release capacity on cleanup;
- mark stale leases expired and recoverable;
- preserve queue semantics by treating queue claim and host lease as separate
  resources.

### `SandboxLease`

Lease state should exist even before a shared control plane.

Fields:

- `leaseId`
- `runId` or `sandboxId`
- `hostId`
- `runtimeId`
- `owner`: local worker ID, PID, hostname, future actor ID
- `status`: `reserved`, `creating`, `running`, `releasing`, `expired`,
  `released`
- `createdAt`, `expiresAt`, `lastHeartbeatAt`, `releasedAt`
- `resources`: CPU, memory, disk, runtime class

### `SecretBroker`

Responsible for secret delivery and revocation.

Initial behavior:

- reuse `factory.ResolveRunSecrets`;
- inject resolved env secrets only into specific bootstrap and agent commands;
- keep raw values in memory only;
- redact all summaries and artifacts through existing redactors.

Future behavior:

- host-side HTTP credential proxy;
- SSH agent forwarding;
- temporary credential files on tmpfs;
- project/org secret resolvers after a control plane exists.

### `NetworkPolicyManager`

Responsible for effective network policy.

Initial behavior:

- persist intended policy in run metadata;
- set container network mode and labels;
- optionally use host firewall/proxy scripts where installed.

Target behavior:

- deny-by-default egress for factory runs;
- allowlist engine/model APIs, Git provider, package registries, project
  domains, CI provider, and artifact upload endpoints;
- block metadata services, private networks, host loopback, and sandbox-to-
  sandbox traffic by default;
- record denied-connection summaries as sanitized logs or artifacts.

## 6. Proposed CLI and Config Shape

These are proposed shapes, not implementation commitments. All new JSON fields
should be optional unless a future `v2` contract is explicitly introduced.

### Global Sandbox Config

Extend `sandbox-config.yaml` additively:

```yaml
provider: hetzner

hosts:
  defaultPool: self-hosted
  pools:
    self-hosted:
      hostSelector:
        labels:
          purpose: factory
      runtimePreference: [docker, podman, ssh-machine]
      maxConcurrentRuns: 8
  registered:
    home-lab-1:
      provider: ssh
      address: host.example.com
      user: root
      labels:
        purpose: factory
        trust: personal
      runtimes:
        docker:
          # Host-side admin transport only. This socket is used by Hal on the
          # host to create/delete runtimes and must not be mounted into the
          # agent-controlled container unless policy explicitly allows it.
          socket: unix:///var/run/docker.sock
          rootless: false
          defaultImage: ghcr.io/jywlabs/hal-agent:latest

runtimes:
  docker:
    defaultImage: ghcr.io/jywlabs/hal-agent:latest
    networkPolicy: balanced
    workspaceMode: remote_clone
    user: agent
    cpus: 2
    memory: 4g
    ttl: 4h
    cleanup: on_success
  podman:
    rootless: true
    defaultImage: ghcr.io/jywlabs/hal-agent:latest

networkPolicies:
  locked:
    default: deny
    allow:
      - github.com:443
      - api.github.com:443
      - api.openai.com:443
      - api.anthropic.com:443
  balanced:
    extends: locked
    allow:
      - '*.npmjs.org:443'
      - pypi.org:443
      - files.pythonhosted.org:443
```

### Project Factory Policy

Extend `.hal/config.yaml` factory policy additively:

```yaml
factory:
  policy:
    sandboxRequired: true
    cleanupBehavior: on_success
    sandboxHostRequired: false
    allowedRuntimeProviders: [docker, podman, ssh-machine]
    deniedRuntimeProviders: []
    workspaceMode: remote_clone
    networkPolicy: locked
    maxConcurrentRunsPerHost: 4
    perRunTTL: 4h
    requireEphemeralRuntime: true
    allowHostDockerSocket: false
    allowBindMountWorkspace: false
```

### CLI Commands

Host management:

```bash
hal sandbox host register ssh home-lab-1 --address host.example.com --user root
hal sandbox host create hetzner --name factory-host-01 --size cx42
hal sandbox host list --json
hal sandbox host status factory-host-01 --live --json
hal sandbox host doctor factory-host-01
hal sandbox host delete factory-host-01
```

Runtime inspection:

```bash
hal sandbox runtime list factory-host-01 --json
hal sandbox runtime doctor factory-host-01 docker
```

Manual sandbox:

```bash
hal sandbox create --name api-debug --host factory-host-01 --runtime docker --scope manual
hal sandbox create --name api-debug --runtime ssh-machine
hal sandbox ssh api-debug
hal sandbox delete api-debug
```

Factory run:

```bash
hal factory run .hal/prd-feature.md --sandbox --base main \
  --host auto \
  --runtime docker \
  --workspace-mode remote-clone \
  --network-policy locked
```

Queue:

```bash
hal factory queue add run-123 sandbox --host-pool self-hosted --runtime docker
hal factory queue work --host-pool self-hosted --json
```

Existing commands remain valid. Without new flags, `hal factory run --sandbox`
continues to use the compatibility path until a project/global policy opts into
shared-host runtime scheduling.

## 7. Data Model and Contract Changes

### Sandbox Host State

Add a new host registry, not a breaking change to the existing sandbox registry:

```text
$HAL_CONFIG_HOME/
  sandbox-config.yaml
  sandbox-hosts/
    factory-host-01.json
  sandboxes/
    api-debug.json
  factory/
    leases/
      <lease-id>.json
```

`SandboxHostState` should be a new type. It must not be squeezed into
`SandboxState`, because hosts and execution environments have different
lifecycles.

### Sandbox State Additive Fields

Add optional fields to `SandboxState` for environments that are not standalone
machines:

- `kind`: `machine`, `container`, `microvm`
- `scope`: `manual`, `factory_run`
- `hostId`
- `hostName`
- `runtimeProvider`: `ssh-machine`, `docker`, `podman`, `gvisor`, `kata`,
  `firecracker`
- `runtimeId`: container ID, VM ID, or runtime-native ID
- `runtimeImage`
- `runtimeClass`
- `workspaceMode`
- `workspacePath`
- `leaseId`
- `expiresAt`
- `lastHeartbeatAt`
- `networkPolicy`
- `resourceLimits`
- `parentSandboxId` for compatibility cases where a container is created inside
  an existing legacy VPS sandbox

Existing fields remain required or optional exactly as documented by
`sandbox-list-v1`. Older entries can omit all new fields and still mean "legacy
machine sandbox".

### Factory Run Metadata

Extend `factory.SandboxMetadata` additively:

- `host`: safe host summary: `id`, `name`, `provider`, `pool`, `labels`
- `runtime`: safe runtime summary: `provider`, `id`, `image`, `class`
- `lease`: safe lease summary: `leaseId`, `status`, `expiresAt`
- `workspace`: `mode`, `path` when safe, `repositoryUrlRedacted`
- `networkPolicy`: name and effective preset, not raw secrets
- `cleanup`: behavior and result

Keep `sandboxName` for compatibility and keep `executorMode=sandbox`.
Do not introduce a new executor mode for every runtime. Runtime is a property
of sandbox execution, not a top-level factory mode.

### Policy

Extend `FactoryPolicy` additively:

- `AllowedRuntimeProviders []string`
- `DeniedRuntimeProviders []string`
- `SandboxHostRequired bool`
- `WorkspaceMode string`
- `NetworkPolicy string`
- `MaxConcurrentRunsPerHost int`
- `PerRunTTL string` or a parsed duration type with raw YAML preservation
- `RequireEphemeralRuntime bool`
- `AllowHostDockerSocket bool`
- `AllowBindMountWorkspace bool`

Policy decisions should continue to be recorded as timeline events using safe
whitelisted metadata.

### Contract Surfaces

Add optional fields only:

- `sandbox-list-v1`: optional `kind`, `scope`, `host`, `runtime`,
  `workspaceMode`, `lease`, `expiresAt`, `networkPolicy`, `resourceLimits`.
- `factory-status-v1`: optional nested fields under `run.sandbox`.
- `factory-run-v1`: optional `telemetry.sandbox.runtime`,
  `telemetry.sandbox.host`, `telemetry.sandbox.estimatedHostCost` if available.
- `factory-queue-entry-v1`: optional scheduling hints such as `hostPool`,
  `runtimeProvider`, `workspaceMode`, and `networkPolicy`.

If Hal later exposes a shared organization scheduler with server-side leases,
that should likely be a new contract version rather than a large hidden
semantic shift in `factory-queue-work-v1`.

## 8. Security Model and Threat Boundaries

### Trust Boundaries

For shared-host factory execution, Hal should define these boundaries:

1. Developer machine or control plane: owns policy, queue, secrets, and durable
   run records.
2. Sandbox host: trusted infrastructure under the user's or team's control.
   A compromised host can affect all runtimes on that host.
3. Runtime environment: the container, VM, or machine where the agent executes.
4. Agent process: untrusted autonomous code execution within the runtime.
5. External network: allowed destinations only.

The agent should be assumed capable of:

- reading and modifying its workspace;
- running arbitrary code;
- attempting network exfiltration;
- attempting privilege escalation inside the runtime;
- attempting to discover host metadata or local services;
- printing secrets or sensitive paths into logs.

### Default Factory Posture

Factory per-run sandboxes should default to:

- no host Docker socket mount;
- no privileged container unless inside a stronger microVM boundary;
- no broad host bind mount;
- no host home directory mount;
- no permanent agent auth files copied by default;
- non-root user inside the runtime where possible;
- explicit resource limits;
- per-run network namespace;
- deny-by-default egress when the host supports enforcement;
- run-scoped secrets only;
- cleanup on success by policy, TTL cleanup for stale runs;
- artifact collection before runtime deletion.

Manual sandboxes may opt into weaker settings with explicit flags and durable
state showing that policy exception.

### Docker Socket and Nested Docker

Mounting `/var/run/docker.sock` into an agent-controlled container should be
blocked by default. It gives the agent control over the host daemon and can
escape the intended runtime boundary.

When Docker access is required:

- prefer a private Docker daemon inside a microVM or Kata/Firecracker runtime;
- consider rootless Podman/BuildKit for build-only workflows;
- allow host socket only for trusted manual sandboxes with
  `allowHostDockerSocket=true`, never for default factory runs.

### Bind Mounts

Bind mounting a workspace into a local container is acceptable for local manual
use and fast iteration. It is not the right default for shared cloud factory
runs because:

- the agent can edit/delete any mounted file;
- ownership and symlink behavior can become host-dependent;
- concurrent agents can collide;
- mounted secrets or config files can be read if included in the tree.

Preferred factory modes are `remote_clone`, `git_bundle`, or
`readonly_mount_clone`.

### Secrets

Current run-scoped secret contracts must be preserved:

- raw values never persisted;
- metadata only in run records;
- redaction before logs, timelines, artifacts, and errors are saved;
- command summaries sanitized.

New runtime layers should not copy all local engine auth files permanently.
Instead:

- copy only the agent auth required by the selected engine;
- prefer short-lived env injection for `hal auto`;
- remove temporary files during cleanup;
- record which secret names were required and present, not values;
- eventually use a proxy or broker that keeps real tokens outside the runtime.

### Network Policy

The target network model:

- per-runtime network namespace;
- default deny egress for factory runs;
- allow HTTP/HTTPS domains by policy;
- allow non-HTTP destinations only by explicit IP/port rule;
- block private ranges, metadata endpoints, host loopback, and link-local by
  default;
- no sandbox-to-sandbox traffic by default;
- logs for blocked destinations with sanitized hostnames and no credentials.

Implementation can phase from recorded policy intent to real enforcement, but
the data model should distinguish `policyRequested`, `policyEnforced`, and
`enforcementMode`.

## 9. Execution Lifecycles

### Manual Sandbox

1. User runs `hal sandbox create --runtime docker --host auto --scope manual`.
2. Hal resolves global config and policy.
3. Scheduler selects or provisions a host if needed.
4. Runtime provider creates a persistent manual environment with a stable
   sandbox name.
5. Workspace mode is selected:
   - local trusted host: optional bind mount;
   - remote/shared host: remote clone or user-provided repository checkout.
6. Runtime health probes run: shell, Git, Hal, engine CLI, network policy.
7. Hal records `SandboxState` with host/runtime/lease/TTL fields.
8. User attaches with `hal sandbox ssh <name>` or future
   `hal sandbox exec <name> -- ...`.
9. Manual sandbox persists until stopped, deleted, or idle TTL policy triggers.
10. Deletion removes runtime environment first, then registry state; host is
    preserved unless explicitly deleted.

### Factory Run on Existing VPS Sandbox

This remains the compatibility lifecycle:

1. User runs `hal factory run --sandbox --base main`.
2. Hal creates a run record with `executorMode=sandbox`.
3. Hal resolves or provisions a legacy machine sandbox.
4. If stopped, Hal starts it.
5. Hal records sandbox metadata and connection handoff.
6. `BootstrapWorkspace` runs over SSH/provider exec:
   - clone/fetch repository;
   - checkout base and run branch;
   - refresh Hal;
   - verify engine tooling;
   - run final checks.
7. Hal syncs required agent auth or run secrets using the existing redaction
   boundary.
8. Remote `hal auto` runs in the remote workspace.
9. Output streams into timeline and logs.
10. Artifacts are copied through `SandboxArtifactCopier`.
11. Cleanup behavior applies to the machine sandbox if policy says so.
12. Failure handoff points to `hal sandbox ssh <name>` or run inspection.

Internally this should become `HostProvider + SSHMachineRuntime`, but external
behavior should remain stable.

### Factory Run as Docker Container Inside Shared Host

1. User or worker runs:

   ```bash
   hal factory run .hal/prd.md --sandbox --base main --runtime docker --host auto
   ```

2. Hal creates a run record and resolves factory policy.
3. Scheduler filters hosts:
   - host status healthy;
   - runtime `docker` available;
   - labels/pool match;
   - enough free CPU/memory/disk/concurrency;
   - network policy can be enforced or policy allows best-effort.
4. Scheduler writes a `SandboxLease` with status `reserved`.
5. Runtime provider creates a per-run container:
   - image/profile selected from config;
   - no host Docker socket by default;
   - no host home mount;
   - resource limits set;
   - per-run network namespace;
   - labels include run ID, lease ID, TTL, cleanup policy.
6. WorkspaceSyncer materializes code:
   - default: remote clone and `BootstrapWorkspace` inside the container;
   - if local-only state is needed: git bundle copy-in;
   - if policy permits: read-only mount plus in-container clone.
7. SecretBroker injects only required run secrets into bootstrap/agent commands.
8. `ExecutionTransport` runs remote `hal auto` via `docker exec` through the host
   admin transport, streaming stdout/stderr to Hal.
9. Hal records timeline/log events tagged with host ID, runtime provider,
   runtime ID, lease ID, workspace mode, and network policy.
10. ArtifactCollector copies artifacts from container to host temp storage,
    then to the factory store, with redaction.
11. On success:
    - if cleanup policy is `on_success` or `always`, delete the container;
    - mark lease `released`;
    - keep host running.
12. On failure:
    - preserve the container if policy says `preserve`;
    - record handoff commands:
      `hal sandbox host ssh <host>` and
      `hal sandbox exec <sandbox-name> -- bash` or equivalent;
    - mark lease status and TTL for later cleanup.
13. A background cleanup command removes expired preserved runtimes after
    artifact collection and warning windows.

## 10. Migration Path from Current Providers

### Phase Compatibility

Keep existing sandbox provider behavior. Introduce new interfaces behind the
factory sandbox executor but adapt current providers:

- Daytona: `HostProvider` and `SSHMachineRuntime` where possible, or legacy
  provider adapter until Daytona support is deprecated or narrowed.
- Hetzner/DigitalOcean/Lightsail: host providers that provision machines; the
  machine can run `SSHMachineRuntime` first, then Docker/Podman after host
  bootstrap supports it.
- Existing `SandboxState` entries with no `kind` or `runtimeProvider` mean
  `kind=machine`, `runtimeProvider=ssh-machine`.

### Phase Shared Host

Add `hal sandbox host register ssh` before cloud host provisioning changes.
This lets users bring an existing VPS with Docker installed and lets Hal test
the runtime model without touching cloud provider creation.

### Phase Cloud Host Pool

Extend Hetzner, DigitalOcean, and Lightsail provisioning to create sandbox
hosts, not per-run sandboxes. Host bootstrap installs the chosen runtime,
network policy helpers, and a Hal runtime shim. Factory runs then schedule
containers onto those hosts.

### Phase Provider Cleanup

Once `HostProvider + RuntimeProvider` is mature:

- move `internal/sandbox.Provider` to a legacy adapter package or rename the new
  abstractions to avoid ambiguity;
- keep CLI compatibility;
- document when `provider` in `SandboxState` means host provider versus legacy
  sandbox provider;
- add migrations that populate optional host/runtime fields only when safe.

## 11. Phased Implementation Plan, File Map, and Tests

### Phase 0: Design and Contract Tests

Deliverables:

- this design doc;
- follow-up ADR documenting the layered abstraction decision;
- contract test plan for optional fields.

Tests:

- doc-code sync tests only after structs exist;
- no runtime tests yet.

### Phase 1: Interfaces and Pure Types

Files:

- `internal/sandbox/host_types.go`
- `internal/sandbox/runtime_types.go`
- `internal/sandbox/transport.go`
- `internal/sandbox/workspace_sync.go`
- `internal/sandbox/lease.go`

Tests:

- validation of host/runtime names and enum values;
- JSON marshal/unmarshal for optional fields;
- redaction-safe display structs;
- no Docker, SSH, cloud, or network calls.

### Phase 2: Host Registry and Lease Store

Files:

- `internal/sandbox/host_registry.go`
- `internal/sandbox/host_registry_test.go`
- `internal/factory/lease_store.go`
- `internal/factory/lease_store_test.go`

Tests:

- atomic writes and missing-file behavior;
- concurrent lease update with local locks;
- stale lease detection using injectable clock;
- no provider calls.

### Phase 3: Legacy Adapter

Files:

- `internal/sandbox/legacy_provider_adapter.go`
- `cmd/factory_sandbox_executor.go` integration seam refactor

Tests:

- current factory sandbox executor tests continue to pass;
- adapter maps legacy `SandboxState` to host/runtime metadata;
- no changes to existing required JSON fields.

### Phase 4: SSH Host Provider

Files:

- `internal/sandbox/provider_ssh_host.go`
- `cmd/sandbox_host.go`
- `cmd/sandbox_host_register.go`
- `cmd/sandbox_host_list.go`
- `docs/contracts/sandbox-host-list-v1.md` if a JSON command ships

Tests:

- CLI parsing and registry writes;
- injected SSH command builder for doctor probes;
- JSON contract field locking if a new JSON surface is added.

### Phase 5: Docker Runtime on SSH Host

Files:

- `internal/sandbox/runtime_docker.go`
- `internal/sandbox/runtime_docker_test.go`
- `internal/sandbox/transport_docker.go`
- `internal/sandbox/workspace_remote_clone.go`
- `cmd/sandbox_runtime.go`

Tests:

- exact docker command construction with fakes;
- no real Docker calls;
- mount policy rejects host socket by default;
- env/secrets are passed only to selected commands;
- streaming output redaction;
- cleanup labels and TTL labels included.

### Phase 6: Scheduler

Files:

- `internal/factory/scheduler.go`
- `internal/factory/scheduler_test.go`
- `cmd/factory_sandbox_executor.go` scheduling integration
- `cmd/factory_queue.go` optional scheduling hints

Tests:

- host filtering by runtime, labels, capacity, health, policy;
- lease reservation and release;
- no-work queue behavior unchanged;
- queue claim and host lease stay separate;
- failed create releases or marks lease correctly.

### Phase 7: Network Policy and Secret Broker

Files:

- `internal/sandbox/network_policy.go`
- `internal/sandbox/network_policy_test.go`
- `internal/factory/secret_broker.go`
- `internal/factory/secret_broker_test.go`

Tests:

- policy validation and additive config merge;
- effective policy metadata redaction;
- denied host/private range validation;
- secret values never marshal into run records, events, logs, or artifacts.

### Phase 8: Artifact and Handoff Expansion

Files:

- `internal/factory/sandbox_artifacts.go`
- `internal/factory/handoff.go`
- `cmd/factory_open.go`

Tests:

- container-preserved failure handoff command;
- artifact copy from runtime transport with fake copier;
- cleanup after artifact collection;
- optional missing artifacts remain partial warning records.

### Phase 9: Cloud Host Pool Bootstrap

Files:

- existing provider files move toward host provisioning:
  - `internal/sandbox/provider_hetzner.go`
  - `internal/sandbox/provider_digitalocean.go`
  - `internal/sandbox/provider_lightsail.go`
- new host bootstrap helpers:
  - `internal/sandbox/host_bootstrap.go`
  - `internal/sandbox/host_bootstrap_test.go`

Tests:

- generated cloud-init installs runtime helpers with no raw secrets in snapshots;
- provider command args remain deterministic;
- rollback on bootstrap failure preserves recovery hints.

## 12. Risks, Rejected Alternatives, and Open Questions

### Risks

- Container isolation on a plain VPS is weaker than a microVM boundary. Hal
  should not overstate the security of Docker namespaces.
- Network policy enforcement differs across hosts. Some hosts may only support
  best-effort policy until a managed proxy/firewall is installed.
- Docker image and runtime drift can cause hard-to-debug failures. Host doctor
  checks and runtime profiles must be explicit.
- Artifact collection before cleanup becomes more important. A bug here can
  delete the only copy of failed-run output.
- Shared hosts concentrate risk. A compromised host may affect every runtime on
  that host.
- Lease cleanup and stale detection are easy to get wrong. Initial leases should
  be local and conservative before becoming distributed.
- Agent auth files are currently copied directly. Moving to least-privilege
  brokered auth requires careful migration and engine-specific support.

### Rejected Alternatives

**Add Docker as `internal/sandbox.Provider`.**
Rejected because it hides the host layer. A Docker sandbox needs to know which
host it runs on, how host capacity is leased, how the runtime is inspected,
which transport copies files, and how host cleanup differs from container
cleanup.

**One VPS per factory run forever.**
Rejected because it hits provider limits, increases cost, slows startup, and
does not match the expected cloud-agent usage pattern.

**Depend on Daytona, E2B, Modal, Vercel, or Docker Sandboxes.**
Rejected because Hal's core should be open-source and self-hostable. These can
remain optional adapters or references.

**Bind-mount the repository by default into every container.**
Rejected for cloud factory runs because it exposes too much host filesystem
state and creates concurrency risks. It remains acceptable for local/manual
trusted workflows.

**Mount the host Docker socket for agent Docker support.**
Rejected for default factory runs because it gives the agent control over the
host daemon.

**Use the factory queue claim as the host-capacity lease.**
Rejected because queue ownership and runtime capacity are separate resources.
They need different failure, heartbeat, and recovery semantics.

### Open Questions

- What is Hal's first supported "stronger than Docker" runtime: gVisor, Kata, or
  Firecracker?
- Should Hal ship a small runtime agent on sandbox hosts, or keep using SSH plus
  runtime CLI commands?
- What is the minimum viable network enforcement layer for self-hosted Linux
  hosts: nftables, Cilium, eBPF, proxy-only, or runtime-specific networks?
- How should Hal package base images or runtime profiles? OCI image plus YAML,
  Hal-specific profile file, or reuse devcontainer-like conventions?
- Which agent auth adapters should be first-class: Codex, Claude, Pi, GitHub
  CLI, SSH agent?
- Should manual sandboxes and factory-run sandboxes share the same runtime
  registry, or should per-run environments live only under factory lease state?
- How should cost tracking split host cost across concurrent runs?
- When the future control plane arrives, which local lease fields become server
  authoritative and which remain local cache?
- How much of Docker Sandboxes' credential-proxy model can Hal implement
  portably without becoming a managed service?

## Final Recommendation

Move Hal toward a layered, self-hostable sandbox architecture:

- Keep current providers working through a legacy SSH machine runtime.
- Add host registration and host state first.
- Add Docker/Podman as runtimes on hosts, not infrastructure providers.
- Make scheduling and leases explicit before running many agents on one host.
- Default factory runs to isolated workspace modes and deny-by-default network
  policy.
- Preserve current JSON contracts through additive optional fields.
- Treat stronger runtimes and credential proxying as the path to production
  security, not as optional polish.

This gives Hal a practical near-term path to shared VPS sandbox hosts while
keeping the architecture open for Podman, gVisor, Kata, Firecracker, and future
control-plane scheduling.
