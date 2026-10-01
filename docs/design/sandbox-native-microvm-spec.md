# Native Hal microVM runtime

Status: proposed spec, 2026-10-01. Tracking: beads epic `hal-zl6`, issue
`hal-zl6.21`. This document is the source of truth for Hal's VM lane. It
replaces the L4-L11 Firecracker documents, which were deleted together with
their code (last commit containing them: `ddeb61eb`).

## 1. Why Hal builds its own microVM runtime

Agent sandboxes are a product category. Per their public material, E2B, Vercel
Sandbox and Fly Machines build on Firecracker, Modal on gVisor, and Docker
Sandboxes run agents in microVMs;
open-source projects such as microsandbox (libkrun) and Gondolin (QEMU or
libkrun) and NVIDIA OpenShell (Landlock, seccomp and an egress supervisor)
converge on the same shape: an isolated workload, egress mediated by the host,
and secrets that never enter the sandbox.

Hal's advantage is not the hypervisor. It is the loop around it: PRD to
stories, agent iterations, verification, durable worker jobs, recovery, and a
reviewed sync-out back into the user's repository. Owning the runtime lets Hal
offer that loop with a strong isolation boundary on a laptop, on a team's own
servers, and later as a hosted service, without depending on another vendor's
sandbox API, pricing, or security claims. Importing a third-party sandbox
runtime would cap the product at that runtime's roadmap; it is therefore a
non-goal.

## 2. Users, tiers and threat models

| Tier | Where it runs | Who is untrusted | What must hold |
| --- | --- | --- | --- |
| T1 local developer | The developer's Linux or macOS machine | The agent and the code it writes or downloads (prompt injection, malicious dependencies) | Host files outside the workspace, host credentials, and the network beyond an allowlist are unreachable from the VM |
| T2 team worker | Self-hosted Linux servers running `hal sandboxd` | As T1, plus jobs from different repositories or people sharing a host | T1, plus jobs cannot see each other, and resource abuse in one VM cannot starve others |
| T3 hosted Hal | Hal-operated fleet | Arbitrary tenants | T2, plus a hardened VMM boundary (jailer, seccomp, cgroups, per-VM UID), metering and abuse controls |

The rootless Podman lane remains the T1 fallback when hardware virtualization
is unavailable. It shares the host kernel and must never claim VM isolation.

Every release states which tier it satisfies. A capability is claimed only
after its live acceptance test passes on real hardware (section 9).

## 3. Goals and non-goals

Goals for the first production release (milestones M1-M4):

- One fresh VM per sandbox, created and managed by `hal sandboxd` through the
  existing `sandboxruntime.Driver` contract, selected with
  `--sandbox-runtime microvm`.
- The same user experience as the rootless lane: `hal run`, `hal auto` and
  `hal factory run` with `--sandbox`, durable jobs, logs, recovery, sync-out and
  `hal sandbox apply`.
- Agents can reach model APIs and allowlisted hosts; all other egress is denied.
- Credentials for HTTPS APIs stay on the host; the VM sees placeholders.
- Linux with KVM (Firecracker). macOS on Apple Silicon follows in M5 (libkrun).

Non-goals until explicitly scheduled: GPU passthrough, Windows hosts, live
migration, confidential computing (SEV/TDX), nested VMs, and any import of a
third-party sandbox runtime.

## 4. Architecture

```text
hal run/auto/factory --sandbox --sandbox-runtime microvm
        |
        v
hal sandboxd (worker daemon, existing)            host services (new, shared with rootless)
  sandboxruntime.Driver "microvm"  ------------>  egress proxy (allowlist, DNS, decision log)
        |                                         credential broker (placeholder -> secret)
        v                                         image store (content-addressed rootfs/kernel)
  per-VM shim process  (owns one VM; survives daemon restart)
        |
        v
  vmm.Backend: firecracker (Linux) | libkrun (macOS, Linux dev)
        |  vsock
        v
  guest: hal-init (PID 1)  ->  hal-agentd  ->  workload (agent CLI, git, tests, dockerd)
```

### 4.1 Existing Hal pieces that stay unchanged

- `sandboxruntime.Driver` (`ID`, lifecycle, `Exec`, `CopyIn`, `CopyOut`). The
  microVM driver implements exactly this interface; no second runtime contract.
- `hal sandboxd`, worker jobs, leases, the scheduler and target selection.
- Workspace materialization from git bundles, sync-out, recovery artifacts and
  `hal sandbox apply`.
- Public JSON contracts. The runtime driver value `microvm` and isolation level
  `vm` already exist as reserved enum values.

### 4.2 New components

| Component | Responsibility | Size budget for v1 |
| --- | --- | --- |
| `internal/sandboxruntime/microvm` | Driver implementation; maps Driver calls to the shim | small |
| `internal/sandboxruntime/microvm/vmm` | `Backend` interface plus `firecracker` and `libkrun` implementations | small per backend |
| `cmd/hal-vm-shim` (or a `hal` subcommand) | One process per VM: starts the VMM, holds the vsock connection, survives daemon restart, exposes a local socket to `sandboxd` | small |
| `cmd/hal-agentd` with an `init` mode | Guest PID 1 duties (mounts, reaping, clock, entropy) and the control server (exec, copy, signals, health) | small, one static binary |
| `internal/egress` | Host egress proxy and policy, shared with the rootless lane (`hal-zl6.24`) | medium |
| `internal/credbroker` | Placeholder issuance and substitution inside the egress proxy | medium |
| `internal/vmimage` | OCI image to VM rootfs conversion, kernel pinning, cache | medium |

"Small" means it fits in one reviewer's head. If a component outgrows its
budget before its milestone has passed live, stop and redesign rather than add
layers.

## 5. Design decisions

### D1. Pluggable VMM, Firecracker first

`vmm.Backend` is a narrow interface: `Create(spec) (Handle, error)`,
`Start`, `Stop(grace)`, `Wait`, `Kill`, and an optional `Snapshotter`
capability. The driver never calls a VMM API directly.

| Option | Strengths | Weaknesses | Role |
| --- | --- | --- | --- |
| Firecracker | Built for multi-tenant untrusted code (AWS Lambda, Fargate); jailer applies cgroups, namespaces and privilege drop; rate limiters; production full snapshots | Linux/KVM only; no virtio-fs; no GPU | Default on Linux; required for T2/T3 |
| libkrun | Linux KVM and macOS Hypervisor.framework; virtio-fs; TSI and passt networking; small library | In-process VMM; its own security model says guest and VMM share a security context, so the VMM must itself be sandboxed for untrusted work; no documented snapshots | macOS backend (M5); optional Linux dev backend |
| Cloud Hypervisor | virtio-fs, snapshots, hotplug | Linux only; larger surface than Firecracker | Candidate if Linux needs virtio-fs later |
| QEMU microvm | Mature, everywhere | Large attack surface | Rejected for T2/T3 |

Decision: implement Firecracker first because T2/T3 are the business tiers, and
add libkrun for macOS once the shared pieces (agent, image, egress, credentials)
have passed live on Linux. The backend seam keeps that second step small.

### D2. Guest image from the existing OCI image

The VM runs the same agent image the rootless lane builds (`sandbox/Dockerfile`),
so engines, versions and tooling stay identical across runtimes.

- `hal sandbox image build --runtime microvm` exports the OCI image's rootfs to
  a read-only ext4 base image, adds `hal-agentd`, and records the image digest,
  kernel version and build inputs. Images are content-addressed and cached.
- Each VM gets the read-only base disk plus a fresh writable disk for the
  workspace and package caches. Nothing on the writable disk outlives the VM
  unless sync-out collects it.
- The kernel is a pinned, minimal guest kernel (Firecracker guest config on
  Linux; libkrunfw on macOS).
- v1 records provenance (digests and inputs). Reproducible-build proofs and
  signature verification are later hardening, not v1 gates.

### D3. Minimal guest: one binary, two modes

`hal-agentd init` runs as PID 1: mount filesystems, set the clock, seed entropy,
reap children, start `hal-agentd serve`, and power off when told to. `serve`
handles the control protocol. The workload runs as an unprivileged user; agents
that need root inside the VM (package installs, `dockerd`) get it inside the VM,
which is the point of having a VM.

No extra guest roles, helpers or monitors in v1. Add a process only when a live
test shows the need.

### D4. Control protocol over vsock

- Transport: vsock from host to guest (Firecracker exposes it as a host Unix
  socket; libkrun maps vsock ports to host Unix sockets).
- Framing: length-prefixed frames carrying versioned JSON control messages and
  binary data frames for stdio and file streams.
- Operations map one to one to the Driver: `exec` (argv, env, workdir, stdio
  streaming, exit status), `signal`, `copy_in` and `copy_out` (tar streams),
  `health`, `shutdown`.
- Bounds: every message and stream has a size and time limit; errors cross the
  boundary as safe codes, never raw host paths or secrets.
- Trust: the guest is untrusted. The host validates every message; the guest
  never chooses host paths.

### D5. Workspace without host filesystem sharing

v1 reuses the existing git-bundle materialization: `CopyIn` the bundle, apply
it with `Exec`, collect results with `Exec` and `CopyOut`. There is no shared
host directory, so the VM cannot read or write host files. Read-only virtio-fs
for faster dependency caches is a later optimization on backends that support
it.

### D6. Egress: no guest NIC in v1, a vsock proxy bridge instead

The simplest secure default is a VM with no network interface at all:

- `hal-agentd` listens on loopback inside the guest (for example
  `127.0.0.1:3128`) and forwards each connection over vsock to the host egress
  proxy.
- The guest environment sets `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` to that
  address. Git over HTTPS, package managers, model API clients and Docker pulls
  honor these variables.
- The host proxy enforces a host allowlist (HTTP CONNECT and SNI), resolves DNS
  itself (the guest needs no resolver), blocks private, link-local and metadata
  addresses, and writes a bounded decision log.

This removes tap devices, bridges and firewall rules from v1 and works the same
on Firecracker and libkrun. The trade-off: tools that open raw TCP without
proxy support cannot reach the network. A later milestone adds a real NIC with
host firewall rules for full TCP when a live use case needs it.

The same egress proxy serves the rootless lane (`hal-zl6.24`), so policy and
logs are identical across runtimes.

Configuration lives in `.hal/config.yaml`:

```yaml
sandbox:
  egress:
    mode: allowlist          # allowlist | open (open is explicit and logged)
    allow:
      - github.com
      - api.openai.com
      - registry.npmjs.org
```

### D7. Credentials: placeholders, substituted on the host

- The VM receives placeholder tokens (for example `hal_ph_<id>`) in the
  environment and config files instead of real secrets.
- For HTTPS hosts that need credentials, the host proxy terminates TLS with a
  per-VM CA that the guest trusts, replaces placeholders in request headers
  with the real secret, and forwards the request only if the destination is on
  that credential's host list. Replies are scanned so secrets are not echoed
  back into the VM.
- A placeholder is bound to one VM and one job; using it elsewhere fails.
- Hard case, scheduled explicitly: agent CLIs that store OAuth tokens and
  refresh them themselves (Codex and Claude subscription logins). The broker
  must intercept refresh endpoints and keep refreshed tokens on the host. Until
  that lands, copying engine auth into the VM is allowed only as a labelled,
  opt-in fallback, and status output must say so.
- SSH agent forwarding over vsock with per-host allowlists comes after HTTPS.

### D8. Lifecycle, durability and recovery

- One shim process per VM owns the VMM process and the vsock connection. The
  daemon talks to shims over local sockets, so restarting `hal sandboxd` does
  not kill running VMs.
- On restart, the daemon reattaches to shims recorded in its durable job store.
  A VM whose state cannot be proven is terminated and its job is reported as
  interrupted, never silently rerun (the existing L2/L3 job semantics).
- Teardown kills the VMM, removes the writable disk, sockets and any network
  state, and releases the lease. A census test asserts nothing is left.

### D9. Hardening by tier

| Control | T1 | T2 | T3 |
| --- | --- | --- | --- |
| Hardware VM boundary | yes | yes | yes |
| VMM runs as the invoking user, no extra privileges | yes | no | no |
| Firecracker jailer (chroot, namespaces, privilege drop) | optional | yes | yes |
| Per-VM UID, cgroups v2 CPU/memory/pids limits, disk quotas | basic limits | yes | yes |
| Firecracker seccomp filters, rate limiters | defaults | yes | yes |
| libkrun VMM wrapped in its own user and mount namespace | yes (macOS: sandbox profile) | n/a | n/a |

### D10. Snapshots and warm starts (after M4)

Firecracker full snapshots are production-ready, but restoring one snapshot
many times duplicates guest state. Restored VMs must reseed entropy (VMGenID),
regenerate per-VM identities and placeholders, fix the guest clock, and
reconnect vsock (connections close on resume). Warm pools are scheduled after
the cold path is solid.

## 6. CLI and configuration

- `hal doctor` reports KVM (Linux) or Hypervisor.framework (macOS)
  availability and which VMM backends are usable.
- `hal sandbox image build --runtime microvm` and `hal sandbox image list`.
- `hal sandboxd --driver microvm [--vmm firecracker|libkrun]`.
- `hal run|auto|factory run --sandbox --sandbox-runtime microvm`.
- `hal sandbox runtime status` shows the backend, tier and which capabilities
  have actually been enabled (egress mode, credential mode).
- Status and JSON output never claim a capability that is not active.

## 7. Milestones

Every milestone ends with a live acceptance test on real hardware and a
capability a user can run. A milestone that only adds contracts, types or
designs is not a milestone.

| # | Capability a user gets | Live acceptance |
| --- | --- | --- |
| M0 | Spike: a Firecracker VM boots the converted agent image and `hal-agentd` runs a command over vsock | Boot, exec `echo`, copy a file in and out, tear down, on a KVM host; record cold boot time |
| M1 | `hal run --sandbox --sandbox-runtime microvm` completes a fixture story in a VM, with egress through the vsock proxy bridge in `open` mode | The 2026-10-01 rootless smoke scenarios pass on the VM lane: run, rerun, apply, failing engine, zero leftover processes |
| M2 | Egress allowlist and DNS policy, shared with rootless | Allowed host succeeds; denied host, private/link-local/metadata addresses and raw TCP fail; decisions logged |
| M3 | HTTPS credential placeholders for GitHub and model APIs | Agent completes a story with no real token in the VM; a canary secret is absent from the VM disk, logs, artifacts and sync-out |
| M4 | Recovery: daemon restart, client loss, VM crash | Existing L2/L3 semantics hold; repeated recovery converges; census finds nothing left |
| M5 | macOS on Apple Silicon via libkrun | M1-M4 acceptance on a Mac |
| M6 | T2 hardening: jailer, per-VM UID, cgroups, quotas, rate limits | Fork bomb, memory hog and disk fill in one VM do not affect another; jailer layout verified |
| M7 | Docker inside the VM | Agent runs `docker build` and `docker run` inside the VM through the egress proxy |
| M8 | Snapshot warm starts | Restored VM is unique (entropy, identities, placeholders) and starts within the target |
| M9 | Fleet: multi-host scheduling, image distribution, metering | Jobs spread across hosts with leases; usage metered per job |

Engine OAuth refresh through the broker (D7) is scheduled into M3 or M4 once its
design is reviewed.

## 8. Testing policy

- Each milestone's acceptance test is a tagged Go test or script that runs on a
  KVM-capable machine (local or a self-hosted CI runner) and fails on any skip.
- Unit tests use fakes at the `vmm.Backend` and shim boundaries. Fakes prove
  logic, never capabilities.
- Tests assert behavior a user can observe. No tests that lock documentation
  text, file hashes, or "this package must not read X" implementation details.
  The removed attempt had such guards; one of them hid a real rerun bug.
- Every capability claim in status output has a live test that would fail if the
  claim were false.

## 9. Lessons from the removed attempt (`ddeb61eb`)

The previous VM lane reached about 108,000 lines of production code and
145,000 lines of tests without ever booting a job end to end. What went wrong,
and the rule each lesson produced:

1. Proof before product. Static call-graph analysis of guest binaries,
   attestation formats and FD-lifetime designs were built for paths that had
   never run. Rule: a walking skeleton (M0, M1) runs before any hardening layer.
2. All-or-nothing claims. "Strict" required every proof at once, so nothing
   could ship incrementally. Rule: each milestone ships its own honest claim.
3. Too many guest roles. A six-role, later eight-FD guest topology multiplied
   lifecycle states. Rule: one guest binary until a live test proves otherwise.
4. No hardware. Months passed without a KVM host. Rule: M0 starts only when a
   KVM-capable machine and CI runner are available.
5. Guard tests that froze implementation details. Rule: test behavior only (see
   section 8).
6. Parking instead of deleting. Unwired code accumulated. Rule: code that is
   not wired into a user path within its milestone is deleted.

Reference material in git history at `ddeb61eb` (read for ideas, reimplement
small; do not restore wholesale):

- `internal/sandboxruntime/networkenforcement/policyproxy`: HTTP/CONNECT policy
  proxy with loopback tests (input for D6).
- `internal/sandboxruntime/microvm/firecracker`, `.../firecrackerhost`: Firecracker
  API and jailer launch code (input for D1, D9).
- `internal/sandboxruntime/microvm/guestagent/frame`, `.../session`: vsock
  framing ideas (input for D4).
- The minimal guest image assembly notes under `tools/microvm/` at that
  commit (input for D2).

## 10. Open questions for the product owner

1. Which tier comes first commercially: T2 (sell to teams running their own
   servers) or T3 (hosted Hal)? This decides whether M6 moves ahead of M5.
2. How important is macOS for the first paying users?
3. Is copying engine OAuth into the VM acceptable as a labelled fallback until
   the broker handles token refresh?
4. Which KVM machine and CI runner will host M0 acceptance?

## Sources

- [Firecracker](https://github.com/firecracker-microvm/firecracker) and its
  [snapshot support notes](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md)
- [libkrun](https://github.com/containers/libkrun) (security model section)
- [microsandbox](https://github.com/superradcompany/microsandbox)
- [Gondolin](https://earendil-works.github.io/gondolin/)
- [NVIDIA OpenShell overview](https://docs.nvidia.com/openshell/about/overview)
- [Vercel: microVMs vs containers](https://vercel.com/i/microvm-vs-container)
