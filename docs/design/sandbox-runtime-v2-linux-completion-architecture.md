# Sandbox Runtime v2 Linux Completion Architecture

## Authority

This document is the checked-in architecture map for issue #49 phases L0-L11.
The three locked issue comments remain authoritative:

- verified scope and Linux-first decision: issue comment `5068151561`;
- Linux-first technical specification: issue comment `5068157402`; and
- implementation order and prepared-Linux handoff: issue comment `5068162708`.

A phase-specific design may refine internal names and algorithms. It must not
weaken the locked behavior, move an acceptance proof to a fake, or claim work
owned by a later phase. A conflict is resolved in the issue before code is
merged.

PR #44 and `feature/sandbox-runtime-secure-default-v2` are the integration
baseline. The long-lived Linux-completion branch is stacked on that branch;
phase branches are merged into Linux completion only after their own gates
pass. A moving integration baseline is merged forward without rebasing shared
history.

## Product boundary and claim model

The completed product has two intentionally different postures:

- **rootless advisory** uses the real rootless Podman worker path but makes no
  microVM or strict security claim; and
- **strict secure default** is available only when every required production
  proof is active, current, warning-free, and correlated to the same sandbox
  and execution.

Strict success is a conjunction, not a score:

```text
strict =
  Firecracker guest isolation and readiness
  AND proxy plus inspected Linux network enforcement
  AND live credential-delivery proof
  AND verified immutable template descriptor
  AND workspace integrity and safe sync-out state
  AND one matching sandbox/execution identity
  AND no fallback, simulation, stale proof, or warning
```

Missing, stale, mismatched, unsupported, cleanup-failed, or simulated evidence
fails closed. Projection and rendering code may downgrade a claim but may never
upgrade it.

## End-to-end architecture

```text
cmd
  parses intent, selects a sandbox/run, wires dependencies, renders safe output
    |
    +-- internal/sandboxtarget
    |     cached selection, capability filtering, scheduler decisions
    |
    +-- internal/sandboxtemplate/acquisition
    |     immutable OCI descriptor resolution and digest verification
    |
    +-- internal/sandboxworker
    |     local daemon, durable jobs, redacted logs, live runtime ownership
    |          |
    |          +-- rootless Podman runtime
    |          |
    |          +-- Firecracker host/runtime
    |                    |
    |                    +-- host-side virtio-vsock bridge
    |                              |
    |                              +-- guestagent server in built guest image
    |
    +-- internal/sandbox/networkenforcement
    |     policy proxy, topology, Linux rules, inspection, cleanup proofs
    |
    +-- credential activation/lifecycle packages
    |     memory-only secret broker plus HTTP/tmpfs/SSH-agent delivery
    |
    +-- internal/sandboxexecution
    |     safe manifest/job reference, containment, recovery journal, artifacts
    |
    +-- internal/sandboxworkspace
          sync-out summaries and explicit safe host apply
```

The command layer composes these packages. It does not own a second scheduler,
job store, policy engine, guest protocol, registry client, firewall adapter, or
secret store.

## Identity and evidence correlation

Every live proof used for a strict claim is bound to safe immutable identity:

- sandbox ID and sandbox name;
- execution/run ID;
- worker ID and durable host ID;
- runtime driver and runtime ID;
- worker job ID and caller-stable submission digest;
- policy snapshot and network-proxy session IDs;
- credential-proxy/delivery session IDs;
- template manifest/blob digests; and
- workspace input revision and sync-out result.

Raw endpoints, hosts, IP addresses, URLs, ports, headers, bodies, credentials,
secret values, process arguments, environment values, and host-local paths are
not evidence identifiers and do not enter durable public metadata.

Evidence is produced by the component that performed or inspected the behavior.
Command status projections sanitize and correlate that evidence; they do not
manufacture it from configuration intent.

## Cross-phase invariants

### Purity and ownership

- Dry-run returns before durable IDs, stores, registries, workers, providers,
  leases, runtimes, workspaces, artifacts, sync-out, apply, or cleanup.
- A daemon-owned job survives initiating-client loss. Client cancellation does
  not imply job cancellation.
- Recovery never provisions, starts, bootstraps, rewrites project inputs,
  re-delivers auth, or relaunches an agent.
- Cleanup affects only resources whose ownership and identity are proved.

### Durability and recovery

- Durable state uses private ownership and modes, strict schemas, contained
  paths, atomic publication, and redaction-safe errors.
- Unknown or interrupted work is never presented as running or successful and
  is never silently rerun.
- Finalization is lock-protected, checkpointed, restartable, and idempotent.
- Artifact metadata uses stable identities; retries do not duplicate entries.
- Host apply remains explicit and fails closed across ambiguous mutation
  windows.

### Protocol and data safety

- All machine output has a documented versioned contract and emits exactly one
  JSON document.
- Protocol payloads, logs, copies, and files are bounded.
- Dynamic errors cross trust boundaries only as safe codes and sanitized
  summaries.
- Secret values stay in memory-only live structures and are redacted before
  logs, errors, manifests, events, artifacts, or process metadata.

### Linux acceptance

- Linux process, KVM, namespace, firewall, topology, vsock, credential lifetime,
  and crash/reconnect behavior is accepted on the prepared Linux machine.
- Ordinary CI and cross-platform compilation remain regression gates.
- A skipped required live test is a blocker/boundary result, never a pass.
- No Hetzner, Lightsail, or other billed cloud call is authorized by this plan.

## Dependency graph

```text
L0 baseline
 ├─> L1 dry-run purity
 ├─> L2 durable jobs ─> L3 recovery UX ────────────────┐
 ├─> L4 guest server ─> L5 guest image/vsock/E2E ────┤
 ├─> L6 policy proxy ─> L7 Linux enforcement/topology ┤
 │                         └─> L8 credential delivery ┤
 └─> L9 OCI acquisition/selection/trust ──────────────┤
                                                      v
                                             L10 composition
                                                      |
                                                      v
                                             L11 final closure
```

L9 is architecturally independent after baseline/purity and may be developed in
parallel. It is merged through the same ordered aggregate branch so integration
evidence remains reproducible.

## Phase contracts

| Phase | Owned deliverable | Prepared-Linux exit | Explicit boundary |
|---|---|---|---|
| L0 | Capability and baseline record | Clean exact base, required capabilities, baseline gates, tagged pass/fail/skip record, cleanup proof | No product changes or billed cloud |
| L1 | Pure run/auto sandbox preview | Panic fakes prove every forbidden boundary is untouched; no durable-looking IDs or active-security claim | No recovery, runtime, provider, or security implementation |
| L2 | Durable asynchronous worker jobs | Job survives client loss; bounded logs/status work; restart is proven terminal or unknown/interrupted; no secret persistence | No sandbox-centric recovery UX or retention pruning |
| L3 | Live discovery, logs, recovery, sync-out, finalization | Kill CLI, rediscover, follow, restart, repeatedly recover, safely collect, release once, converge state/counts | No guest, proxy, firewall, credential, OCI, or implicit apply work |
| L4 | Production guest-agent server behind injected transport | Readiness/version, exec/copy, bounds, containment, timeout/cancel, malformed input, redaction | No Firecracker transport/image claim |
| L5 | Reproducible guest image and Firecracker vsock integration | Boot produced assets; real guest readiness/exec/copy/timeout/cancel and teardown | API socket/process launch alone is insufficient |
| L6 | Production HTTP/CONNECT policy proxy | Allowed and denied live traffic; health/lifecycle; bounded safe decisions; cleanup | No strict network claim without Linux rule proof |
| L7 | Podman/Firecracker topology and Linux rules/inspection | Positive traffic plus DNS/direct/private/link-local/metadata/IPv4/IPv6 bypass negatives; restart cleanup | No config-only or plan-only enforcement claim |
| L8 | HTTP, tmpfs-file, and SSH-agent credential activation | Credential usable only in intended job and absent after every terminal/failure/restart path | Env/legacy/simulated modes remain compatibility-only |
| L9 | Production OCI Distribution acquisition and selection | Local-registry pull/cache; media/size/digest/auth/mutation failures close safely; cleanup | Signature/transparency is later hardening, not initial trust proof |
| L10 | Strict composition and default selection | Full correlated scenario succeeds; removing/corrupting any proof fails closed | Rootless advisory can never be upgraded |
| L11 | Final matrix, cleanup, contract/docs/release evidence | Rootless and strict scenarios, crash/reconnect, negative security, artifacts, and zero leaked resources | Hetzner/Lightsail remain deferred or move to a separate issue |

## Phase design and implementation rule

Before a phase changes production code, its branch contains a design note that
defines:

1. exact inputs, outputs, states, and failure codes;
2. package ownership and import boundaries;
3. durable and machine-contract schema changes;
4. redaction and containment rules;
5. crash, retry, cancellation, and cleanup semantics;
6. red-first fake and live acceptance tests; and
7. non-goals and the next-phase handoff.

Red tests are committed before their implementation. Independent reviewers use
clean detached worktrees at the exact candidate commit and compare against the
stack base. Generated patches are evidence only until independently validated.

## Validation and evidence

Every phase runs at least:

```text
focused unit and race tests
go test ./...
go test -count=1 -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
gofmt verification
golangci-lint when installed
```

Relevant tagged prepared-Linux tests, cross-platform compile checks, security
negative tests, and resource cleanup checks are additional gates, not
substitutes. The issue evidence records the exact base, phase head, aggregate
merge, commands/results, reviews, skips, cleanup, and next handoff without
endpoints, sockets, hostnames, identifying paths, or secrets.
