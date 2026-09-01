# Sandbox Runtime v2 Host-Owned Strict Boundary

## Status and authority

This note records the selected simplification for the next issue #49
implementation slice. It refines the locked Linux-first comments `5068151561`,
`5068157402`, and `5068162708`; it does not weaken their fail-closed rule. The
source baseline is `3713cddaf7f4d0cb1591093f795fc6e551969cb6` on
`feature/sandbox-runtime-secure-default-v2`.

The architecture decision is selected. The implementation and prepared-Linux
acceptance are not complete. This document is not L8, L10, or L11 evidence and
does not change the current blocked/default-off state.

### Observed at the baseline

- Firecracker has a live process-launch path, but the current start plan can
  execute the configured Firecracker binary directly. `JailerPath` is optional
  configuration, not a strict launch requirement.
- Rootless Podman is implemented as a lower-isolation advisory runtime.
- L1-L7 and L9 provide useful orchestration, recovery, guest, network,
  workspace, and immutable-template authorities that should be reused.
- HL8E issuance remains fail-closed. The complete native role graph is bounded,
  while the five Go guest-role graphs remain unbounded without a complete
  points-to proof. No generated production evidence exists on this baseline.
- L8 prepared-Linux acceptance, L10 live composition, and L11 closure remain
  unaccepted.

### Proposed until live acceptance

Every strict behavior below remains a design and acceptance requirement until
production wiring and the selected prepared-Linux tests prove it. Configuration
intent, a fake, a plan, a runtime name, or this document cannot produce a
strict claim.

## Decision

The guest, including its kernel, init, helper processes, coding agent, tools,
and workspace contents, is untrusted. It may request work and consume scoped
capabilities, but it cannot create evidence that upgrades its own security
posture.

The prepared Linux host owns the security boundary:

- Firecracker provides the VM boundary, and the Firecracker Jailer is mandatory
  for every strict launch;
- host-owned namespaces, cgroups, process supervision, policy proxying, and
  inspected Linux rules own resource and network containment;
- the host-owned secret broker owns credential values, scope, lifetime,
  revocation, and cleanup proof; a guest receives only the minimum ephemeral
  capability required for the job; and
- host observers correlate live runtime, network, credential, immutable
  template, workspace, and cleanup evidence before publishing a strict state.

Firecracker alone is not strict proof, and the Jailer alone is not strict
proof. Strict success remains the conjunction of the existing real host-side
authorities. The simplification is where trust lives, not removal of network,
credential, template, workspace, or cleanup controls.

## Initial operating model

The first accepted deployment uses one prepared Linux worker with
`MaxConcurrentSandboxes=1`. Each run receives one fresh Firecracker microVM.
The VM and its owned host resources are torn down after the run; a VM is not
reassigned to a later run.

This is an intentionally small operational starting point. It avoids a
multi-tenant allocator while the boundary is proven. It is not a hardware
tenant-separation claim, a distributed scheduling claim, or permission to
reuse stale runtime authority.

Rootless Podman remains available for local development and advisory work. It
can never be projected, configured, or renamed into strict isolation. A direct
non-Jailer Firecracker launch may remain only as an explicitly non-strict
compatibility or test path; it cannot satisfy strict selection.

## Authority flow

```text
untrusted coding job inside one fresh guest
                    |
                    v
        scoped guest protocol/capabilities
                    |
                    v
prepared Linux host: Jailer + Firecracker + cgroup/namespace owner
                    |
                    +-- host network proxy and inspected rules
                    +-- host secret broker and revocation/cleanup
                    +-- immutable template and workspace authorities
                    |
                    v
        correlated, sanitized strict decision
```

The guest may report application results and readiness responses. Those are
inputs to host inspection, not security authority. Durable metadata contains
only sanitized identities, states, reason codes, and digests; it cannot be
deserialized into live authority.

## Migration and compatibility

No committed slice needs to be reverted before implementation. Existing
fail-closed checks stay in place while the host-owned path is added. In
particular, HL8E must remain unissued and must not be changed to a success
fixture merely to unblock strict mode.

The cutover removes HL8E from the strict selection critical path only after
red-first tests prove that strict authority comes exclusively from the
host-owned launch and live host evidence. The old generator may then remain as
offline hardening research or be removed in a separately reviewed cleanup;
neither outcome may weaken current fail-closed behavior during migration.

Compatibility behavior is explicit:

- rootless Podman remains advisory;
- direct Firecracker remains non-strict;
- existing local and SSH-machine behavior is not silently upgraded; and
- failure to satisfy the Jailer or any other strict authority returns a safe
  blocked result, never an advisory fallback presented as strict.

## Red-first implementation plan

### 1. Lock the host launch contract

Add focused failing tests before production changes. They must prove that a
strict Firecracker plan requires a configured Jailer, launches through that
Jailer rather than the raw Firecracker executable, rejects a direct-executable
substitution, and keeps public errors and summaries free of host paths. Keep a
passing compatibility test showing that the explicitly non-strict planning
path has not been silently removed.

### 2. Implement the smallest Jailer-owned launch seam

Extend the existing Firecracker config/start-plan/process-adapter boundary
instead of adding another runtime package. Make strict intent explicit in the
typed launch input. Validate it before process creation, build one immutable
Jailer launch plan, and have the existing process runner execute that plan.
Do not add a second supervisor, scheduler, proof format, or command-side
security evaluator.

The implementation must keep private paths and process arguments out of public
metadata and errors. Partial launch failure revokes authority and cleans only
the exactly owned VM, process, socket, namespace, cgroup, and state directory.

### 3. Move the strict claim to host evidence

Wire the existing strict-composition consumer to require the fresh Jailer-owned
Firecracker launch proof together with the existing live L7 network, L8
credential, L9 immutable-template, workspace, and cleanup authorities. Remove
HL8E from this selection dependency; do not manufacture an HL8E success.

Add remove-one-proof tests for Jailer launch, Firecracker readiness, network,
credentials, template, workspace, identity correlation, warnings, and cleanup.
Rootless, direct Firecracker, stale evidence, mismatched evidence, and durable
JSON alone must remain blocked.

### 4. Accept on prepared Linux, then enable selection

Keep strict default-off until a no-skip prepared-Linux lane proves one complete
run and each negative case. The live gate must inspect the actual Jailer-owned
process/cgroup/namespace boundary, guest readiness, network rules and proxy,
credential usability and absence after cleanup, immutable template binding,
workspace integrity, and zero owned-resource leaks.

Only after that evidence passes may L10 select strict by default and L11 record
the final matrix. Rollout starts with the one-worker/one-VM capacity limit.
Rollback disables strict selection and preserves evidence for diagnosis; it
must not relabel rootless or direct Firecracker as strict.

## Acceptance and verification

Default fake-safe checks for this boundary are:

```sh
go test -count=1 ./cmd -run '^TestL8HostOwnedStrictBoundary'
go test -count=1 ./internal/sandboxruntime/microvm/firecracker
go test -count=1 ./internal/strictcomposition ./internal/sandboxtarget
go test -count=1 -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

The focused launch tests must run before broader checks. `golangci-lint` is
reported as passed only when `command -v golangci-lint` succeeds and the tool
runs successfully.

The prepared-Linux acceptance command is introduced with the production slice,
not invented by this documentation change. It must use the repository's
selected-test wrapper, fail on a missing test or any skip, make no billed cloud
call, and clean all owned resources before returning. Until that lane exists
and passes, the honest result is `blocked`.

## Explicit non-goals

This direction does not add:

- a whole-Go syscall verifier or another attempt to solve global guest binary
  points-to analysis;
- gVisor, Kata Containers, or a second strict runtime;
- a distributed scheduler, worker mTLS, or hardware attestation;
- a multi-tenant UID/cgroup allocator or cross-tenant worker packing;
- a transparency log, signature framework, or new artifact publisher; or
- Hetzner, Lightsail, or any other billed-cloud acceptance dependency.

These may be separately justified later. None is required to prove the first
simple host-owned strict sandbox.
