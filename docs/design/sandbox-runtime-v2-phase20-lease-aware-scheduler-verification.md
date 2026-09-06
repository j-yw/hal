# Sandbox Runtime v2 Phase 20 Lease-Aware Scheduler Verification

Phase 20 covers the lease-aware scheduler for explicit sandbox host/runtime
requests. It keeps scheduling in `internal/sandboxtarget`, wires explicit
`hal run --sandbox`, `hal auto --sandbox`, and `hal factory run --sandbox`
requests through command-layer scheduler and lease helpers, and preserves the
legacy default sandbox resolver when no `--sandbox-host` or `--sandbox-runtime`
flag is provided.

## Scope

The scheduler is a cached metadata decision layer. It enumerates durable
`sandbox.SandboxHost` records through fakeable command dependencies, filters by
explicit host, cached health, runtime, isolation, and lease-aware capacity,
ranks candidates deterministically, and returns a selected target plus a lease
requirement for the command boundary to acquire.

Command code owns lease acquisition, release, and persistence. Persisted
metadata must include only safe `SandboxLeaseRef` or factory
`SandboxLeaseMetadata` fields: lease id, selected host id/name, runtime driver,
resource key, purpose, run id, acquired time, and expiry time. It must omit
lease holders, endpoints, hostnames, filesystem paths, repository URLs, worker
socket paths, bundle paths, credential values, and raw provider details.

Phase 20 verification is fake-only. Tests must use fake cached hosts, fake
leases, fake clocks, fake runtime drivers, fake providers where setup still
needs a provider boundary, temporary `HAL_CONFIG_HOME` values, and no live
worker or sandbox daemon.

## Focused Verification Commands

Run scheduler contract, filtering, capacity, ranking, import-boundary, and
safety checks:

```sh
go test -timeout=120s ./internal/sandboxtarget -run 'TestScheduler|TestSandboxtarget|TestSchedulerProductionImportsStayCommandAgnosticAndOffline|TestSchedulerImportBoundaryRejectsWorkerProviderAndNetworkCoupling'
```

Run default-preservation checks:

```sh
go test -timeout=120s ./cmd -run 'Test(Run|Auto|Factory)SandboxLegacyDefaultResolutionDoesNotUseSchedulerOrLeaseMetadata|Test(Run|Auto|Factory)SandboxDefaultTargetResolutionStaysCachedAndFakeOnly'
```

Run explicit scheduler and lease wiring checks:

```sh
go test -timeout=120s ./cmd -run 'Test(Run|Auto|Factory)SandboxExplicitSchedulerAcquiresLeaseAndPersists|Test(Run|Auto|Factory)SandboxSchedulerFailure|TestFactorySandboxSchedulerFailureRecordsFailureBeforeRuntimeConstruction'
```

Run lease lifecycle and scheduler safety checks:

```sh
go test -timeout=120s ./cmd -run 'TestScheduledSandboxCommandsReleaseAcquiredLeaseExactlyOnce|TestScheduledSandboxCommandCancellationReleasesLease|TestSandboxCommandDefaultLeaseListerExpiresStaleLeases|TestSandboxScheduler'
```

Run the Phase 20 documentation guard:

```sh
go test -timeout=120s ./cmd -run 'TestPhase20LeaseAwareSchedulerDocumentationCoversVerificationAndScope'
```

Run doc/build/typecheck verification:

```sh
make docs-check
git diff --check
go test -timeout=300s ./...
go vet ./...
make build
make lint
```

Run `make docs-cli` before `make docs-check` when command metadata, examples,
or generated CLI surfaces change.

These commands cover command-agnostic scheduler boundaries, deterministic
cached host enumeration, health/runtime/isolation filtering, capacity counting,
candidate ranking, explicit run/auto/factory wiring, safe lease metadata,
lease release and stale-expiry behavior, scheduler safety redaction, generated
documentation drift, the full Go package graph, vet, build, and lint when the
linter is installed.

## Phase 20 Non-Goals

Phase 20 verification explicitly excludes scheduler daemon behavior, live
refresh, Podman or Docker workflows, cloud provider dependencies, microVM
execution, network proxy enforcement, firewall enforcement, and secret broker
support.

Do not start a scheduler daemon, run `hal sandboxd`, refresh live worker
capabilities, bind real worker sockets, contact remote worker hosts, run Podman
or Docker workflows, pull images, access KVM or other microVM devices, access
cloud APIs, open network connections, configure a network proxy, configure a
secret broker, or require provider credentials as part of Phase 20 story
verification.

No scheduler daemon, no live refresh, no Podman/Docker/cloud dependency, no
microVM, no network proxy, and no secret broker are required for this phase.

## Review Notes

`internal/sandboxtarget` must remain command-agnostic. Scheduler production code
must not import Cobra, `cmd`, factory, engine, loop, PRD, compound, concrete
runtime adapters, worker clients, provider packages, or network-only
dependencies.

Default `hal run --sandbox`, `hal auto --sandbox`, and
`hal factory run --sandbox` without explicit host/runtime flags must remain on
the legacy resolver path. Explicit scheduler rejections happen before provider
construction, worker client construction, runtime driver construction, target
ready hooks, or persisted target metadata.
