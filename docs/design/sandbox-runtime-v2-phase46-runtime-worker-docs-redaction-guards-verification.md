# Sandbox Runtime v2 Phase 46 Runtime Worker Docs Redaction Guards Verification

Phase 46 adds runtime and worker metadata redaction guards plus CLI
documentation example safety checks for credential-delivery live-readiness
work.

Default Phase 46 verification is fake-only and default-safe. It strengthens the
guard layer around `internal/sandboxruntime.RuntimeMetadata`,
`internal/sandboxworker.SecurityControls`, and
`internal/sandboxworker.RuntimeDriver` without adding live credential delivery,
network listeners, firewall mutation, provider integration, or microVM worker
enforcement.

## Guarded Metadata Scope

Runtime and worker metadata may carry only compact safe identifiers, enum-like
modes, status labels, reason codes, counts, and proven activation labels.

They must not carry secret values, raw endpoints, local paths, socket paths,
environment values, headers, bearer tokens, command lines, or raw credential
proxy metadata.

Plan-only credential delivery remains non-active. Active credential delivery
metadata requires a sanitized activation result with a safe activation ID and
safe active mode labels. Compatibility auth sync remains compatibility
metadata and must not be presented as active secure delivery.

Network enforcement metadata remains capability/result metadata only. A failed,
unsupported, partial, best-effort, or plan-only result must not be presented as
default network enforcement.

## CLI Documentation Safety

CLI examples must not present secure credential delivery, network enforcement,
or microVM worker enforcement as default availability.

Default CLI examples may show ordinary commands, cached metadata inspection, or
explicit `--live` refresh flags for supported status commands, but those
examples must not claim that secure credential delivery, network enforcement,
or microVM worker enforcement is generally available by default.

## Optional Live Behavior

Optional live behavior remains outside default Phase 46 verification.

Any optional live behavior mentioned by docs must stay behind explicit build
tags, explicit environment opt-ins, and skip by default when those opt-ins are
absent. Existing optional live network-enforcement coverage remains behind
`network_enforcement_live` plus `HAL_NETWORK_ENFORCEMENT_LIVE=1`,
`HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=1`, and
`HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=1`. Those optional checks are not part
of the Phase 46 default command examples.

## Focused Verification Commands

Run runtime metadata redaction guards:

```sh
go test -count=1 ./internal/sandboxruntime
```

Run worker metadata redaction guards:

```sh
go test -count=1 ./internal/sandboxworker
```

Run Phase 46 command, documentation, and CLI example guards:

```sh
go test -count=1 ./cmd -run 'TestPhase46'
```

Run repository typecheck:

```sh
go test -count=1 -run '^$' ./...
```

Run generated CLI documentation and whitespace checks:

```sh
make docs-check
git diff --check
```

Run `golangci-lint run ./...` only when `golangci-lint` is installed. If it is
unavailable, report lint unavailable instead of reporting lint as passed.

## Non-Goals

Phase 46 does not add live credential injection, proxy credential injection,
tmpfs secret delivery, SSH-agent forwarding, environment secret mutation,
production network enforcement, production microVM egress, provider
credentials, template acquisition, worker daemon requirements, Firecracker live
tests, or default live E2E verification.

Future live delivery work must keep default examples fake-only/default-safe,
preserve sanitized runtime and worker metadata boundaries, and document any
optional live test with explicit build tags, explicit environment opt-ins, and
default skips.
