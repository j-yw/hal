# Sandbox Runtime v2 Phase 30 Security Readiness Gate Verification

Phase 30 adds a strict security readiness gate contract and evaluator for
sanitized Phase 29 readiness diagnostics. The evaluator is data-only and
redaction-safe; command wiring must stay explicit and non-blocking unless a
clean policy hook already exists for a command path.

## Gate Behavior

The pure evaluator lives in `internal/sandbox/security_capability_gate.go`.
It converts sanitized `capabilityReadinessDiagnostics` into a
`SandboxSecurityCapabilityReadinessGateDecision` with stable, safe policy
mode, outcome, reason, code, and aggregate count metadata only.

The supported policy modes are `off`, `advisory`, and `strict`.

- `off` is the default and always allows execution, even when diagnostics say
  a strict gate would block.
- `advisory` records advisory gate metadata when strict mode would block, but
  still allows execution.
- `strict` blocks only when the diagnostics contain strict-blocking readiness
  conditions or when readiness diagnostics are missing.

The default Phase 30 behavior remains non-blocking. Readiness diagnostics
continue to be advisory metadata unless a command path explicitly opts into a
strict policy hook.

## Run/Auto Strict Mode Hook Decision

`hal run --sandbox` and `hal auto --sandbox` remain advisory-only for readiness diagnostics in Phase 30.

The run/auto sandbox security request path was inspected. Both commands load
local sandbox configuration through `compound.LoadSandboxConfig` before
workspace planning and remote execution, and `compound.LoadSandboxConfig` maps
`sandbox.networkPolicy` and `sandbox.secrets` into
`sandbox.SecurityEvaluationRequest`. Those typed config surfaces describe
requested network policy metadata and secret delivery metadata only.

No run/auto config hook currently represents `off`, `advisory`, and `strict`
readiness-gate policy modes before workspace planning, auth sync, or remote
execution. Reusing `sandbox.networkPolicy`, `sandbox.secrets`, or `auto.mode:
strict` would conflate unrelated policy concepts: `auto.mode` is the compound
review/CI policy preset and does not apply to `hal run --sandbox`.

Because no clean existing run/auto hook exists, run/auto strict readiness mode
is not wired in Phase 30. Default behavior and advisory readiness diagnostics
remain non-blocking. No run or auto command flag is added for readiness-gate
strict mode. Non-factory sandbox manifests do not persist readiness gate
policy-decision metadata. The factory policy hook
`factory.policy.securityReadinessGatePolicyMode` is the accepted explicit
policy surface, so factory is the first strict blocking path.

## Command And Factory Wiring

Factory policy configuration accepts `factory.policy.securityReadinessGatePolicyMode`
as the Phase 30 opt-in policy surface. Missing configuration remains equivalent
to `off` while preserving `omitempty` behavior on durable policy snapshots.

Factory sandbox execution evaluates the gate after sanitized factory sandbox
security metadata and readiness diagnostics have been attached to the run
record, and before remote bootstrap, runtime driver resolution, or remote
execution. In `strict` mode, a blocking decision records a redaction-safe
policy decision event, fails the run at `prepare_inputs`, and returns an error
containing only safe gate metadata. In `advisory` mode, the same policy
decision metadata is recorded without blocking execution.

Run and auto sandbox execution keep using advisory readiness diagnostics only.
They do not add readiness-gate command flags, remote arguments, manifest gate
fields, scheduler calls, lease acquisition, live provider refreshes, or worker
runtime resolution on the default path.

## Focused Verification Commands

Run the pure evaluator coverage:

```bash
go test -timeout=120s ./internal/sandbox -run 'TestSecurityCapabilityReadinessGate'
```

Run factory policy-mode config and additive JSON coverage:

```bash
go test -timeout=120s ./internal/factory -run 'Test(FactoryPolicy.*SecurityReadinessGate|LoadPolicyConfig.*SecurityReadinessGate|PolicyDecisionMetadataSecurityReadinessGate)'
```

Run the factory strict/advisory gate coverage:

```bash
go test -timeout=120s ./cmd -run 'TestRunFactorySandboxExecutor(StrictReadinessGateBlocksBeforeRemoteExecution|AdvisoryReadinessGateRecordsWithoutBlocking)'
```

Run the run/auto advisory-only non-wiring coverage:

```bash
go test -timeout=120s ./cmd -run 'Test(Run|Auto)SandboxLocalReadinessGateConfigRemainsAdvisoryOnly|TestRunAutoReadinessGateNonWiringDocumented'
```

Run default run/auto non-blocking and no scheduler/lease/live-refresh coverage:

```bash
go test -timeout=120s ./cmd -run 'Test(Run|Auto)SandboxDefaultReadinessGateDoesNotTriggerSchedulerLeaseOrLiveRefresh'
```

Run scheduler, target-selection, sandboxexec, and worker-protocol regression
coverage:

```bash
go test -timeout=120s ./internal/sandboxtarget -run 'Test(ScheduleIgnoresStrictBlockingSecurityReadinessForFilteringAndLease|ScheduleCapacityRejectionIgnoresStrictBlockingSecurityReadiness|SelectExplicitSandboxDoesNotRejectStrictBlockingSecurityReadiness)'
go test -timeout=120s ./internal/sandboxexec -run 'TestRunDoesNotRejectWorkerTargetWithStrictBlockingSecurityReadiness'
go test -timeout=120s ./internal/sandboxworker -run 'TestWorkerProtocolOmitsSecurityReadinessGateDecisionFields'
```

These focused commands are fake-only. They cover the pure evaluator, policy
config parsing, factory strict/advisory behavior, default non-blocking
run/auto behavior, scheduler and target-selection non-wiring, sandboxexec
non-rejection, and worker protocol non-expansion.

## Broad Verification Commands

Run the full package test pass, empty-run typecheck, vet, documentation check,
build, and whitespace verification before integrating Phase 30:

```bash
go test -count=1 -timeout=420s ./...
go test -count=1 -timeout=300s -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

`make lint` is optional for Phase 30 and may be unavailable when
`golangci-lint` is not installed. Run it only when the tool is available, and
record it as unavailable rather than as a required failed check when it cannot
run in the current environment.

## Fake-Only Scope

Phase 30 verification is metadata-only and fake-only. Tests should use pure
data contracts, JSON marshaling, reflection over struct tags, temporary
stores, fake command dependencies, fake clocks, fake runtime drivers, cached
target metadata, factory stores, production source scans, and seeded unsafe
strings.

Phase 30 test commands must not use integration build tags, require live
environment variables, contact remote services, start providers, start
runtimes, start worker daemons, run `hal sandboxd`, bind live worker sockets,
start network proxies, mutate firewall state, deliver credentials, or perform
live scheduler/lease/provider/runtime enforcement.

## Non-Goals

No scheduler filtering is included in Phase 30.
No target rejection based on readiness diagnostics is included in Phase 30.
No lease rejection based on readiness diagnostics is included in Phase 30.
No live enforcement is included in Phase 30.
No live network proxy enforcement is included in Phase 30.
No firewall integration or firewall mutation is included in Phase 30.
No credential broker behavior or credential delivery is included in Phase 30.
No worker protocol changes are included in Phase 30.
No worker daemon behavior is included in Phase 30.
No runtime/provider integrations are included in Phase 30.
No Docker, Podman, KVM, or microVM runtime requirement is included in Phase 30.
No run/auto strict readiness-gate mode is wired in Phase 30.
No broad CLI UX changes are included in Phase 30.

Future phases are responsible for any scheduler readiness filtering, target
rejection, lease rejection, live enforcement, worker protocol changes,
runtime/provider integrations, run/auto strict-mode policy surface, or broad
CLI UX changes based on security readiness diagnostics.

## Review Notes

Keep Phase 30 gate evaluation deterministic, redaction-safe, and separated
from live enforcement. The evaluator belongs in `internal/sandbox` and should
stay independent from command orchestration, factory orchestration, provider
adapters, runtime adapters, worker clients, process execution, Docker, Podman,
KVM, microVM, cloud SDKs, network clients, HTTP proxies, firewalls, credential
brokers, SSH agents, and tmpfs writers.

When Phase 30 test names change, update this document and the focused
verification commands together so the fake-only coverage remains aligned with
the implementation.
