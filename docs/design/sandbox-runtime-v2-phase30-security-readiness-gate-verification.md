# Sandbox Runtime v2 Phase 30 Security Readiness Gate Verification

Phase 30 adds a strict security readiness gate contract and evaluator for
sanitized Phase 29 readiness diagnostics. The evaluator is data-only and
redaction-safe; command wiring must stay explicit and non-blocking unless a
clean policy hook already exists for a command path.

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

## Focused Verification

Run the pure evaluator coverage:

```bash
go test -timeout=120s ./internal/sandbox -run 'TestSecurityCapabilityReadinessGate'
```

Run the factory strict/advisory gate coverage:

```bash
go test -timeout=120s ./cmd -run 'TestRunFactorySandboxExecutor(StrictReadinessGateBlocksBeforeRemoteExecution|AdvisoryReadinessGateRecordsWithoutBlocking)'
```

Run the run/auto advisory-only non-wiring coverage:

```bash
go test -timeout=120s ./cmd -run 'Test(Run|Auto)SandboxLocalReadinessGateConfigRemainsAdvisoryOnly|TestRunAutoReadinessGateNonWiringDocumented'
```

Phase 30 run/auto verification remains fake-only. It must not require live
cloud providers, Docker, Podman, KVM, microVMs, worker daemons, live network
proxies, firewall mutation, credential delivery, auth sync against a live
remote, scheduler filtering, target rejection, lease rejection, or broad CLI
UX changes.
