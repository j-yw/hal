# Sandbox Runtime v2 Phase 48 Secure-Default Runtime Status Verification

Phase 48 wires secure-default readiness decisions into runtime status/list
output and documentation. It is a status and documentation phase only: it does
not add live runtime execution, live network enforcement, credential delivery,
template acquisition, VM boot validation, or worker daemon validation.

Default Phase 48 runtime status/docs verification is fake-only.

Live E2E validation is future Phase 49 scope.

## Focused Checks

```bash
go test -count=1 ./cmd -run 'TestUS009SandboxRuntime'
go test -count=1 ./cmd -run 'TestUS009RuntimeDocs'
go test -count=1 -run '^$' ./...
make docs-check
git diff --check
```

These checks cover cached runtime list/status output, JSON contract surfacing,
human output wording, contract documentation, generated CLI examples, redaction,
and documentation drift. They must stay fake-only and deterministic.

## Secure-Default Output Expectations

Runtime list/status output may include `security.securityReadinessGate` when
sanitized readiness metadata or a stored gate decision is available. The field
must carry only redaction-safe labels: decision code, outcome, policy mode,
reason, aggregate counts, and reason-code counts.

Strict secure-default readiness reports blocked decisions when required proof is
missing. Compatibility advisory output reports diagnostics without claiming live
protection. Proof-complete allowed states report aggregate counts and reason
codes for satisfied proof families.

Requested/planned metadata alone does not prove deny-by-default networking,
active credentials, digest-locked templates, or VM isolation. Runtime status and
docs must keep those distinctions explicit.

## Non-Goals

Phase 48 does not require KVM, Firecracker live boot, real firewall/proxy, real secret broker, Docker/Podman, cloud, or network execution.

Do not add live Firecracker boot checks, firewall or proxy mutation, credential
broker sessions, credential injection, Docker or Podman workflows, cloud API
calls, external network calls, or live worker daemon requirements to Phase 48
verification.
