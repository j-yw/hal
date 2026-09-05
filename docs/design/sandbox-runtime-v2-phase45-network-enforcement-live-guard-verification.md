# Sandbox Runtime v2 Phase 45 Network Enforcement Live Guard Verification

Phase 45 adds guardrails for optional live network enforcement tests and
documentation only. It does not add production listener setup, firewall
mutation, runtime rule application, microVM egress enforcement, worker
availability guarantees, or default CLI behavior.

## Scope

Default verification is fake-only and does not require root privileges, network
access, firewall state, KVM, Docker, Podman, Firecracker, or live environment
variables. The default test path covers sanitized contracts, fake lifecycle
adapters, aggregation semantics, runtime projection, worker projection,
command-level guards, documentation checks, and source checks.

Optional live coverage is behind the `network_enforcement_live` build tag and
is not part of default verification. The current tagged file is a harness stub:
it compiles the opt-in boundary and skips unless every documented prerequisite
is present. Future live adapter tests must keep the same opt-in shape before
touching listeners, firewall/runtime rules, or process state.

The conversion command for this PRD is
`hal convert <generated-prd-md> --validate --json`:

```sh
hal convert <generated-prd-md> --validate --json
```

## Default Verification

Run the Phase 45 guard selector:

```sh
go test -count=1 -timeout=180s ./cmd -run 'Phase45|NetworkEnforcementLiveGuard'
```

Run network enforcement contract and fake lifecycle coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime/networkenforcement
```

Run the full repository verification stack:

```sh
go test -count=1 -timeout=420s ./...
go test -count=1 -timeout=300s -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

Run `golangci-lint run ./...` only when `golangci-lint` is installed. If it is
unavailable, report lint unavailable instead of reporting lint as passed.

## Optional Live Verification

Run optional live coverage only on a deliberately prepared host:

```sh
go test -tags=network_enforcement_live -count=1 -timeout=120s ./internal/sandboxruntime/networkenforcement -run 'TestNetworkEnforcementLiveHarnessRequiresExplicitOptIn|TestNetworkEnforcementLivePrerequisiteSkipMessagesAreClearAndRedacted'
```

The optional command is separate from default verification. It requires all of
these explicit opt-ins before any future live adapter test may touch live state:

- `HAL_NETWORK_ENFORCEMENT_LIVE=1`
- `HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=1`
- `HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=1`

The current stub still skips after validating the opt-ins because this phase
does not implement a live listener adapter or firewall/runtime adapter. Future
tests may add narrower adapter-specific variables for concrete implementations,
but they must keep the global opt-in and mechanism-level opt-ins above.

Optional live harnesses must clean up any listener, firewall, runtime rule, or
process state they create and report cleanup failures with sanitized warnings.
Cleanup instructions must identify only safe test-owned resources and must not
include raw endpoints, host paths, command lines, credentials, tokens, or
operator secrets.

## Documentation Guardrails

Default docs and CLI examples must not imply default secure enforcement,
default firewall mutation, default listener binding, or default microVM worker
availability. Examples may show requested policy metadata and explicit
capability metadata, but they must keep requested policy, planned policy,
metadata-only posture, active proxy listeners, active firewall/runtime rules,
and strong enforcement claims distinct.

Default command examples must not include `-tags=network_enforcement_live`,
live environment variables, root setup, firewall setup, Docker, Podman,
Firecracker, KVM, listener binding, `hal sandboxd` startup, or `--live`.
Optional live examples must be clearly labeled as opt-in and excluded from the
default verification matrix.

## Non-Goals

Phase 45 does not implement real proxy listeners, default listener binding,
firewall mutation, iptables/nftables or pf rule application, Docker or Podman
network policy tests, Firecracker network setup, KVM tests, root-required
tests, production microVM worker availability, cloud provider networking, or
live E2E network-policy enforcement.

Phase 45 also does not change `hal run`, `hal auto`, `hal factory run`,
`sandboxexec`, scheduler selection, worker routing, or `hal sandboxd` defaults.
Requested network policy metadata remains separate from proven enforcement.

## Review Notes

Keep this document, `cmd/phase45_network_enforcement_live_guard_test.go`, and
`internal/sandboxruntime/networkenforcement/network_enforcement_live_test.go`
in sync when optional live harnesses or documentation examples change. The
default verification matrix must remain fake-only, and the optional live
command must remain an explicitly tagged, explicitly environment-gated path.
