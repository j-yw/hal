# L8 D7 prepared-Linux acceptance remains unaccepted

This document freezes D7 prepared-Linux acceptance as **unaccepted**.
D7 prepared-Linux acceptance remains unaccepted after PRs 46–55.
This slice does not claim L8 complete, does not claim L10, and does not claim L11.
It does not implement live proofs, sealed PID1 digests, live
helper transport, a durable handle store, or a production L7 session
factory.

`tools/microvm/l8/verify-selected-live.sh` already names
`TestL8PreparedLinuxCredentialDeliveryPrerequisites` and
`TestL8PreparedLinuxCredentialDeliveryE2E` under package
`./internal/sandboxruntime/microvm/firecrackerhost` with tags
`firecracker_live`, `network_enforcement_live`,
`l7_linux_network_integration`, and
`l8_production_credential_delivery_live`. Those test functions now exist
only as tagged RED stubs. They `t.Fatal` with the four closures and must
not `t.Skip`. The wrapper must never t.Skip after the selected live test is discovered.
The wrapper must never treat a fixture as a passing live proof; `fixture-as-strict` is a forbidden practice.

The default go test ./... does not run D7 live tests. The stubs stay behind
the exact four-tag Linux constraint:

```
linux && firecracker_live && network_enforcement_live && l7_linux_network_integration && l8_production_credential_delivery_live
```

## Four RED closures

Live selected tests must `t.Fatal` naming all four still-unaccepted
closures. They must not `t.Skip`. The stable failure text contains
`dependency_unaccepted` and these four names:

1. `sealed PID1 expected digests` — `cmd/hal-guest-init/pid1_start_gate_linux.go`
   `loadPID1StartGateExpected` still returns absent (`present` false).
   Expected helper, client, and composition digests would come from
   sealed `L8ProcessCompositionFacts` compiled or inherited at image
   issuance. That sealed channel does not exist.
2. `live helper transport` — `credentialclient` already defines
   non-serializable authenticated packet and capability contracts and
   dispatches controller readiness through an injected transport. Helper
   lifecycle exchange still fail-closes with
   `ErrClientControlDependencyUnaccepted`; `control_contract_red.go` provides
   contracts and packet constructors, not a production listener, dialer, or
   `SCM_RIGHTS` transport adapter.
3. `durable handle store` — `L8JobCredentialRuntime.RecoverJobCredentials`
   returns `dependency_unaccepted` and mints no cleanup proof. HTTP
   tickets, tmpfs files, and SSH leases exist only as in-memory handles
   after Prepare.
4. `production L7 session factory` — Finalize fail-closes unless
   `recoverNetwork` or a complete `l7network.ReconcilerOptions` value is
   injected. Default constructors and
   `NewProductionL8JobCredentialRuntime` do not call
   `l7network.NewReconciler`.

## Selected live gates

```
tools/microvm/l8/verify-selected-live.sh prerequisites
tools/microvm/l8/verify-selected-live.sh e2e
```

`tools/microvm/l8/verify-selected-live.sh prerequisites` selects
`TestL8PreparedLinuxCredentialDeliveryPrerequisites`.
`tools/microvm/l8/verify-selected-live.sh e2e` selects
`TestL8PreparedLinuxCredentialDeliveryE2E` with subtests `http_only`,
`file_tmpfs_only`, `ssh_agent_only`, `all_modes`, and
`failure_recovery_matrix`.

Until the four closures exist, those tests stay RED: they `t.Fatal` and
must not `t.Skip`. A later GREEN slice may replace the fatal only after
sealed PID1 expected digests, live helper transport, a durable handle
store, and a production L7 session factory are actually accepted.

## Image and digest handoff names

D7 image issuance is not accepted here. Handoff names remain
`VerifiedL8Profile`, `verified-syscall-policy.hl8q`, and
`verified-pinned-callsites.hl8e`. This document does not treat those
artifacts, a fixture profile, or metadata as live proof.

## Focused fake-only commands

```
go test ./cmd -run '^TestL8D7PreparedLinux' -count=1
go test ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestL8D7PreparedLinux' -count=1
go vet ./cmd ./internal/sandboxruntime/microvm/firecrackerhost
```

These commands are fake-only. They do not boot a VM, call billed APIs,
or select the live tags.

## Broad verification

```
go test ./...
go vet ./...
make docs-check
make build
git diff --check
```

`golangci-lint` reported only when `command -v golangci-lint` succeeds.

## Non-goals

This slice does not:

- accept D7 prepared-Linux live proof;
- implement sealed PID1 expected digests, live helper transport, a
  durable handle store, or a production L7 session factory;
- claim L8, L10, or L11 complete;
- treat environment delivery as strict proof;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`.
