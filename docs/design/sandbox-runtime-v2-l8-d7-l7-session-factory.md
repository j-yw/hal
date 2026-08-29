# L8 D7 production L7 recovery session factory

This slice adds the default-off Firecracker host factory that builds complete
`l7network.ReconcilerOptions` for same-boot Finalize cleanup. Callers construct
it with `NewProductionL7RecoverySessionFactory` from injected journal, TAP,
rules, and recovery topology. The factory always attaches
`l7network.NewRecoveredVMTerminationVerifier` and never invents missing
adapters. A recovery binding may hold the factory and pass those options into
Finalize when `recoverNetwork` is unset.

Missing or typed-nil dependencies fail closed with
`l7network.ErrInvalidConfiguration`. A nil factory or incomplete stored options
fail closed with `errL8RuntimeOwnerInvalid` before Finalize persists `finalized`.
`l8RuntimeOwnerCleanupAfterVMQuiesced` still constructs `l7network.NewReconciler`
from those complete options. Default constructors and
`NewProductionL8JobCredentialRuntime` do not call `l7network.NewReconciler`.

`sandboxd`, `hal run`, `hal auto`, factory, worker `Service`, and
`NewProductionL8JobCredentialRuntime` do not invoke the factory unless a caller
injects it. This slice does not accept D7 prepared-Linux live proof, does not claim L8,
L10, or L11 complete, and does not change live stub fatals.

Tests are fake-only. They inject existing l7network TAP construction with a
fake namespace command plus fake recovery topology and rule adapters. They do
not boot a VM, call billed APIs, or select live tags.

## Focused verification

```sh
go test ./internal/sandboxruntime/microvm/firecrackerhost -run 'ProductionL7RecoverySessionFactory|L7SessionFactory' -count=1
go test ./cmd -run 'L7SessionFactory|L8D7PreparedLinuxDefaultConstructorsDoNotCreateL7SessionFactory' -count=1
go test ./internal/sandboxruntime/microvm/firecrackerhost/l7network -run 'ImportBoundary|NotWiredIntoDefaultPaths' -count=1
go vet ./internal/sandboxruntime/microvm/firecrackerhost ./cmd
```

## Broad verification

```sh
go test ./...
go vet ./...
make docs-check
make build
git diff --check
```

`golangci-lint` is reported only when `command -v golangci-lint` succeeds.

## Non-goals

This slice does not:

- accept D7 prepared-Linux live proof;
- implement sealed PID1 expected digests, live helper transport, or a durable
  handle store;
- wire sandboxd, run, auto, or factory defaults;
- claim L8, L10, or L11 complete;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`.
