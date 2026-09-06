# Selected Jailer prelaunch vsock parent pin

## Scope and observed gap

Base: `de9518fbcbcf4f81fa8b5626376dae8810fddb68`. The selected surviving
supervisor owns the existing strict lifecycle manager and coordinator. Its
constructor currently omits `withProcessLifecycleProductionVsock()`. Therefore
`startStrictJailerProcess` records the runtime UID and mapped host paths but
does not capture the private state-directory device/inode/owner before calling
the namespace runner. The resulting strict socket owner remains invalid; it
must not be repaired by statting an already running path.

This is DESIGN/RED, not a selected transport or live-runtime acceptance claim.
The approved extraction `newJailerRecoveryLifecycle` preserves the current
constructor behavior. Both the actual selected constructor and focused tests
call it. The root-only enclosing constructor's sealed-FD admission, reconnect
listener, coordinator staging and real Jailer are not exercised by these tests.

## Minimal proposed correction

After RED review, add only the existing production-vsock option to this private
selected helper. Do not change `newStrictJailerLifecycle` or the default
`NewProcessLifecycleManager` behavior. The option must be selected before
coordinator start, not attached after launch. No new manager, stat override,
transport, public flag, durable schema, generation, or proof is needed.

The existing lifecycle owns these checks:

- A missing, non-directory, symlink, wrong-owner or non-0700 state directory
  returns the existing sanitized `ErrUnsafeCleanupPath` chain before namespace
  duplication or process start; no process record is created.
- A valid directory's device/inode/UID is captured before the runner. Replacing
  it during namespace handoff or after start must not replace that stored pin.
- Later socket admission and pinned cleanup compare against that original
  identity. A replacement is rejected, including when the named endpoint is
  absent; replacement contents remain untouched. Restoring the exact original
  directory does not require or authorize re-pinning.
- Caller cancellation before start reaches neither the runner nor process.
  This slice adds no retry, watcher or cleanup owner.

The pin is not a promise that directory replacement prevents the fake or real
runner from returning a process. It is retained ownership for later admission
and cleanup; no raw stream is opened here. The coordinator continues owning
process containment, jail/cgroup/UID release, and terminal recovery ordering.

## Behavioral RED and controls

The Linux tests use the actual selected lifecycle helper, actual lifecycle
start and real caller-owned temporary directories. Existing fake process and
pipe-backed namespace objects avoid executing commands, entering namespaces,
creating sockets, changing UID/ownership, or touching host setup. A callback at
the namespace-duplication boundary replaces the directory deterministically.

The selected route must retain the original pin and reject unsafe parents.
The explicit existing-option route is a positive control with identical
behavioral assertions. The legacy constructor remains unpinned and cannot
acquire active strict socket-owner authority. Replacement tests check exact
canary bytes and exercise the real pinned cleanup check without a listener.
Fixture process disposal is not product cleanup evidence.

Run on an unprivileged Linux account (root skips these real-file fixtures
explicitly rather than chowning files or manufacturing an unprivileged owner):

```sh
go test -p 2 -race -count=3 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestJailerRecoveryPrelaunchVsock'
```

RED must fail selected pin/rejection cases while existing-option and legacy
controls pass. A compile failure, missing selected tests or skip is not that
RED evidence. Focused tests and race checks suffice for this frozen RED; the
supervisor owns broader integration gates.

## Remaining handoff

After GREEN, the same surviving supervisor may later consume its retained
manager and `selected.coordinator.generation.process` after gate release and
the running-record transition. Public boot binding/key ownership, NIC/L7
composition, authenticated readiness and credentials remain separate work.
This slice changes no default selection, legacy v1/v2 admission, guest binary,
HL8E gate, D7 live stub, or L8/L10/L11 acceptance requirement.
