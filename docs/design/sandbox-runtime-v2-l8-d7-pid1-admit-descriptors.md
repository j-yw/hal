# L8 D7 PID1 helper-then-client admit

This slice binds `releasePID1AgentStartGate` to inherited helper-then-client
process descriptors. It is default-off. It does not claim D7 live, does not
claim HL8E issuance, does not claim L8 complete, does not claim L10, and
does not claim L11. It does not change live D7 stub fatals.

## Admit path

When sealed expected digests are present on inherited FD **15**, Linux PID1
loads already-authenticated HL8D descriptors from the documented inherited
slots and calls `admitPID1StartGate`:

- Fixed inherited FD **16** is the helper process descriptor.
- Fixed inherited FD **17** is the client process descriptor.

PID1 never constructs helper or client processes (`l8composition.NewHelper`
/ `l8composition.NewClient`). It only admits descriptors that already exist
on those slots. `admitPID1StartGate` success returns 0. Any mismatch,
missing slot, swapped role order, or invalid sealed payload returns 127.

Each inherited source uses the same close-on-exec discipline as the expected
FD: restore `FD_CLOEXEC`, `F_DUPFD_CLOEXEC` into the private transient range
after FD 17, validate only that snapshot, and consume a valid sealed source
so the descriptor cannot cross later child exec.

Missing unsigned FD 15 still returns 0 and keeps the L7 supervisor path.
Invalid sealed expected payloads stay 127.

Non-Linux stays unsupported/absent. Tests inject the inherited FD numbers;
production keeps 15 then 16 then 17.

## Default-off

`sandboxd`, `hal run`, `hal auto`, and factory stay unwired. No KVM.

D7 prepared-Linux acceptance remains unaccepted. Live helper transport, a
durable handle store, and a production L7 session factory remain unaccepted.
HL8E remains unissued.

## Focused fake-only commands

```
go test ./cmd/hal-guest-init -count=1
go test ./internal/sandboxruntime/microvm/guestagent/l8composition -run 'PID1StartGate' -count=1
go test ./cmd -run '^TestL8D7PID1AdmitDescriptors|^TestL8GuestInitDoesNotInvent|^TestL8PID1GuestInit' -count=1
go vet ./cmd/hal-guest-init ./cmd
```

These commands are fake-only. They do not boot a VM, call billed APIs, or
select live tags.

## Broad verification

```
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
- change D7 live stub fatals;
- issue HL8E or enable `generateEvidence` success;
- construct helper or client processes;
- wire HL8L `controller_attestation` or HL8A `client_attestation` receive
  paths;
- wire sandboxd, `hal run`, `hal auto`, or factory;
- claim L8, L10, or L11 complete;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`.
