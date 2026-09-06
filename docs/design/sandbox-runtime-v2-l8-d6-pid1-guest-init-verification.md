# L8 D6 PID1 guest-init start-gate verification

This slice wires `cmd/hal-guest-init` (Linux) to `l8composition.PID1StartGateState`.
PID1 admits canonical helper then client process descriptors through
`NewPID1StartGateState`, `AcceptHelperDescriptor`, and `AcceptClientDescriptor`
before `os.StartProcess`. It does not construct helper or client objects
(`l8composition.NewHelper` / `l8composition.NewClient`).

## Sealed inherited memfd expected-digest channel

Expected helper, client, and composition digests come from sealed
image-profile process-composition correlation already owned by PID1:
`L8ProcessCompositionFacts.helperDescriptorSha256`,
`clientDescriptorSha256`, and `compositionSha256`.

Linux PID1 consumes a sealed inherited anonymous memfd at fixed FD 15. The
source has `FD_CLOEXEC` clear only for the PID1 exec handoff; PID1 immediately
restores `FD_CLOEXEC`, uses `F_DUPFD_CLOEXEC` into the private transient range,
and inspects only that snapshot (regular, zero-link, not write-only, seals
`F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE`). The syscall-policy FD
table reserves this optional D7 slot only until it is protected; a valid
sealed source is closed and read from the snapshot. Bounded JSON copies those
three lowercase hex digests into
`l8composition.PID1StartGateExpected`.
Unsigned file/env/cmdline parsing is rejected.

Missing sealed FD remains the L7 path so `--require-l7-network` is not
regressed. Wrong-type, empty, or unsealed descriptors also stay absent, but
every supplied FD 15 is consumed or protected by `FD_CLOEXEC` before
classification and cannot cross into the L7 child.
Present-but-invalid or zero/aliased digests fail closed (exit 127). A
claimed expected without authenticated helper-then-client descriptors
fails closed (exit 127). This slice does not claim live start-gate release
and does not claim D7 live complete.

The native-bootstrap sealed config pipe specified in the syscall-policy
FD table is not this channel; PID1 has no dedicated composition-facts
pipe there.

Authenticated HL8L `controller_attestation` and HL8A `client_attestation`
receive paths are also absent from PID1; tests inject descriptors into the
extracted helper only.

## Focused verification

```
go test ./internal/sandboxruntime/microvm/guestagent/l8composition -run 'PID1StartGate' -count=1
go test ./cmd/hal-guest-init -count=1
go test ./cmd -run 'L8CredentialDeliverySourceGuardsCommandComposition|PID1|GuestInit' -count=1
go vet ./cmd/hal-guest-init ./internal/sandboxruntime/microvm/guestagent/l8composition
```

Fake-only: no KVM, Firecracker, network, or cloud. Default tests do not require
PID 1. `golangci-lint` is reported only when `command -v golangci-lint` succeeds.

This slice does not wire `sandboxd`, `hal run`, `hal auto`, factory, or
`cmd/hal-guest-agent`.
