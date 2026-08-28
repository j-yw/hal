# L8 D6 PID1 guest-init start-gate verification

This slice wires `cmd/hal-guest-init` (Linux) to `l8composition.PID1StartGateState`.
PID1 admits canonical helper then client process descriptors through
`NewPID1StartGateState`, `AcceptHelperDescriptor`, and `AcceptClientDescriptor`
before `os.StartProcess`. It does not construct helper or client objects
(`l8composition.NewHelper` / `l8composition.NewClient`).

## Honest RED: missing sealed expected-digest channel

Expected helper, client, and composition digests must come from sealed
image-profile process-composition correlation already owned by PID1:
`L8ProcessCompositionFacts.helperDescriptorSha256`,
`clientDescriptorSha256`, and `compositionSha256`, compiled or inherited at
D7 image issuance, or from the native-bootstrap sealed config pipe specified
in the syscall-policy FD table.

This binary has **no** such sealed channel. `loadPID1StartGateExpected`
returns absent. Unsigned file/env/cmdline parsing is rejected. Missing
expected leaves the L7 supervisor path so `--require-l7-network` is not
regressed. A claimed expected without authenticated helper-then-client
descriptors fails closed (exit 127). This slice does not claim live start-gate release.

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
