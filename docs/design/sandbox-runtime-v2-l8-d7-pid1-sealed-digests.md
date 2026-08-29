# L8 D7 PID1 sealed expected digests

`cmd/hal-guest-init` on Linux loads start-gate expected digests from one
sealed inherited anonymous memfd. This is the D7 digest channel. It does
not claim D7 live complete.

## Channel

- Fixed inherited FD **15**. The syscall-policy table lists PID1 FD 15 as
  Closed; this optional slot is the sealed composition-facts memfd when
  inherited.
- Descriptor requirements match the runtime-owner sealed memfd shape:
  `FD_CLOEXEC`, regular, zero-link, not write-only, and
  `F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE`.
- Bounded JSON (32 KiB) of `assetbuild.L8ProcessCompositionFacts` or the
  three-field subset `helperDescriptorSha256`, `clientDescriptorSha256`,
  `compositionSha256`. Hex-decode into
  `l8composition.PID1StartGateExpected`; reject aliases and zero.
- Missing, wrong-type, empty, or unsealed FDs return absent
  (`present=false`) and keep the L7 supervisor path.
- Invalid sealed payloads fail closed (exit 127).
- Unsigned file, env, and cmdline digest inputs are rejected.

Non-Linux stays unsupported/absent. Tests inject the inherited FD number;
production keeps 15. `releasePID1AgentStartGate` uses the loaded expected
when present and still fails closed without authenticated helper-then-client
descriptors.

## Default-off

`sandboxd`, `hal run`, `hal auto`, and factory stay unwired. No KVM.

D7 prepared-Linux live tests remain RED: live helper transport, a durable
handle store, and a production L7 session factory are still unaccepted,
and this loader is not live-issued.

## Focused verification

```
go test ./cmd/hal-guest-init -count=1
go test ./cmd -run '^TestL8D7PreparedLinuxPID1StartGateExpected|^TestL8GuestInitDoesNotInvent|^TestL8PID1GuestInit' -count=1
go vet ./cmd/hal-guest-init
```

`golangci-lint` is reported only when `command -v golangci-lint` succeeds.

## Non-goals

This slice does not:

- accept D7 prepared-Linux live proof;
- wire helper or client attestation receive paths into PID1;
- edit the L8 production-credential-delivery architecture document;
- claim L8, L10, or L11 complete.
