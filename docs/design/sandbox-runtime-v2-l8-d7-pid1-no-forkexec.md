# L8 D7 PID1 is bound without ForkExec; HL8E remains unissued

This slice build-tags production L8 `cmd/hal-guest-init` so the L8-built
`hal-init` does not import `os/exec` and does not call `os.StartProcess`.
Go PID1 extras that still blocked HL8E were `clone` and `clone3` from
`syscall.rawVforkSyscall` used by `os.StartProcess` / `os/exec`. The
inspector is not value-sensitive: those CALL sites are extras if they
are reachable from `main.main`. This slice removes them from the
L8-tagged binary. It does not catalog `clone` or `clone3` as
`runtimeEnvelope`. HL8E remains unissued. `generateEvidence` still fails
closed with `errEvidenceInputsUnavailable`. This slice does not claim
D7 live, does not claim L8 complete, does not claim L10, and does not
claim L11. It does not change live D7 stub fatals.

## Tagged L8 PID1

Production L8 PID1 uses build tag `l8_production_pid1`. After successful
helper-then-client admit, L8 PID1 must not spawn via ForkExec; child
descriptors are already admitted. Missing FD 15 L7 `os.StartProcess`
belongs only to the untagged L7-compatible binary. L8 PID1 treats missing
or failed admit as exit 127 and never calls `os.StartProcess`.

The L8 image pipeline (`tools/microvm/l8/build-in-container.sh`) compiles
`hal-init` with `-tags=l8_production_pid1`. Other guest role binaries keep
their untagged builds. L5 and L7 image pipelines stay untagged.

Default untagged `EmbeddedExpectedPinnedCallsiteEvidence` stays
fail-closed in `pinned_evidence_default.go`. The generator never writes
`verified-pinned-callsites.hl8e` from a fixture.
`requireCompleteHonestIssuanceInputs` keeps the unique/reachable D4/D6
fail-closed last return even if extras become empty.
`ImportPinnedCallsiteEvidence` is not enabled as an HL8E issuer by this
slice.

## Focused fake-only commands

```
go test ./cmd/hal-guest-init -count=1
go test -tags=l8_production_pid1 ./cmd/hal-guest-init -count=1
go test ./tools/microvm/l8/policy/generate -count=1
go test ./tools/microvm/l8 -count=1
go test ./cmd -run '^TestL8D7PID1NoForkExec|^TestL8D7HL8E' -count=1
go vet ./cmd/hal-guest-init ./tools/microvm/l8/policy/generate ./cmd
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
- issue HL8E or enable `generateEvidence` success;
- generate `verified-pinned-callsites.hl8e` from a fixture;
- add `clone` or `clone3` to the Go runtime envelope;
- claim extras empty as pinned-direct HL8E evidence;
- treat L5 images as L8 proof;
- boot Firecracker or require KVM;
- wire sandboxd, `hal run`, `hal auto`, or factory;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`;
- claim L8, L10, or L11 complete.
