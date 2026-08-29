# L8 D7 HL8E remains unissued; runtime envelope catalog is bound

This slice binds Go PID1 reachable named extras as explicit D7
catalog/runtime-row authority. HL8E remains unissued. `generateEvidence`
still fails closed with `errEvidenceInputsUnavailable`. This slice does
not claim D7 live, does not claim L8 complete, does not claim L10, and
does not claim L11. It does not change live D7 stub fatals.

Prefix membership such as `runtime.*`, `syscall.*`, `unix.*`, or
`internal/runtime/syscall.*` is not catalog authority.
`runtime.reviewerAuthority` is extra if it is reachable with an unlisted
named syscall. Unknown trampolines stay extra even when they live under
`syscall.*`.

## Catalog authority

`roles-v1.yaml` keeps the exact ten-role schema. The named Go runtime
envelope is a documented `runtimeEnvelope` list locked by
`exactRuntimeEnvelope()` and encoded as extra launch-base origin-3
runtime rows (`runtimeRuleIndexes`). Catalog class is Ordinary only for
role syscalls plus that envelope; other x/sys names stay Fatal.

A reachable named syscall is extra only if it is not the pinned-direct
`internal/runtime/syscall.Syscall6` `0f05` at offset 12 and is not listed
as catalog authority for that binary's role union. Unknown-number sites
(`unknown:symbol`) remain extra always.

The envelope names from `cmd/hal-guest-init` `main.main` are
`clock_gettime`, `exit_group`, `futex`, `getpid`, `gettid`, `madvise`,
`mmap`, `munmap`, `nanosleep`, `read`, `rt_sigaction`,
`rt_sigprocmask`, `sched_yield`, `tgkill`, `timer_create`,
`timer_delete`, `timer_settime`, and `write`. They are not extras for
Go guest role binaries. Unknown trampolines
`syscall.rawSyscallNoError.abi0` and `syscall.rawVforkSyscall.abi0`
still block issuance. Native `_start` extras stay fail-closed live
behavior, not HL8E pinned-direct evidence.

Generic Go binaries and a singular `-evidence-binary` stay rejected.
Default untagged `EmbeddedExpectedPinnedCallsiteEvidence` stays
fail-closed in `pinned_evidence_default.go`. The generator never writes
`verified-pinned-callsites.hl8e` from a fixture.
`requireCompleteHonestIssuanceInputs` keeps the unique/reachable D4/D6
fail-closed last return.

## Focused fake-only commands

```
go test ./tools/microvm/l8/policy/generate -count=1
go test ./internal/sandboxruntime/microvm/guestagent/syscallpolicy -count=1
go test ./cmd -run '^TestL8D7RuntimeEnvelope|^TestL8D7HL8E' -count=1
go vet ./tools/microvm/l8/policy/generate ./cmd
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
- treat L5 images as L8 proof;
- boot Firecracker or require KVM;
- wire sandboxd, `hal run`, `hal auto`, or factory;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`;
- claim L8, L10, or L11 complete.
