# L8 D7 HL8E remains unissued; reachable syscall graph is bound

This slice replaces namespace-prefix syscall classification with an
entry-point plus call-edge reachable graph. HL8E remains unissued.
`generateEvidence` still fails closed with
`errEvidenceInputsUnavailable`. This slice does not claim D7 live, does
not claim L8 complete, does not claim L10, and does not claim L11. It
does not change live D7 stub fatals.

Prefix membership such as `runtime.*`, `syscall.*`, `unix.*`, or
`internal/runtime/syscall.*` is not proof of non-authority.
`runtime.reviewerAuthority` is extra if it is reachable. A decoded
`syscall` / `sysenter` / `int $0x80` is authority only if it is on a
reachable path from the role entry.

## Reachable graph

The inspector builds linux/amd64 guest packages with Go 1.25.7, treats
`runtime.text`-relocated pclntab spans as authoritative, supplements only
non-overlapping ELF `STT_FUNC` spans, and walks x86-64 instruction
boundaries. Ambiguous entry symbols and ELF spans fail closed.

- Go role entry is `main.main`.
- Native role entry is `_start`.
- Direct `CALL` and every out-of-function relative branch, including
  conditional and loop branches, are graph edges.
- Pinned-direct allow is only `internal/runtime/syscall.Syscall6` plus
  source-derived `0f05` at offset 12.
- Any reachable extra raw syscall that is not that pinned-direct site
  fails closed with a bounded named reason.
- Unreachable library syscalls are ignored because they are unreachable,
  not because of a prefix.
- Unknown branch targets, truncated transfers, and indirect `CALL`/`JMP`
  are unbounded; they cannot issue HL8E.

HL8E pinned binding is launch-base plus pinned Go runtime. The Go guest
that carries launch-base is `cmd/hal-guest-init` (`hal-init`, PID1).
Native `hal-guest-role-bootstrap` is a different kind.

## Honest extras that still block issuance

Go PID1 still has reachable extra syscalls from `main.main`. HL8E is not
issued. The named extras include `clock_gettime`, `exit_group`,
`futex`, `getpid`, `gettid`, `madvise`, `mmap`, `munmap`, `nanosleep`,
`read`, `rt_sigaction`, `rt_sigprocmask`, `sched_yield`, `tgkill`,
`timer_create`, `timer_delete`, `timer_settime`, `write`, plus unknown
number trampolines `syscall.rawSyscallNoError.abi0` and
`syscall.rawVforkSyscall.abi0`. `clone` is not on this `main.main`
direct-call graph; process creation is the `rawVforkSyscall` trampoline.

Native bootstrap reachable syscalls are `_start` only: `getuid`,
`geteuid`, `getgid`, `getegid`, `capget`, `prlimit64`, then
`exit_group(127)`. That is fail-closed live behavior, not HL8E
pinned-direct evidence for launch-base Go runtime.

Generic Go binaries and a singular `-evidence-binary` stay rejected.
Default untagged `EmbeddedExpectedPinnedCallsiteEvidence` stays
fail-closed in `pinned_evidence_default.go`. The generator never writes
`verified-pinned-callsites.hl8e` from a fixture.

## Focused fake-only commands

```
go test ./tools/microvm/l8/policy/generate -count=1
go test ./internal/sandboxruntime/microvm/guestagent/syscallpolicy -count=1
go test ./cmd -run '^TestL8D7HL8EReachableGraph' -count=1
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
