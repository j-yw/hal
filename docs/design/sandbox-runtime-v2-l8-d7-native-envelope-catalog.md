# L8 D7 HL8E remains unissued; native envelope catalog is bound

This slice binds remaining honest named extras as explicit D7 catalog
authority. HL8E remains unissued. `generateEvidence` still fails closed
with `errEvidenceInputsUnavailable`. This slice does not claim D7 live,
does not claim L8 complete, does not claim L10, and does not claim L11.
It does not change live D7 stub fatals.

Prefix membership such as `runtime.*`, `syscall.*`, `unix.*`, or
`internal/runtime/syscall.*` is not catalog authority.
`runtime.reviewerAuthority` is extra if it is reachable with an unlisted
named syscall. Unknown trampolines stay extra even when they live under
`syscall.*` if the trap/number is unproven.

## Catalog authority

`roles-v1.yaml` keeps the exact ten-role schema. The named Go runtime
envelope remains a documented `runtimeEnvelope` list locked by
`exactRuntimeEnvelope()`. This slice adds `getppid` to that Go PID1
catalog because it is an ordinary runtime extra from `cmd/hal-guest-init`
`main.main`. `clone` and `clone3` are not added: they remain extras
because they are process-creation/shim authority and lack exact argument
templates in this slice.

The native `_start` union is a documented `nativeEnvelope` list locked
by `exactNativeEnvelope()` and used only for the native bootstrap binary
`hal-guest-role-bootstrap`. It is encoded as extra launch-bootstrap
origin-1 rows. Prefix is not authority. Catalog class is Ordinary for
role syscalls plus the Go runtime envelope plus this native envelope;
other x/sys names stay Fatal.

The native envelope names are the identity preflight plus the PID1
listen-table subset: `getuid`, `geteuid`, `getgid`, `getegid`, `capget`,
`prlimit64`, `socket`, `bind`, `listen`, `dup3`, `close`, and
`exit_group`. They are not extras for the native bootstrap binary.
`clone3`, `execve`, and `seccomp` are not added: they stay unimplemented
on `_start` and still exit 127 after listen. They are not reachable
syscall sites.

A reachable named syscall is extra only if it is not the pinned-direct
`internal/runtime/syscall.Syscall6` `0f05` at offset 12 and is not listed
as catalog authority for that binary's role union. Unknown-number sites
(`unknown:symbol`) remain extra always.

Remaining extras after this slice are `clone` and `clone3` from Go
`main.main`. Unknown trampolines stay extra if unproven. Native `_start`
named envelope sites are catalog authority, not HL8E pinned-direct
evidence.

Generic Go binaries and a singular `-evidence-binary` stay rejected.
Default untagged `EmbeddedExpectedPinnedCallsiteEvidence` stays
fail-closed in `pinned_evidence_default.go`. The generator never writes
`verified-pinned-callsites.hl8e` from a fixture.
`requireCompleteHonestIssuanceInputs` keeps the unique/reachable D4/D6
fail-closed last return even if extras become empty.

## Focused fake-only commands

```
go test ./tools/microvm/l8/policy/generate -count=1
go test ./internal/sandboxruntime/microvm/guestagent/syscallpolicy -count=1
go test ./cmd -run '^TestL8D7NativeEnvelope|^TestL8D7RuntimeEnvelope|^TestL8D7HL8E' -count=1
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
- add `clone` or `clone3` to the Go runtime envelope;
- add `clone3`, `execve`, or `seccomp` to the native envelope;
- treat L5 images as L8 proof;
- boot Firecracker or require KVM;
- wire sandboxd, `hal run`, `hal auto`, or factory;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`;
- claim L8, L10, or L11 complete.
