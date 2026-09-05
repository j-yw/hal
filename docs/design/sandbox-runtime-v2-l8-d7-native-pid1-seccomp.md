# L8 D7 native PID1 installs launch-base seccomp; HL8E remains unissued

This slice installs the reviewed `launch-base` ancestor seccomp filter on
native PID1 after a successful listen-table. HL8E remains unissued.
`generateEvidence` still fails closed with `errEvidenceInputsUnavailable`.
This slice does not claim D7 live, does not claim L8 complete, does not
claim L10, and does not claim L11. It does not change live D7 stub fatals.

Prefix membership such as `runtime.*`, `syscall.*`, `unix.*`, or
`internal/runtime/syscall.*` is not authority.

## PID1 launch-base filter install

After shared identity preflight and the exact D2 listen-table subset
(`socket`/`bind`/`listen`/`dup3`/`close` onto FDs 12/13/14), PID1:

1. `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` (syscall 157);
2. installs a deny-by-default classic BPF filter for `RoleLaunchBase` via
   `seccomp(SECCOMP_SET_MODE_FILTER)` (syscall 317).

The host-side compiler is `syscallpolicy.CompileFilterProfile`. Its only
input is `FilterProfile(RoleLaunchBase)` from the issued HL8Q. The
program validates `AUDIT_ARCH_X86_64`, rejects the x32 syscall bit,
compares native amd64 syscall numbers, and uses `ActionKillProcess` as
the default. Allow/EPERM/kill actions match `FilterProfile.Decide`. The
compiled `sock_fprog` is embedded as read-only image data. The native
`_start` builds `sock_fprog` on the bounded stack pointing at that RO
filter. Negative `prctl`/`seccomp` results fail-closed with
`exit_group 127`.

Filters are inherited and cannot be relaxed. This is native filter
commit, not D7 live proof.

After a successful install, PID1 still jumps to unimplemented `execve`,
`clone3`, and SCM_RIGHTS and still exits 127. Child roles still
fail-closed after preflight at their unimplemented labels. `clone3`,
`execve`, `sendmsg`, and `recvmsg` remain unimplemented syscall sites.

`prctl` and `seccomp` become native `_start` catalog authority through
`exactNativeEnvelope()`. They are not added to the Go `runtimeEnvelope`.
`clone3` and `execve` are not added to the native envelope.

Default untagged `EmbeddedExpectedPinnedCallsiteEvidence` stays
fail-closed in `pinned_evidence_default.go`. The generator never writes
`verified-pinned-callsites.hl8e` from a fixture.
`requireCompleteHonestIssuanceInputs` keeps the unique/reachable D4/D6
fail-closed last return even if extras become empty.
`ImportPinnedCallsiteEvidence` is not enabled as an issuer.

## Focused fake-only commands

```
go test ./tools/microvm/l8/role-bootstrap/generate -count=1
go test ./tools/microvm/l8/policy/generate -count=1
go test ./internal/sandboxruntime/microvm/guestagent/syscallpolicy -count=1
go test -tags=l8_verified_native_artifact ./internal/sandboxruntime/microvm/guestagent/rolebootstrap -count=1
go test ./cmd -run '^TestL8D7NativePID1Seccomp|^TestL8D7NativeEnvelope|^TestL8D7NativeRoleBootstrap|^TestL8D7HL8E' -count=1
go vet ./tools/microvm/l8/role-bootstrap/generate ./tools/microvm/l8/policy/generate ./internal/sandboxruntime/microvm/guestagent/syscallpolicy ./cmd
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
- implement clone3, execve, or SCM_RIGHTS;
- add `clone` or `clone3` to the Go runtime envelope;
- add `clone3` or `execve` to the native envelope;
- treat L5 images as L8 proof;
- boot Firecracker or require KVM;
- wire sandboxd, `hal run`, `hal auto`, or factory;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`;
- claim L8, L10, or L11 complete.
