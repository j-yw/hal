# L8 D7 native PID1 clone3 and execve; HL8E remains unissued

This slice reaches native PID1 exact `clone3` plus pathname `execve` of
image-pinned role children after a successful listen-table and launch-base
seccomp install. HL8E remains unissued. `generateEvidence` still fails closed
with `errEvidenceInputsUnavailable`. This slice does not claim D7 live, does
not claim L8 complete, does not claim L10, and does not claim L11. It does not
change live D7 stub fatals.

Prefix membership such as `runtime.*`, `syscall.*`, `unix.*`, or
`internal/runtime/syscall.*` is not authority.

## PID1 clone3 and pathname execve

After shared identity preflight, the exact D2 listen-table subset, and
launch-base `prctl`/`seccomp` install, native PID1:

1. `clone3`s image-pinned role children with pinned amd64 `clone_args`
   (Go 1.25.7 size 88) and a pidfd pointer in `clone_args.pidfd`;
2. pathname-`execve`s the closed image-pinned Go role path when clone3
   returns 0.

Exact flags:

- Boot-only controller/agent: `CLONE_VFORK|CLONE_VM|CLONE_PIDFD`,
  `exit_signal=SIGCHLD`, no namespace or cgroup flag.
- Monitor: `CLONE_VFORK|CLONE_VM|CLONE_NEWNS|CLONE_PIDFD`,
  `exit_signal=SIGCHLD`.
- Shim: `CLONE_VFORK|CLONE_VM|CLONE_PIDFD|CLONE_INTO_CGROUP`,
  `exit_signal=SIGCHLD`, `cgroup=9`, every other optional field zero.

Pathnames are read-only image tokens
(`/usr/bin/hal-guest-credential-helper`, `/usr/bin/hal-guest-agent`,
`/usr/bin/hal-guest-mount-monitor`, `/usr/bin/hal-guest-workload-shim`).
argv is that closed path token only. envp is NULL. Pointers address only RO
image tokens or bounded stack. There is no libc and no gcc; `as`/`ld` only.

Negative syscall results fail-closed with `exit_group 127`. This process does
not exit 0. Required live sockets, live cgroup fd 9, and host paths are not
present on the default fake path, so clone3/execve remain fail-closed rather
than a completed live launch. Launch-base has no exact clone3/execve argument
template; those syscalls are native envelope authority, not a launch-base
allow.

SCM_RIGHTS monitor-ready stays unimplemented and still exits 127. `sendmsg`
and `recvmsg` are not added. Child argv modes stay at their unimplemented
native identity labels. Native PID1 is the image-init supervisor; Go PID1
remains ForkExec-free. This slice does not add `clone` or `clone3` to the Go
`runtimeEnvelope`.

`clone3` and `execve` become native `_start` catalog authority through
`exactNativeEnvelope()`. They are not extras for the native bootstrap binary.
`clone` (syscall 56) is not added.

Default untagged `EmbeddedExpectedPinnedCallsiteEvidence` stays fail-closed
in `pinned_evidence_default.go`. The generator never writes
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
go test ./cmd -run '^TestL8D7NativePID1Clone3Execve|^TestL8D7NativePID1Seccomp|^TestL8D7NativeEnvelope|^TestL8D7NativeRoleBootstrap|^TestL8D7HL8E' -count=1
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
- implement SCM_RIGHTS, sendmsg, or recvmsg;
- add `clone` or `clone3` to the Go runtime envelope;
- treat L5 images as L8 proof;
- boot Firecracker or require KVM;
- wire sandboxd, `hal run`, `hal auto`, or factory;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`;
- claim L8, L10, or L11 complete.
