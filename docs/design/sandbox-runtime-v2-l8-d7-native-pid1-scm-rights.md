# L8 D7 native PID1 SCM_RIGHTS monitor-ready; HL8E remains unissued

This slice reaches native PID1 exact `recvmsg` of SCM_RIGHTS monitor-ready
after a successful listen-table, launch-base seccomp install, and clone3
plus pathname execve of image-pinned role children. HL8E remains unissued.
`generateEvidence` still fails closed with `errEvidenceInputsUnavailable`.
This slice does not claim D7 live, does not claim L8 complete, does not
claim L10, and does not claim L11. It does not change live D7 stub fatals.

Prefix membership such as `runtime.*`, `syscall.*`, `unix.*`, or
`internal/runtime/syscall.*` is not authority. Catalog membership of
`recvmsg` in `nativeEnvelope` is also not authority: launch-base allow is
template-bound not catalog-name-bound.

## PID1 SCM_RIGHTS monitor-ready recvmsg

After shared identity preflight, the exact D2 listen-table subset,
launch-base `prctl`/`seccomp` install, and exact clone3 plus pathname
`execve` of image-pinned role children, native PID1 `recvmsg`s SCM_RIGHTS
monitor-ready from the PID1-held recorded transient bootstrap peer.

Exact ABI:

- `recvmsg` (47) on compiled FD 16, the first transient slot. PID1 fixed
  FD 10 remains the monitor pidfd and is never the protocol endpoint.
- flags `MSG_CMSG_CLOEXEC|MSG_DONTWAIT` (`0x40000040`).
- `msghdr` plus one `iovec`, 256-byte iov, and 64-byte cmsg on the bounded
  stack. Canonical monitor-ready is 211 bytes plus `SCM_CREDENTIALS` and
  exactly two `SCM_RIGHTS` descriptors (controller peer then mount
  namespace). `CMSG_SPACE(ucred)+CMSG_SPACE(2*int)` is 56; the 64-byte
  control buffer is that bound rounded up.
- Pointers address only RO image tokens or bounded stack. There is no
  libc and no gcc; `as`/`ld` only.

Negative syscall results, empty payload, and `MSG_TRUNC`/`MSG_CTRUNC`
fail-closed with `exit_group 127`. This process does not exit 0. Required
live sockets and the recorded bootstrap peer FD are not present on the
default fake path, so recvmsg remains fail-closed rather than a completed
live monitor-ready. Success is not live proof: reinspection and HL8L
`job_created` relay stay unimplemented and still exit 127.

`sendmsg` is not added. PID1 never originates an HL8M packet. Child argv
modes stay at their unimplemented native identity labels, including
monitor-child SCM_RIGHTS send. Native PID1 is the image-init supervisor;
Go PID1 remains ForkExec-free. This slice does not add `sendmsg` or
`recvmsg` to the Go `runtimeEnvelope`.

## Launch-base grammar gap

Classic seccomp cannot see SCM_RIGHTS fd contents. It observes only
`recvmsg` registers: sockfd in `rdi` (`args[0]`), `msghdr*` in `rsi`
(`args[1]`), flags in `rdx` (`args[2]`). SCM_RIGHTS fd contents, cmsg
level/type, and iov payload live inside pointed-to memory. The HL8Q
scalar grammar cannot encode those interior fields without lying about
the syscall ABI.

This slice FAIL CLOSED: it does not allow unrestricted `sendmsg`/`recvmsg`
by catalog name. Launch-base keeps `sendmsg` and `recvmsg` unlisted, so
Decide and the compiled filter EPERM the exact FD 16
`MSG_CMSG_CLOEXEC|MSG_DONTWAIT` recvmsg shape and empty recvmsg, and kill
catalog-name sendmsg (`sendmsg` stays Fatal). Same honesty as pathname
`execve` in the prior launch-base clone3/execve templates slice: encoding
any recvmsg row without an exact SCM_RIGHTS scalar would allow every
cmsg.

`recvmsg` becomes native `_start` catalog authority through
`exactNativeEnvelope()`. It is not an extra for the native bootstrap
binary. `sendmsg` (syscall 46) is not added.

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
go test ./cmd -run '^TestL8D7NativePID1SCMRights|^TestL8D7NativePID1Clone3Execve|^TestL8D7NativePID1Seccomp|^TestL8D7NativeEnvelope|^TestL8D7NativeRoleBootstrap|^TestL8D7HL8E' -count=1
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
- allow unrestricted sendmsg or recvmsg by catalog name;
- encode SCM_RIGHTS templates that the HL8Q scalar grammar cannot
  represent honestly;
- implement sendmsg or monitor-child SCM_RIGHTS send;
- add `sendmsg` or `recvmsg` to the Go runtime envelope;
- treat L5 images as L8 proof;
- boot Firecracker or require KVM;
- wire sandboxd, `hal run`, `hal auto`, or factory;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`;
- claim L8, L10, or L11 complete.
