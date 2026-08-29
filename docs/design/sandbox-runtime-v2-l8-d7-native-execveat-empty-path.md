# L8 D7 native PID1 execveat AT_EMPTY_PATH; HL8E remains unissued

This slice replaces native PID1 child pathname `execve` with exact
`execveat` (322) `AT_EMPTY_PATH` of already-admitted sealed image FDs
after a successful listen-table, launch-base seccomp install, and clone3
of image-pinned role children. HL8E remains unissued.
`generateEvidence` still fails closed with `errEvidenceInputsUnavailable`.
This slice does not claim D7 live, does not claim L8 complete, does not
claim L10, and does not claim L11. It does not change live D7 stub fatals.

Prefix membership such as `runtime.*`, `syscall.*`, `unix.*`, or
`internal/runtime/syscall.*` is not authority. Catalog membership of
`execveat` in `nativeEnvelope` is also not authority: launch-base allow is
template-bound not catalog-name-bound.

## PID1 execveat of sealed executable FDs

Classic seccomp cannot see pathname bytes. The prior launch-base clone3
and execve templates slice therefore FAIL CLOSED on pathname `execve`
(59): encoding any execve row without an exact pathname scalar would
allow every pathname. The honest BPF-visible alternative is
`execveat(dirfd, "", one image-owned argv[0], NULL, AT_EMPTY_PATH)` of an
already-admitted sealed image FD.

Exact ABI:

- `execveat` (322). `args[0]` is a compiled PID1-held pinned executable
  FD. `args[4]` is `AT_EMPTY_PATH` (`0x1000`). `args[3]` is envp NULL.
- pathname is the RO empty-path token `""`. argv is exactly one
  image-owned role token (`monitor` or `workload-shim`) followed by NULL,
  so the admitted Go entrypoints receive a valid argv[0] and no extra
  arguments. envp is NULL. Pointers address only RO image tokens or
  bounded stack. There is no libc and no gcc; `as`/`ld` only.
- Image-init plan FDs: FD 5 is the pinned mount-monitor executable; FD 6
  is the pinned workload-shim executable. Launch-base Allows only those
  two FDs plus envp NULL plus `AT_EMPTY_PATH`.
- Controller and agent have no PID1-held sealed executable FD in that
  plan. Those clone3 children FAIL CLOSED without `execveat` and without
  inventing a live `open()` of `/usr/bin/hal-guest-*`. That remaining
  FD-admission gap is documented, not papered over with an execveat
  allow-all.
- Pathname `execve` (59) is no longer a native `_start` site. There is
  one child-exec site: `execveat`.

Negative syscall results and absent FDs fail-closed with `exit_group
127`. This process does not exit 0. Required live sockets, live cgroup
fd 9, and inherited sealed executable FDs are not present on the default
fake path, so clone3/execveat remain fail-closed rather than a completed
live launch. Success is not live proof.

`sendmsg` is not added. Child argv modes stay at their unimplemented
native identity labels. Native PID1 is the image-init supervisor; Go
PID1 remains ForkExec-free. This slice does not add `execve` or
`execveat` to the Go `runtimeEnvelope`.

## Launch-base exact register template

Launch-base authors one Direct `RuleOriginRole` filter row for
`execveat` (322):

- `args[0]` `ScalarOneOf` `{5, 6}`;
- `args[3]` `ScalarZero` (envp NULL);
- `args[4]` `ScalarEqual` `0x1000` (`AT_EMPTY_PATH`);
- mismatch `ActionErrnoEPERM` / `ReasonScalarMismatch`.

`FilterProfile(RoleLaunchBase).Decide` and the compiled
`launch_base_filter.inc` Allow the exact FD 5 and FD 6
`AT_EMPTY_PATH` operations with envp NULL, and EPERM empty execveat,
wrong FD, missing `AT_EMPTY_PATH`, nonempty envp, and catalog-name-only
execveat. Pathname `execve` is Fatal (no longer nativeEnvelope
authority), so Decide and the compiled filter Kill empty execve and the
four pathname register shapes. Launch-base does not allow unrestricted
`execve`/`execveat` by catalog name.

`execveat` becomes native `_start` catalog authority through
`exactNativeEnvelope()`. It is not an extra for the native bootstrap
binary. Pathname `execve` (syscall 59) is not added.

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
go test ./cmd -run '^TestL8D7NativeExecveatEmptyPath|^TestL8D7NativePID1SCMRights|^TestL8D7NativePID1Clone3Execve|^TestL8D7NativePID1Seccomp|^TestL8D7NativeEnvelope|^TestL8D7NativeRoleBootstrap|^TestL8D7HL8E' -count=1
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
- allow unrestricted execve or execveat by catalog name;
- invent a live open of `/usr/bin/hal-guest-*` or admit controller/agent
  sealed executable FDs that the image-init plan does not name;
- add `execve` or `execveat` to the Go runtime envelope;
- treat L5 images as L8 proof;
- boot Firecracker or require KVM;
- wire sandboxd, `hal run`, `hal auto`, or factory;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`;
- claim L8, L10, or L11 complete.
