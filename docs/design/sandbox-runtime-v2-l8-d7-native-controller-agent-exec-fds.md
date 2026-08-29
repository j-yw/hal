# L8 D7 native controller/agent exec FDs remain unadmitted; HL8E remains unissued

This slice evaluates whether native PID1 child `execveat` (322)
`AT_EMPTY_PATH` can honestly bind compiled PID1-held sealed executable
FDs for **controller** and **agent** the same kind of pinned FD as
monitor=5 and shim=6. It cannot. HL8E remains unissued.
`generateEvidence` still fails closed with `errEvidenceInputsUnavailable`.
This slice does not claim D7 live, does not claim L8 complete, does not
claim L10, and does not claim L11. It does not change live D7 stub fatals.

Prefix membership such as `runtime.*`, `syscall.*`, `unix.*`, or
`internal/runtime/syscall.*` is not authority. Catalog membership of
`execveat` in `nativeEnvelope` is also not authority: launch-base allow is
template-bound not catalog-name-bound.

## Remaining admission gap

The frozen image-init / role-bootstrap PID1 descriptor plan names only
two PID1-held pinned executable FDs:

- FD 5 is the pinned mount-monitor executable;
- FD 6 is the pinned workload-shim executable.

Those are the same compiled immediates launch-base already Allows for
`execveat` `args[0]` `ScalarOneOf` `{5, 6}` plus envp NULL plus
`AT_EMPTY_PATH`. Controller and agent have no PID1-held sealed executable
FD in that plan.

The frozen PID1 launch-supervisor table already assigns the adjacent
fixed slots to other objects:

- FD 3 is the controller supervisor endpoint, not a sealed executable;
- FD 4 is the delegated cgroup-v2 root, not a sealed executable.

Transient slots 16 through 255 are not the same kind of pinned FD as
monitor=5 and shim=6. Reusing a frozen fixed number, inventing a
transient as a new fixed executable, or a live `open()` of
`/usr/bin/hal-guest-*` would not be an honest image-init name.

Therefore this remaining admission gap FAIL CLOSED:

- Native `_start` keeps the mapping rbx 0 controller / rbx 1 agent /
  rbx 2 monitor / rbx 3 shim, but rbx 0 and rbx 1 fail-closed before
  `execveat`. Only rbx 2 and rbx 3 execveat the compiled FDs 5 and 6.
- Launch-base does not extend `args[0]` `ScalarOneOf` beyond `{5, 6}`.
- It does not allow-all execveat.
- argv[0] remains the matching image-owned role token (`monitor` or
  `workload-shim`) then NULL. Pathname empty. envp NULL. `AT_EMPTY_PATH`.
- Pathname `execve` (59) stays unlisted. There is still one child-exec
  site: `execveat`.

Negative syscall results and absent FDs fail-closed with `exit_group
127`. This process does not exit 0. Required live sockets, live cgroup
fd 9, and inherited sealed executable FDs are not present on the default
fake path, so clone3/execveat remain fail-closed rather than a completed
live launch. Success is not live proof.

`sendmsg` is not added. Child argv modes stay at their unimplemented
native identity labels. Native PID1 is the image-init supervisor; Go
PID1 remains ForkExec-free. This slice does not add `execve` or
`execveat` to the Go `runtimeEnvelope`. nativeEnvelope only.

A later slice may bind controller/agent execveat only after the
image-init / role-bootstrap plan names new PID1-held sealed executable
FDs without a live host-path open and without reusing frozen descriptor
roles.

## Launch-base exact register template

Launch-base still authors one Direct `RuleOriginRole` filter row for
`execveat` (322):

- `args[0]` `ScalarOneOf` `{5, 6}` (unchanged; not extended);
- `args[3]` `ScalarZero` (envp NULL);
- `args[4]` `ScalarEqual` `0x1000` (`AT_EMPTY_PATH`);
- mismatch `ActionErrnoEPERM` / `ReasonScalarMismatch`.

`FilterProfile(RoleLaunchBase).Decide` and the compiled
`launch_base_filter.inc` Allow the exact FD 5 and FD 6
`AT_EMPTY_PATH` operations with envp NULL, and EPERM empty execveat,
wrong FD including controller/agent candidates 3 and 4 as the remaining admission gap, missing
`AT_EMPTY_PATH`, nonempty envp, and catalog-name-only execveat.
Pathname `execve` is Fatal (no longer nativeEnvelope authority), so
Decide and the compiled filter Kill empty execve and the four pathname
register shapes. Launch-base does not allow unrestricted
`execve`/`execveat` by catalog name.

`execveat` remains native `_start` catalog authority through
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
go test ./cmd -run '^TestL8D7NativeControllerAgentExecFDs|^TestL8D7NativeExecveatEmptyPath|^TestL8D7NativePID1SCMRights|^TestL8D7NativePID1Clone3Execve|^TestL8D7NativePID1Seccomp|^TestL8D7NativeEnvelope|^TestL8D7NativeRoleBootstrap|^TestL8D7HL8E' -count=1
go vet ./tools/microvm/l8/role-bootstrap/generate ./tools/microvm/l8/policy/generate ./internal/sandboxruntime/microvm/guestagent/syscallpolicy ./cmd
tools/microvm/l8/policy/verify-artifact.sh
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
- extend launch-base execveat `ScalarOneOf` beyond FD 5 and FD 6;
- add `execve` or `execveat` to the Go runtime envelope;
- treat L5 images as L8 proof;
- boot Firecracker or require KVM;
- wire sandboxd, `hal run`, `hal auto`, or factory;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`;
- claim L8, L10, or L11 complete.
