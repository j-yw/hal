# L8 D7 native role-bootstrap identities

This slice lands the default-off native `hal-guest-role-bootstrap` source
and tagged D7 generated artifact identities. It does not claim D7 live,
does not claim HL8E issuance, does not claim L8 complete, does not claim
L10, and does not claim L11.

## Default-off / tagged issuer

`rolebootstrap.EmbeddedGeneratedArtifact` stays fail-closed under
`!l8_verified_native_artifact`. The tagged issuer
`generated_artifact_d7_gen.go` is compiled only with
`l8_verified_native_artifact` and returns a `GeneratedArtifact` whose
four digests are the real SHA-256 identities of:

- `PolicySHA256` — already-issued HL8Q policy artifact identity
- `NativeSourceSHA256` — native source bytes
- `NativeCallsiteSHA256` — native callsite inventory
- `NativeInstallTableSHA256` — D4 native install table

Default/untagged tests still see `EmbeddedGeneratedArtifact` fail closed
with `ErrDependency`. HL8E issuance remains fail-closed. `generateEvidence`
is unchanged.

## Native ELF constraints

`tools/microvm/l8/role-bootstrap/hal-guest-role-bootstrap.S` is one
freestanding static Linux-amd64 ELF `_start`. `build.sh` uses `as`/`ld`
only (no gcc libc). The linked image is `ET_EXEC`, static, has no
`INTERP`, no libc `NEEDED`, exports `_start`, and does not pull a Go
runtime.

The native syscall union is the documented D2 set. Pointers address only
fixed read-only image tokens or bounded stack objects. There is no
mutable global or general path/argv/env parameter. PID1 mode is image
init. Child modes are selected only by the supervisor adapter closed
enum (`rolebootstrap.Role`: PID1, Controller, Agent, Monitor,
WorkloadShim) via compiled-in argv tokens.

After shared identity preflight (`getuid`/`geteuid`/`getgid`/`getegid`/
`capget`/read-only `prlimit64`), each role enters explicit remaining
stages. PID1 attempts the exact D2 `socket`/`bind`/`listen`/`dup3`/
`close` subset: three `AF_VSOCK`/`SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC`
listeners at CID any, ports 1024/1025/1026, backlogs 64/1/4, then `dup3`
onto FDs 12/13/14. Any negative syscall result fail-closes with exit
127. A successful host bind is not live vsock proof and does not
complete the listen table: PID1 then fail-closes through unimplemented
`seccomp`, `execve`, `clone3` shim, and SCM_RIGHTS stages. Child roles
fail-close after preflight at explicit unimplemented labels
(controller, agent, monitor, workload-shim). Unimplemented live PID1
supervisor behavior still fails closed with exit 127. This slice does
not claim live vsock, clone3, SCM_RIGHTS, seccomp, or execve.

D4 install bindings stay:

1. PID1 -> policy role 1 / BinaryBindingKind native bootstrap
2. controller -> policy role 3
3. agent -> policy role 5
4. monitor -> policy role 7
5. workload shim -> policy role 9

## Focused fake-only commands

```
go test ./internal/sandboxruntime/microvm/guestagent/rolebootstrap -count=1
go test -tags=l8_verified_native_artifact ./internal/sandboxruntime/microvm/guestagent/rolebootstrap -count=1
go test ./tools/microvm/l8/role-bootstrap/generate -count=1
go test ./cmd -run '^TestL8D7NativeRoleBootstrap' -count=1
go vet ./internal/sandboxruntime/microvm/guestagent/rolebootstrap ./tools/microvm/l8/role-bootstrap/generate ./cmd
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
- complete live PID1 vsock, clone3, SCM_RIGHTS monitor ready, seccomp, or execve;
- treat L5 images as L8 proof;
- boot Firecracker or require KVM;
- wire sandboxd, `hal run`, `hal auto`, or factory;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`;
- claim L8, L10, or L11 complete.
