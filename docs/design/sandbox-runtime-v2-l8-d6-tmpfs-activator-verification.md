# L8 D6 Production File-Tmpfs Credential Activator Verification

This slice implements the default-off Firecracker host
`l8JobCredentialFileTmpfsActivator` / `l8JobCredentialFileHandle` production
path. It is the host materializer that `L8JobCredentialRuntime` already calls
during prepare: fill from `LiveSecretSource`, then copy guest `TargetPath`,
`DeclaredFileBytes`, and SHA-256 into the guest prepare manifest.

It does not implement or claim guest mount-monitor/PID1 wiring, D7 live tmpfs
acceptance, HTTP/SSH activators, worker v2 protocol operations, or command
defaults.

## Real operations

- `NewProductionL8JobCredentialFileTmpfsActivator` requires an explicit
  absolute scratch root. It never defaults to the project `.hal/` directory,
  and it is never invoked by sandboxd, `hal run`, `hal auto`, factory, worker
  defaults, or `NewProductionL8JobCredentialRuntime` unless a later caller
  injects the returned activator.
- `Materialize` requires `JobCredentialDeliveryModeFileTmpfs`, a complete
  identity that names that file binding, and a non-nil `LiveSecretSource`. It
  fills once, does not retain the live source, exposes the guest `TargetPath`
  from the binding identity token (never a host absolute scratch path), and
  records `DeclaredFileBytes` plus SHA-256 of the exact filled bytes.
- Oversize, empty-when-required, identity mismatch, nil source, nil context,
  and cancellation fail closed before a durable host file is left behind.
- A source panic, including one after filling the bounded sink, is contained;
  the activator wipes its sink copy and returns only the stable unavailable
  error.
- `Revoke` overwrites then unlinks the host materialization. A failed revoke
  keeps ownership so a later retry can still wipe and unlink.
- Non-Linux constructors and `Materialize` fail closed with
  `ErrL8JobCredentialRuntimeUnsupported` before creating files.
- Errors, `String`/`GoString`/`Format`, and JSON/text/binary encodings never
  include secret bytes, host scratch paths, or `.hal` locations.

## Still unsupported / documented gaps

- Guest tmpfs mount-namespace, mount-monitor, and PID1 composition remain D4/D6
  guest work, not this host activator.
- D7 prepared-Linux live tmpfs acceptance is not claimed.
- HTTP proxy and SSH-relay production activators are separate slices.
- Default sandboxd/run/auto/factory/worker paths stay inert.

## Fake-only commands

```
go test ./internal/sandboxruntime/microvm/firecrackerhost -run 'Tmpfs|FileTmpfs|FileHandle' -count=1
go test ./internal/sandboxruntime/microvm/firecrackerhost -run '^$' -count=1
go test ./cmd -run 'TmpfsActivator|FileTmpfs' -count=1
go vet ./internal/sandboxruntime/microvm/firecrackerhost
```

No test requires KVM, Firecracker, a live guest, network, or cloud APIs.
Tests use in-memory/fake `LiveSecretSource` values plus temporary directories.

## Broad verification

```
go test ./...
go vet ./...
make docs-check
make build
git diff --check
```

`golangci-lint` is reported only when `command -v golangci-lint` succeeds.

```
GOOS=linux GOARCH=amd64 go test -c -o /tmp/hal-firecrackerhost-linux.test ./internal/sandboxruntime/microvm/firecrackerhost
GOOS=windows GOARCH=amd64 go test -c -o /tmp/hal-firecrackerhost-windows.test.exe ./internal/sandboxruntime/microvm/firecrackerhost
```
