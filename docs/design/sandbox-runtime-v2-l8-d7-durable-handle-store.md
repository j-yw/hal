# L8 D7 durable credential handle store

This slice adds a Linux-only, default-off durable store of **handle
metadata** (not secrets) so
`L8JobCredentialRuntime.RecoverJobCredentials` can reacquire cleanup
authority after restart. It does not claim L8 complete, does not claim
L10, and does not claim L11. D7 prepared-Linux live acceptance remains
unaccepted.

The store is never constructed by sandboxd, `hal run`, `hal auto`,
factory, worker defaults, or `NewProductionL8JobCredentialRuntime`
unless a caller injects it.

## Real operations

- `NewProductionL8JobCredentialHandleStore` requires an existing
  absolute mode-`0700` directory owned by the service UID. Non-Linux
  constructors fail closed with `ErrL8JobCredentialRuntimeUnsupported`
  before creating files.
- Records are written beside runtime-owner state with `openat` +
  `O_NOFOLLOW`, mode `0600`, exclusive temp create, `fsync`, and
  `renameat`. Directory flock is exclusive for save and shared for load.
- After successful Prepare (and Renew), the runtime persists binding
  IDs, modes, guest `TargetPath`, file SHA-256/size, HTTP service ID
  (not ticket bytes), SSH policy ID/revision, identity digest, and
  revision. Secret values, host paths, and raw tickets are rejected.
- `RecoverJobCredentials` with a nil store, or with no metadata for
  this identity, still returns `dependency_unaccepted` and mints no
  cleanup proof. Invalid identity is still mismatch.
- When metadata is present, recovery attempts revoke/cleanup through
  injected activators if they still hold the resource. If every
  resource can be proved absent, or was never durable in this process,
  recovery returns a real `NewJobCredentialCleanupProof`.
- Errors, `String`/`GoString`/`Format`, and JSON/text/binary encodings
  never include secret bytes, host paths, tickets, or directory paths.

## Still unsupported / documented gaps

- Sealed PID1 expected digests, live helper transport, and a production
  L7 session factory remain unaccepted D7 closures.
- Default sandboxd/run/auto/factory/worker paths stay inert.
- This slice does not implement live selected credential delivery
  proofs.

## Fake-only commands

```
go test ./internal/sandboxruntime/microvm/firecrackerhost -run 'HandleStore|HandleRecord|RecoverJobCredentials|RecoverMints|RecoverFailsClosed|RecoverDoesNotMint' -count=1
go test ./cmd -run 'TestL8D7PreparedLinuxRecoverJobCredentials' -count=1
go vet ./internal/sandboxruntime/microvm/firecrackerhost ./cmd
```

No test requires KVM, Firecracker, a live guest, network, or cloud APIs.
Tests use in-memory stores plus temporary directories.

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
