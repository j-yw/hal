# L8 D7 injected helper transport

This slice admits default-off, injected helper I/O for the unprivileged
credential client. It does not claim L8 complete, does not claim L10, and
does not claim L11. D7 prepared-Linux acceptance remains unaccepted.

`credentialclient` already defines helper packet constructors. `Client.Serve`
now sends `PacketTypePrepareBegin` after the first controller prepare only
when a `HelperConnectionOwner` is injected. A nil owner keeps
`ErrClientControlDependencyUnaccepted` and does not call `SendHelper`.

The owner returns one same-object revalidated `VerifiedHelperStream`. It is
inherited/preopened. This slice does not add `net.Listen`, `net.Dial`,
`unix.Socket`, or `SOCK_STREAM` to `control_contract_red.go`. Unix
`SOCK_SEQPACKET` socketpairs exist in tests only. Linux production code
revalidates an injected `syscall.Conn` stream and never creates sockets.

After a successful prepare-begin send, Serve retains the same revalidated
stream for that one logical prepare. It emits same-request prepare-commit only
when no ordered file payload is required; otherwise it fails closed before
receiving another controller request. Payload send (`prepare-file`,
`exec-private`, nonempty `exec-stream`), SCM_RIGHTS SSH send, and JobCredential
proofs remain `dependency_unaccepted`. This slice does not mint proofs.

Default command paths stay unwired. There is no sandboxd, `hal run`,
`hal auto`, or factory helper-transport wiring.

## Focused fake-only commands

```
go test ./internal/sandboxruntime/microvm/guestagent/server/credentialclient -run '^TestL8D7GuestHelper' -count=1
go test ./cmd -run '^TestL8D7HelperTransport' -count=1
go vet ./internal/sandboxruntime/microvm/guestagent/server/credentialclient ./cmd
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

`golangci-lint` reported only when `command -v golangci-lint` succeeds.

## Non-goals

This slice does not:

- accept D7 prepared-Linux live proof;
- implement payload-bearing helper send or SCM_RIGHTS SSH send;
- mint JobCredential active or cleanup proofs;
- wire sandboxd, `hal run`, `hal auto`, or factory;
- claim L8, L10, or L11 complete;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`.
