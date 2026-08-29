# L8 D7 injected helper metadata sends

This slice admits default-off, injected helper metadata sends for the
unprivileged credential client after prepare-begin. It does not claim L8 complete,
does not claim L10, and does not claim L11. D7 prepared-Linux acceptance remains
unaccepted. Live D7 remains unaccepted.

`credentialclient` already defines helper packet constructors.
`Client.Serve` now sends `PacketTypePrepareBegin` after the first controller
prepare only when a `HelperConnectionOwner` is injected, then continues the
Serve loop. A later controller prepare, renew, revoke, or exec with the pinned
session identity digest sends the matching metadata-only helper packet on the
same revalidated `VerifiedHelperStream` using `newHelperPrepareCommitSendPacket`,
`newHelperRenewSendPacket`, `newHelperRevokeSendPacket`, and
`newHelperExecSendPacket`. The packet types now sent are
`PacketTypePrepareBegin`, `PacketTypePrepareCommit`, `PacketTypeRenew`,
`PacketTypeRevoke`, and `PacketTypeExec`. A nil owner keeps
`ErrClientControlDependencyUnaccepted` and does not call `SendHelper`.

The owner returns one same-object revalidated `VerifiedHelperStream`. It is
inherited/preopened. This slice does not add `net.Listen`, `net.Dial`,
`unix.Socket`, or `SOCK_STREAM` to `control_contract_red.go`. Unix
`SOCK_SEQPACKET` socketpairs exist in tests only. Linux production code
revalidates an injected `syscall.Conn` stream and never creates sockets.

Payload send (`prepare-file`, `exec-private`, nonempty `exec-stream`),
SCM_RIGHTS SSH send, and JobCredential proofs remain `dependency_unaccepted`.
If a later operation requires those, Serve fails closed the same way. This
slice does not mint proofs.

Default command paths stay unwired. There is no sandboxd, `hal run`,
`hal auto`, or factory helper-metadata-sends wiring.

## Focused fake-only commands

```
go test ./internal/sandboxruntime/microvm/guestagent/server/credentialclient -run '^TestL8D7GuestHelper' -count=1
go test ./cmd -run '^TestL8D7HelperMetadataSends' -count=1
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
