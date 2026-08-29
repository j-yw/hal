# L8 D7 helper exec-private payload send

This slice admits default-off, injected helper exec-private payload send for
the unprivileged credential client after a successful helper-response ledger
install. HL8E remains unissued. This slice does not change live D7 stub
fatals. It does not claim D7 live, does not claim L8 complete, does not claim
L10, and does not claim L11. D7 prepared-Linux acceptance remains unaccepted.
Live D7 remains unaccepted.

After an active helper-response ledger exists (metadata-only
`PacketTypePrepareCommit` succeeded) on an injected `HelperConnectionOwner`,
Serve keeps the same revalidated `VerifiedHelperStream`. Serve may send
`PacketTypeExec` metadata as today. For a prepare/exec that admits a nonempty
private exec binding, it then sends exactly one `PacketTypeExecPrivate`
(`0x17`) on that stream with the next helper sequence and the same request ID.
Private bytes come only from an already-admitted live exec payload on the
existing D6/D7 controller private-record path
(`PrivateRecordKindOpaqueExecBinding`). Encode uses
`EncodeHelperExecPrivateBody`. An opaque wipeable `helperExecPrivateOwner`
matches `HelperExecPrivateBody` (defensive copy, cap==len, Wipe, deny
serialization) and wipes private bodies after send or failure. Serve does not
log, format, or JSON-marshal private bytes.

After that single exec-private payload succeeds, Serve keeps the existing
helper-response ledger receive/map/`SendController` success path for exec.
Policy allow is still required before helper send if `ClientPolicy` is
injected. A nil `HelperConnectionOwner` stays unaccepted and does not call
`SendHelper`.

The helper exec-private path is fail-closed (`ErrClientControlDependencyUnaccepted`
or existing contract errors) for missing/nil helper owner, a private payload
whose length/digest/binding index/kind do not match the admitted exec
declaration, nonempty `exec-stream` payload, SCM_RIGHTS SSH send, and
JobCredential active/cleanup proof minting. This slice does not mint
JobCredential proofs. Serve does not receive a second controller prepare to
stand in for an outstanding exec-private transaction.

This slice does not add `net.Listen`, `net.Dial`, `unix.Socket`, or
`SOCK_STREAM` to `control_contract_red.go`. Unix `SOCK_SEQPACKET` socketpairs
exist in tests only. Linux production code revalidates an injected
`syscall.Conn` stream and never creates sockets.

Default command paths stay unwired. There is no sandboxd, `hal run`,
`hal auto`, or factory helper-exec-private wiring.

## Focused fake-only commands

```
go test ./internal/sandboxruntime/microvm/guestagent/server/credentialclient -run '^TestL8D7GuestHelper' -count=1
go test ./cmd -run '^TestL8D7HelperExecPrivate|^TestL8D7HelperPrepareFile|^TestL8D7HelperResponseLedger' -count=1
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
- implement nonempty `exec-stream` payload or SCM_RIGHTS SSH send;
- mint JobCredential active or cleanup proofs;
- wire sandboxd, `hal run`, `hal auto`, or factory;
- claim L8, L10, or L11 complete;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`;
- treat L5 images as L8 proof / L5-as-L8;
- generate HL8E from a fixture;
- generate `verified-pinned-callsites.hl8e` from a fixture;
- issue HL8E or enable `generateEvidence` success.
