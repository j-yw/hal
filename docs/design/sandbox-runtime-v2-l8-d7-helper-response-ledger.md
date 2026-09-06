# L8 D7 helper response ledger

This slice admits the default-off helper-response path that establishes the
exact active ledger after metadata-only prepare-commit, then allows Serve to
send correlated renew, revoke, and exec metadata. It does not claim L8 complete,
does not claim L10, and does not claim L11. D7 prepared-Linux acceptance remains
unaccepted. Live D7 remains unaccepted.

After a successful metadata-only `PacketTypePrepareCommit` send, Serve may
`ReceiveHelper` once with a correlated `HelperReceiveRequest` (sequence, request
ID set, identity digest) on the same revalidated `VerifiedHelperStream`. It
accepts only a well-formed `HelperResponseBody` for `requestType=prepare_commit`.
Ordered helper binding proofs must match the projected helper records
one-for-one (count, binding ID, mapped mode) before any active ledger is
installed. Mismatch is terminal and installs no active state.

The exact active ledger stores identity digest, request ID, helper generation,
projected helper manifest SHA-256, revision/expiry as already modeled, and
ordered proof IDs copied only after those checks. Credentialclient does not
hash v2 JSON and claims no digest authority for the full v2 manifest.

Once the active ledger exists, Serve may send correlated `PacketTypeRenew`,
`PacketTypeRevoke`, and `PacketTypeExec` metadata (zero payload, no SCM_RIGHTS)
and receive their helper responses, mapping success through
`mapHelperPrepareSuccessToV2`, `mapHelperRenewSuccessToV2`,
`mapHelperRevokeSuccessToV2`, and `mapHelperExecSuccessToV2`, then
`SendController` the v2 success. Policy allow is still required before helper
send if `ClientPolicy` is injected; missing policy for those operations stays
fail-closed.

File-bearing prepare, nonempty private exec, exec-stream payload, and
SCM_RIGHTS SSH remain `ErrClientControlDependencyUnaccepted`. This slice does
not mint JobCredential active or cleanup proofs. A nil `HelperConnectionOwner`
stays unaccepted and does not call `SendHelper`.

This slice does not add `net.Listen`, `net.Dial`, `unix.Socket`, or
`SOCK_STREAM` to `control_contract_red.go`. Unix `SOCK_SEQPACKET` socketpairs
exist in tests only. Linux production code revalidates an injected
`syscall.Conn` stream and never creates sockets.

Default command paths stay unwired. There is no sandboxd, `hal run`,
`hal auto`, or factory helper-response-ledger wiring.

## Focused fake-only commands

```
go test ./internal/sandboxruntime/microvm/guestagent/server/credentialclient -run '^TestL8D7GuestHelper' -count=1
go test ./cmd -run '^TestL8D7HelperResponseLedger' -count=1
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
