# L8 D7 helper SCM_RIGHTS SSH send

This slice admits default-off, injected helper-to-agent SCM_RIGHTS SSH
receive for the unprivileged credential client after a successful
helper-response ledger install. The frozen catalog names this transfer
`PacketTypeSSHAcceptedFD` (`0x16`, `ssh_accepted_fd`): helper-to-agent
only. The client does not send SCM_RIGHTS and does not add a helper send
arm for SSH. HL8E remains unissued. This slice does not change live D7 stub
fatals. It does not claim D7 live, does not claim L8 complete, does not claim
L10, and does not claim L11. D7 prepared-Linux acceptance remains unaccepted.
Live D7 remains unaccepted.

After an active helper-response ledger exists (metadata-only
`PacketTypePrepareCommit` succeeded) on an injected `HelperConnectionOwner`,
Serve keeps the same revalidated `VerifiedHelperStream`. When idle, or after
the next controller packet is admitted and before the next helper send,
Serve drains at most one pending helper-to-agent `PacketTypeSSHAcceptedFD`
with non-blocking `recvmsg` on the injected `syscall.Conn`. Linux production code
revalidates that injected stream and never creates sockets. Unix
`SOCK_SEQPACKET` socketpairs exist in tests only. The receive path uses
`DecodeHelperSSHAcceptedFDBody` and `newHelperSSHAcceptedPacket` /
`helperPacketArmSSHAccepted`. Exactly one SCM_RIGHTS descriptor is required.
The private right is consume-once, never logged, formatted, or
JSON-marshaled, and is closed or wiped on every failure path. Destroy/cleanup
errors override dispatch and must not continue into helper/controller
success.

Dispatch maps the received arm onto the one registered SSH extension
(`ExtensionSession.Handle`). Ownership transfers only after `Handle` returns
nil, the caller context remains valid, and the client drain latch is still
clear (`commitExtensionPacketOwnership`). Cancellation and drain use an
internal bounded cleanup context, so they close the still-client-owned right
instead of transferring it to an extension whose `Close` already ran. A nil
`HelperConnectionOwner`, a non-`syscall.Conn` stream, missing/extra rights, a
non-SSH idle helper packet, a missing SSH extension, or a binding/revision
mismatch stays fail-closed (`ErrClientControlDependencyUnaccepted` or existing
contract errors). This slice does not mint JobCredential proofs. JobCredential
active/cleanup proof minting stays unaccepted.

This slice does not add `net.Listen`, `net.Dial`, `unix.Socket`, or
`SOCK_STREAM` to `control_contract_red.go`. It does not invent a client-to-helper
SSH send packet. A blocking helper/controller dual-wait mux remains
unaccepted: pending SSH is drained with `MSG_DONTWAIT` recvmsg, so an SSH
accepted FD that arrives while Serve is blocked on the controller is consumed
only after the next controller packet is admitted.

Default command paths stay unwired. There is no sandboxd, `hal run`,
`hal auto`, or factory helper-SCM_RIGHTS wiring.

## Focused fake-only commands

```
go test ./internal/sandboxruntime/microvm/guestagent/server/credentialclient -run '^TestL8D7GuestHelper' -count=1
go test ./internal/sandboxruntime/microvm/guestagent/credentialprotocol -run '^TestHelperSSHAccepted' -count=1
go test ./cmd -run '^TestL8D7HelperSCMRights|^TestL8D7HelperExecStream|^TestL8D7HelperExecPrivate|^TestL8D7HelperPrepareFile|^TestL8D7HelperResponseLedger' -count=1
go vet ./internal/sandboxruntime/microvm/guestagent/server/credentialclient ./internal/sandboxruntime/microvm/guestagent/credentialprotocol ./cmd
```

These commands are fake-only. They do not boot a VM, call billed APIs, or
select live tags. Linux socketpair SCM_RIGHTS checks stay inside the
credentialclient `TestL8D7GuestHelper` selector.

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
- mint JobCredential active or cleanup proofs;
- implement a client-to-helper SCM_RIGHTS send arm or helper-side sendmsg adapter;
- implement a blocking helper/controller dual-wait mux;
- wire sandboxd, `hal run`, `hal auto`, or factory;
- claim L8, L10, or L11 complete;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`;
- treat L5 images as L8 proof / L5-as-L8;
- generate HL8E from a fixture;
- generate `verified-pinned-callsites.hl8e` from a fixture;
- issue HL8E or enable `generateEvidence` success.
