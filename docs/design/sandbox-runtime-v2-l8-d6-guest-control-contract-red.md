# L8 D6 guest control contract verification

This candidate implements the accepted default-off guest-side request inspector,
readiness dispatcher, and process-local lifecycle composition around the frozen
contracts for a persistent authenticated control session on fixed VSOCK port
1025. Controller credential operations prepare, renew, revoke, and exec are
accepted packet constructors alongside readiness. Each success constructor
consumes the exact originating controller packet as its sequence, session,
request-ID, identity-digest, and lifecycle-correlation authority. Helper
packets, unknown and malformed controller arms, private/stream/credit/close-notify controller
packets, helper receive construction, and helper `writeCanonicalBody` remain
`dependency_unaccepted`.

The frozen surface is limited to:

- a bodyless canonical v2 request-root inspector and initial-prepare decoder;
- an injected inherited/preopened `ControlConnectionOwner` returning only a
  same-object revalidated `VerifiedControlStream`;
- immutable runtime-owned control boot identity and public-key correlation;
- package-private controller/helper packet issuers, body capabilities, send
  sinks, authenticated transport identity, and complete closed unions;
- one `credentialclient.Client.Serve` dispatcher and synchronous terminal
  `Close` owner; and
- an explicit optional `server.Options.CredentialClient` plus a process-local
  `l8composition.Agent` wrapper. A nil credential client preserves the existing
  v1 lifecycle and default entrypoints.

Focused selectors:

```sh
go test ./internal/sandboxruntime/microvm/guestagent/v2control -run '^TestL8D6GuestV2' -count=1
go test ./internal/sandboxruntime/microvm/guestagent/server/credentialclient -run '^TestL8D6Guest(Control|Transport|Packet|CredentialClient)' -count=1
go test ./internal/sandboxruntime/microvm/guestagent/server -run '^TestL8D6GuestServer' -count=1
go test ./internal/sandboxruntime/microvm/guestagent/l8composition -run '^TestL8D6Guest(ControlBoot|Agent)' -count=1
```

Compile-only boundary check:

```sh
go test ./internal/sandboxruntime/microvm/guestagent/v2control ./internal/sandboxruntime/microvm/guestagent/server/credentialclient ./internal/sandboxruntime/microvm/guestagent/server ./internal/sandboxruntime/microvm/guestagent/l8composition -run '^$' -count=1
```

Source guards require no bind, listen, dial, socket creation, ambient
credential discovery, externally exported packet issuer, or external
production packet-authority reference. The Go role accepts only injected,
preopened, revalidated ownership. This candidate adds no command/default
wiring, host/provider/worker/recovery integration, credential proof constructor,
synthetic active or cleanup proof, production readiness/liveness claim, D7 or
HL8E acceptance, live integration test, or absence proof.
