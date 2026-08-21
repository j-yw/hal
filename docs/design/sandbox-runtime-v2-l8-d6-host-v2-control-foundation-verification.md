# Sandbox Runtime v2 L8 D6 Host v2 Control Foundation Verification

## Scope

This default-off D6 foundation owns one process-local host session on the
fixed guest-agent v2 control port 1025. It uses the existing retained
`ProductionVsockBridge` authority to correlate the exact live Firecracker
process, private VSOCK socket identity, and safe runtime target before opening
the stream. It then performs only the already-frozen canonical compatibility
preface, controller-authenticated session handshake, Finished exchange, and
readiness request/response.

The owner is one-shot. One admitted open consumes the bridge whether it
succeeds or fails. A successful session retains the stream and cryptographic
state until explicit close, bridge close, or exact process loss. Close is
terminal and idempotent. Public values expose only the authenticated guest
session and helper generation through nonserializable, redacted values.

This slice does not implement or claim `JobCredentialRuntime`, a runtime
provider, a preflight, prepare/renew/revoke/exec dispatch, active or cleanup
proofs, runtime absence, recovery, worker/cmd wiring, D7/HL8E acceptance, or
live availability. The production guest-side port-1025 accept/dispatcher and
controller application transport remain `dependency_unaccepted`; therefore
this foundation is a prerequisite rather than L8 runtime completion.

## Focused verification

```sh
go test -count=20 ./internal/sandboxruntime/microvm/firecrackerhost -run 'TestL8D6V2ControlFoundation'
go test -race -count=5 ./internal/sandboxruntime/microvm/firecrackerhost -run 'TestL8D6V2ControlFoundation'
GOOS=linux GOARCH=amd64 go test ./internal/sandboxruntime/microvm/firecrackerhost -run '^$'
GOOS=windows GOARCH=amd64 go test ./internal/sandboxruntime/microvm/firecrackerhost -run '^$'
```

## Broad verification

```sh
go test ./...
go vet ./...
make docs-check
make build
git diff --check
```

`golangci-lint` is reported only when `command -v golangci-lint` succeeds.
