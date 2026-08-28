# Sandbox Runtime v2 L8 D6 HTTP Credential Activator Verification

This slice adds the default-off production HTTP credential activator that
implements `firecrackerhost.l8JobCredentialHTTPProxyActivator` by wrapping
`internal/credentialproxy.TicketStore`. Callers construct it with
`NewProductionL8JobCredentialHTTPProxyActivator` and inject it into the host
JobCredentialRuntime. `sandboxd`, `hal run`, `hal auto`, factory, worker
`Service`, and `NewProductionL8JobCredentialRuntime` do not invoke it unless
the caller injects the activator.

Activate requires HTTP-proxy delivery mode plus a valid identity, binding, and
source, then issues a TicketStore ticket. The handle `ServiceID()` is the
binding service id (safe identifier only). Renew and Revoke go through the
ticket store. Revoke is mandatory cleanup; a failed revoke does not drop ownership.
Tickets, secrets, source values, and host paths are never serialized.
Panic, nil, typed-nil, and identity-mismatch fail closed.

This slice is TicketStore-backed and fake-only. It does not listen or dial, does
not start a live proxy, KVM, or Firecracker process, and does not claim D7, L10, L11,
or live HTTP enforcement. Default command paths stay unwired.

## Focused verification

```sh
go test ./internal/sandboxruntime/microvm/firecrackerhost -run 'L8JobCredential.*HTTP|HTTPActivator|HttpActivator' -count=1
go test ./internal/credentialproxy -count=1
go test ./internal/sandboxruntime/microvm/firecrackerhost -run '^$' -count=1
go test ./cmd -run 'HTTPActivator|HttpActivator' -count=1
go vet ./internal/sandboxruntime/microvm/firecrackerhost ./internal/credentialproxy
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
