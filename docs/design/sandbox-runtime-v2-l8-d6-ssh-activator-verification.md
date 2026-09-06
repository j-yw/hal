# Sandbox Runtime v2 L8 D6 SSH-Agent Credential Activator Verification

## Scope

This default-off D6 slice implements the production Firecracker host
SSH-agent credential activator. It satisfies
`firecrackerhost.l8JobCredentialSSHRelayActivator` /
`l8JobCredentialSSHRelayHandle` by wrapping the existing daemon-local
`internal/sandboxruntime/microvm/firecrackerhost/sshrelay` registry and lease.

`NewProductionL8JobCredentialSSHRelayActivator` is explicit. It is never invoked by sandboxd,
`hal run`, `hal auto`, factory, worker defaults, or `NewProductionL8JobCredentialRuntime`
unless a caller injects the returned activator into `l8JobCredentialRuntimeDependencies.SSHRelay`.

`Activate` requires `JobCredentialDeliveryModeSSHAgent`, acquires one daemon-local sshrelay lease
against the host-admin `ConfigIdentity` injected at construction, and returns `PolicyID` /
`PolicyRevision` from that lease's policy identity. It does not open ambient agents, does not
call `OpenVerifiedConnection`, and does not persist entry, path, peer, or key selectors.
`Renew` and `Revoke` operate on that exact lease. A failed revoke must not drop ownership.
Live activator and handle values deny serialization using the sshrelay `liveValue` /
`ErrSerialization` pattern. Errors contain no agent paths, sockets, peer keys, or secrets.

This slice does not implement HTTP/tmpfs activators, recovery/finalize,
`credentialclient`, `cmd/hal-guest-init`, worker v2, L10/L11, unrestricted
host-agent forwarding, or sshrelay public-contract changes. The shared
architecture document remains unchanged.

## Focused verification

```sh
gofmt -w internal/sandboxruntime/microvm/firecrackerhost/l8_job_credential_ssh_activator.go \
  internal/sandboxruntime/microvm/firecrackerhost/l8_job_credential_ssh_activator_test.go \
  cmd/l8_d6_ssh_activator_docs_test.go
go test ./internal/sandboxruntime/microvm/firecrackerhost -run 'SSHRelay|SSHActivator|JobCredential.*SSH' -count=1
go test ./internal/sandboxruntime/microvm/firecrackerhost/sshrelay -count=1
go test ./internal/sandboxruntime/microvm/firecrackerhost -run '^$' -count=1
go test ./cmd -run 'SSHActivator|SSHRelayActivator' -count=1
go vet ./internal/sandboxruntime/microvm/firecrackerhost ./internal/sandboxruntime/microvm/firecrackerhost/sshrelay
```

Default tests are fake-only. They inject a fake sshrelay registry/lease or a
daemon-local `sshrelay.Registry` populated with a fake `LiveHostAgentEntry`.
They open no real ssh-agent sockets, create no network listeners, and do not use KVM.

## Broad verification

```sh
go test ./...
go vet ./...
make docs-check
make build
git diff --check
```

`golangci-lint` is reported only when `command -v golangci-lint` succeeds.
