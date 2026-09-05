# Sandbox Runtime v2 Phase 15 Worker Host Registry Verification

Phase 15 covers the durable sandbox host registry and status CLI for local
worker daemon metadata. It documents and verifies `hal sandbox host` command
surfaces, safe JSON contracts, and the regression that registered worker hosts
do not change default sandbox runtime-driver selection.

## Commands

- `hal sandbox host register worker <id> --socket <path>`
- `hal sandbox host register worker <id> --socket <path> --live`
- `hal sandbox host list`
- `hal sandbox host list --json`
- `hal sandbox host status <id>`
- `hal sandbox host status <id> --json`
- `hal sandbox host status <id> --live`
- `hal sandbox host status <id> --live --json`
- `hal sandbox host delete <id>`

## Contract References

`sandbox-host-list-v1` is emitted by `hal sandbox host list --json`.

- Top-level fields are `contractVersion`, `hosts`, and `totals`.
- Host entries include identity, kind, endpoint summary, health,
  `supportedRuntimes`, and capacity.
- Entries are sorted by host name, then id, matching the durable registry order.
- Endpoint data is summary-only. Raw socket paths, hostnames, credentials, and URL query strings are intentionally omitted.
- The contract documentation includes an empty-registry example and a
  multiple-host example payload.

`sandbox-host-status-v1` is emitted by `hal sandbox host status <id> --json`.

- Top-level fields are `contractVersion`, `source`, `refresh`, and `host`.
- `source.mode` is `cached` for durable registry reads and `live-refreshed`
  after a successful explicit worker refresh.
- Cached responses do not contact worker daemons or runtime providers.
- Live responses update the durable cache only after a successful local Unix
  socket worker query.
- Endpoint data is summary-only. Raw socket paths, hostnames, credentials, and URL query strings are intentionally omitted.
- The contract documentation includes cached and live-refreshed example
  payloads.

## Verification Commands

Run focused checks for the host command family:

```sh
go test -timeout=120s ./cmd -run 'TestSandboxHostCommandScaffoldRegistered|TestSandboxHostHelpListsScaffoldSubcommands'
go test -timeout=120s ./cmd -run 'TestSandboxHostRegisterWorker'
go test -timeout=120s ./cmd -run 'TestSandboxHostList'
go test -timeout=120s ./cmd -run 'TestSandboxHostStatus'
go test -timeout=120s ./cmd -run 'TestSandboxHostDelete'
go test -timeout=120s ./cmd -run 'TestContractDocsIncludeSandboxHostListFields|TestContractDocsIncludeSandboxHostStatusFields|TestSandboxHostContractDocsDocumentAutomationSafety|TestPhase15WorkerHostDocumentationCoversContractsVerificationAndScope'
go test -timeout=180s ./cmd -run 'TestExistingSandboxExecutionDefaultResolversStayWorkerOptIn|TestClientDriverSelectedOnlyWhenExplicitlyConstructed|TestRunSandboxDefaultRuntimeDriverResolver|TestAutoSandboxDefaultRuntimeDriverResolver|TestFactorySandboxDefaultRuntimeDriverResolver'
make docs-check
make build
make vet
go test -timeout=300s ./...
```

These commands cover command registration, worker registration, list output,
status output, deletion, JSON contract documentation, generated CLI reference
drift, runtime-selection regression, build, vet, and the full Go package graph.

## Phase 15 Non-Goals

Phase 15 does not implement scheduling, remote worker networking, Podman host management, microVM support, credential proxying, network proxying, or automatic runtime selection.

The durable host registry stores metadata for inspection. It does not schedule
sandboxes onto hosts, select worker-backed drivers by default, create or manage
Podman hosts, start remote worker networking, or mutate runtime targets.

## Security Metadata

Worker security metadata distinguishes requested security controls from
actually enforced worker controls. Requested controls describe the policy the
worker would like to provide. Actually enforced worker controls describe only
what the worker reports as enforced.

The local worker foundation must not claim deny-by-default network enforcement,
firewall or proxy enforcement, credential proxy support, network proxy support,
or microVM isolation unless a future phase implements and verifies those
controls.
