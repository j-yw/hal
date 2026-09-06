# Sandbox Runtime v2 Phase 16 Runtime Inspection Verification

Phase 16 covers the read-only `hal sandbox runtime` inspection command family.
It documents and verifies cached and live runtime list/status output, endpoint
safety, JSON contracts, and regression guards that keep runtime inspection
separate from sandbox daemon and execution behavior.

## Commands

- `hal sandbox runtime list <host-id>`
- `hal sandbox runtime list <host-id> --json`
- `hal sandbox runtime list <host-id> --live`
- `hal sandbox runtime list <host-id> --live --json`
- `hal sandbox runtime status <host-id> <runtime-id>`
- `hal sandbox runtime status <host-id> <runtime-id> --json`
- `hal sandbox runtime status <host-id> <runtime-id> --live`
- `hal sandbox runtime status <host-id> <runtime-id> --live --json`

## Contract References

`sandbox-runtime-list-v1` is emitted by
`hal sandbox runtime list <host-id> --json`.

- Top-level fields are `contractType`, `contractVersion`, `host`, `source`,
  `runtimes`, `capacity`, `security`, `diagnostics`, and `errors`.
- Source modes are `cached`, `live-refreshed`, and `unsupported-live`.
- Cached output reads durable host records only and does not construct worker
  clients.
- Live worker output is response-only. It may query fakeable worker
  status/capabilities, but Phase 16 does not persist refreshed runtime data.
- Runtime entries are sorted by runtime id.
- Endpoint data is summary-only. Raw socket paths, hostnames, credentials, URL
  query strings, temp paths, and sensitive endpoint details are intentionally
  omitted.

`sandbox-runtime-status-v1` is emitted by
`hal sandbox runtime status <host-id> <runtime-id> --json`.

- Top-level fields are `contractType`, `contractVersion`, `host`, `runtime`,
  `source`, `supportedOperations`, `capacity`, `readiness`, `security`,
  `diagnostics`, and `errors`.
- Source modes are `cached`, `live-refreshed`, and `unsupported-live`.
- Readiness values are `ready`, `unavailable`, and `unknown`.
- JSON error responses keep the full endpoint-safe response shape with stable
  error codes such as `runtime_not_found`.
- Live worker status uses worker capabilities as the authority for the
  requested runtime and does not persist refreshed runtime data.
- Endpoint data is summary-only. Raw socket paths, hostnames, credentials, URL
  query strings, temp paths, and sensitive endpoint details are intentionally
  omitted.

## Verification Commands

Run focused checks for the runtime inspection command family:

```sh
go test -timeout=120s ./cmd -run 'TestSandboxRuntime(Command|Help|Generated)'
go test -timeout=120s ./cmd -run 'TestContractDocsIncludeSandboxRuntime(List|Status)Fields|TestSandboxRuntime(List|Status)ContractExamplesMatchSchema|TestPhase16RuntimeInspectionDocumentationCoversVerificationAndScope'
go test -timeout=120s ./cmd -run 'TestSandboxRuntimeList'
go test -timeout=120s ./cmd -run 'TestSandboxRuntimeStatus'
go test -timeout=120s ./cmd -run 'TestSandboxRuntimeInspectionDoesNotBleedIntoExecutionCommands|TestSandboxHost(Command|Help|RegisterWorker|List|Status|Delete)'
go test -timeout=120s ./cmd -run 'TestExistingSandboxExecutionDefaultResolversStayWorkerOptIn|TestClientDriverSelectedOnlyWhenExplicitlyConstructed|TestSandboxRuntimeCompat'
make docs-check
git diff --check
go test -timeout=300s ./...
go vet ./...
make build
make lint
```

These commands cover command registration, generated CLI reference drift,
runtime list/status contracts, cached and live output, unsupported-live
fallbacks, endpoint redaction, sandbox host regression guards, sandbox daemon
and execution command separation, default runtime resolver compatibility, the
full Go package graph, vet, build, and lint when the linter is installed.

Run `make docs-cli` before `make docs-check` when command metadata or examples
change.

## Phase 16 Non-Goals

Phase 16 verification explicitly excludes real worker socket integration tests,
Podman workflows, network tests, and sandbox execution behavior changes.

Do not run real worker daemons, bind real worker sockets, contact remote worker
hosts, run Podman or Docker workflows, pull images, access cloud resources,
open network connections, or execute `hal run`, `hal auto`, `hal factory run`,
or `hal sandboxd` as part of Phase 16 story verification.

Runtime inspection is read-only. Cached paths read durable host metadata. Live
paths may query fakeable local worker clients in tests, but they must not write
refreshed capability data back to durable host records or alter sandbox runtime
selection.

## Security Metadata

Security metadata separates requested controls from enforced controls. Runtime
inspection output must not claim deny-by-default network enforcement, firewall
or proxy enforcement, credential proxy support, network proxy support, or
microVM isolation unless those claims are present in durable metadata or live
worker capabilities.
