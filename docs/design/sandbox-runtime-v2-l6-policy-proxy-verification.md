# Sandbox Runtime v2 L6 Policy Proxy Verification

## Focused fake/default checks

```sh
go test -count=1 -timeout=120s \
  ./internal/sandboxruntime/networkenforcement \
  ./internal/sandboxruntime/networkenforcement/policyproxy \
  ./cmd \
  -run 'TestL6|TestPolicyProxy'

go test -race -count=1 -timeout=180s \
  ./internal/sandboxruntime/networkenforcement/policyproxy
```

These checks cover policy decisions, listener lifecycle, HTTP and CONNECT
forwarding, DNS/IP rebinding controls, bounds, redaction, cancellation,
cleanup, proxy-only proof, import boundaries, documentation, and default-path
non-activation. They use local fakes and disposable loopback listeners only.

## Selected tagged live check

```sh
env HAL_NETWORK_ENFORCEMENT_LIVE=1 HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=1 \
  go test -tags=network_enforcement_live -count=1 -timeout=120s \
  ./internal/sandboxruntime/networkenforcement/policyproxy \
  -run '^TestL6PolicyProxyLiveHTTPAndConnect$'
```

The selected test never skips. It fails when an opt-in marker or local
prerequisite is missing. It binds only ephemeral loopback listeners, uses no
external DNS or internet endpoint, and leaves no listener or goroutine behind.
It proves the real listener, HTTP transport, CONNECT tunnel, decision sink, and
cleanup path. It does not prove firewall/runtime enforcement or sandbox
reachability.

## Broad and portability gates

```sh
go test -count=1 -timeout=420s ./...
go test -count=1 -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

Compile the affected packages for Linux, Darwin, FreeBSD, and Windows. Run
`golangci-lint run --new-from-rev <L6-base> ./...` only when
`golangci-lint` is installed; the Make target's install hint is not a pass.

## Required evidence

Record the aggregate base, red-test commit and failure, green commits, exact
commands/results, selected-live zero-skip result, cleanup checks, cross-platform
compile results, lint availability/result, and worktree cleanliness. L5 not
being integrated blocks no fake/default L6 result, but final L6 live acceptance
must not be described as Firecracker or strict-network validation.
