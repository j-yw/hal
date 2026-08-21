# L8 D6 Firecracker Overlay Foundation Verification

This slice adds the exact default-off `L8LiveBootConfigProvider` boundary to
the Firecracker runtime. It accepts only the resolver-owned opaque
`VerifiedL8Profile` and `VerifiedL8AssetLease` pair, keeps L7 and L8 authority
mutually exclusive, snapshots caller-mutable overlay data, contains provider
panics, and closes a provisionally transferred lease on every rejection or
pre-handoff start failure. The L8 render path is mutually exclusive with L7,
revalidates currentness immediately before and after synchronous process start,
and transfers the lease into process-keyed ownership until stop, delete, or
start-failure cleanup positively proves that the process is absent. Cleanup
uncertainty retains both process and lease ownership. Retained cleanup is
reachable through the original target's Start, Stop, or Delete operation and
is serialized by runtime generation. A cleanup-only Start always returns an
explicit retry-required error after proving absence, so it cannot launch a
second process in the same invocation. Provisional, active, and
cleanup-uncertain ownership are distinct registry states: duplicate Start on a
healthy active runtime is a stable nonmutating rejection and only the
cleanup-uncertain state enters recovery.

The foundation does not wire a command, worker, or `firecrackerhost` provider.
Planning-only/default construction remains inert. L8 authority is omitted from
JSON and runtime target metadata; no label, target metadata field, descriptor,
or image ID can mint or substitute for the opaque resolver result.

The positive accepted-profile start path is deliberately unaccepted. The
aggregate does not yet provide truthful D7 HL8E through
`EmbeddedExpectedPinnedCallsiteEvidence`, so the sole resolver issuer cannot
produce the accepted profile/lease fixture required by this lane. The tagged
`l8_d6_live_firecracker_overlay` dependency test therefore remains red with
`dependency_unaccepted` until D7 lands the exact host-only evidence. This slice
does not add a production fake issuer, synthetic production proof, active L8
claim, real Firecracker process start, or command default change. Package-local
direct state fixtures exercise render, handoff, close-error, close-panic,
successful-stop, value-plus-error process handles, typed-nil and panic
boundaries, post-start drift, concurrent retry, eventual cleanup, and
uncertain-cleanup ownership semantics; they cannot be configured through `BackendOptions` or command wiring.

Focused verification:

```text
go test -count=20 ./internal/sandboxruntime/microvm/firecracker -run '^(TestL8.*|TestBackendConfigJSONNeverProjectsL8Authority)$'
go test -race -count=5 ./internal/sandboxruntime/microvm/firecracker -run '^(TestL8.*|TestBackendConfigJSONNeverProjectsL8Authority)$'
go test -count=20 ./cmd -run '^(TestL8D6FirecrackerOverlayFoundation|TestPhase34DefaultFirecracker)'
```

Broad compile-only and quality checks remain:

```text
go test -run '^$' ./...
go vet ./internal/sandboxruntime/microvm/firecracker ./cmd
GOOS=linux GOARCH=amd64 go test -run '^$' ./internal/sandboxruntime/microvm/firecracker
GOOS=darwin GOARCH=arm64 go test -c -o /tmp/hal-l8-d6-firecracker-darwin-arm64.test ./internal/sandboxruntime/microvm/firecracker
GOOS=windows GOARCH=amd64 go test -c -o /tmp/hal-l8-d6-firecracker-windows-amd64.test.exe ./internal/sandboxruntime/microvm/firecracker
make build
```

The expected dependency gate is checked separately and must fail until D7 is
accepted:

```text
go test -tags=l8_d6_live_firecracker_overlay ./internal/sandboxruntime/microvm/firecracker -run '^TestL8LiveBootConfigAcceptedAuthorityDependencyGate$'
```
