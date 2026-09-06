# Sandbox Runtime v2 Phase 46 Final Fake-Only Verification

Phase 46 final verification barrier is fake-only and default-safe. It fans in
the completed credential delivery activation contracts, fake activation
adapters, fail-closed downgrade rules, sanitized command/factory projection,
runtime and worker metadata redaction guards, import-boundary guards, optional
live-harness gate, and documentation safety checks without making secure
credential delivery generally available.

Phase 46 records the default-safe credential delivery matrix without making
secure credential delivery generally available. Secure default selection/gating
is Phase 48 and is not part of Phase 46. Template acquisition is Phase 47 and
is not implemented by Phase 46.

No story implementation or documentation requires running `hal run`.

## Default-Safe Credential Delivery Matrix

| Mode | Phase 46 behavior | Default-safe barrier | Not included in Phase 46 |
| --- | --- | --- | --- |
| `http_proxy` | Fake activation can report active only when sanitized credential proxy, secret broker, network proxy, and Phase 45 network-enforcement proof metadata correlate through an injected adapter. | No default active delivery; missing proof, missing adapter, or uncorrelated metadata is skipped or plan-only. | No live proxy credential injection, live upstream proxying, secure default selection, or default gating. |
| `file_tmpfs` | Fake activation can report sanitized active metadata for explicit test fixtures. | No default active delivery; without an injected fake adapter it is skipped or plan-only. | No tmpfs mount, file write, guest file injection, secure default selection, or default gating. |
| `ssh_agent` | Fake activation can report sanitized active metadata for explicit test fixtures. | No default active delivery; without an injected fake adapter it is skipped or plan-only. | No SSH-agent forwarding, `SSH_AUTH_SOCK` dependency, secure default selection, or default gating. |
| `env` | Fake activation can report sanitized active metadata for explicit test fixtures. | No default active delivery; without an injected fake adapter it is skipped or plan-only. | No environment mutation, environment secret injection, secure default selection, or default gating. |
| `legacy_auth_sync` | Compatibility metadata remains requested/skipped metadata with a compatibility warning. | Never projected as an active secure credential delivery mode. | No secure delivery proof, no default active delivery, no secure default selection, or default gating. |

## Focused Fake-Only Checks

Run credential delivery activation contract, fake adapter, downgrade,
projection, redaction, import-boundary, and optional-live gate coverage:

```sh
go test -count=1 ./internal/credentialdelivery
```

Run sandbox credential proxy and credential delivery metadata coverage:

```sh
go test -count=1 ./internal/sandbox
```

Run factory secret broker, credential proxy bridge, credential delivery proof,
and redaction coverage:

```sh
go test -count=1 ./internal/factory
```

Run runtime credential delivery metadata and import-boundary coverage:

```sh
go test -count=1 ./internal/sandboxruntime
```

Run worker credential delivery metadata and import-boundary coverage:

```sh
go test -count=1 ./internal/sandboxworker
```

Run command, projection, redaction, credential proxy, Phase 46 docs, and final
barrier guards:

```sh
go test -count=1 ./cmd -run 'TestCredentialDelivery|TestCredentialProxy|TestPhase46'
```

## Broad Quality Checks

Run the repository default test suite:

```sh
go test -count=1 -timeout=420s ./...
```

Run repository typecheck by compiling tests without running test bodies:

```sh
go test -count=1 -run '^$' ./...
```

Run vet, generated CLI documentation, build, and whitespace checks:

```sh
go vet ./...
make docs-check
make build
git diff --check
```

Run `golangci-lint run ./...` only when `golangci-lint` is installed. If it is
unavailable, report lint unavailable instead of reporting lint as passed.

Passing this matrix satisfies the Phase 46 fake-only checks and typecheck gate.

## Default-Safe Non-Goals

Phase 46 does not add live credential injection, proxy credential injection,
tmpfs secret delivery, SSH-agent forwarding, environment secret mutation,
secure default selection/gating, production network enforcement, production
microVM egress, provider credentials, template acquisition, worker daemon
requirements, Firecracker live tests, or default live E2E verification.

Phase 47 owns template acquisition. Phase 46 documents that boundary and does
not acquire templates, read OCI registries, fetch remote artifacts, or lock
template inputs.

Phase 48 owns secure default selection/gating. Phase 46 leaves activation
behind explicit sanitized metadata and injected fake adapters, and leaves any
future default selection policy to Phase 48.

Optional credential delivery live-harness coverage remains behind the
`credential_delivery_live` build tag and explicit `HAL_CREDENTIAL_DELIVERY_LIVE`
mode opt-ins. It is not part of default Phase 46 verification, and the current
placeholder still skips because no live delivery adapter is implemented in this
phase.

## Review Notes

Keep this document, `cmd/phase46_final_fake_only_verification_test.go`, and
`cmd/phase46_runtime_worker_docs_test.go` in sync when Phase 46 selectors,
optional live guardrails, docs boundaries, or broad verification commands
change. The default verification matrix must remain fake-only, optional live
commands must stay out of default command examples, and documentation must keep
Phase 47 template acquisition and Phase 48 secure default selection/gating
outside Phase 46.
