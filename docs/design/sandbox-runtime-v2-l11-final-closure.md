# Sandbox Runtime v2 L11 Final Closure

L11 is the final closure node for issue #49. It does not add another runtime,
policy engine, credential broker, proof format, scheduler, or cleanup owner. It
composes the accepted production authorities from L3, L5, L7, L8, L9, and L10
on the prepared Linux machine, exercises the exact final matrix below, and
records sanitized release evidence.

Current closure state: `blocked`.

No acceptance is claimed by this document. All nine rows are unmet and
`blocked`. No L11 production live wiring is added by this contract-only slice.
The selected L11 test, wrapper, prepared-host results, and final release record
are future work after the L8 and L10 dependencies described below are accepted
on the aggregate.

The canonical blocked document is protected by a same-repository SHA-256
tripwire plus regular-file identity checks. That tripwire detects accidental or
uncoordinated drift, but it cannot defend against a coordinated edit of both the
document and its checked-in digest. Code review and external branch protection
remain required trust boundaries for every change to this contract.

## 1. Inputs, outputs, states, and failure codes

### Required inputs

The future L11 selected lane consumes only existing production authorities and
their exact correlated identities:

1. the exact aggregate base, L11 head and tree, and candidate aggregate merge;
2. a prepared Linux amd64 host satisfying the accepted L3/L5/L7 prerequisite
   contracts without a skip;
3. Accepted L8 live credential authority, obtained from the production
   `JobCredentialRuntime` lifecycle for the selected job and represented by
   mutually exclusive live active and cleanup proof values;
4. accepted L10 strict-composition authority, including the live opaque active
   attestation at selection time and its exact terminal `complete` decision;
5. the accepted L9 immutable OCI selection and runtime-image binding;
6. an isolated clone/copy workspace, durable job/finalization state, collected
   artifacts, sync-out summary, and optional explicit safe-apply result; and
7. exact before/after observations of every resource owned by the selected
   scenarios.

A durable L10 decision cannot recreate live authority. Runtime names, cached
readiness, requested intent, sanitized projections, fake adapters, fixture
proofs, and manually constructed proof values are not L11 inputs. The L10 and
L11 selected tests and every helper reachable from them must not call or retain
`NewJobCredentialActiveProof` or `NewJobCredentialCleanupProof`; the live L8
owner must issue those proof values through the production lifecycle.

### Outputs and states

The selected lane eventually produces one sanitized result for each exact
scenario ID plus a final verification record. These are release evidence only;
they are not runtime authority and cannot select, start, resume, or upgrade a
sandbox.

The release-evidence states are `blocked`, `running`, `passed`, and `failed`.
Every row starts `blocked`. A row may be recorded as `passed` only from the
future exact selected live result after its test and cleanup finish. Overall
L11 closure may be accepted only when all nine exact rows pass once, the
selected run contains zero skips, the L8 and L10 authorities are accepted and
correlated, all artifact checks pass, and the final owned-resource census is
zero. A missing dependency, prerequisite, test, result, or cleanup observation
keeps the closure blocked.

Stable sanitized failure codes are:

- `dependency_unaccepted`;
- `prerequisite_missing`;
- `required_test_missing`;
- `required_test_skipped`;
- `scenario_failed`;
- `authority_synthetic`;
- `evidence_mismatch`;
- `artifact_invalid`;
- `cleanup_incomplete`;
- `resource_leak`; and
- `evidence_unsafe`.

These codes describe verification outcomes. They do not expand a public runtime
or command schema in this contract-only slice.

## 2. Package ownership and import boundaries

Existing component owners remain authoritative:

- `cmd` owns command composition, the final prepared-Linux black-box tests,
  static L11 documentation/source guards, and sanitized command projections;
- `internal/sandboxworker` owns durable jobs, reconnect/recovery, bounded logs,
  worker capacity, and the production L8 worker-v2 path;
- `internal/sandboxruntime/microvm/firecrackerhost` owns Firecracker, retained
  L7 network authority, guest transport, and runtime teardown;
- the accepted L8 packages own secret sources, locked memory, helper/session
  lifecycles, HTTP/file/SSH activation, and credential absence proof;
- `internal/strictcomposition` owns the future accepted L10 conjunction and
  opaque live attestation;
- `internal/sandboxtemplate` owns L9 acquisition, immutable selection, and
  digest trust;
- `internal/sandboxexecution` and `internal/sandboxworkspace` own durable
  finalization, artifact containment, sync-out, and explicit safe apply; and
- the future `tools/microvm/l11/verify-selected-live.sh` wrapper owns exact test
  discovery, JSON result counting, and rejection of skips.

L11 must not recreate any of those authorities in a new package. In
particular, `cmd` cannot mint active/cleanup credential proofs, reconstruct the
L10 attestation from JSON, infer strict state from a driver label, or interpret
resource names as ownership. Any production defect found by the matrix is fixed
and reviewed in its existing owner before the L11 lane is rerun.

The present slice contains only this design note and static `_test.go` guards.
It adds no production import, constructor, live marker, test transport,
provider, process, listener, namespace, rule, mount, credential, or release
projection.

## 3. Durable and machine-contract schema changes

This contract-only slice changes no durable or public machine schema. It does
not add an L11 field to manifests, jobs, sandbox state, factory records,
timeline events, status output, or runtime inspection output.

After L10 is accepted, L11 must audit every additive L10 projection against the
versioned run, auto, factory, sandbox-status, and sandbox-runtime contract docs
and examples. Any required documentation/example update follows the accepted
production shape; L11 does not predeclare that shape. Decoding a durable strict
decision remains data-only and cannot mint a live attestation.

The checked-in final verification record, when it exists, is operator/release
evidence rather than a product API. It records the exact aggregate base, L11
head and tree, accepted aggregate merge, commands and exit states, selected
test/row counts, zero selected-test skips, zero owned-resource leaks, artifact
content digests, independent reviews, cleanup result, and final handoff.
Its public detail is limited to safe scenario IDs, stable failure codes, counts,
and content digests plus the exact identities and commands above.

## 4. Redaction and containment rules

Release evidence may contain exact Git commit/tree identities, documented
commands, build-tag names, exact selected-test and safe scenario IDs, stable
failure codes, pass/fail/blocked states, bounded counts, and content digests.

Release evidence and test failures must not contain endpoints, sockets,
hostnames, IP addresses, ports, URLs, credentials, secret values, environment
values, PIDs, inode/device IDs, rule bodies, provider handles, or identifying
host paths. It also omits raw process arguments, HTTP headers/bodies, registry
credentials, SSH key material, credential payloads, workspace repository URLs,
and dynamic source errors.

Live probes keep raw observation material inside the selected process and
reduce it to safe categories and counts before reporting. Test roots are
private, contained, and created beneath an explicitly validated parent. An
artifact is accepted only after its store path, stable ID, declared size, and
content digest are revalidated through the production store boundary. L11
never follows an ambient path or removes an unrelated resource.

## 5. Crash, retry, cancellation, and cleanup semantics

Each matrix row uses a fresh sandbox, execution, worker-job, runtime generation,
network generation, credential generation, workspace, and resource baseline.
There is no retry that reuses live authority. Repeated recovery or cleanup
means a new bounded observation of the same exactly owned terminal state; it
does not rerun the admitted workload or recreate a credential.

The crash rows deliberately lose the initiating client, worker daemon,
Firecracker/guest, retained L7 authority, or L8 credential component at the
documented boundary. Reconnect uses durable identity and the production
discovery/recovery path. Unknown or interrupted work remains terminal and is
never silently restarted. Cancellation or timeout after live work begins is a
failed row until finalization converges and resource absence is proven.

Cleanup is lock-protected, checkpointed, bounded, repeatable, and restricted to
resources whose exact ownership is established. Cleanup errors are joined and
sanitized; a partial cleanup cannot publish success or begin final artifact
handoff. The final census covers owned containers, Firecracker processes,
helpers, listeners/connections, namespaces, mounts, monitors, cgroups, sockets,
network rules/routes, locks, leases, credential tickets/buffers/sessions, and
temporary/cache/artifact staging. Historical and unrelated resources are
observed but never removed without exact ownership proof.

Hetzner, Lightsail, and every other billed cloud call remain unauthorized.
Prepared fixtures are local and owned. The selected lane must not contact the
public internet, probe a cloud account, read cloud credentials, or turn missing
local prerequisites into a skip.

## 6. Red-first fake and live acceptance tests

### Exact nine-phase final matrix

| Phase | Scenario ID | Runtime boundary | Required live observation | Initial state |
|---|---|---|---|---|
| 1 | `rootless_advisory_success` | Rootless Podman | Production execution succeeds, remains advisory, and cannot obtain strict selection | `blocked` |
| 2 | `rootless_client_loss_reconnect` | Rootless Podman | Initiating client is lost after durable admission; reconnect observes one continuing job with no rerun | `blocked` |
| 3 | `rootless_daemon_restart_recovery` | Rootless Podman | Worker daemon restarts; durable recovery, artifacts, lease release, and teardown converge once | `blocked` |
| 4 | `strict_firecracker_success` | Strict Firecracker | Exact live L5/L7/L8/L9/L10 conjunction selects strict, executes, and reaches terminal complete | `blocked` |
| 5 | `strict_remove_one_proof` | Strict Firecracker | Each required live proof is independently removed or corrupted and strict selection fails closed | `blocked` |
| 6 | `strict_runtime_loss_reconnect` | Strict Firecracker | Client, worker, guest/Firecracker, and retained-network loss paths reconnect or recover without rerun | `blocked` |
| 7 | `strict_credential_loss_recovery` | Strict Firecracker | Proxy/helper/relay/credential loss revokes authority, proves absence, and never retains strict active state | `blocked` |
| 8 | `artifact_integrity_and_safe_handoff` | Both runtime classes | Durable artifacts, recovery, sync-out, digest validation, and explicit safe handoff remain contained and exact | `blocked` |
| 9 | `zero_resource_leaks` | Both runtime classes | Repeated terminal recovery and cleanup leave the exact owned-resource census at zero | `blocked` |

All nine rows are unmet and `blocked`. Their order and IDs are closed. Missing,
duplicate, renamed, reordered, prematurely passed, or prematurely completed
rows invalidate the matrix.

The future top-level selected test name is
`TestL11PreparedLinuxFinalClosure`, behind the distinct
`l11_final_closure_integration` build tag plus the accepted prerequisite tags.
Its implementation must expose the nine scenario IDs above as exact subtests.
A selected required live test that skips is a blocker, never a pass. Neither
the top-level test nor any reachable helper may call `t.Skip`, `t.Skipf`, or
`t.SkipNow`.

The future selected wrapper must first discover exactly one selected top-level
test. It must capture `go test -json`, wait for the child process, reject every
skip event, require exactly one run and one pass event for the selected
top-level test, and require exactly one run and one pass event for each of the
nine required rows. A missing row, duplicate result, child failure, cleanup
failure, or nonzero final resource count fails the wrapper.

The reserved future command is:

```sh
tools/microvm/l11/verify-selected-live.sh matrix
```

That wrapper and selected test do not exist in this contract-only slice. Their
absence is `required_test_missing`, so the current closure remains blocked.

Red-first guard coverage locks the document sections, exact row catalog and
initial state, duplicate/missing/renamed mutations, premature pass/completion
mutations, no-skip rule, no synthetic credential-proof constructors throughout
the selected L10/L11 reachable helper graph, no billed-cloud markers, and safe
release evidence. Later red tests must precede the rootless, strict, crash,
artifact, and resource-census implementation.

Static contract verification commands are:

```sh
go test -count=1 ./cmd -run '^TestL11FinalClosure'
go test -race -count=1 ./cmd -run '^TestL11FinalClosure'
go test -count=20 ./cmd -run '^TestL11FinalClosure'
```

Broad fake-safe release gates are:

```sh
go test -count=1 ./...
go test -count=1 -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

Tracked Go files also require a clean gofmt check. Run `golangci-lint` only
when installed and report unavailable separately from passed. Cross-platform
compile checks remain required regression gates, but they are not non-Linux
sandbox-security claims.

## 7. Non-goals and final handoff

L11 does not implement a runtime, credential mechanism, network rule engine,
template verifier, workspace apply policy, proof constructor, live attestation,
cloud provider, or automatic host mutation. It does not upgrade rootless
Podman, accept simulated or metadata-only authority, make live tests default,
publish a release, or treat an optional/required skip as success.

This contract-only slice hands off three explicitly blocked implementation
lanes:

1. L8 must land its production credential runtime, full D4 wrapper, root
   composition, selected prerequisite test, selected E2E, terminal/restart
   matrix, and no-skip evidence on the aggregate.
2. L10 must be reconciled onto that accepted aggregate, consume real L8-issued
   proof values rather than synthetic constructors, pass its exact remove-one-
   proof matrix, and produce accepted no-skip prepared-Linux evidence.
3. L11 may then implement the selected nine-row test, owned-resource census,
   wrapper, machine-contract audit, and final sanitized release record.

Hetzner and Lightsail remain deferred to a separately authorized issue if
accounts and billing authority later exist. Until all three handoffs close, the
only truthful L11 result is `blocked`.
