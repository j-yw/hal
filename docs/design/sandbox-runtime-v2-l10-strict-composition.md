# Sandbox Runtime v2 L10 Strict Composition and Default Selection

## Authority and phase boundary

L10 implements issue #49's locked strict-composition node. The authoritative
inputs are issue comments `5068151561`, `5068157402`, and `5068162708`, the
Linux-completion architecture, and the accepted L3, L5, L7, L8, and L9
handoffs. The exact integration base is
`357090101f8479ed11a6a84976787a9c09a1f4ff`.

Strict success is a conjunction. It is never inferred from a score, a runtime
name, cached readiness labels, requested policy, or independently successful
but uncorrelated components. At the claim point all live inputs must describe
the same sandbox, execution, worker, Firecracker generation, network plan,
policy snapshot, proxy generation, topology generation, rule generation,
credential authority, immutable template, and workspace policy.

Rootless Podman remains advisory even when its proxy and Linux rules are
active. L10 does not turn rootless, SSH-machine, compatibility, simulated,
metadata-only, planned, historical, fallback, stale, warning-bearing, or
cleanup-incomplete evidence into strict readiness.

## Package ownership and import boundary

`internal/strictcomposition` owns the sole live conjunction evaluator and the
opaque, short-lived active attestation. It may import only the existing pure or
live authority contracts in `internal/sandbox`, `internal/sandboxruntime`,
`internal/sandboxruntime/microvm/firecrackerhost/l7network`,
`internal/sandboxtemplate/selection`, and `internal/sandboxworkspace`, plus the
standard library. It must not import `cmd`, factory orchestration, workers,
providers, Cobra, concrete cloud SDKs, or rootless runtime packages.

The existing authorities remain authoritative:

- the active Firecracker/L7 controller freshly inspects its exact retained
  guest binding, proxy, namespace, TAP, raw-packet isolation, and Linux rules;
- `sandboxruntime.ValidateJobCredentialActiveProof` and
  `sandboxruntime.ValidateJobCredentialCleanupProof` validate the sealed L8
  proof for the exact complete credential identity and revision;
- `selection.Bind` revalidates the strict, immutable L9 selection and binds it
  to the exact execution, sandbox, runtime, driver, isolation tier, runtime
  image, and manifest digest;
- the workspace input reuses `sandbox.SandboxWorkspace`,
  `sandboxworkspace.SyncOutSummary`, and `sandboxworkspace.SafeApplyResult`
  behind one minimal L10 correlation envelope.

`internal/sandbox` owns only the durable, redaction-safe decision projection.
`internal/sandboxtarget` consumes a fresh opaque active attestation for strict
default selection. `cmd` and `internal/factory` only wire the evaluator and
render or persist the sanitized projection. They must not recreate the
conjunction or accept a durable projection as live authority.

## Exact inputs

The live active request contains:

1. a non-nil context and a non-zero trusted observation time;
2. one complete `sandboxruntime.JobCredentialIdentity` whose runtime driver is
   `microvm` and whose complete network, template, and workspace tuple is
   present;
3. the exact L7 identity derived from that credential identity and a live
   Firecracker/L7 proof source which performs a fresh inspection at evaluation;
4. one `JobCredentialActiveProof`, its exact revision, and no cleanup proof;
5. the exact L9 selection result plus a binding request matching the same
   sandbox/execution/runtime and digest-pinned runtime image;
6. one isolated-workspace evidence envelope correlated to the same sandbox,
   execution, and workspace-policy ID, observed within the bounded freshness
   horizon, with a sanitized sync-out summary and optional safe-apply result;
7. no fallback, simulation, compatibility mode, warning, or retained cleanup
   failure marker.

The evaluator derives the L7 identity and the template/workspace policy IDs
from the authoritative evidence. Caller-supplied duplicates must match exactly
or the request is rejected. Unknown fields do not become authority.

Workspace evidence is strict-ready only for `clone` or `copy`, never `direct`;
its workspace reference must match the sanitized sync-out workspace reference;
recovery must be collected; sync-out and apply warnings must be empty; and an
apply result, when present, must be either an exact successful dry-run or an
exact successful apply of the summary's eligible artifact. Handoff-required,
dirty, partial, unavailable, unknown, or mismatched output fails closed.

## Outputs, states, and failure codes

Evaluation returns both:

- a live opaque active attestation that cannot be reconstructed from JSON; and
- a sanitized `SandboxStrictCompositionDecision` safe for command, manifest,
  factory, status, and issue evidence.

The decision states are `blocked`, `active`, and `complete`. Stable failure
codes are:

- `identity_invalid` and `identity_mismatch`;
- `runtime_proof_missing`, `runtime_proof_stale`, and
  `runtime_proof_mismatch`;
- `credential_active_missing`, `credential_cleanup_missing`,
  `credential_proof_stale`, and `credential_proof_mismatch`;
- `template_proof_missing`, `template_proof_rejected`, and
  `template_proof_mismatch`;
- `workspace_proof_missing`, `workspace_proof_stale`,
  `workspace_proof_unsafe`, and `workspace_proof_mismatch`;
- `warning_bearing`, `fallback_forbidden`, `simulation_forbidden`,
  `cleanup_incomplete`, and `attestation_stale`.

Only safe enum labels, a bounded evidence-state list, an opaque composition ID,
and timestamps may be durable. Raw credentials, endpoints, registry
references, repository URLs, hostnames, paths, socket data, firewall rules,
process metadata, live proof objects, and source errors are omitted.

The active attestation is bound to a digest of the complete credential
identity, exact credential revision, exact immutable manifest digest, workspace
policy ID, and the evaluator's observation/expiry interval. It expires after a
short bounded horizon and is not serializable. Copying a durable decision does
not produce an attestation.

## Active and terminal lifecycle

`EvaluateActive` performs the fresh live conjunction and returns `active` only
after every check succeeds. A strict default may be selected only while that
exact attestation remains valid for the selected sandbox, execution, and
runtime. Selection must also reject any fallback path and any non-Firecracker
runtime. Projection code may downgrade a claim, but cannot create or extend an
attestation.

`EvaluateTerminal` consumes the exact active attestation after execution. It
requires the active credential proof to have been discarded and the mutually
exclusive, fresh `JobCredentialCleanupProof` for the same complete identity and
revision. It revalidates immutable template/workspace correlation and rejects
warnings or cleanup uncertainty. It never accepts both active and cleanup
proofs. A successful terminal decision is `complete`; it is not reusable for
strict default selection.

L10 terminal completion establishes the L8 credential-absence boundary and
the immutable/correlated decision history. L11 separately proves whole-system
absence of processes, rules, namespaces, sockets, mounts, leases, and temporary
artifacts. L10 does not predeclare those L11 observations.

## Concurrency, retry, cancellation, and cleanup

Composition performs no retry. Each active evaluation performs one fresh L7
inspection and one validation of every other input. Cancellation before or
during inspection returns a blocked decision. Concurrent evaluations are
independent; no global allowed flag exists. An attestation is immutable and
expires even if a caller retains it.

Any source error is mapped to a fixed failure code without wrapping unsafe
text. A failed active evaluation yields no attestation. A failed terminal
evaluation does not destroy or replace the active attestation and cannot claim
cleanup. Cleanup failures remain blocking until the underlying authority emits
a fresh valid cleanup proof.

## Red-first acceptance matrix

The first L10 tests must be red before implementation and must cover:

- one complete correlated active scenario;
- omission and independent corruption of runtime/guest, network, active
  credential, immutable template, and workspace evidence;
- same-shaped evidence from another sandbox, execution, runtime generation,
  network plan, policy snapshot, template digest, or workspace policy;
- expired active/cleanup proofs, stale workspace observation, warnings,
  simulated/fallback markers, rootless runtime, advisory template trust, and
  direct workspace;
- active-versus-cleanup mutual exclusion and terminal completion requiring the
  exact prior active attestation;
- selection refusing cached/durable allowed metadata without the live token;
- command/factory/status projections remaining sanitized and unable to mint
  strict state;
- deterministic output and cancellation/error redaction;
- import-boundary and JSON-shape guards.

The fake matrix validates the pure conjunction. Prepared-Linux acceptance must
also run the real L5/L7/L8/L9 authorities and remove or corrupt each live proof
one at a time. Fake or simulated sources can never satisfy that live lane.

## Durable/schema projection

`SandboxSecurity` gains an additive `strictComposition,omitempty` decision.
Execution manifests, factory sandbox metadata/events, and runtime status may
copy only the sanitized decision. Existing compatibility readiness fields stay
additive and advisory. An `allowed` legacy capability gate without an active
L10 decision must render as non-strict and must not authorize strict selection.

No raw proof or live attestation is serialized. Decoding a durable decision
creates data only; it cannot recreate selection authority.

## Verification and L11 handoff

Focused fake-safe verification will cover `internal/strictcomposition`,
`internal/sandboxtarget`, command/factory projection, redaction, import guards,
and the full remove-one-proof matrix. Relevant race and repeated runs are
required. Prepared-Linux verification composes the real L5/L7/L8/L9 scenario;
a skip is a boundary failure, not a pass.

Broad gates are `go test ./...`, typecheck-only tests, `go vet ./...`,
`make docs-check`, `make build`, base-relative lint when installed, gofmt, and
`git diff --check`.

The exact fake-safe and prepared-Linux commands are:

```sh
go test -count=1 ./internal/strictcomposition ./internal/sandbox ./internal/sandboxtarget ./internal/factory ./cmd -run '^TestL10'
go test -race -count=1 ./internal/strictcomposition ./internal/sandboxtarget -run '^TestL10'
go test -count=10 ./internal/strictcomposition ./internal/sandboxtarget -run '^TestL10'
go test -count=1 -tags=l10_strict_composition_integration ./internal/strictcomposition -run '^TestL10PreparedLinuxStrictCompositionE2E$'
go test -count=1 ./...
go test -count=1 -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

The explicitly selected prepared-Linux test must fail, rather than skip, when
its local Firecracker binary, immutable kernel/rootfs, KVM, proxy, Linux-rule,
credential-helper, registry, or isolated-workspace prerequisites are absent.
It makes no cloud or billed provider call. The prepared lane must use the real
retained L5/L7/L8/L9 authorities; a fake `RuntimeProofSource`, synthesized
proof token, cached readiness projection, or simulated template/workspace
record cannot satisfy it.

L10 does not implement new Firecracker, networking, credential, registry,
workspace-collection, provider, or cloud behavior. It makes no billed provider
call. L11 receives the strict active/complete decision and runs the final
rootless-advisory and strict-Firecracker matrix, crash/reconnect negatives,
artifact integrity, resource-absence cleanup, docs/contracts, and release
evidence. Hetzner and Lightsail remain deferred until accounts exist or their
verification is moved to a separate issue.
