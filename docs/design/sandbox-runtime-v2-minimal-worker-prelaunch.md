# Minimal worker prelaunch authority and reservation

## Status and scope

Design only, based on `f448cad67541537420116798fca942d6f64fe5b1` for issue #99.
The [Linux completion architecture](sandbox-runtime-v2-linux-completion-architecture.md)
and [L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md) remain
authoritative. Names below are proposed, not implemented APIs or evidence of a
runnable worker path. This document changes no protocol, store, launch,
credential, default-selection, or recovery behavior.

This revision replaces the exact per-job grant rows proposed in `7b63b7b2`.
Pre-enumerating execution/submission/runtime generations would require repeated
worker reconstruction and is not a production authorization model.

Add one preparation permission and durable reservation phase to the existing L8
service/manager, not another manager, store, scheduler, policy engine or daemon.
Permission authorizes preparing one VM, never credential access, workload
execution or strict readiness.

## Source constraints

These are concrete implementation constraints, not assumptions about missing
hardware:

- `sandboxworker/job_v2_service.go`, `HandleAuthenticatedRequest`, validates a
  principal through the exact service-owned `AuthenticatedWorkerPrincipalAuthority`,
  checks accepted submissions, then calls `binder.Bind` before accepting a job.
  Request JSON cannot supply a principal object.
- `job_manager_v2.go`, `acceptCredentialSeed`, takes `WorkerJobID` from a complete
  seed. `job_credential_identity.go`, `ValidateJobCredentialIdentitySeed`, already
  requires process/vsock, activation/credential generations and delivery bindings.
  This is pre-authentication correlation, not a prelaunch issuer.
- `credentialsource/contracts.go`, `NewAdmissionGrantRegistration` and
  `validAdmissionRequest`, also require process/vsock. Existing credential
  authorization cannot be weakened into a VM launch permission.
- `job_manager_v2.go` owns one mutex, process-shared state lock, submission index
  and state map. `job_helpers.go`, `newOpaqueJobID`, already generates safe random
  job IDs. Reuse these boundaries, not the legacy job manager itself.
- `job_store_v2.go`, `save`, writes, syncs, closes, renames and syncs the directory.
  An error after rename can mean a record exists although the caller received an
  error. `load` is bounded and decoded through `protocol_decode.go`; the current
  `Lstat` then open is not an exact retained-inode readback primitive.
- Current validation requires credential state for a credential-requesting queued
  job. Current startup first recovers credential records, then marks other queued
  jobs interrupted. Neither rule may accidentally classify a new uncertain launch
  as safe to discard. `newJobManagerV2` also rejects a different worker or daemon
  generation; submission and request keys include that generation.
- `job_v2_helpers.go`, `jobSubmissionKeyV2`, also includes grant/revision, plan
  and credential intent. It is not a stable `(principal, submissionId)` key.
  A changed grant must not bypass a selected job's existing reservation.
- `jailer_recovery_producer_linux.go` consumes retained verified assets and a
  finalized FC config, but currently accepts only a six-ID job tuple from its
  trusted caller. It has no worker reservation consumer. Its same surviving
  supervisor owns cleanup; a fresh reconnect client is cleanup-only.

All source paths above are under `internal/` unless otherwise stated.

## Permission: configured scope, per-request issuance

Recommend a constructor-owned `MinimalLaunchAuthorizer` with an immutable local
scope and one terminal close latch. It evaluates each new authenticated request;
it does not look up a pre-registered job or provide a remote grant-administration
API. The existing service and manager retain all per-job state.

Trusted composition supplies the same `AuthenticatedWorkerPrincipalAuthority`,
configured allowed principal IDs, worker/host identity, runtime driver `microvm`,
and allowed template/workspace/network-policy scope. Each scope entry has a safe
policy ID and positive revision identifying that exact configuration. Scope is
explicit, with no wildcard-by-omission. Reject ambiguous/invalid configuration;
an empty scope is deny-all. Do not impose an invented job-count or worker-uptime
limit. Ordinary configuration/input bounds are not a deployment quota.

Scope entries identify durable policies, not the ephemeral IDs of their future
instances. For example, one approved template/workspace/network policy can admit
new executions A and B with distinct submissions, runtime generations and plans.
The resolved instance of each policy still has to match its configured scope.

| Input | Source and meaning |
| --- | --- |
| Principal | Exact authenticated service-issued object, checked against configured principal scope; equal visible IDs from another authority fail |
| Host and runtime selection | Current handle resolved by the constructor-injected concrete provider from its trusted host/runtime configuration and retained verified inputs, never from request metadata alone |
| Template/workspace/network policy | Independently resolved actual policy identities/fingerprints, checked against immutable configured scope; request labels are selection hints |
| Execution, submission, plan and command intent | Validated caller correlation plus full existing request fingerprint; does not grant authority and need not be pre-enumerated |
| WorkerJobID and JobGeneration | Fresh manager allocation, made once under its existing lock and bound before durable reservation |
| LaunchGrantID | Fresh internal authorizer output for that exact reservation; never copied from request `AdmissionGrantID` |

`Authorize(ownerContext, principal, validatedIntent, selection, allocatedJob)`
checks those sources. `validatedIntent` contains the safe request correlation
IDs and full existing request fingerprint, not raw argv/environment/inputs.
It returns a private one-shot grant bound to the full resolved tuple,
the exact request fingerprint, policy ID/revision, WorkerJobID and JobGeneration.
The authorizer is a small local exact-match/checking object, not a second policy
engine: it does not resolve registries, schedule hosts, register secrets or
interpret arbitrary rules. Same scope can issue successive grants without
restart or refresh. Capacity remains enforced by the existing manager/host and
Jailer resource owners, not by the number of previously issued grants.

The request's credential `AdmissionGrantID`, revision and bindings remain
credential-intent correlation. They cannot select or issue launch permission.
Their presence in a request fingerprint or later public boot binding does not
authorize credential access; the later credential authorizer must independently
approve them. Keep the new internal launch grant in a distinct namespace/schema.

All guest-bound IDs retain the minimal protocol's 1–64 byte syntax; reject rather
than truncate broader values. Scope and authorizer handles are trusted local
constructor inputs, with no worker JSON construction path. Service construction
checks the authorizer uses its exact principal issuer and configured provider.

### Lifetime and revocation

A grant lasts only for one live reservation's bounded, service-owned preparation
attempt. Use the concrete provider's explicit preparation budget and cancellation,
not a deployment-wide expiry. Selected start already uses a bounded context in
`jailerRecoveryRuntime.startChild`; the adapter must pass/compose its preparation
deadline rather than reset it at each stage. Expiry retires the grant permanently,
without changing credential/session lifetime or authorizing a new attempt.

Per-job revocation uses the existing authenticated cancellation route and that
reservation's terminal latch; do not add a grant-ID cancellation API. Closing the
authorizer disables all further issuance and revokes its outstanding preparation
grants through the same owners. It has no add/update/renew method. Admission and
claim check revocation using manager-then-authorizer lock order; no provider call
occurs under either lock. Revocation after claim requests exact owned cleanup,
not proof the provider never ran.

This close latch is service-lifetime revocation, not durable policy revocation.
For durable policy withdrawal, trusted composition must continue excluding the
principal/scope on restart; installing the old permissive configuration would
authorize new submissions. This slice adds no policy database and does not
pretend the latch survives restart. Existing durable cancellation/tombstones
independently stop old submissions. Restart creates no grants for stored jobs.

## Proposed API and actual consumer

Keep the public worker request/response family unchanged. The new option is
constructor-only and explicitly selects the minimal path for that service:

```text
L8DurableServiceOptions.MinimalLaunch
  Authorizer: constructor-owned MinimalLaunchAuthorizer
  Provider: MinimalJobRuntimeProvider

MinimalJobRuntimeProvider
  ResolveMinimalSelection(requestContext, selectionHints)
      -> retainedSelection, error
  StartMinimalJob(ownerContext, reservation, retainedSelection, validatedRequest)
      -> ownedJob, error
  RecoverMinimalJob(cleanupContext, recoveryIdentity)
      -> cleanupOnlyOwnedJob, error
```

These narrow neutral types belong in `sandboxruntime`; concrete selected-provider
code belongs in `firecrackerhost`. Worker production code must not import the
concrete runtime. `ResolveMinimalSelection` is a read-only preflight: no VM,
namespace, cgroup, identity-slot allocation or asset-lease consumption. It resolves
the already configured trusted host, policy bindings and verified image/input
objects, and returns an opaque handle owned by that same provider. Descriptor
strings, copied handles from another provider, closed or stale input ownership
cannot substitute. Any temporary read handles are closed on conflict/failure.

The concrete adapter reuses the trusted host policy/verified distribution in
`jailer_recovery_producer_linux.go` and independently resolved template/workspace/
network policy bindings. It does not require already-created job namespaces or
future L10 workspace proof: permission to prepare those resources precedes their
creation. Runtime/plan generations identify the selected host-owned attempt;
they are never invented evidence that preparation succeeded. The provider must
perform and correlate actual preparation after claim. Missing trusted selection
fails unavailable; a new metadata-only `trusted: true` object is not a resolver.
This actual resolver/consumer pair is required, not an API already implemented.

`reservation` is opaque/nonserializable; copies share one `ClaimLaunch(ctx)`.
Claim checks the exact live manager entry in `dispatching`, issued grant and
cancellation, then returns a copied safe tuple and revocation signal. Later
currentness checks cannot claim again. The provider revalidates selection before
claim and at pre-allocation/prelaunch barriers; changed input is not permitted.
The existing manager owns it; deserialization cannot create permission.
`validatedRequest` is a bounded defensive copy, not new durable raw input.

The owned result must retain cleanup even on partial start or readiness failure.
It exposes cancellation/terminal notification and exact bounded finalization;
it does not hand leases or private keys back to the worker. A cleanup-only result
cannot start, resume or activate anything. Its terminal result must be validated
by that provider against the existing surviving supervisor's exact commit result;
an arbitrary interface implementation or serialized `cleaned: true` is not proof.
The concrete receipt shape is a coupled follow-up to the selected owner adapter,
not permission to reuse a historical credential cleanup receipt.

`NewL8DurableService` keeps its current branch unchanged when `MinimalLaunch` is
absent. When present, require a nonnil authorizer and non-typed-nil provider with
selection/start and cleanup-only recovery, and reject a simultaneous legacy
binder. Request-controlled profile strings cannot choose the route.
`NewL8Service` and ordinary `Service` remain unchanged/default-off.

The selected `HandleAuthenticatedRequest` sequence is:

1. Validate context, existing request schema and the exact server-issued
   principal. Resolve an already accepted submission first: a duplicate returns
   its existing safe state even if permission has since expired; it never starts
   work. In the selected branch, first find the existing minimal reservation by
   exact `(principal, daemonGeneration, submissionId)` in the manager's state map.
   A different full request fingerprint conflicts even when the legacy computed
   submission key changed. Preserve the old helper/key behavior for old records.
2. Check authorizer scope and complete provider availability, then call the
   read-only selection resolver. Validate exact principal/scope/selection and
   request correlation. Missing scope, trusted selection or complete minimal
   provider fails before ID allocation, store mutation or launch. Never install
   a fake complete seed or the legacy helper-based provider as fallback.
3. Under the existing manager mutex/state lock, recheck duplicate/conflict,
   allocate `WorkerJobID` with `newOpaqueJobID`, allocate a separate random
   `JobGeneration`, issue the exact reservation-bound launch grant through the
   local authorizer with the finite owned preparation context, and publish the
   exact `reserved` record. Check request cancellation before durable acceptance;
   the owned context does not inherit client-disconnect cancellation afterwards.
   Persist once before any provider launch call. Job generation is not activation
   generation. Reject
   another nonterminal reservation for the exact worker/host/driver/runtime ID,
   even if a different request supplies a new runtime generation or grant. Reuse
   after another submission requires that earlier reservation's validated
   terminal cleanup; do not rely only on the later Jailer busy-slot rejection.
4. Retain the live reservation in that manager. Recheck grant/cancellation,
   durably publish `dispatching`, mark that live entry dispatched and call the
   provider exactly once. Provider calls `ClaimLaunch` before its first host
   allocation and observes its revocation/cancellation latch at subsequent launch
   barriers. The service never consumes the provider's claim a second time.
5. Retain any returned owner before inspecting error/success. Nil success is
   invalid. An error after dispatch with no owner is uncertain, not no-op cleanup.
   Complete the state transition only after validating exact result correlation.
   No readiness/credential success is published merely because a VM started.
6. Route explicit cancellation and failure to that same owner. Preserve a durable
   tombstone after terminal cleanup so a repeated submission never launches again.

The initiating request context applies until durable acceptance. Afterwards,
client disconnect does not imply job cancellation: preparation uses the existing
service/job ownership lifetime with a bounded deadline and explicit cancellation
latches. On service shutdown, stop admission and retain the state lock until
local handoff/cleanup bookkeeping is settled; a surviving supervisor continues
to own unresolved resources. A new daemon obtains only cleanup authority.

If the real minimal postlaunch provider is not implemented, the selected service
is unavailable. The first worker slice may verify this full call sequence using
injected fakes, but cannot advertise runnable credential support or use a launch-
only stub to make a credential-requesting job succeed.

## Private reservation schema and transitions

Add one optional private `minimalLaunch` member to `storedJobStateV2`, with a
distinct `sandboxjob-minimal-launch-private-v1` discriminator. Old records omit it
byte-for-byte. Extend only the private decoder's exact schema; no generic map or
unknown-field allowance. Keep the existing 64 KiB total record bound.

The new member contains `contractVersion`, positive `revision`, `phase`,
`jobGeneration`, `sandboxId`, `executionId`, `submissionId`, `runtimeGeneration`,
`launchGrantId`, `launchPolicyId`, `launchPolicyRevision`, `preparationStartedAt`,
`preparationDeadline`, and a canonical safe selection/policy-correlation digest.
The deadline is diagnostic/rejection metadata; it never revives authority on
restart. Original credential grant ID/revision stay in `CredentialIntent` and
are not equated with these launch fields. Other tuple members remain in existing
JobV2/principal/credential-intent fields and are cross-validated. A bounded
optional `ownerCorrelation` holds only the supervisor config digest and owner
generation after actual publication; it is not a path, PID authority or handle.
Terminal records also require `terminalKind` (`no_dispatch` or `owned_cleanup`).
Only `owned_cleanup` includes `finalizedOwnerRevision` and `ownerCommitId`, checked
by the concrete provider against its original owner correlation and the exact
acknowledged terminal receipt. These safe fields are bookkeeping, not independent
authority. Reject phase/terminal-kind/receipt contradictions, unexpected fields,
zero revisions and mismatched duplicate tuple members.
The future concrete provider must choose the owner-directory locator from its
trusted root and this fixed job identity before dispatch, so a crash before
`ownerCorrelation` publication does not require discovering arbitrary paths.
That locator convention is a required adapter contract, not an existing worker
primitive. No environment, raw request, key, nonce, FD or user-supplied path enters
this record. Recovery does not trust this metadata to reconstruct ownership.

| Private phase | Meaning and permitted next action |
| --- | --- |
| `reserved` | Durable identity allocated; provider has not been authorized. Continue only through the live reservation's single dispatch claim. Restart never resumes it. |
| `dispatching` | Durable boundary published before provider entry; provider may have run. Only retain the exact returned owner or attempt cleanup-only recovery. |
| `owned` | Same provider returned exact retained ownership; not credential/readiness proof. |
| `cleanup_pending` | Cancellation, error, uncertain I/O or lost owner; deny redispatch. |
| `terminal` | Durable no-dispatch termination, or provider-validated exact owned cleanup; tombstone remains. |

`reserved`/`dispatching`/`owned` initially project public `queued`, without active
credential proof; `cleanup_pending` projects `unknown` with a safe failure code.
No new public state enum is needed. Only a subsequent reviewed actual credential/
workload result can publish running/success. Terminal preparation failure maps
to existing failed/canceled/interrupted states and never gets a fabricated exit
code. Existing cancel must branch on this discriminator before
`clearCredentialState`; a nil legacy credential state cannot authorize release.

The first slice rejects simultaneous `minimalLaunch` and legacy credential state
or receipt. A future credential handoff must define the explicit atomic transition
while retaining the job-generation/tombstone correlation; do not loosen the old
seed schema or insert a fictional helper generation to make this possible.

### Write and crash ordering

- Install the pending in-memory claim before the first write under the manager
  mutex. A persistence error must poison admission for that manager instance and
  retain the claim, including errors after rename. Do not roll back maps and
  accept another launch. Cleanup bookkeeping may continue; new admission cannot.
- Reuse the store transaction, but add selected-path exact bounded no-follow
  descriptor readback and current-file identity/content verification after file
  and directory sync. The current `Lstat`/open loader alone is insufficient for
  this new launch barrier. A mismatch is poison, not repaired by rereading until
  expected bytes return. Require this for both reserved and dispatching writes.
- Only fully durable, verified `dispatching` authorizes provider launch entry.
  A crash before that commit cannot be followed by a launch; a crash afterwards
  is conservatively possibly launched, even if the process had not yet entered it.
- Startup handles this discriminator before credential recovery and the generic
  queued-job interruption loop. `reserved` can become interrupted/no-dispatch
  terminal after validated readback, never resume. All later nonterminal phases
  require cleanup-only recovery of the same surviving owner. Missing record,
  missing owner, zero PID, free lock, elapsed time or missing commit ACK is not
  cleanup proof. Without recovery support startup fails closed, preserving files.
- Keep the existing exact worker/daemon-generation requirement for this initial
  slice. A newly configured daemon generation rejects the old store; do not
  rewrite its submission keys or bypass stale work by choosing another state
  directory. A broader cross-generation migration is not silently included.
- A live cancellation can publish `no_dispatch` only while the manager has
  atomically prevented provider entry, or an unconsumed provider claim has been
  irreversibly invalidated and the trusted provider has returned without mutation.
  It cannot infer this from a nil result after the claim or from a vanished PID.
- Recovery never reissues a launch permit. Terminal-write/readback uncertainty
  remains cleanup pending even when resource cleanup succeeded. Repeated cleanup
  uses the existing exact owner/receipt rules and cannot touch a successor.

## Ordered implementation and RED requirements

First implementation ownership should cover narrowly named neutral policy/permit
types in `sandboxruntime`, selected routing in `sandboxworker/job_v2_service.go`,
and coupled manager/store/private decoder tests. Source-guard changes require
separate review and must preserve their safety intent. No command defaults,
credential registry, strict composition or baseline constructor edits belong to
that first worker slice.

Meaningful compiling REDs must cover:

1. Same authority/principal and in-scope selection allow; wrong authority with
   equal visible IDs; missing/typed-nil dependencies; every substituted scope,
   selection and issued-grant field; invalid scope/revision/64-byte identifiers.
   Selection from the wrong provider, closed/replaced inputs, permission based
   only on matching request policy labels, and resolver mutation all fail.
   Forged request credential grant IDs confer no launch permission. A valid
   launch grant does not cause credential-source resolution or authorization.
2. Successive distinct run/auto/factory-shaped requests are independently issued
   grants by one unchanged authorizer, including after one hour of worker uptime
   and after more than 16 completed jobs. Job identifiers need no pre-registration.
   Preparation-deadline expiry, cancellation before/after claim, authorizer close,
   copied-grant replay and observed-expiry clock rollback all remain fail-closed.
   Restart with withdrawn scope still denies new work; the old live latch is not
   claimed as durable revocation evidence.
3. Concurrent identical submissions allocate one pair of IDs and enter provider
   once; differing request fingerprints conflict, including changes that alter
   the legacy submission key. A new submission cannot bypass occupied runtime
   identity by changing grant/generation. Cancellation and provider panic cannot
   make a second attempt. RNG failure and ID collision launch nothing.
4. Write, sync, rename, directory-sync and exact-readback failures at both durable
   boundaries; failure after rename preserves poison. Assert zero provider launches
   unless the dispatch barrier completed, not merely an error return.
5. Restart from every phase; same/different daemon identity; absent or malformed
   owner record; replay and failed terminal commit. No startup test may call start.
   Missing provider on new requests must fail before mutation, while existing
   uncertain state is preserved and reported unavailable, not silently cleared.
6. Client disconnect after acceptance versus explicit job cancellation; provider
   nil/nil, handle-plus-error, no-handle error, mismatched correlation and cleanup
   failure. Keep owned cleanup alive until durable terminal publication.
7. Exact old worker-v2 codecs/records, binder call order and credential behavior
   when the new option is absent; default construction remains unchanged.
8. Real selected-consumer tests with the existing Jailer producer follow only
   when its complete minimal provider and controller handoff are implemented.
   Fake provider tests alone do not establish that connection.

Future focused test names/selectors must be committed with the tests, not listed
here as already runnable evidence. Default checks remain deterministic and
CLI-free; race checks exercise claim/revoke/cancel/state publication. Required
Linux acceptance remains separate and cannot pass through skips.

## Subsequent producer/controller handoff

The reservation's safe tuple feeds the existing selected Jailer producer.
Boot/image generations and fresh Ed25519 key/nonce are minted only there, after
the permission and retained image/L7 input checks. The exact 25-field public
bootstrap binding is rendered before FC config hashing/sealing. Real process and
stream generations are added only after launch from the original supervisor's
manager and raw minimal stream, then authenticated with unchanged
`session.NewControllerHandshake`.

The existing minimal binding fields `admissionGrantId` and `admissionRevision`
remain the validated credential-intent references from the authenticated request.
They bind requested intent only: neither prelaunch issuance nor authenticated
minimal readiness proves a postlaunch credential grant exists. The later actual
credential authorizer must validate/register those references after complete
runtime correlation, preserving existing request/seed equality. Do not substitute
`launchGrantId` or `launchPolicyRevision` into those fields. If a later selected
credential contract cannot preserve that meaning, it requires an explicit schema
decision; this design does not silently rename the legacy semantics.

Use a distinct selected config version and eighth `minimal-controller-key` FD,
with a fixed sealed 32-byte Ed25519 seed and exact public-key correlation. Keep
the existing seven-role and legacy six-role paths unchanged. Never derive the
controller key from the stable recovery HMAC root key. The same supervisor
consumes/closes the seed FD before child launch and retains the one-shot
controller owner; no key reaches the gate, Jailer, guest, worker JSON or journal.
This later slice must implement an actual post-release controller consumer and
revocation/cleanup integration, not only serialize pins. Parent pinning and L7
NIC composition have separate owners; this design does not change them.

## Decisions requiring supervisor approval

- Accept a constructor-owned per-request authorizer over configured durable
  scope, with independently resolved current selection and separate internal
  launch grants. Operational inputs are the current allowed principal/host/policy
  configuration, actual selected-provider dependencies and its existing bounded
  preparation budget. New job IDs need no configuration update. Durable scope
  withdrawal must still be reflected in trusted configuration after restart.
- Accept the initial existing daemon-generation restriction and fail-closed
  startup when cleanup support is unavailable, rather than a new migration or
  recovery service. A fresh cleanup-only client to the surviving owner remains
  the only authorized restart mechanism.
- Approve the coupled selected-path store readback and private schema expansion
  before GREEN. Merely adding a policy gate would leave the durable launch gap.

This documentation-only checkpoint is verified by source inspection and
`git diff --check`. No behavior test, VM boot, credential activation, prepared-
Linux acceptance, strict-default readiness or full restart recovery is claimed.
