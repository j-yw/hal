# Minimal worker prelaunch authority and reservation

## Status and scope

Design only, based on `f448cad67541537420116798fca942d6f64fe5b1` for issue #99.
The [Linux completion architecture](sandbox-runtime-v2-linux-completion-architecture.md)
and [L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md) remain
authoritative. Names below are proposed, not implemented APIs or evidence of a
runnable worker path. This document changes no protocol, store, launch,
credential, default-selection, or recovery behavior.

The next implementation should add one preparation permission and one durable
reservation phase to the existing authenticated L8 service and job manager.
It must not introduce another manager, job store, scheduler, policy engine,
daemon, or credential registry. A permission authorizes preparing one selected
VM; it never authorizes reading a secret, activating credentials, executing a
workload, or advertising strict readiness.

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

## Permission: fixed policy, terminal revocation

Recommend constructor-frozen exact grant rows with an irreversible revocation
latch per row. Immutable rows alone provide expiry but cannot provide in-process
revocation. A mutable grant registry with add/update/renew, persistence or remote
administration is unnecessary for the initial prepared-host use case.

The trusted host composition supplies `MinimalLaunchPolicy` to an optional
`MinimalLaunch` member of `L8DurableServiceOptions`. Its constructor receives the
same principal authority and a bounded list of `MinimalLaunchGrant` registrations
(`NewMinimalLaunchPolicy(authority, grants)`). Service construction checks this
authority is its exact principal issuer. An empty list is a valid deny-all policy
for cleanup-only operation, not implicit unrestricted permission.
It defensively copies them and rejects duplicate grant IDs, zero revisions,
ambiguous matches, invalid bounds and invalid identifiers. Initial maximum: 16
rows, selected as a small explicit bound rather than unlimited cardinality.

Each immutable row contains:

| Group | Exact values |
| --- | --- |
| Principal | Principal ID plus the constructor-owned principal authority; matching strings from another authority are insufficient |
| Permission | Grant ID, positive revision, `NotBefore`, `ExpiresAt` |
| Job intent | Sandbox ID, execution ID, submission ID, plan ID |
| Selection | Worker ID, host ID, runtime driver `microvm`, runtime ID and runtime generation |
| Input policies | Template policy ID and workspace policy ID |

All guest-bound IDs use the minimal protocol's 1–64 byte syntax. Reject, never
truncate, broader worker IDs. Registration has no JSON decoder and is a trusted
composition input, not a new worker operation. Grant fields in `JobStartRequestV2`
select a registered row; they cannot create or edit it. The row's host/runtime
tuple is independently supplied by trusted host composition, not copied from a
caller runtime descriptor. Matching that row is permission, not proof of live
host state; the provider must still validate its actual prepared-host inputs.
The complete validated request fingerprint still binds argv, workspace and
credential intent for duplicate/conflict detection; this permission does not
authorize those credential bindings.

Use a half-open admission interval `[NotBefore, ExpiresAt)`, with an explicit
finite maximum grant lifetime of one hour. Capture real production time at each
admission check; tests inject the private clock. Once expiry or revocation is
observed, that row is permanently unavailable in that policy instance, including
after a backwards clock adjustment. Restart does not reconstruct permissions
from job files: trusted composition must explicitly supply policy again.

The trusted holder may call `Revoke(grantID, revision)` or `Close()` on the policy.
These only close matching terminal latches; they cannot increase a revision,
alter scope or re-enable a row. Revoke is idempotent for an exact row and errors
on unknown/mismatched identity. No public CLI, worker opcode or refresh service is
added. Replacing the constructor policy is an explicit administrative action,
not automatic expiry renewal. These latches are service-lifetime revocation,
not durable policy revocation. On restart, trusted composition must omit a revoked
grant; reinstalling the original permissive
rows would reauthorize other, unreserved work and is not safe revocation recovery.
The operational owner must persist its policy decision outside this slice and
supply the current snapshot. This design adds no hidden policy file or database
and does not claim an in-memory bit survives a crash. Existing reservation
tombstones independently prevent reusing already accepted submissions.

Admission checks the exact principal object and row before allocating a job, and
again immediately before authorizing provider dispatch. A per-reservation
one-shot claim and revocation serialize under policy/manager ownership; use one
documented lock order (manager then policy), with no provider call under either
lock. Revocation after that claim means cancellation plus exact owned cleanup,
not proof that the provider never ran. Expiry is a launch-admission deadline,
not a new credential/session lifetime. Explicit revocation also cancels an
in-flight preparation; later active-job revocation must converge on the same
job owner's cancellation path, not a second cleanup worker.

## Proposed API and actual consumer

Keep the public worker request/response family unchanged. The new option is
constructor-only and explicitly selects the minimal path for that service:

```text
L8DurableServiceOptions.MinimalLaunch
  Policy: exact-authority MinimalLaunchPolicy
  Provider: MinimalJobRuntimeProvider

MinimalJobRuntimeProvider
  StartMinimalJob(ownerContext, reservation, validatedRequest)
      -> ownedJob, error
  RecoverMinimalJob(cleanupContext, recoveryIdentity)
      -> cleanupOnlyOwnedJob, error
```

These narrow neutral types belong in `sandboxruntime`; concrete selected-provider
code belongs in `firecrackerhost`. Worker production code must not import the
concrete runtime. `reservation` is an opaque, nonserializable, owner-checked handle
whose copies share one launch claim. Its proposed `ClaimLaunch(ctx)` method
validates the exact live manager reservation in `dispatching`, current policy
and cancellation, then consumes that claim before returning a copied safe tuple
and revocation signal. Later currentness checks do not consume a second claim.
Its owner is the existing job manager, not a new global token registry. A
deserialized tuple is never an operational permit.
`validatedRequest` is a bounded defensive copy of existing request input, not a
second durable copy of argv, environment, stdin or workspace bytes.

The owned result must retain cleanup even on partial start or readiness failure.
It exposes cancellation/terminal notification and exact bounded finalization;
it does not hand leases or private keys back to the worker. A cleanup-only result
cannot start, resume or activate anything. Its terminal result must be validated
by that provider against the existing surviving supervisor's exact commit result;
an arbitrary interface implementation or serialized `cleaned: true` is not proof.
The concrete receipt shape is a coupled follow-up to the selected owner adapter,
not permission to reuse a historical credential cleanup receipt.

`NewL8DurableService` keeps its current branch unchanged when `MinimalLaunch` is
absent. When present, require a nonnil policy and non-typed-nil provider with both
start and cleanup-only recovery support, and reject a simultaneously configured
legacy binder. Do not choose a route from request-controlled profile strings.
`NewL8Service` and ordinary `Service` remain unchanged/default-off.

The selected `HandleAuthenticatedRequest` sequence is:

1. Validate context, existing request schema and the exact server-issued
   principal. Resolve an already accepted submission first: a duplicate returns
   its existing safe state even if permission has since expired; it never starts
   work. In the selected branch, first find the existing minimal reservation by
   exact `(principal, daemonGeneration, submissionId)` in the manager's state map.
   A different full request fingerprint conflicts even when the legacy computed
   submission key changed. Preserve the old helper/key behavior for old records.
2. Validate the registered launch permission, independently configured selection
   and provider availability. Missing policy or missing complete minimal provider
   fails before ID allocation, store mutation or launch. In particular, do not
   install a fake complete seed or the legacy helper-based provider as fallback.
3. Under the existing manager mutex/state lock, recheck duplicate/conflict,
   allocate `WorkerJobID` with `newOpaqueJobID`, allocate a separate random
   `JobGeneration`, and publish the exact `reserved` record. Persist once before
   any provider call. Job generation is not activation generation. Also reject
   another nonterminal reservation for the exact worker/host/driver/runtime ID,
   even if a different request supplies a new runtime generation or grant. Reuse
   after another submission requires that earlier reservation's validated
   terminal cleanup; do not rely only on the later Jailer busy-slot rejection.
4. Retain the live reservation in that manager. Recheck permission/cancellation,
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
`grantId`, `grantRevision`, `grantNotBefore`, `grantExpiresAt`, and a canonical
safe policy-correlation digest. Other exact tuple members remain in the existing
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
- Only fully durable, verified `dispatching` authorizes provider entry. A crash
  before that commit cannot be followed by a provider call; a crash afterwards
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

1. Same authority/principal exact allow; wrong authority with equal visible IDs;
   missing/typed-nil dependencies; every mismatched grant/selection/policy field;
   malformed rows, duplicates, zero revision and 64-byte boundary violations.
2. Exact NotBefore/ExpiresAt boundaries, observed-expiry clock rollback, revoke
   before reservation and dispatch, revoke racing dispatch, repeat revoke and
   no ability to revive a closed policy or claim via a copied permit. Restart
   with a trusted snapshot excluding a revoked row must still deny it; explicitly
   demonstrate that revocation persistence is not supplied by the old live latch.
3. Concurrent identical submissions allocate one pair of IDs and enter provider
   once; differing request fingerprints conflict, including changes that alter
   the legacy submission key. A new submission cannot bypass occupied runtime
   identity by changing grant/generation. Cancellation and provider panic cannot
   make a second attempt. RNG failure and ID collision launch nothing.
4. Write, sync, rename, directory-sync and exact-readback failures at both durable
   boundaries; failure after rename preserves poison. Assert zero provider calls
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

- Accept fixed constructor rows plus irreversible per-row revocation, maximum
  16 rows and one-hour admission lifetime, rather than live grant registration.
  Repeated unattended workloads needing new tuples will need an explicitly
  authorized configuration/registration handoff; this design does not pretend
  the initial immutable table solves dynamic provisioning. The operational input
  is a trusted current policy snapshot that continues excluding revoked grants
  after restart, alongside the same principal authority binding and selected
  prepared-host tuple; worker job JSON cannot regenerate that input.
- Accept the initial existing daemon-generation restriction and fail-closed
  startup when cleanup support is unavailable, rather than a new migration or
  recovery service. A fresh cleanup-only client to the surviving owner remains
  the only authorized restart mechanism.
- Approve the coupled selected-path store readback and private schema expansion
  before GREEN. Merely adding a policy gate would leave the durable launch gap.

This documentation-only checkpoint is verified by source inspection and
`git diff --check`. No behavior test, VM boot, credential activation, prepared-
Linux acceptance, strict-default readiness or full restart recovery is claimed.
