# Selected minimal worker cancellation coordination

Status: DESIGN/compiling RED only, based on `ed32e374`. No cancellation,
terminal cleanup, recovery, or concrete host-provider implementation is added.
This refines the cancellation handoff in
[the worker prelaunch design](sandbox-runtime-v2-minimal-worker-prelaunch.md).

## Actual missing boundary

`L8Service.HandleAuthenticatedRequest` validates the exact constructor-owned
principal issuer and request context, then sends selected minimal requests to
`handleMinimalLaunch`. That handler supports only `job_start_v2`; an actual
`job_cancel_v2` currently returns `unsupported_operation`, including while a
provider has claimed the durable `dispatching` reservation and is still inside
`StartMinimalJob`. The reservation remains active. The old authenticated
credential cancel handler is a different path and must not be reused.

The existing entry already retains the original reservation, prepared selection,
and any returned partial owner. `finishMinimalDispatch` keeps a nonnil owner even
when Start returns an error. `finishMinimalClose` revokes locally and joins active
preparations before releasing the held store and lock; it does not finalize an
owner. These are the ownership foundations, not terminal-cleanup proof.

## Proposed bounded GREEN

Use the existing `OperationJobCancelV2` and `JobCancelRequestV2` without new public
fields. The selected branch validates the exact envelope, microVM driver, and
job ID before consulting the existing manager. Under its mutex, require:

- the authenticated issuer accepted by this service and exact stored principal;
- this worker and current daemon generation, original request/submission key,
  and selected private record;
- the original live entry, nonnil reservation and selection, matching original
  job generation, launch grant, runtime generation, and selected identity;
- retained record-root/lock authority and exact canonical current record bytes.

There is no client-supplied generation or principal to trust. Foreign issuer,
foreign principal, missing job, or identity mismatch never selects another
entry, invokes the provider, or changes its record. Scope withdrawal can forbid
new launches without turning an already authorized cleanup request into a new
launch authorization. A prior Start error/poisoned admission must not discard an
exact retained entry or by itself make local cancellation impossible.

After authenticating that exact ownership, irreversibly call the original
reservation's `Revoke`. Persist one selected-only CAS transition from
`dispatching/2` to private `cleanup_pending/3`, with public
`CancelRequested=true`, through the existing held-root writer/readback. Preserve
all identity, intent, submission, preparation, and policy fields. A failed or
uncertain save cannot undo local revocation, release occupancy, or acknowledge
durable cancellation; retain ownership and poison new admission conservatively.
An authorized exact live reservation may still be revoked locally when store
authority is lost, but that is not permission to mutate a replacement store or
claim a durable transition.

The public state remains `queued`, with no `FinishedAt`, `StartedAt`, or
`ExitCode`. This is deliberately not `unknown`: today's `JobV2.Validate` requires
a `FinishedAt` for that state. `queued` here preserves the initial non-completion
projection, not evidence that no runtime was allocated. `CancelRequested` plus
the private pending phase records the stronger cancellation fact without a new
public schema or fabricated completion timestamp.

Each retained entry needs one dispatch-done latch, installed before dispatch and
closed exactly once only after `finishMinimalDispatch` retains the returned
owner, including partial owner plus error. Cancel releases the manager mutex
before waiting on that latch. No provider callback, finalizer, selection close,
or wait may run under the manager mutex. All concurrent/repeated cancels join
the same entry; they do not increment the revision again or restart dispatch.

The caller's request context bounds its wait, not the owned cancellation.
Cancellation before request admission has no side effects. Cancellation after
local revoke stops only that waiter; it does not undo the durable pending intent,
revive the reservation, abandon the in-flight Start, or release the service's
ownership. A later request can join the same retained dispatch. The manager's
existing service-close join remains authoritative for outstanding callbacks.

After dispatch returns, this slice still returns a sanitized unavailable failure,
not successful cancellation or a terminal job. It keeps the entry, owner,
selection, record, and runtime occupancy. It never calls `Finalize` or `Recover`,
creates a cleanup receipt, infers `no_dispatch` from a nil owner, or marks a job
canceled/interrupted/succeeded/failed. There is no concrete provider yet.

Expected implementation files after separate GREEN approval: dedicated
`minimal_launch_cancel.go`, the existing dispatch route/entry/final-retention
latch, and the selected private store validator/CAS transition. Existing exact
source-lock guards need separately reviewed narrow updates with their bypass
negatives retained. This RED changes none of those production files or guards.

## Executable RED and controls

`TestMinimalLaunchCancelRevokesAndJoinsClaimedDispatch` enters the actual selected
service. A fake provider claims the actual reservation and independently reads
the real ordinary-file `dispatching` record, then blocks its Start callback until
the fixture releases it. The test calls the actual authenticated cancel route.
Its first failure is the returned unsupported response with an uncanceled
reservation. Later pending-record, join, partial-owner retention, and occupancy
assertions are intentionally not counted as reached on the baseline.

Independent controls execute a valid complete provider-return handoff and reject
another issuer and another principal without changing record bytes or revoking
the claimed reservation. The same-issuer foreign-principal control establishes
non-interference on the baseline, not an implemented selected per-job cancel
validator: the currently unsupported route rejects that request too.

The provider does not start a runtime or perform cleanup. Watchdogs only fail
tests; teardown releases and joins fixture goroutines before service close and
is never counted as product cancellation. No live Unix listener, namespace,
KVM, credential, host setup, or new runtime authority is involved.

Focused reproduction (Go 1.25.7, `GOMAXPROCS=3`, no network dependencies):

```sh
go test -p 2 -race -count=3 ./internal/sandboxworker -run '^(TestMinimalLaunchCancel|TestMinimalLaunchDispatch|TestL8D6WorkerCancel|TestL8ServiceDefaultPathPreservesExactEarlyUnsupportedResponse|TestL8ServiceDoesNotBindNoIntentOrNonStartV2Operations)'
```

The baseline result is three failures of the single missing-cancel test, 69
passing test/subtest events, zero skips, and no race or fixture-join failure.
The later assertions do not establish implemented pending persistence or cleanup.

## Explicit subsequent slices

Neutral owner finalization/recovery wrappers and reserved-only restart need
separate reviewed REDs. Startup remains nonempty-store quarantine in this slice.
A future cleanup-only restart must establish which prior daemon epochs are
trusted and preserve their original identity/request keys; rejecting every
previous epoch would make restart impossible. Neither accepting arbitrary epoch
strings nor rekeying an old record to the new daemon is safe.

Owned terminal publication requires the actual provider's complete cleanup
proof and a receipt-before-worker-terminal-commit crash order, using the existing
stores. Host record retirement followed by a crash before worker receipt
persistence must not become terminal success from a missing owner. Plain receipt
metadata, partial cleanup, canceled contexts, and `no_dispatch` guesses are not
that proof. No second daemon/store or public schema is proposed here.
