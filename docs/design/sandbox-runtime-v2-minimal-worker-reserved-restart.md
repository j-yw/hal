# Minimal worker reserved-only restart: trust boundary and proposal

## Status and scope

DESIGN ONLY, based on `3a1b5320dbcf46055cba0657e1e16a9b2f92ff8c`.
No source, test, startup policy or runtime behavior changes are included.
This refines the reserved-only restart handoff in
`sandbox-runtime-v2-minimal-worker-prelaunch.md` and
`sandbox-runtime-v2-minimal-worker-cancel.md`; it does not enable it.

The proposed conclusion is conditional: an authentic, current `reserved/1`
record in the same trusted crash-consistent store proves that this worker did
not admit `StartMinimalJob` for that reservation. It proves neither successful
execution nor absence of resources throughout the host. No provider Resolve,
Start, Recover, Finalize, controller reconnect or cleanup receipt is needed to
classify this exact pre-dispatch case.

Current code does not establish the complete prior-store/epoch trust condition.
Do not enable reclaim by merely accepting a syntactically valid old epoch.
All `dispatching/2`, `cleanup_pending/3`, unknown, mixed or otherwise unproved
nonempty stores remain quarantined. No selection, reservation or grant is
reconstructed from a stored record.

## Source evidence

- `minimal_launch_dispatch.go:157` holds the manager mutex across reservation
  and both publications. It installs pending local ownership first, durably
  saves `reserved/1`, then durably saves `dispatching/2`, and only then calls
  `ArmDispatch`. Any uncertainty poisons that manager and revokes the handle.
- `minimal_launch_store.go:101` syncs the file and directory, checks the retained
  root/lock, verifies exact inode and canonical byte readback, and reports close
  errors before admission. Initial publication is exclusive. Uncertain private
  temporary entries are deliberately retained.
- `minimal_launch_admission.go:232` admits at most one provider attempt through
  the original armed reservation and selection. After provider Current, the
  actual manager barrier rereads exact `dispatching/2` bytes before provider
  entry. Merely decoding a phase cannot arm or claim a reservation.
- `minimal_launch_dispatch.go:251` revokes and joins all preparation/provider
  handoffs before closing the retained store and releasing its flock. A live
  old handler cannot legitimately continue after an orderly unlock. Process
  crash releases its noninherited handles; later provider ownership, if any,
  is conservatively represented by `dispatching`, not `reserved`.
- `job_manager_v2.go:60` currently requires an empty selected store, before any
  legacy reconciliation. Its later identity check requires the current daemon
  generation. Neither condition implements prior-epoch recovery.
- `job_state_lock.go:29` creates a missing lock file. The selected currentness
  check in `minimal_launch_store_ops.go:19` compares handles and names in this
  process; it does not remember a former directory or lock across a crash.
- `storedJobStateV2.Validate` checks the old daemon string's syntax. Request
  and submission keys are unkeyed hashes, not signatures or a trusted epoch
  registry. The full Exec request is not stored, so startup cannot recompute
  the complete request hash from the record alone.
- The authenticated principal issuer and `MinimalLaunchAuthorizer` are live,
  constructor-owned handles. An old `PrincipalID` string cannot recreate the
  old issuer. Current launch scopes are not a record of historical epochs.

## What is sufficient, and what is missing

Within the existing trusted-host crash model, the ordering above provides a
useful invariant: successful provider admission requires a successfully synced
dispatching record. A normal process crash cannot turn that committed record
back into reserved. Incomplete publication can leave reserved plus a temporary;
that directory is uncertain and is not eligible for this narrow recovery.

The inference requires all of the following to be independently established:

1. This configured store is the original, exclusively owned store for the
   worker, not an imported directory, snapshot restore or replacement.
2. Its persisted history has not been rolled back or rewritten outside the
   accepted writer. Ordinary file/directory sync guarantees apply.
3. The old daemon epoch and complete worker/host/principal/launch-policy scope
   are recognized by trusted startup composition. Recovery authorization must
   not restore withdrawn launch permission.
4. The new owner holds the original existing lock and exact current directory;
   no old in-flight request can legally dispatch while the new owner owns them.

The present `StateDir`, current daemon ID and live authorizer options do not
provide an independent prior-epoch association. A future constructor-only
input may explicitly identify authorized old epochs and their exact scopes,
but an allowlist alone is not provenance for arbitrary supplied record bytes.
It must rely on an approved trusted-store continuity model, not record-derived
expected fields. Zero/missing authorization must preserve today's quarantine.
For this prior-epoch slice, the recognized old epoch must differ from the new
service epoch; accepting equality is not a way to avoid the lineage decision.

Counterexample to a stronger claim: retain authentic reserved bytes, let the
old daemon publish dispatching and admit the provider, then restore the saved
reserved bytes after that daemon exits. IDs, scope, hash syntax and canonical
JSON can all be unchanged; the current inode may also be unchanged after an
in-place rewrite. A new flock and current-directory checks cannot distinguish
this history from a genuine pre-dispatch crash. A checksum or a signature on
the reserved snapshot alone would not solve replay. This is not a reachable
reclaim bug today: startup rejects both histories. It defines why this proposal
does not claim hostile-host or filesystem-rollback resistance.

Before implementation, approve either the trusted unchanged-store crash model
and its actual constructor source of prior-epoch authorization, or keep this
case quarantined until that authority exists. No second store, signing-key
scheme, epoch daemon or speculative proof issuer is proposed here.

## Minimum conditional recovery algorithm

If that trust boundary is approved, use the existing selected store and flock:

1. Validate trusted startup identity/old-epoch policy before effects. For a
   nonempty recovery store, require the existing private directory and lock;
   do not create a replacement lock or chmod/repair an unsafe recovery root.
   Retain nofollow directory/lock handles and use the existing exact authority
   checks. Empty new-store construction and all legacy startup stay unchanged.
2. Before any record mutation, enumerate a bounded exact entry set using the
   retained directory. Accept only the lock and canonical job filenames. Reject
   temporary files, links, extra hardlinks, directories, FIFOs, unknown names,
   duplicate identities and any unsupported record. Use the existing 64 KiB
   per-record bound and a reviewed finite total/count bound, not unbounded
   `ReadDir` plus whole-store allocation.
3. Read every record nofollow/nonblocking and validate actual owner/mode, exact
   filename/job ID, canonical schema and full tuple. Require `reserved/1`,
   queued, no cancellation, credentials, receipt, start/heartbeat/finish time,
   exit code, failure code, output cursor or truncation flags. Validate the
   original submission key using stored submission/credential intent and old
   epoch. Preserve the opaque request hash; do not pretend this recomputes the
   absent Exec payload. Match old scope against trusted recovery policy, not a
   request or a provider freshly resolving candidate metadata.
4. Reject the whole admission before mutation if any entry is unproved or a
   later phase exists. The deadline is diagnostic: elapsed time, a free flock,
   queued state or a missing owner is not the proof. Fresh reserved records
   are equally pre-dispatch once exclusive old-owner exclusion is established.
5. Classify an eligible record as a retained no-dispatch tombstone, using the
   already planned private `terminalKind=no_dispatch` distinction and existing
   public interrupted state. Preserve every original identity, request key,
   submission key, epoch and credential-intent field. Record only the actual
   classification time; do not fabricate StartedAt, exit status, successful
   completion or provider-cleanup metadata. This private schema extension and
   its exact public projection require their own reviewed RED before coding.
6. Publish using the same selected retained-root, exact-prior-byte CAS,
   file/directory sync and inode/byte readback discipline. Recheck directory,
   lock, entry set and every source identity before first mutation and around
   each commit. Never delete originals by name or roll back a possibly consumed
   rename. A write/readback/close/currentness failure rejects startup and retains
   uncertainty. Already committed no-dispatch tombstones may survive a partial
   batch; later startup must validate them idempotently, never redispatch them.
7. Release only the logical occupancy represented by proven no-dispatch records,
   after durable readback; preserve tombstones and original epochs. Do not add
   them to `minimalLive` or create owner bindings. Before provider Resolve for a
   later request, check the original principal/submission across authorized old
   epochs. Recompute its request hash using the stored epoch and incoming full
   request; exact replay returns the prior interrupted record, changed payload
   conflicts. Do not rekey an old submission to the new daemon or silently rerun
   it. Ambiguous cross-epoch matches fail closed. Any genuinely new submission
   still needs the current authenticated principal and current launch scope.

This only retires a never-dispatched reservation. The selected start response,
credential/workload consumer and concrete-provider cleanup remain independent
work. No runtime is destroyed or declared absent by this algorithm.

## Proposed REDs through actual service startup

Tests must construct records through `NewL8DurableService` and its actual
authenticated Start route, not hand-write a positive `reserved` label. A narrow
existing publication seam can stop after fully synced reserved publication and
before the dispatch transition. Any new seam must preserve the real save/arm
ordering and distinguish pre-transition interruption from a failed publication.

- Positive/control: valid service dispatch reaches a claiming fixture provider;
  a genuine pre-dispatch interruption leaves exact reserved bytes with zero
  provider starts. Restart under the independently approved old-epoch policy
  retains one interrupted tombstone, releases only logical occupancy, and makes
  zero Resolve/Start/Recover/Finalize calls for the recovered record.
- Crash boundaries: before initial publication, after link with temporary still
  present, after complete reserved sync, before/after dispatch rename, after
  dispatch sync but before provider entry, and after provider claim. Only a
  completely proved reserved directory is eligible. All post-dispatch and
  uncertain cases retain bytes and reject startup even when provider calls are
  known to be zero in the fixture.
- Identity/schema: missing or unapproved epoch/scope, foreign worker/host/
  principal, withdrawn launch scope, conflicting original submission keys,
  canonical-looking synthetic records outside the trusted lineage, filename
  mismatch, duplicate/aliased JSON, extra fields, partial/oversized records,
  contradictions and mixed old phases. Unknown state is never repaired.
- Filesystem: missing/replaced lock, competing successor flock, replacement
  directory/record, unsafe mode/owner, hardlink/symlink/FIFO, extra temporary,
  mutation between enumeration/readback/publication and uncertain writes. Assert
  exact canary bytes/inodes remain; never count a rejected preliminary fixture
  as having exercised the later recovery write.
- Lifetime: block the real old handler before/after dispatch publication. A
  successor cannot acquire the lock before joined Close or actual process exit.
  Resuming a pre-dispatch old handler cannot call the provider after revocation.
  A provider already entered always corresponds to quarantined dispatching.
- Replay: same request under a new epoch does not relaunch; altered Exec conflicts
  before Resolve; another principal cannot inspect/reclaim it. Repeated restart
  and a partial tombstone-publication batch converge without duplicate records.
- Controls independently execute empty selected startup, wrong-issuer rejection,
  existing default/legacy startup, nonempty dispatch quarantine and current
  original Close joins. Source guards retain all publication and callback
  invariants; exact new file/call enrollment needs separate review.

## Candidate implementation ownership and handoff

After authority approval, the smallest coupled worker slice would touch the
selected branch in `job_manager_v2.go`, narrowly selected constructor options in
`job_v2_service.go`, new `minimal_launch_restart*.go` helpers/tests, retained store
helpers/validator and exact private decoder enrollment, plus prior-submission
lookup in `minimal_launch_dispatch.go`. Any pure historical-scope comparison in
`sandboxruntime` needs explicit scope approval; it must not call a provider or
issue a principal, grant or owner. Keep generic lock/store and legacy byte
semantics unchanged; reuse their mechanics only behind selected-only admission.

This note supplies a conditional algorithm and executable-test plan, not the
missing authority itself. No tests were added or run for it. The worktree contains
only this design document. Owned cleanup/terminal receipts, L8 host/provider
composition, L9 immutable-provider handoff and L10 activation remain later work.
