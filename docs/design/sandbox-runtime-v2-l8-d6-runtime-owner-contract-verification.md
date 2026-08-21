# L8 D6 Restart-Stable Runtime Owner Contract Verification

The original contract slice changed documentation and documentation guards
only. R1 now adds the exact neutral recovery contracts plus default-off private
record, digest, HMAC, store, boot, and process-inspection foundations. It keeps
the L8 restart architecture requirement for a separate Linux runtime-owner
supervisor that directly parents Firecracker and remains reconnectable across a
sandbox-daemon restart. The main L8 architecture is the normative contract for
the exact neutral recovery API, private owner record, reconnect/replay FSM,
stop/reap escalation, supervisor-crash containment, L7 recovery ordering, and
default behavior.

## Frozen boundary

The documentation guard locks the exact declaration and field order of:

- `JobCredentialRuntimeAbsenceProofInput` and the sealed 41-byte
  `JobCredentialRuntimeAbsenceProof`;
- `NewJobCredentialRuntimeAbsenceProof` and
  `ValidateJobCredentialRuntimeAbsenceProof`;
- `JobCredentialRuntimeRecoveryProvider` and
  `JobCredentialRuntimeRecoveryBinding`, whose methods remain ordered as
  complete-identity recovery, seed-bound stop/reap, proof-bearing finalize that
  returns an owner-bound commit receipt, receipt commit, and bounded close;
- the private `storedJobCredentialRuntimeRecoveryReceiptV1`, which contains
  only the validated safe seed and exact commit ID; and
- the package-private `firecrackerRuntimeOwnerRecordV1`, including its exact
  host-boot identity, full-seed correlation digest, runtime/process/vsock/L7
  correlation, and private reconnect fields.

The record is strict, bounded to 16 KiB, atomically replaced under service-UID
owned mode-0700 state, and stored as a mode-0600 regular file. It becomes
durable before Firecracker publication. PID/start identity, listener identity,
and the random one-use secret stay exclusively inside the private owner
boundary. They never enter worker state, status, proof projection, runtime
metadata, manifests, command output, or errors.

The neutral absence proof contains only a kind byte, an internal
domain-separated full-seed correlation digest, and its observation time. Its
digest binds every seed field, the signed `IssuedAt.UnixNano()`, and the count
plus ordered binding/mode pairs. It has no accessor and creates no public
seed-digest contract; only the private owner record may contain its lowercase-
hex form for anti-substitution. The proof is useful
only as the fresh validated return of the injected seed-bound recovery binding;
it cannot be transported through metadata to create authority. Binding `Close`
is idempotent and bounded but never means process or resource absence.
R1 has no production absence-proof constructor call: the concrete stop/reap
owner and its causal validated-absence fact do not exist yet. The AST guard
requires zero host issuers in this dependency-unaccepted state. A later slice
may tighten it to the sole exact owner call only together with the real
stop/reap observation; a caller-provided boolean or time is not a substitute.
The commit receipt's exported persistence bridge is locked to
`json:"-" xml:"-"`, redacted string/fmt output, fail-closed
JSON/gob/text/binary encoding, XML field omission, and one exact
future `sandboxworker/job_store_v2.go` private DTO copy site. The repo-wide
guard binds each permitted `CommitID` read to the exact receipt-typed parameter
object and exact package-function signature. It rejects same-name unrelated
fields, value/type aliases, methods, closures, helper escape, reflection,
unsafe conversion, wrong results, and indirect field access. The root validator
and owner verifier must land together; the worker converter remains absent
until worker persistence wiring lands. Outside those allowlisted files and
functions, even naming the receipt type through an explicit alias, dot import,
or raw-string import fails. Receipt-bearing allowlisted files cannot import
`reflect` or `unsafe`, so a selector-free indirect read is rejected repo-wide.
Root-file receipt references are separately confined to the exact type
declaration, validator parameter, unnamed sealed redaction/denial receivers,
and the exact Finalize/Commit positions in the recovery interface. Extra root
helpers, methods, assignments, values, parameters, results, and `any` retention
are rejected, including bare cross-file receipt identifiers in sibling root
package files where parser object resolution is unavailable.
The only frozen future result-type exception is the exact pointer method
`(*l8RuntimeOwnerRecoveryBinding).FinalizeJobCredentialRuntimeRecovery` in the
common owner file. Its parameters and two results are source locked and its
body may not access a receipt field; wrong receiver, file, signature, alias, or
field-read mutations fail.
Its commit ID is an HMAC over the full-seed digest and finalized revision under
one stable mode-0600 owner-root key. That constant key is durable before any
owner record and never projected or rotated while receipts exist. Post-record-
retirement replay uses a commit-only binding, verifies that HMAC, and requires
the exact per-job record still absent under lock. The HMAC proves Finalize
minted it only after L7 cleanup; replay neither reopens the removed L7 journal
nor persists a second per-job committed-outcome tombstone.

## Lifecycle acceptance to implement later

Future red-first production work must prove the following before claiming live
restart recovery:

1. The daemon retains the supervisor and private bootstrap pipe/start gate
   through revision-one publication. The supervisor persists revision-zero
   `starting` before the gated fork, holds the child behind a private pre-exec
   gate, arms Pdeathsig, rechecks the parent, sends a child-armed
   acknowledgement, persists its exact PID/start identity as revision one, and only then
   releases exec and publication. Any bootstrap pipe/start-gate loss before revision-one publication
   makes the supervisor kill, Wait, and exit; `AbortStart` is the sole recovery
   transition and no `starting` record can launch or replace a runtime.
2. The supervisor directly parents the exact Firecracker child and admits
   exactly one live controller through same-UID peer authentication plus the
   current one-use secret.
3. Secret rotation is durable before handshake acknowledgement. Immediate
   duplicate request sequence replay returns the cached response exactly once;
   stale, skipped, wrapped, concurrent, or cross-session sequences fail closed.
4. Normal stop/reap uses one caller-independent 30-second budget across TERM,
   the bounded grace wait, KILL, and child Wait/reap. Only successful Wait of
   the exact child produces normal-parent absence. A replacement never claims
   to Wait a non-child: pidfd terminal readiness is insufficient, and only two
   locked inspections proving the exact proc entry gone may establish
   externally reaped absence; zombies remain uncertain.
5. `PR_SET_PDEATHSIG` protects supervisor crash. Same-boot replacement uses
   pidfd plus exact recorded start-time identity before signalling or accepting
   absence; stale, replaced, PID-reused, mismatched, or uncertain records retain
   quarantine. A recorded `/proc/sys/kernel/random/boot_id` mismatch never
   authorizes signalling a current PID. Existing L7 recovery cannot reopen an
   old-boot namespace, so old-boot owner and L7 journals remain quarantined
   pending a real `l7network`-owned retirement API.
6. Exact same-boot process absence precedes `l7network.NewReconciler`; the seed-derived L7
   identity and private recovered `TerminatedVMBinding` drive
   `CleanupAfterVMQuiesced`. Stop/reap retains ownership while the worker
   validates the proof. Finalize completes L7 cleanup and durably writes a
   finalized tombstone and returns its exact commit receipt. One atomic worker
   write replaces CredentialState with the private seed-plus-commit-ID receipt;
   commit alone retires the owner tombstone and the worker then clears its
   receipt. Every crash point resumes from either CredentialState or the
   receipt, and post-commit replay returns the idempotent committed result.
   Close and time-based GC cannot substitute for this handshake.
7. Seed-only restart uses stop/reap directly. Complete-identity restart first
   attempts ordinary credential recovery, validates or rejects that result, and
   then always invokes the same seed-bound stop/reap, validation, finalize,
   durable-clear, and commit sequence. Containment is mandatory after
   successful and failed recovery because execution is never resumed.
8. A failure before record rename leaves the old revision; rename success with
   directory-sync failure is commit-uncertain and requires locked reopen plus
   exact old-or-new revision/digest reconciliation before acknowledgement.
9. Panic, error, deadline, cancellation, disconnect, partial persistence, and
   record-retirement failures remain sanitized, bounded, idempotently retryable,
   and cleanup-incomplete. None reconstruct active proof, source material,
   guest sessions, or execution.

The existing L8 Firecracker overlay foundation provides only same-process
retained cleanup through its in-memory registry. It is not daemon-restart
reacquisition evidence and cannot satisfy this matrix until the supervisor and
provider land.

## Guard coverage

The focused documentation tests are:

- `TestL8D6RuntimeOwnerContractArchitectureIsExact`;
- `TestL8D6RuntimeOwnerContractArchitectureMutationGuards`;
- `TestL8D6RuntimeOwnerContractVerificationIsFrozen`;
- `TestL8D6RuntimeOwnerContractProofConstructorHasOneProductionOwner`;
- `TestL8D6RuntimeOwnerContractProofConstructorGuardRejectsSecondIssuer`; and
- `TestL8D6RuntimeOwnerContractCommitReceiptHasOnePrivateStoreProjection`; and
- `TestL8D6RuntimeOwnerContractDefaultsRemainInert`.

Run them repeatedly and under the race detector:

```text
go test -count=20 ./cmd -run '^TestL8D6RuntimeOwnerContract'
go test -race -count=5 ./cmd -run '^TestL8D6RuntimeOwnerContract'
```

The exact-block guard detects renamed, reordered, added, or removed neutral API
declarations and private owner-record fields. The normative marker guard covers
permissions, bounds, publication ordering, authentication, replay, stop/reap,
pidfd replacement-owner behavior, L7 cleanup, proof opacity, non-Linux failure,
and default/V1 inertness. The source guard checks only established default and
v1 production entrypoints; later explicit D6 implementation files must not
bypass or weaken those paths.

## Broad gates

After the focused checks, run:

```text
go test -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

`make docs-check` continues to verify generated CLI documentation; the focused
`cmd` test above is the authoritative design-document guard. Reviewers also
confirm that the aggregate base, red commit, green commit, and final tree are
exact and that production changes remain confined to the four R1 foundation
files plus the neutral codec guard correction.

## Fake-only scope and non-goals

No test requires KVM, root, Firecracker, a live guest, or a daemon. This slice
does not implement the supervisor and does not open a listener, launch, signal,
stop, or reap a process. R1 adds the neutral root API and exercises only bounded
read-only `/proc` plus pidfd identity inspection of the test process.
It does not wire worker, command, provider, scheduler, or default runtime paths.
It does not implement prepare/session transfer, guest packets, credential
delivery, live L7 recovery, active proof, cleanup proof, or selected prepared-
Linux acceptance.

Non-Linux construction remains unsupported and fail-closed. Existing L5/L7,
planning-only, v1 worker, default command, default scheduler, and ordinary
Firecracker constructors remain inert. The contract does not claim actual live
restart cleanup until a production supervisor, reacquirer, exact-process
verifier, and L7 recovered-binding implementation pass the later fake, race,
mutation, crash, and selected Linux acceptance matrices.

## R1 foundation dependency-unaccepted

This is the exact `dependency_unaccepted` boundary for concrete recovery.

R1 adds only the neutral proof, receipt, validation, and denial-codec API; the
private record, seed-digest, HMAC, strict store, boot-ID, and pidfd/start-time
primitives; and non-Linux fail-closed stubs. The host layer deliberately has no
absence-proof issuer. All are unreferenced and default-off. It reserves the
private type `l8RuntimeOwnerRecoveryBinding`
but does not implement `FinalizeJobCredentialRuntimeRecovery`, a concrete
provider, process signaling, supervisor control, or L7 cleanup.

The recovered `l7network.TerminatedVMBinding` constructor remains absent.
Existing production termination bindings depend on the same-process in-memory
process tracker, while the restart path needs independently reacquired process
absence correlated to the recovered L7 journal. R1 therefore cannot honestly
finalize or satisfy the neutral binding. Old-boot journal retirement also
remains unavailable and fail-closed; no private `l7network` schema is copied or
invented here.

The strict Linux store walks every absolute path component with `openat` plus
`O_NOFOLLOW`, takes a nonblocking exclusive directory lock around the complete
read/check/replace/sync transaction, accepts only revision-zero `starting` as a
missing-record genesis, and serializes concurrent next-revision writers. The
decoder requires every canonical JSON key exactly once, so case aliases cannot
overwrite a field, and it rejects `null` or the wrong JSON scalar type before
typed decoding. Process inspection opens and checks the pidfd before any
`/proc/<pid>` read, then repeats nonterminal pidfd checks around the double stat
read; the retained descriptor therefore cannot be correlated to a replacement
PID. A zero observation owns no file descriptor. The HMAC fixed vector locks
raw key-generation and seed-digest bytes after the two length-prefixed strings,
and commit validation recomputes that HMAC from the stable key, full seed, and
finalized revision rather than trusting a caller-supplied expected token.

## R2 supervisor/bootstrap/reconnect prerequisite

R2 adds only the explicit default-off `hal-firecracker-runtime-owner`
executable, its strict sealed configuration and inherited-fd ABI, the bounded
private `SOCK_SEQPACKET` codec, namespace-fd retention/transfer, the durable
owner transition/CAS machinery, and direct-parent plus replacement-owner
containment primitives. It does not construct the executable from a default
runtime, publish an absence proof, implement the neutral recovery provider,
perform L7 recovery/finalization, persist a worker receipt, or wire command,
worker, sandboxd, factory, or profile selection.

Focused fake-safe verification is:

```bash
go test ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestL8RuntimeOwner(Protocol|Transition|CommitUncertain|Containment|SupervisorConfig|Seqpacket|NamespaceTransfer|Executable|Process|Replacement)'
go test ./cmd -run '^TestL8D6RuntimeOwnerSupervisor'
go test -count=20 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestL8RuntimeOwner(Protocol|Transition|CommitUncertain|Containment|SupervisorConfig|Seqpacket|NamespaceTransfer|Executable|Process|Replacement)'
go test -race -count=5 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestL8RuntimeOwner(Protocol|Transition|CommitUncertain|Containment|SupervisorConfig|Seqpacket|NamespaceTransfer|Executable|Process|Replacement)'
```

The standalone executable is compiled on Linux and cross-compiled on a
non-Linux target. Linux tests use only local socketpairs, sealed memfds,
namespace descriptor duplication, and direct child processes; they require no
KVM, Firecracker binary, network access, cloud account, guest image, worker, or
daemon. The production absence-proof constructor call count remains zero until
the later provider/L7 integration slice.
