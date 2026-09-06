# Jailer recovery through the existing runtime owner

Status: DESIGN/RED only, based on `42a9517d119f205b486aea50f5e32dd6c13ea688`.
No production behavior changes here. The selected first slice is daemon-client
loss/reconnect while the existing supervisor survives. Supervisor loss,
all-handle loss, and host reboot remain incomplete/quarantined, not accepted J
restart recovery. The Linux completion architecture and L8 minimal contract
reset remain authoritative; no strict selector or credential claim is enabled.

## Source-grounded gap

- `jailer_coordinator.go:startWithMinimalLease` commits the identity reservation
  before inspection/allocation, then retains cgroup, staging and process only in
  `strictJailerCoordinatorGeneration`. Its mutex and session are process-local.
- `jailer_identity.go:jailerIdentityRecord` contains only the prepared pair,
  runtime ID, config digest, nonce and busy/idle state. `reserve` correctly
  rejects stale busy; deserializing this record cannot construct a release
  lease. No cgroup, jail-root or child authority survives in this journal.
- `jailer_coordinator.go:releaseGenerationRoot` already orders owned cgroup
  kill/empty, jail-root cleanup, cgroup removal, process-forget, and durable
  identity idle. `retryCleanup` requires the same retained generation.
- The actual existing executable is
  `cmd/hal-firecracker-runtime-owner/main.go`, delegating to
  `RunPrivateL8RuntimeOwnerExecutable`. Its `supervise` role enters
  `runL8RuntimeOwnerSupervisorLinux`; the `child-gate` role remains separate.
  This is the owner to extend, not a second executable/daemon or scheduler.
- `l8RuntimeOwnerSupervisorConfigV1` requires a complete credential identity
  seed. `newL8RuntimeOwnerLinuxRuntime` validates six inherited descriptors,
  opens its reconnect listener and creates seed-correlated genesis.
  `startChild` currently calls `startL8RuntimeOwnerLinuxChild`; its released
  gate uses `remapAndExecL8RuntimeOwnerChild` to run direct Firecracker via the
  namespace wrapper. It does not invoke the accepted Jailer coordinator.
- `HandleBootstrap` publishes genesis, starts an armed child, records PID/start
  time, releases the child, then records running. `ControllerLost`,
  `AdmitController`, `HandleController`, `reinspectAbsence`, `finalize` and
  commit already implement one-owner reconnect/replay/finalization. The Linux
  owner currently retains namespaces and a direct child, not Jailer leases.
- `l8RuntimeOwnerRecoveryBinding` produces seed-bound absence, runs recovered L7
  cleanup and commits a receipt. Its replacement containment checks boot,
  process start time and pidfds. Those are not authority to remove a Jailer
  root or release its UID, and its finalized receipt does not cover them.

## Selected approach and hard assumptions

Keep the coordinator, identity lock/journal descriptors, cgroup descriptor,
staging-root descriptors and exact process handle **inside the existing
supervisor before any resource allocation**. Do not start in the daemon and
later attempt to serialize or transfer a Go lease graph. A restarted daemon
reconnects to that same live owner; it does not reacquire a busy identity slot.
The owner retains its actual descriptors across controller changes.

The existing capacity-one prepared-host assumptions still apply: one canonical
root-owned identity authority/pair used by every Hal process, no outside-Hal
use of that UID/GID, trusted root-owned cgroup/chroot anchors and executables,
enabled controllers, and durable local filesystem semantics. These are not
proved by account/PID scans or an empty cgroup. No automatic host preparation,
chown, account creation, mount, controller enabling, or invented default IDs.

Only an exact live supervisor can perform this slice's destructive recovery.
Reconnection must bind boot ID, supervisor PID/start-time/pidfd, supervisor and
runtime generation, rotating one-use secret, record revision, peer identity,
and the original reservation nonce/config digest. Stale controller requests
must fail before touching resources. Caller-supplied paths, booleans, numeric
UIDs, or a free lock cannot mint this authority.

If that owner is absent, its identity changed, its handles are lost/replaced,
or the record is missing/uncorrelatable, return quarantine. A known cleanup
failure stays quarantined but may retry through that same live owner and its
retained handles. **Do not reopen cgroup or
jail paths for destructive cleanup in this first slice.** In particular,
device/inode numbers serialized before a crash do not independently exclude
later object reuse. The source of authority here is the surviving owner and
its continuously retained descriptors, not recovered pathname metadata.

## Smallest useful GREEN: one selected pre-credential owner variant

The following is a coupled implementation, not separate metadata-only phases.
Making the admission RED pass by adding an unused dependency is insufficient.

1. Add an explicit, bounded minimal-launch variant at the **existing**
   `supervise` config decoder and Linux runtime constructor. Leave the exact v1
   config, record schema, child-gate and credential recovery behavior intact.
   The selected variant must not accept or synthesize a
   `JobCredentialIdentitySeed`, guest/helper generation, readiness, or mode
   activation. Use host job/runtime references, measured config/image identity,
   and an actual supervisor-issued generation. Only after reservation exists
   can its actual nonce be recorded. Bind that exact reservation into the owner
   record and durably read it back before cgroup/staging allocation; a failed
   correlation update cannot authorize launch or a cleanup-complete result.
   Keep a distinct private record version and receipt domain in the existing
   store/FSM, not a parallel journal owner.
2. The trusted host preparation boundary supplies the reserved-slot/cgroup/
   executable policy and verified minimal inputs, never a public worker request
   choosing alternate privileged anchors. Take the existing minimal launch
   lease, borrow its sources, and copy bounded measured bytes into sealed
   descriptor snapshots for this process boundary. Hash the copied snapshots
   independently, verify sizes/seals and correlate the sealed config. Retain
   the borrowed lease through acknowledgement/cancellation; never close a
   transferred alias. Current owner FD validation already requires sealed
   assets, so ordinary mutable source FDs are not an equivalent substitute.
   No production supervisor bootstrap producer for this selected handoff was
   found at the base: that narrow private producer is part of GREEN, not assumed
   to exist. Snapshot resource exhaustion fails before launch.
3. Preserve the legacy six-descriptor layout. For the selected variant define
   an exact versioned role/count list, adding a separately bounded measured
   Firecracker-config descriptor rather than embedding its up-to-1-MiB bytes
   in the existing 32-KiB supervisor config. Reject extra/missing/swapped roles,
   size/digest/seal mismatches and config version confusion. No raw secret or
   environment delivery. Close every partial snapshot/received FD on failure.
4. In `l8RuntimeOwnerLinuxRuntime.startChild`, the selected branch constructs
   the accepted coordinator/lifecycle with those trusted inputs and an opaque
   owner capability issued only by this supervisor instance. Feed validated
   descriptor readers and independent measurements into the existing stager
   (`jailerStagingResourceInput` already accepts `io.ReadSeeker`). Preserve
   stream-copy plus independent staged-byte hashing, executable snapshots,
   namespace lifetime, cgroup-at-clone and Pdeathsig, and strict socket UID/PID
   correlation. Do not fall back to direct Firecracker, rebuild image metadata,
   or manufacture a `VerifiedL8MinimalDistribution` from paths.
5. The supervisor's selected containment adapter calls the exact coordinator's
   stop/retry path and retains terminal cleanup state. An absence response is
   allowed only after process termination, cgroup empty, jailed bytes/socket
   cleanup and cgroup removal succeeded. Cleanup errors retain the generation
   and mark the existing owner uncertain; retries use the same handles. The
   selected finalization adapter must include the durable cleanup checkpoint
   and identity idle transition, not just the legacy `CloseNamespaces` callback.
   Keep a terminal receipt after releasing handles so replay cannot operate on
   a successor. Do not change legacy `stop` callers merely to split these steps:
   use a narrow owner-bound completion hook/state if the selected ordering needs
   a pre-idle journal checkpoint.
6. Reconnect through the existing authenticated control protocol, with a
   selected runtime-only cleanup result distinct from credential absence proof.
   Extend its existing store/record validation with the selected version, using
   the same locking, bounded IO and one owner. Do not feed a minimal receipt to
   `FinalizeJobCredentialRuntimeRecovery` as if credential cleanup occurred.
   Later credential/network owners must attach their real identities to this
   same owner and finish revocation/cleanup before final strict publication or
   reuse; until then this private variant cannot admit credential-bearing jobs.

Prospective implementation ownership (requires a new GREEN assignment): new
`jailer_recovery*` private files; narrow coordinator terminal-hook integration;
existing `l8_runtime_owner_executable{,_linux}.go`,
`l8_runtime_owner_runtime_linux.go`, `l8_runtime_owner_supervisor.go`,
`l8_runtime_owner_recovery.go` and their platform counterparts/tests. These are
coupled owner/config/record consumers, not permission for unrelated refactors.
Reuse the minimal resolver's existing lease API without changing build,
assembler, selected guest control, default cmd paths, identity journal, or
source guards. Any required guard ownership adjustment needs separate evidence
and approval. The command entrypoint should need no new command or flags.

## Crash ordering and commit points

Implementation refinement: use a private `jailer-child-gate-v1` role of the
same runtime-owner executable, with exactly two inherited descriptors: control
socket and sealed bounded gate config. Do not pad the legacy six-descriptor
child-gate ABI. The selected starter reuses `startStrictJailerOSExecCommand`
for private executable mounts, the retained creating thread, network namespace,
clone-time cgroup and additive Pdeathsig. The gate checks canonical derived
Jailer argv, current mounted snapshot identity/hash, unchanged parent and
SIGKILL parent-death setting; it waits for bounded armed/release acknowledgement
and closes inherited descriptors before same-PID Jailer exec. Actual armed
PID/start time is durably published before release. This is a private role,
not a new public command, guest role or daemon.

| Window | Required outcome |
| --- | --- |
| Before durable selected genesis and valid owner capability | No reservation/allocation/launch; close local inputs. |
| Busy write/sync/readback uncertain | No allocation; retain/quarantine, never repair idle. |
| Busy committed, allocation/staging incomplete | Surviving supervisor owns every partial lease and cleans/retries exactly; dead supervisor leaves busy quarantine. |
| Child created before PID/running publication | Existing armed-release discipline must be preserved or an equivalent Jailer pre-exec barrier proved. Publication failure invokes exact containment; it never relaunches. The current coordinator starts immediately, so this adapter/barrier is real implementation work. |
| Daemon disconnects before/after launch acknowledgement | Owner, lock and descriptors remain live. Reconnect/replay recovers the same generation; no duplicate launch. |
| Cleanup fails or terminal journal checkpoint is uncertain | No finalized/reusable result; retain exact handles and busy identity. No absence inferred from PID disappearance. |
| Exact cleanup and durable selected cleanup checkpoint complete | Commit/read back identity idle under its existing lock, then publish/retain final receipt. |
| Idle durably committed, later Close/receipt publication fails | Resources were already terminal. Retry only old handles/receipt; never rewrite or reacquire a successor's identity. A remaining old record cannot authorize new cleanup. |
| Supervisor dies or boot changes at any nonterminal point | Quarantine, even if PID is gone, cgroup looks empty or lock is free. No all-owner-loss recovery claim. |

The identity journal keeps its permanent lock and stable journal inode. Do not
borrow the older owner store's uncertain-rename readback reconciliation as
proof that a failed filesystem sync durably completed a new cleanup checkpoint;
selected checkpoint IO needs explicit successful synchronization and readback.
Recovery after all handles are lost is a later design: it must establish
anti-reuse identity for reopened cgroup/root/anchor objects, crash-consistent
allocation/removal intent and slot correlation, and safe authority when any
record is absent or torn. A serialised path, PID, timestamp or generation label
alone cannot do that. No new recovery daemon is proposed.

## Tests and evidence boundary

`TestJailerRecoveryCoordinatorRejectsLaunchWithoutSurvivingOwner` is a compiling
behavioral RED. It supplies a valid reserved identity plus existing fake
cgroup/staging/lifecycle dependencies but no surviving-owner authority. At this
base it returns nil error, records `[allocate-cgroup verify start]`, retains a
generation, and leaves the identity busy. Desired behavior is rejection before
busy/allocation. This is a missing selected-path prerequisite, not evidence of
an enabled default-path vulnerability.

`TestJailerRecoveryExistingSupervisorKeepsCoordinatorAcrossReconnect` deliberately
wires existing fake callbacks into the existing supervisor FSM. It passes at
the base: bootstrap once; lose/reconnect controller; reject stale session;
retain exact coordinator/identity/cgroup/root; finish or fail-and-retry owned
cleanup; replay stop without repeating cleanup; finalize and reconnect again
to commit. The failure case denies finalization and UID reuse. Legacy
seed/token fixtures and a two-element nil descriptor shape test only the FSM;
they are not production identity, descriptor, process or minimal-launch proof.

```sh
go test -p 2 -count=1 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestJailerRecoveryCoordinatorRejectsLaunchWithoutSurvivingOwner$'
go test -p 2 -race -count=3 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestJailerRecoveryExistingSupervisorKeepsCoordinatorAcrossReconnect$'
```

GREEN additionally requires tests against the actual selected Linux config and
`startChild` consumer, not only these callbacks: absent/wrong/closed owner,
genesis/busy/publication failures, wrong FD role/seal/size/hash, source mutation,
pre-exec cancellation, controller loss at each acknowledgement, stale/replayed
session, exact terminal cleanup and partial-cleanup retry, successor safety,
and supervisor-loss quarantine. Ordinary descriptor tests stay unprivileged;
subprocess tests are explicitly tagged. Run whole-package/race, vet, Darwin
compile, existing L8/source/default guards and broad integration gates.

Prepared-Linux acceptance still must demonstrate the actual owner executable,
fresh Jailer VM, reserved UID/GID, clone-time cgroup placement, authenticated
minimal guest operations, daemon kill/reconnect without relaunch, exact cleanup
and zero leaked resources. Supervisor/all-owner loss is a separate required
remaining recovery gate. L8's selected `verify-selected-live.sh prerequisites`
and `e2e` matrix, including credential/network teardown, remain later dependent
zero-skip requirements. None is established by this design or fake coverage.
