# Jailer reserved identity lease: design and RED checkpoint

Status: approved design and a failing regression only. This checkpoint adds no
production identity authority, changes no default path, and does not establish
UID dedication, Jailer launch acceptance, or daemon-restart recovery.

## Required prepared-host assumptions

The initial deployment has capacity one: one explicitly reserved non-root host
UID and GID, reused between jobs only after exact cleanup. It is not a pool or
multi-tenant allocator. The prepared-host operator must ensure that:

- Both identities are excluded from all non-Hal processes, services, login
  accounts, supplementary-group use, and concurrent administrative reuse.
- Every Hal process on this host uses the same canonical identity authority
  directory and reserved pair. Separate anchors are not separate safe leases
  for the same UID or GID. The configured pair cannot change while the authority
  has unresolved ownership.
- The directory, its full nofollow ancestry, permanent lock file, and initial
  idle journal are explicitly prepared and root-owned, inaccessible for writes
  by the reserved identity or other unprivileged users. The final directory is
  private; the files are private regular files with one link.
- The selected local filesystem provides process-shared locking and honors
  successful file/directory synchronization across crashes. Restoring old
  journal backups or deleting an authority directory is not recovery.

Hal can enforce its own exclusive allocation under these assumptions. It cannot
prove absence of outside-Hal users by checking account names, scanning PIDs,
observing an empty cgroup, or accepting a caller's `dedicated` assertion. This
slice does not create users/groups, change host ownership, initialize an absent
journal, install host configuration, or invent reserved numeric defaults.

## Existing source and concrete consumer

`jailer_host_inspector.go`, `strictJailerHostInspectionRequest`, explicitly leaves
dedication to a later authority. `inspectStrictJailerHostWithFilesystem` rejects
zero UID/GID but accepts other numeric pairs. `strictJailerCoordinatorAuthority`
checks numeric agreement and projects the pair into the staging authority.

`strictJailerCoordinator.startWithMinimalLease` serializes only the current
coordinator instance. Two instances or daemon processes do not share that
mutex. Existing cgroup ownership correlates runtime/config identity but does
not reserve the runtime UID or GID.

The intended consumer is this existing coordinator, before cgroup creation or
staging. Its `releaseGenerationRoot` already orders cgroup kill/empty evidence,
exact jail-root removal (including owned contents and sockets), cgroup removal,
and terminal-process record removal. Identity release belongs after all of
those steps, not merely after the main process exits. The stager's
`linuxJailerStagingRoot.removeOwned` explicitly requires UID quiescence for its
final identity-check/unlink interval; the identity lease closes competing Hal
allocation, while the prepared-host assumption excludes outside-Hal writers.

The existing runtime-owner recovery layer records boot identity, process start
times and generations, and uses pidfds when checking process correlation. Those
facts are not yet a Jailer identity-release authority. Do not add a second
recovery daemon or use its legacy direct-Firecracker behavior as Jailer proof.

## Private authority and lifetime

The proposed private authority is supplied through coordinator construction,
not a job request, runtime/guest JSON, durable capability metadata, or a boolean
claim. It names the trusted prepared slot; it does not let a job choose a UID,
GID or alternate lock anchor. Existing numeric inspection fields must agree
with the lease-derived pair before they can reach staging and launch.

Reservation returns an opaque in-memory lease bound to the exact authority,
UID/GID, runtime ID, measured config digest, and a fresh ownership nonce. Copies
refer to one synchronized lease state. Neither deserializing its journal nor
knowing its numeric pair creates a release handle. Acquisition reopens and
validates the shared permanent lock inode, holds a nonblocking exclusive kernel
lock, and validates the current bounded journal before committing busy intent.
An in-process mutex alone is insufficient across independent coordinators.

Keep the lock inode permanent: never unlink or rename it on release. The
proposed minimal journal also keeps its prepared inode stable, using bounded
in-place writes under the permanent lock. This avoids treating our own rename
as a hostile replacement. Validate retained descriptors against current
nofollow directory entries, owner/mode/type/device/inode/link count and the
expected record both before and after an update. No partial read, trailing
bytes, duplicate/unknown fields or unsupported record version becomes idle.
The precise private encoding is an implementation detail; it is not a public
proof format or an additional runtime-owner store.

Keep every descriptor close-on-exec and retain authority through the complete
generation. Close/revoke without a successful exact-owner release leaves the
busy journal intact. A stale alias cannot close another generation's lock or
mark its journal idle. Concurrent close/acquire/release must serialize on the
shared lease state, with bounded, cancellation-aware operations.

## Durability and crash ordering

Busy transition: validate idle under the permanent lock; write the complete
bounded busy record; set its exact length; synchronize; independently read back
the exact record and verify path/descriptor currentness. Only then may the
coordinator allocate a cgroup, stage/chown resources, or launch a process. A
partial write, synchronization, readback or currentness failure never authorizes
launch or a same-attempt inference that the slot is idle. Keep failed ownership
quarantined; do not restore the previous idle record as an error fallback.

Crash before the busy commit can leave the old idle record or an invalid/torn
record, but no resources may yet have been allocated. Crash after the busy
commit leaves busy even though the kernel lock is released. On restart,
missing, invalid or busy state cannot be promoted to idle. A free kernel lock,
missing PID, reused PID, different boot, timestamp or expired lease is not
release evidence. No process inspection is needed to reject these records.

Idle transition: first complete existing exact terminal cleanup while retaining
the identity lock. Then verify the current busy record matches this live
lease, write/synchronize/read back the complete idle record, and check current
inode identity before releasing descriptors and lock. If the transition fails,
report incomplete cleanup and do not report or infer reusable identity in that
attempt. Crash during this transition may leave busy/invalid (quarantine) or a
complete idle record; a complete idle record is safe only because every owned
resource was already terminal before the first idle write. Never write idle
before cleanup to make crash recovery appear successful.

An unresolved partial cgroup/staging acquisition, failed kill/empty observation,
socket or jail-root removal, process-forget failure, replaced authority, or
uncertain close retains/quarantines identity ownership. A later retry needs the
same exact live owner. Reclaiming a stale journal after daemon crash requires
separate integration with the existing runtime-owner recovery authority; it is
explicitly not implemented by this slice.

## RED and subsequent acceptance

The committed default regression uses only existing fake cgroup/staging/process
dependencies. Its request has a valid config and a non-root numeric pair, but
its explicit dependency literal omits any future prepared identity authority.
It requires rejection before resource allocation. At the design base the
coordinator instead allocates a fake cgroup and reaches process start.

```sh
go test -p 2 -count=1 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestJailerIdentityCoordinatorRejectsNumericIdentityWithoutReservation$'
```

The GREEN implementation is not authorized by this checkpoint. Its required
tests are: genuine process-shared lock behavior on ordinary filesystem
fixtures; fake root-owned admission; absent/zero/mismatched identity; concurrent
coordinators; busy/stale/torn/missing journals; wrong/replaced/symlinked/hardlinked
anchor or files; bounded reads and failed write/sync/readback; cancellation
before and after busy commit; no PID/age-based reuse; shared-alias close races;
every partial cleanup failure; exact cleanup-before-idle ordering; idempotent
same-owner retry; stale-owner rejection after a successful new reservation;
and preservation of unselected/legacy behavior. Actual root-owned filesystem
acceptance remains distinct from injected ownership observations. Any tests
requiring external CLIs must be explicitly tagged, not availability-skipped
default tests.

After GREEN, run the full firecrackerhost package, race three times, vet,
Darwin compile, and the relevant default/source guards. Those unprivileged
checks do not replace prepared-Linux Jailer launch, dedicated-identity host
validation, cgroup enforcement, guest operations, teardown, or daemon-crash
recovery acceptance. The selected minimal guest topology and strict admission
gates remain unchanged.
