# Minimal verified assets into the existing Jailer coordinator

## Scope and ownership

This slice consumes the distinct B1 `VerifiedL8MinimalDistribution`, not a
planning descriptor, a legacy L8 seal, or a relabeled L7 rootfs. B2 continues to
produce its exact seven-file bundle and independently retained expected receipt.
No assembler, source lock, credential protocol, default selection, or strict
admission contract changes here.

The resolver adds `TakeLaunchLease(ctx)`, a one-shot ownership transfer of its
already retained child and parent files. Transfer and `Close` serialize on the
same state lock. After transfer, every original distribution alias rejects
selection and another transfer; its `Close` is a no-op for the transferred
files. Only the opaque launch lease closes those files. A failed transfer does
not consume a still-valid distribution. Closing the lease is idempotent.

The lease lends bounded read/seek views for the exact kernel and rootfs through
`WithAssets`. Views expose no file descriptor or mutable source path. Their
lifetime ends when the callback returns, including panic/error unwinding;
retained views fail closed afterward. Concurrent close waits for the callback.
Callbacks must not recursively close or re-enter their lease. Source currentness
is checked before and after the callback, including child/parent inode, digest,
metadata and exact inventory correlation. `ConfirmCurrent` is the final
pre-launch check. Both operations observe cancellation.

`firecrackerhost` adds a private `startMinimal` entry to the existing
`strictJailerCoordinator`. It derives kernel/rootfs staging inputs from the
lease, never from caller-provided bytes/digests. The ordinary coordinator owns
all filesystem, executable snapshot, namespace, start and cleanup steps. The
same existing stager hashes bytes as copied, then syncs and independently reads
and hashes the staged file before ownership/mode publication. Before/after
source checks are additional checks, not substitutes for the staged-byte checks.

The coordinator closes the source lease on every return. The staged root is
retained by its existing generation owner through start/stop/retry. A failure
after staging removes only the owned root; uncertain removal retains the
existing cleanup-pending token. Cancellation before the final start gate denies
launch and follows that cleanup path. Cancellation after the process-start
commit point is a lifecycle containment matter, never permission to delete an
active process's files retroactively. No raw paths or source errors enter public
metadata. No new durable schema or parallel launch framework is introduced.

## Red-first acceptance

- Cancellation before staging, after staging, and after planning starts no
  process; post-staging failures release or quarantine the exact owned root.
- The one-shot transfer rejects zero/closed/stale authority and serializes
  concurrent take/close; alias close cannot invalidate an accepted lease.
- Child/parent file and directory replacement, symlink substitution, and
  same-inode modification fail closed. Staged-byte hashing rejects modified
  bytes even if the source is restored before its final currentness check.
- Callback views reject use after return and cancellation. Success, failure,
  panic, interrupted copying and cleanup retries retain no unowned source FD.
- A concrete coordinator test consumes a resolver-verified fixture bundle,
  uses the actual stager with a fake filesystem, and verifies the exact staged
  kernel/rootfs measurements and unchanged executable/namespace lifecycle.

Default tests are filesystem/fake tests only. They do not run image tools,
Jailer, Firecracker, KVM, privileged mount operations, or a guest. Focused gates:

```sh
go test -p 2 -count=1 ./internal/sandboxruntime/microvm/assets/localresolver -run '^TestL8MinimalLaunch'
go test -p 2 -count=1 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestStrictJailer(CoordinatorCancellation|Minimal)'
go test -p 2 -race -count=3 ./internal/sandboxruntime/microvm/assets/localresolver ./internal/sandboxruntime/microvm/firecrackerhost
go vet ./internal/sandboxruntime/microvm/assets/localresolver ./internal/sandboxruntime/microvm/firecrackerhost
```

## Remaining acceptance boundary

This is an exact-byte launch handoff, not full B2 source-build reproducibility,
guest boot/readiness, credential delivery, active L7 topology, dedicated-UID
allocation, cgroup enforcement, orphan containment or restart recovery proof.
The selected prepared-Linux L8 tests remain fail-closed and untouched. Strict
admission stays disabled until real fresh Jailer launch, guest operations,
credential matrix and owned teardown pass without skips on a prepared host.
