# Retained Jailer cgroup-v2 boundary

The private strict coordinator requires an explicit trusted existing anchor and
finite limits. It never defaults the anchor to `/`, enables controllers, mounts,
chowns, migrates a running process, or modifies host-wide settings. One exclusive
child is bound to runtime ID and the measured Firecracker config. The anchor's
entire nofollow chain must be root-owned and not group/other writable; the anchor
and child must be cgroup-v2 domain directories with cpu/memory/pids already
enabled at the anchor. Retained FD identity and independent limit readback are
required before launch and throughout cleanup.

Accepted bounds: CPU period 1,000..1,000,000 microseconds; quota
1,000..1,024,000,000 microseconds, at most 1,024 periods; memory 1 MiB..1 TiB;
swap 0..1 TiB; pids 1..1,048,576. Memory and swap must be host-page aligned,
and memory must cover the explicitly correlated guest memory allocation.
These are validation ceilings, not default allocations or performance promises.

The existing private starter consumes a CLOEXEC duplicate as `CgroupFD` with
`UseCgroupFD=true`; it preserves SIGKILL parent-death configuration and does not
put the FD in ExtraFiles. Go 1.25.7 `src/syscall/exec_linux.go` lines 107-108 and
313-347 implement clone3/CLONE_INTO_CGROUP and propagate clone failure. No
post-exec migration or unrestricted fallback is permitted.

The coordinator owns every partial lease. A launch callback is one-shot, holds
the lease against concurrent cleanup, and closes its duplicate after success,
failure, panic, or cancellation. Failure after a process started returns that
process to the existing runner's stop/reap path; uncertain stop retains ownership.
Cleanup kills only the exactly owned
cgroup, waits within a bounded deadline for empty evidence, then releases the
jail and exact cgroup. Replaced, unknown, populated, or failed-cleanup resources
remain quarantined and block reuse. No recursive cgroup deletion is performed.
Empty observation uses a two-second maximum deadline and ten-millisecond poll
interval; an earlier caller deadline wins. Every control read is capped at
4 KiB. Requests rejected before allocation cause no filesystem mutation.

The [kernel cgroup-v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)
defines subtree controller enablement, descendant-inclusive populated state,
cgroup.kill, and memory page rounding. Aligned inputs avoid accepting a rounded
limit different from the requested bound.

Default tests use private fake filesystem/syscall observations and ordinary
filesystem refusal, never a live cgroup. Cgroup-empty evidence is not UID
dedication, post-daemon-crash recovery, guest boot, or strict admission proof.
The minimal guest topology and default-off gates remain unchanged.

Verification commands (pinned Go 1.25.7, `GOMAXPROCS=3`):

```sh
go test -p 2 -count=1 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestJailerCgroup'
go test -p 2 -race -count=3 ./internal/sandboxruntime/microvm/firecrackerhost -run '^(TestJailerCgroup|TestStrictJailer|TestLinuxJailer)'
go test -p 2 -count=1 ./internal/sandboxruntime/microvm/firecrackerhost
go test -p 2 -race -count=3 ./internal/sandboxruntime/microvm/firecrackerhost
go vet ./internal/sandboxruntime/microvm/firecrackerhost
GOOS=darwin GOARCH=arm64 go test -p 2 -c -o /dev/null ./internal/sandboxruntime/microvm/firecrackerhost
```

The existing cmd L8 authority/default/reset/live-stub guard selector must also
remain green. Darwin compilation is not execution evidence. No live cgroup or
KVM acceptance was performed by these commands. Prepared Linux must still prove
actual clone3 placement, limits, post-drop behavior, teardown, and restart
containment before the strict path is selectable.
