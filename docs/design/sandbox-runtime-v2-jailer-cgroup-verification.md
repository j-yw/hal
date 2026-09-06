# Retained Jailer cgroup-v2 boundary

The private strict coordinator requires an explicit trusted existing anchor and
finite limits. It never defaults the anchor to `/`, enables controllers, mounts,
chowns, migrates a running process, or modifies host-wide settings. One exclusive
child is bound to runtime ID and the measured Firecracker config. The anchor's
entire nofollow chain must be root-owned and not group/other writable; the anchor
and child must be cgroup-v2 domain directories with cpu/memory/pids already
enabled at the anchor. Retained FD identity and independent limit readback are
required before launch and throughout cleanup.

Proposed accepted bounds: CPU period 1,000..1,000,000 microseconds; quota
1,000..1,024,000,000 microseconds, at most 1,024 periods; memory 1 MiB..1 TiB;
swap 0..1 TiB; pids 1..1,048,576. Memory and swap must be host-page aligned,
and memory must cover the explicitly correlated guest memory allocation.
These are validation ceilings, not default allocations or performance promises.

The existing private starter consumes a CLOEXEC duplicate as `CgroupFD` with
`UseCgroupFD=true`; it preserves SIGKILL parent-death configuration and does not
put the FD in ExtraFiles. Go 1.25.7 `src/syscall/exec_linux.go` lines 107-108 and
313-347 implement clone3/CLONE_INTO_CGROUP and propagate clone failure. No
post-exec migration or unrestricted fallback is permitted.

The coordinator owns every partial lease. Cleanup kills only the exactly owned
cgroup, waits within a bounded deadline for empty evidence, then releases the
jail and exact cgroup. Replaced, unknown, populated, or failed-cleanup resources
remain quarantined and block reuse. No recursive cgroup deletion is performed.

The [kernel cgroup-v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)
defines subtree controller enablement, descendant-inclusive populated state,
cgroup.kill, and memory page rounding. Aligned inputs avoid accepting a rounded
limit different from the requested bound.

Default tests use private fake filesystem/syscall observations and ordinary
filesystem refusal, never a live cgroup. Cgroup-empty evidence is not UID
dedication, post-daemon-crash recovery, guest boot, or strict admission proof.
The minimal guest topology and default-off gates remain unchanged.
