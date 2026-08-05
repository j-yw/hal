# Sandbox Runtime v2 L8 Helper Syscall Policy

## Authority and scope

This document closes the D2 syscall-policy architecture left open by
`sandbox-runtime-v2-l8-production-credential-delivery-architecture.md`. That
architecture remains authoritative for protocol, identity, resource, mount,
cgroup, execution, and cleanup semantics. This file narrows those semantics
into one normative Linux amd64 helper policy; it does not expand them.

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.
The policy applies only to the L8 `hal-guest-credential-helper`, its bounded
namespace keeper, and the privileged transition of a credential-aware child.
It does not replace the frozen L4 workload execution contract or the L7
workload network policy.

D2 adds no live implementation. In particular, it does not mount, create a
cgroup, launch a process, open a socket, install seccomp, or change a production
command. A platform other than Linux amd64 is unsupported and fails before
helper readiness.

## Closed policy model

The policy is deny-by-default. A syscall is permitted only when its role,
syscall name, scalar arguments, descriptor role, object provenance, and current
state match a rule below. A syscall name appearing in a family is not a general
allow: all stated restrictions remain mandatory.

The three roles are:

1. `bootstrap`: the helper after `exec` and before it emits `helper_ready`;
2. `steady`: the authenticated privileged helper after bootstrap; and
3. `child`: a keeper or workload child from successful `clone3` return until
   the keeper loop or workload `execveat` transition is established.

Role transition is one-way. `bootstrap -> steady` happens only after fixed-FD,
`SO_PASSCRED`, capability, securebits, pivot-root, config, and seccomp checks
succeed and the canonical `helper_ready` is sent under the committed filter.
`steady -> child` exists only in the newly created child task. A child
cannot return to `steady` and no role can return to `bootstrap`.

Linux seccomp filters are inherited and cannot be relaxed. The steady helper
must deny network and vsock creation, while the existing L4/L7 workload may
need its separately constrained application networking. D4 therefore MUST
prove a kernel-enforced role composition in which:

- the helper receives only the `steady` authority below;
- a child receives only the `child` transition authority before applying the
  existing workload policy; and
- no unfiltered or more-privileged launcher remains reachable from the helper,
  guest agent, or workload.

A single ordinary inherited filter that either grants workload syscalls to the
helper or leaves the workload trapped by the helper policy is nonconforming.
D2 intentionally does not choose a live composition mechanism. D4 owns that
choice and its kernel proof; D6 owns whole-VM fallback. No metadata or fake
policy result can substitute for that proof.

Every installed filter MUST validate `AUDIT_ARCH_X86_64`, reject the x32
syscall bit, and compare native amd64 syscall numbers. There is no audit-only,
trace, log, or permissive production mode.

## Descriptor roles

Descriptor authority is fixed. Closing a fixed descriptor does not authorize
reusing its number for another object in the same role.

| FD | Bootstrap and steady helper role | Child role |
|---:|---|---|
| 0-2 | No authority. They may be closed or image-owned inert sinks, but are never accepted as a root, protocol, process, namespace, or mount FD. | Exact inspected stdin-read, stdout-write, and stderr-write pipes after remap. |
| 3 | Connected unnamed `AF_UNIX/SOCK_SEQPACKET` helper control endpoint with `SO_PASSCRED=1`. | Closed before keeper wait or workload gate release. |
| 4 | Credential-root `O_PATH|O_DIRECTORY` FD. | Closed before keeper wait or workload gate release. |
| 5 | Delegated cgroup-v2 root `O_PATH|O_DIRECTORY` FD. | Closed before keeper wait or workload gate release. |
| 6 | Minimal-root `O_PATH|O_DIRECTORY` FD. | Read-only resolution authority during transition, then closed before `execveat`. |
| 7 | Sealed, read-only bootstrap config; permanently closed at bootstrap commit. | Never inherited. |
| 8 | Exact active job mount-namespace FD, or closed when no job exists. | The same namespace FD until successful `setns`, then closed. |
| 9 | Exact active job cgroup directory FD, or closed when no job exists. | Used only as the validated `clone3.cgroup` source in the parent; never inherited by the workload. |
| 10 | Exact keeper pidfd, or closed when no job exists. | Never inherited. |
| 11 | Exact current child start-gate endpoint, or closed. | Start-gate read endpoint; after the gate is consumed and closed, the already inspected executable may be moved to 11 for `execveat(11, "", ..., AT_EMPTY_PATH)`. An interpreter script uses the frozen L4 child-only inherited-descriptor exception. |

Transient helper FDs are 12 through 255, consistent with the frozen maximum of
256 helper-owned descriptors. A newly returned lower-numbered FD MUST be moved
with `dup3(..., O_CLOEXEC)` into an unused transient slot and the original
closed before it can enter helper state. Each transient slot has one recorded
kind and generation: regular file, directory, pipe end, pidfd, mount FD,
filesystem-context FD, or connected/listening Unix socket. It is revalidated
after creation or receipt and immediately before every authority-bearing use.
FDs 8 through 11 are populated only by a validated transient FD and are cleared
on rollback. No fixed or transient helper FD except 0, 1, 2, and the frozen L4
interpreter-script executable descriptor survives workload exec.

## Allowed syscall families

### Bootstrap only

Bootstrap permits only the following operations in addition to the common
runtime family below:

- `getsockopt(3, SOL_SOCKET, SO_TYPE|SO_DOMAIN|SO_PROTOCOL|SO_PASSCRED, ...)`
  and `setsockopt(3, SOL_SOCKET, SO_PASSCRED, one)`; all returned values are
  checked against the fixed seqpacket role;
- `fcntl(3..7, F_GETFD|F_SETFD|F_GETFL|F_DUPFD_CLOEXEC, ...)`, where `F_SETFD`
  may only add `FD_CLOEXEC`, and `dup3`/`close_range` only establish the table
  above and remove unrelated FDs;
- `getuid`, `geteuid`, `getgid`, and `getegid` only to verify the expected
  bootstrap identity, `prlimit64` only to read and confirm `RLIMIT_CORE=0`, and
  `capget`/`capset` only to verify and establish the exact five-capability
  helper set described below;
- `prctl` only for `PR_SET_DUMPABLE=0`, exact locked securebits,
  `PR_SET_NO_NEW_PRIVS=1`, `PR_CAPBSET_READ`, and read-back of those
  properties;
- `fchdir(6)`, one `pivot_root` using the fixed minimal-root staging names,
  `chdir("/")`, one normal `umount2` of the fixed old-root staging mount with
  flags zero, and exact `unlinkat(..., AT_REMOVEDIR)` removal of that empty
  staging directory;
- `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, program)` once
  to commit the steady policy; and
- `sendmsg(3, ...)` for the canonical sequence-zero `helper_ready` only.

The path pointers used by `pivot_root`, `chdir`, and `umount2` are fixed image
constants, never protocol/config values. Bootstrap closes FD 7 and every
unrelated descriptor before readiness. Any bootstrap failure exits; it cannot
continue with a partial root, capability set, descriptor table, or filter.

After the steady filter commits, `pivot_root`, `chdir`, bootstrap `setsockopt`,
`capget`, and any seccomp filter replacement are forbidden.

### Common bounded runtime

The common runtime family is exact:

```text
read write readv writev close close_range dup3 fcntl lseek
fstat statx fstatfs getdents64
mmap mprotect munmap madvise brk mlock munlock
clock_gettime clock_nanosleep ppoll
futex sched_yield
rt_sigaction rt_sigprocmask rt_sigreturn sigaltstack
getpid gettid getrandom
exit exit_group
```

These calls are for helper-owned memory, clocks, signals, and recorded FDs only.
The following restrictions apply:

- `mmap` is anonymous/private data or a read-only sealed image mapping; it may
  never create an executable writable mapping. `mprotect` cannot add execute
  permission and cannot make credential memory readable after wipe.
- `madvise` is limited to `MADV_DONTDUMP`, `MADV_DONTFORK`,
  `MADV_WIPEONFORK`, `MADV_DONTNEED` on pinned-runtime noncredential pages or
  post-wipe helper mappings, and `MADV_NOHUGEPAGE` on pinned-runtime
  noncredential pages. `MADV_FREE`, `MADV_HUGEPAGE`, and `MADV_COLLAPSE` are
  forbidden.
- `mlock`/`munlock` apply only to bounded helper-owned mutable mappings. Full
  capacity is overwritten before `munlock`/`munmap`.
- `getrandom` accepts only a bounded mutable destination and flags zero; it may
  create nonces or safe opaque IDs, never replace authenticated generations.
- `clock_gettime` uses only `CLOCK_MONOTONIC`, `CLOCK_BOOTTIME`, or
  `CLOCK_REALTIME`. Sleeps use an absolute monotonic deadline and cannot extend
  the 35-minute activation or 30-second cleanup limits.
- `ppoll` watches only recorded control, pipe, pidfd, cgroup-event, and Unix
  relay FDs with a bounded timeout. Signal-mask and timespec pointers are
  helper-owned.
- `fcntl` is limited to `F_GETFD`, `F_SETFD` adding `FD_CLOEXEC`, `F_GETFL`,
  `F_SETFL` changing only `O_NONBLOCK`, and `F_DUPFD_CLOEXEC` into 12..255.
  The sole clearing exception is child FD 11 for an already detected and
  pinned L4 interpreter script immediately before `execveat`.
- `statx` is limited to `AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW` reinspection of a
  recorded FD; it is not a pathname lookup. `fstatfs` and `getdents64` apply
  only to a recorded mount, cgroup, or directory FD.
- `close_range` may only close a validated inclusive range; it never uses
  `CLOSE_RANGE_UNSHARE` or `CLOSE_RANGE_CLOEXEC` as proof that an individual
  authority was closed.
- signal disposition calls may install only the construction-time fixed
  handlers. The policy does not allow `kill` or `tkill`; `tgkill` has only the
  pinned Go-runtime exception below.

An implementation whose language runtime needs another syscall does not gain
an implied exception. It must remove that dependency or amend this D2 contract
before D4 can claim conformance.

### Pinned Go 1.25.7 runtime envelope

The production helper entrypoint is the repository's exact static
`CGO_ENABLED=0` Go 1.25.7 build, not a generic language runtime. PID1 supplies
the sealed runtime settings `GOMAXPROCS=1` and
`GODEBUG=madvdontneed=1,disablethp=1`; the helper confirms them before
readiness and never inherits caller-controlled Go settings. The steady filter
adds only these runtime calls:

```text
clone arch_prctl tgkill
```

`clone` is only a same-process runtime thread with exactly
`CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_SYSVSEM|CLONE_THREAD` plus
optional `CLONE_SETTLS`; its exit signal, parent-TID pointer, child-TID pointer,
and every namespace/privilege flag are zero. The stack and optional TLS pointer
must fall within the pinned runtime's own noncredential mappings. It cannot
create a process, namespace, pidfd, cgroup placement, or different file table.
`arch_prctl` is only `ARCH_SET_FS` to that runtime-owned TLS pointer.
`tgkill` embeds the already inspected helper TGID in the filter, targets a
thread in that same thread group, and permits only `SIGURG` for Go asynchronous
preemption. Profiling, cgo, plugins, `os/signal`, generic network polling, and
runtime-created application sockets are absent from the helper build.

Bootstrap may additionally use `sched_getaffinity(0, boundedMaskBytes, ...)`
and `mincore` only while the pinned Go runtime initializes, before capability,
root, descriptor, and filter commit. The committed steady policy forbids both.
D4's safe normalized strace fixtures must prove this exact runtime envelope at
the locked toolchain and binary digest; a toolchain or runtime-dependency change
is a contract change, never an automatically learned syscall.

### Authenticated helper IPC

The steady helper may use:

```text
recvmsg sendmsg getsockopt
```

Ordinary `recvmsg` and `sendmsg` are only on FD 3. Receive flags are exactly
`MSG_CMSG_CLOEXEC` plus optional `MSG_DONTWAIT`; send flags are zero or
`MSG_NOSIGNAL`. The helper allocates the fixed bounded control and ancillary
buffers before the call. It rejects truncation and reinspects the complete
`msghdr`, one kernel credentials record, rights cardinality, and every received
FD as required by the architecture. `getsockopt` is limited to read-only
reinspection of FD 3's fixed socket properties and accepted Unix peers.

`sendto`, `recvfrom`, `sendmmsg`, `recvmmsg`, and generic `ioctl` are not
substitutes.

### Descriptor-relative filesystem and cgroup operations

The steady helper may use:

```text
openat2 mkdirat unlinkat renameat2
fchmod fchown ftruncate fsync fdatasync
```

`open`, `openat`, and `creat` are never permitted. `openat2` begins only at FD
4, 5, 6, 9, or an already revalidated descendant directory. Every request uses
an exact-size `open_how`, `O_CLOEXEC`, the minimum access needed, and:

```text
RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV
```

`O_CREAT` additionally requires `O_EXCL|O_NOFOLLOW`; credential files are
regular, mode 0600, single-link, fixed UID/GID 1000. Cgroup control files are
opened only beneath FD 9 with their fixed names and expected cgroup-v2
filesystem identity. `mkdirat`, `unlinkat`, and `renameat2` operate only beneath
the credential or delegated cgroup root on a canonical helper-generated safe
generation/component name. `unlinkat` uses zero or `AT_REMOVEDIR` as required;
`renameat2` uses `RENAME_NOREPLACE` for publication. There is no exchange,
whiteout, caller-selected overwrite, hard link, symlink, node, FIFO, or device
creation.

Writes are permitted only to an inspected staging regular file, child pipe,
`cgroup.kill`, or another closed-catalog cgroup control file needed for the
already specified owned leaf. The cgroup kill body is exactly `1`. Reads of
`cgroup.events` are bounded and accept cleanup proof only after parsing the
exact `populated 0` record. `fsync`/`fdatasync`, ownership, mode, size, inode,
link count, mount ID, and filesystem type are reinspected at the architecture's
publication and cleanup boundaries.

### FD-oriented mount and namespace operations

The steady helper may use:

```text
fsopen fsconfig fsmount open_tree move_mount mount_setattr
umount2
```

The only filesystem created is `tmpfs`. `fsopen` uses `FSOPEN_CLOEXEC`;
`fsconfig` accepts only the helper constants `size=4194304`,
`nr_inodes=65536`,
and `mode=0700`, followed once by `FSCONFIG_CMD_CREATE`. The resulting mount is
made by `fsmount(..., FSMOUNT_CLOEXEC, 0)`. `open_tree` uses only
`OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC`; `move_mount` uses only empty-path
FD-to-FD movement with
`MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH`; and `mount_setattr` uses
`AT_EMPTY_PATH`, the kernel ABI size, zero user/group mappings, and only
`MOUNT_ATTR_NODEV|MOUNT_ATTR_NOSUID|MOUNT_ATTR_NOEXEC` plus private
propagation.
The mount ceiling covers bounded directory/inode overhead for the existing
4096-byte, 16-binding path grammar; it does not raise the frozen 64 KiB per-file
or 1 MiB aggregate credential-byte limits.
No caller supplies filesystem type, option name/value, target, propagation, or
mount flags.

The steady helper never enters a job namespace; only the gated workload child
may call `setns(8, CLONE_NEWNS)`. `umount2` is a normal unmount with flags zero
of the one helper-generated job mountpoint after mount identity reinspection.
`MNT_DETACH`, recursive mount attributes, shared/slave propagation, bind mounts
from caller paths, classic `mount`, and arbitrary namespace entry are
forbidden. Normal unmount failure follows the bounded retry/stop-VM contract;
it is never converted to success by a lazy unmount.

### Process creation, supervision, and cleanup

The steady helper may use:

```text
clone3 pipe2 socketpair setsockopt ioctl pidfd_send_signal waitid
```

There are only two canonical `clone3` templates:

- keeper: `CLONE_NEWNS|CLONE_PIDFD`, `exit_signal=SIGCHLD`, no sharing flags,
  no user/network/UTS/IPC/time namespace, no TID/TLS pointers, and no cgroup FD;
- workload: `CLONE_INTO_CGROUP|CLONE_PIDFD`, `exit_signal=SIGCHLD`,
  `cgroup=9`, and every other optional field/flag zero.

The `clone_args` size is the one D4 compile-time kernel ABI size. Unknown tail
bytes and kernel ABI fallback sizes are rejected. There is no `fork`, `vfork`,
`clone`, spawn-then-write-`cgroup.procs`, or caller-selected clone flag.

The keeper namespace FD handoff is the only `socketpair` rule. Immediately
before keeper clone, the helper creates
`socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0)`, applies only
`setsockopt(endpoint, SOL_SOCKET, SO_PASSCRED, one)` to both transient
endpoints, and records the pair for that pending keeper
generation. In the new `CLONE_NEWNS` child, the keeper uses exact-constant
`openat2(6, "proc/self/ns/mnt", ...)` solely to acquire its own mount namespace
pseudo-file. This one lookup permits the required procfs crossing/magic link;
it is not a credential/cgroup/file lookup and no protocol value can influence
it. The keeper sends exactly that one FD with its kernel credentials, then
closes its handoff endpoint. The parent requires the exact keeper PID/UID/GID,
one FD, no truncation, and the expected generation, moves the reinspected FD to
8, closes both handoff endpoints, proves `NSFS_MAGIC` with `fstatfs`, and calls
only `ioctl(8, NS_GET_NSTYPE)` with no third argument to require
`CLONE_NEWNS` before recording it. Any discrepancy kills/reaps the
keeper and rolls back. No internal socketpair survives preparation.

`pipe2` uses `O_CLOEXEC` plus optional `O_NONBLOCK`; the returned pair is
immediately type/direction inspected. `pidfd_send_signal` targets FD 10 or a
recorded current workload pidfd, uses signal zero for liveness or `SIGKILL` for
termination, `siginfo=NULL`, and flags zero. `waitid` uses `P_PIDFD` and that
same recorded pidfd with `WEXITED`, optionally `WNOHANG` during bounded polling;
the final reap omits `WNOWAIT`. PID numbers, process groups, and ambient `/proc`
lookups are not process authority.

Direct pidfd kill is a bounded launch/leader fast path, not descendant absence
proof. Credential revoke always writes `1` to the exact `cgroup.kill`, observes
`populated 0`, then reaps each recorded leader and the keeper in the required
order. `setsid` and `setpgid` descendants remain covered by cgroup kill.

### Unix SSH relay extension

Only a D5-enabled helper build may add:

```text
socket bind listen accept4 connect shutdown
```

`socket` is exactly `AF_UNIX`, `SOCK_STREAM|SOCK_CLOEXEC` with optional
`SOCK_NONBLOCK`, protocol zero. `accept4` adds `SOCK_CLOEXEC` and optional
`SOCK_NONBLOCK`. `bind`/`connect` use only the helper-owned job relay address
under the fixed credential root; abstract names, unnamed caller sockets, and
any network or vsock family are rejected. The pointer is copied and validated
before the syscall, and the resulting local/peer identity, type, connected
state, ownership, and generation are reinspected. `listen` backlog is 1 through
4, matching the frozen relay concurrency. `shutdown` is `SHUT_RD`, `SHUT_WR`,
or `SHUT_RDWR` on a recorded relay FD only.

D2 owns the policy rule and fake decisions. D5 owns all live creation,
descriptor passing, peer validation, and pumping. D4 alone MUST NOT enable this
extension.

## Child transition policy

A keeper child may call only the common runtime subset needed to close FDs,
the exact namespace-FD `openat2`/`sendmsg` handoff above, identity/capability
drop calls, bounded `ppoll`, and exit. It first sends its private mount
namespace FD, closes the handoff endpoint, drops supplementary groups and every
capability, retains fixed UID/GID 0 with locked `SECBIT_NOROOT` and no
supplementary groups, sets
`PR_SET_DUMPABLE=0` and `PR_SET_NO_NEW_PRIVS=1`, and then waits without a
protocol, mount, cgroup, socket, or filesystem mutation capability. The keeper
never launches a workload.

A workload child transition may call only:

```text
read close close_range dup3 fcntl fchdir
setns setgroups setresgid setresuid capset prctl
seccomp execveat exit exit_group rt_sigreturn
```

The exact sequence is:

1. close FD 3, 4, 5, 6, 7, 9, 10 and every unrelated transient FD;
2. `setns(8, CLONE_NEWNS)`, then close FD 8;
3. remap the three already inspected pipes to 0, 1, and 2;
4. `fchdir` to the already opened/reinspected work-directory FD and close it;
5. consume the one-byte start gate only after the helper committed the private
   binding, then close the gate;
6. `setgroups(0, NULL)`, `setresgid(1000,1000,1000)`, and
   `setresuid(1000,1000,1000)`;
7. drop each of the five remaining bounding bits with `PR_CAPBSET_DROP`, clear
   ambient state with `PR_CAP_AMBIENT_CLEAR_ALL`, clear permitted/effective/
   inheritable state with `capset`, lock the same securebits, set
   `PR_SET_DUMPABLE=0`, and set `PR_SET_NO_NEW_PRIVS=1`;
8. apply the existing workload seccomp policy; and
9. move the already pinned and reinspected executable to FD 11 and call
   `execveat(11, "", argv, envp, AT_EMPTY_PATH)`. FD 11 remains close-on-exec
   for a native executable. For an already detected and pinned interpreter
   script only, the child clears `FD_CLOEXEC` immediately before `execveat` so
   the kernel interpreter handoff can use the same inode, exactly preserving
   the frozen L4 child-only descriptor behavior.

The child does not use pathname `execve`, ambient `PATH`, `chdir`, or a
request-derived `open*`/`/proc/self/fd` lookup. The keeper namespace constant
and frozen L4 kernel interpreter handoff are the only exceptions. `argv` and
`envp` are constructed solely from the
validated bounded `ExecPlan` plus authenticated prepared bindings; their
pointers are not seccomp-inspectable. Failure at any step closes pipes and the
gate and exits without a second launch attempt. The parent kills/reaps the
recorded pidfd and continues cgroup cleanup.

The final workload policy is not broadened here. It MUST retain the existing
L4 execution semantics and L7 network confinement and MUST deny at least the
forbidden process-inspection and privilege syscalls below. A child may not
install `SECCOMP_FILTER_FLAG_NEW_LISTENER`, `TSYNC`, `LOG`, or a permissive
filter.

## Capability and identity invariants

At helper entry and after bootstrap, the bounding, permitted, and effective
sets are exactly:

```text
CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_CHOWN
```

The inheritable and ambient sets are empty. The helper locks
`SECBIT_NOROOT`, `SECBIT_NO_SETUID_FIXUP`, and
`SECBIT_NO_CAP_AMBIENT_RAISE`, including each corresponding locked bit. It is
non-dumpable and cannot gain any capability outside the five-bit bounding set.
No file capability, setuid/setgid binary, user namespace, keyring, or ambient
raise can restore authority.

The service agent remains UID/GID 998 with empty capabilities. The workload is
UID/GID 1000, has no supplementary groups, has all five capability sets empty,
and has `no_new_privs` before exec. The keeper has no protocol/control FD and
no capability after namespace creation. Any mismatch blocks readiness or gate
release; it is never downgraded to a warning.

## Forbidden syscall catalog

The following are always forbidden to the bootstrap/steady helper except for
the single exact bootstrap or child rule above, and forbidden to workload
children where applicable:

- arbitrary path and mutation: `open`, `openat`, `creat`, `mount`, `chroot`,
  `name_to_handle_at`, `open_by_handle_at`, `link`, `linkat`, `symlink`,
  `symlinkat`, `mknod`, `mknodat`, `mkfifo`, and `pivot_root` after bootstrap;
- arbitrary namespace or privilege: `unshare`, arbitrary `setns`,
  `setuid`, `setgid`, `setreuid`, `setregid`, `setfsuid`, `setfsgid`,
  `personality`, `uselib`, and seccomp listener creation;
- device, kernel, or key authority: every `ioctl` except exact
  `ioctl(8, NS_GET_NSTYPE)`, `iopl`, `ioperm`, `kexec_load`,
  `kexec_file_load`, `init_module`, `finit_module`, `delete_module`,
  `reboot`, `swapon`, `swapoff`, `quotactl`, `syslog`, `acct`,
  `add_key`, `request_key`, and `keyctl`;
- process inspection or cross-process memory: `ptrace`, `process_vm_readv`,
  `process_vm_writev`, `pidfd_getfd`, `kcmp`, `perf_event_open`, `bpf`,
  `userfaultfd`, and `membarrier` registration;
- uncontrolled process/signal authority: `fork`, `vfork`, every `clone` and
  `tgkill` outside the pinned Go-runtime envelope, `kill`, `tkill`, and
  caller-selected `clone3`;
- network/vsock authority: every `socket` family except the exact D5 `AF_UNIX`
  rule, plus `socketpair`, `accept`, `sendto`, `recvfrom`, `sendmmsg`,
  `recvmmsg`, and `setsockopt` after bootstrap, except the exact temporary
  keeper handoff above; and
- asynchronous or opaque kernel execution: `io_uring_setup`,
  `io_uring_enter`, `io_uring_register`, `fanotify_init`, `inotify_init`,
  `inotify_init1`, `epoll_create`, `epoll_create1`, and `restart_syscall`.

Unknown syscalls are forbidden even when a newer kernel implements them. There
is no `ENOSYS` compatibility fallback to an older, broader syscall.

## Pointer arguments and reinspection

Classic seccomp BPF can inspect syscall numbers and scalar argument words; it
cannot safely dereference pointers. Therefore the filter alone does not prove
any pathname, `open_how`, `clone_args`, `msghdr`/control message, `sockaddr`,
mount option, `timespec`, capability data, seccomp program, argv, envp, or
mutable I/O buffer restriction in this document.

D4 MUST put each pointer-bearing call behind the sole syscall adapter for that
operation. Before the syscall, the adapter copies variable input into bounded
helper-owned memory, validates the closed union and every reserved byte, and
prevents concurrent mutation. After success it reinspects the returned kernel
object before recording authority:

- files/directories: type, mode, UID/GID, link count, device/inode, mount ID,
  filesystem type, access mode, and containment beneath the fixed dirfd;
- pipes: pipe type and exact read/write direction;
- pidfds: pidfd type, expected generation/liveness, poll state, and signal-zero
  result;
- namespaces/mounts: namespace type, mount ID, parent/root relation, tmpfs
  type, exact attributes, propagation, and generation;
- cgroups: cgroup-v2 filesystem, delegated-root descent, exact leaf identity,
  and `populated` observation;
- sockets: domain, type, protocol, local/peer identity, connected/listening
  state, ownership, and generation; and
- ancillary messages: truncation flags, exactly one credentials record,
  exact rights count, and every received FD kind.

Failure to reinspect is a failed operation, not an unsupported optimization.
The object is closed, unpublished staging is rolled back, mutable buffers are
wiped, and cleanup proceeds. Tests and documentation MUST distinguish scalar
checks enforced by seccomp from pointer and provenance checks enforced by the
adapter; neither may be reported as the other.

## Denial actions

The generated decision is exact:

- architecture mismatch, x32 syscall encoding, a syscall in the forbidden
  privilege/process-inspection/kernel-authority catalog, forbidden socket
  family, arbitrary namespace entry, or impossible role transition returns
  `SECCOMP_RET_KILL_PROCESS`;
- a known but unlisted ordinary syscall, a listed syscall in the wrong role,
  or a scalar flag/command/FD outside its closed rule returns
  `SECCOMP_RET_ERRNO | EPERM` before any state change; and
- only an exact matching rule returns `SECCOMP_RET_ALLOW`.

The filter never returns `TRACE`, `TRAP`, `LOG`, `USER_NOTIF`, or unconditional
allow. An actual helper `KILL_PROCESS` outcome is permanent helper loss. The
agent invalidates readiness and active proofs; the guest cannot claim local
cleanup complete. D6 stops/reaps the exact microVM and inspects host-owned
absence.

## Kill, reap, and cleanup convergence

Before child gate release, any authentication, descriptor, private-binding,
policy, or setup failure closes the gate and pipes, wipes buffers, kills/reaps
the recorded child pidfd if necessary, and rolls back unpublished state.

After gate release, cancel, timeout, protocol/session/helper loss, malformed
stream, output failure, expiry, or revoke denies new exec and converges through
the exact job cgroup:

1. write exactly `1` to `cgroup.kill` beneath fixed FD 9;
2. poll and parse bounded `cgroup.events` until exact `populated 0`;
3. reap all recorded workload leaders with `waitid(P_PIDFD, ...)`;
4. close child pipes, pidfds, files, private buffers, and namespace references;
5. normally unmount and prove mount/file absence;
6. signal/reap the keeper through FD 10; and
7. remove and reinspect the owned generation directory and cgroup.

There are at most three idempotent attempts inside one 30-second total
deadline. A retry begins with reinspection and never recreates a resource.
Process-group signals, leader pidfd death, descriptor closure, and helper exit
are not descendant-absence proof. Missing cgroup kill/inspection, unknown
ownership, nonzero population, normal-unmount failure, keeper-reap failure,
helper death, or policy-kill yields `stop_vm_required`. Only D6's exact
Firecracker stop/reap plus host absence inspection can then produce the root
cleanup proof.

## Required D2 and D4 tests

D2 owns pure policy data, validators, decision tables, fake syscall adapters,
and fixtures. Its default tests MUST be Linux-independent and perform no live
syscall. They include:

- one positive decision for every role/syscall rule and every exact allowed
  flag/command/FD variant;
- table-driven “plus one” negatives changing one dimension at a time: syscall
  number, architecture/x32 bit, role, fixed FD, transient kind/generation,
  flag bit, enum, clone field, mount command, socket family/type, signal,
  wait option, path class, bounds, reserved byte, or sequence;
- pointer-blindness tests proving the seccomp decision does not claim to inspect
  pointed-to data and the fake adapter independently rejects mutated
  `open_how`, `clone_args`, paths, ancillary data, mount options, sockaddr,
  argv/env, and object reinspection;
- capability/securebits/UID/GID and fixed-FD transition matrices;
- partial prepare, child-before-gate, pidfd loss, `setsid` descendant,
  cgroup-kill, nonzero population, unmount, keeper-reap, three-attempt/deadline,
  and `stop_vm_required` state-machine tests; and
- compiler golden tests proving exact `ALLOW`, `ERRNO(EPERM)`, and
  `KILL_PROCESS` decisions, amd64 arch check, x32 rejection, no permissive
  action, and stable syscall-name/number mapping.

D4 owns the Linux implementation and adds:

- subprocess probes for every `KILL_PROCESS` class and representative
  `ERRNO(EPERM)` classes, asserting the process disposition and absence of a
  performed side effect;
- positive kernel tests for fixed-FD bootstrap, filesystem/mount/cgroup,
  canonical keeper/workload `clone3`, child identity/capability drop, and
  kill/reap ordering through injected syscall fakes before any prepared-host
  test;
- one normalized, committed strace fixture for each bootstrap, prepare,
  exec-success, exec-failure, revoke, and cleanup path. The fixture contains
  syscall names and safe scalar categories only—never paths, payloads,
  arguments, environment values, nonces, socket names, or credentials. The set
  difference `observed - policy` and `policy-required - observed` MUST both be
  empty, except explicitly enumerated state-dependent alternatives already in
  the D2 table; and
- a role-composition regression proving the helper cannot create network/vsock
  sockets or use workload authority, the workload is not accidentally confined
  to helper-only syscalls, and no privileged/unfiltered launcher survives.

Strace is test evidence, not an allowlist generator. An observed extra syscall
fails the test; it is never automatically added. Kernel tests remain behind an
explicit D4 integration tag and prepared prerequisite checks. A skip cannot
become selected live evidence.

## Ownership and non-goals

D2 owns this immutable policy vocabulary, exact tables, fake decisions,
pointer/provenance validators, test fixtures, and source/import guards. D4 owns
the live PID1/helper/agent role composition, filter compilation and
installation, direct syscalls, namespaces, tmpfs, cgroups, workload launch,
and guest cleanup retries. D5 owns live SSH Unix sockets and relay I/O under the
optional extension. D6 owns helper-loss and whole-VM stop/reap composition.

This closure does not add a helper binary, syscall wrapper, BPF program,
listener, mount, namespace, cgroup, process, command wiring, guest image, live
test, capability claim, active proof, or cleanup proof. It does not alter v1,
the D2 packet/exec codecs, L4 workload behavior, L7 network enforcement, or the
existing D2/D4/D5/D6 ownership split.
