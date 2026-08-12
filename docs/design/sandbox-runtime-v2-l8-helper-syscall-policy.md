# Sandbox Runtime v2 L8 Helper Syscall Policy

## Authority and scope

This document closes the D2 syscall-policy architecture left open by
`sandbox-runtime-v2-l8-production-credential-delivery-architecture.md`. That
architecture remains authoritative for protocol, identity, resource, mount,
cgroup, execution, and cleanup semantics. This file narrows those semantics
into one normative Linux amd64 helper policy; it does not expand them.
In particular, the architecture's normative HL8M controller-monitor ABI is the
sole authority for monitor packet bodies, sequences, credentials, rights,
ownership transfer, state/correlation decisions, and digest domains.

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.
The policy applies to the single-threaded native `hal-guest-role-bootstrap`,
L8 PID1 launch supervisor, unprivileged service agent,
`hal-guest-credential-helper` controller, per-job
`hal-guest-mount-monitor`, and one-shot `hal-guest-workload-shim`. It does not
replace the frozen L4 workload execution contract or the L7 workload network
policy.

D2 adds no live implementation. In particular, it does not mount, create a
cgroup, launch a process, open a socket, install seccomp, or change a production
command. A platform other than Linux amd64 is unsupported and fails before
helper readiness.

## Closed policy model

The policy is deny-by-default. A syscall is permitted only when its role,
syscall name, scalar arguments, descriptor role, object provenance, and current
state match a rule below. A syscall name appearing in a family is not a general
allow: all stated restrictions remain mandatory.

The roles are `launch-bootstrap`, `launch-base`, `controller-bootstrap`,
`steady-controller`, `agent-bootstrap`, `steady-agent`, `monitor-bootstrap`, `steady-monitor`,
`workload-transition`, and the existing L4/L7 `workload`. Transitions are
one-way:

```text
PID1 launch-bootstrap -> launch-base
PID1 launch-base -> controller-bootstrap -> steady-controller
PID1 launch-base -> agent-bootstrap      -> steady-agent
PID1 launch-base -> monitor-bootstrap    -> steady-monitor
PID1 launch-base -> workload-transition -> workload -> execveat
```

Linux seccomp filters are inherited and cannot be relaxed. The native role
bootstrap establishes each role's per-thread capability/identity state before
any Go runtime starts. PID1 then installs the reviewed `launch-base` ancestor
filter, whose allow set is the union mechanically required by its four
image-pinned descendants. Native child modes do not install another filter:
the native bootstrap commits role state, not a child role filter. Each Go child
stacks its narrower role filter before protocol input. The steady controller never launches a
process, and neither does the steady agent; monitors and workload shims are
direct PID1 children and never inherit either steady service filter. A monitor
cannot clone or exec. A workload shim cannot
return to PID1 or a service role and stacks the existing L4/L7 workload policy
before its final exec.

PID1 is the one explicit launch TCB. Its private authenticated protocol accepts
only create-job, launch-shim, terminate-job, and destroy-job closed records plus
the exact inspected FD matrices below. It accepts no caller path, arbitrary
clone flag, argv, environment, or credential body. There is no unmediated or
general-purpose launcher. An ordinary helper-child inherited-filter design is
nonconforming; no metadata or fake policy result can substitute for the filter
ancestry above.

Every installed filter MUST validate `AUDIT_ARCH_X86_64`, reject the x32
syscall bit, and compare native amd64 syscall numbers. There is no audit-only,
trace, log, or permissive production mode.

## Descriptor roles

Descriptor authority is process-specific and fixed. Closing a fixed descriptor
does not authorize reusing its number for another object in that role.

| FD | PID1 launch supervisor | Controller | Service agent | Mount monitor | Workload shim |
|---:|---|---|---|---|---|
| 0-2 | Image-owned inert console/sinks. | Inert sinks. | Inert sinks. | Inert sinks. | Inspected stdin-read, stdout-write, stderr-write pipes after remap. |
| 3 | Controller supervisor endpoint. | Agent control endpoint. | Controller control endpoint. | Controller-monitor endpoint. | Native-only monitor namespace FD, closed before Go starts. |
| 4 | Delegated cgroup-v2 root. | PID1 supervisor endpoint. | Agent-supervisor seqpacket endpoint. | `verified_proc_root_fd`, revalidated procfs. | Reinspected workdir FD. |
| 5 | Pinned mount-monitor executable. | Minimal controller root. | Preopened v1 VSOCK listener, port 1024. | Fixed job mount-target `O_PATH|O_DIRECTORY`. | Pinned workload executable FD. |
| 6 | Pinned workload-shim executable. | Sealed bootstrap config, closed at commit. | Preopened v2 control VSOCK listener, port 1025. | Sealed monitor config, closed at commit. | Sealed controller-to-shim launch-block read FD; this is the complete shim config. |
| 7 | Verified proc root. | Agent pidfd after bootstrap. | Preopened v2 SSH-relay VSOCK listener, port 1026. | Self mount-namespace FD after exact lookup. | Supervisor start-gate read FD. |
| 8 | Fixed monitor mount-target root. | Active monitor endpoint or closed. | Closed. | Active tmpfs root or closed. | Closed. |
| 9 | Active job cgroup or closed. | Active monitor namespace or closed. | Closed. | Launch-only long-lived controller peer; sent once during readiness, then permanently closed. | Closed. |
| 10 | Active monitor pidfd or closed. | Closed. | Closed. | Launch-only PID1 bootstrap endpoint; one readiness send, then permanently closed. | Closed. |
| 11 | Closed; workload pidfds occupy recorded transient slots. | Closed. | Closed. | Closed. | Pinned executable after final remap for `execveat(11, "", ..., AT_EMPTY_PATH)`. |
| 12 | Preopened v1 VSOCK listener until agent transfer. | Closed. | Closed. | Closed. | Closed. |
| 13 | Preopened v2 control VSOCK listener until agent transfer. | Closed. | Closed. | Closed. | Closed. |
| 14 | Preopened v2 SSH-relay VSOCK listener until agent transfer. | Closed. | Closed. | Closed. | Closed. |
| 15 | Closed. | Closed. | Closed. | Closed. | Closed. |

Transient FDs are 16 through 255, consistent with the frozen maximum of 256
descriptors per role. A newly returned lower-numbered FD MUST be moved
with `dup3(..., O_CLOEXEC)` into an unused transient slot and the original
closed before it can enter helper state. Each transient slot has one recorded
kind and generation: regular file, directory, pipe end, pidfd, mount FD,
filesystem-context FD, connected/listening Unix socket, or connected/listening
VSOCK.
It is revalidated
after creation or receipt and immediately before every authority-bearing use.
Active fixed slots are populated only by a validated transient FD and are
cleared on rollback. No fixed or transient FD except 0, 1, 2, and the frozen L4
interpreter-script executable descriptor survives workload exec.

## Allowed syscall families

### PID1 launch bootstrap

`launch-bootstrap` is PID1 mode of the native role bootstrap. It runs before
any Go runtime, controller, agent, monitor, shim, or protocol input. Starting
from the image verifier's exact PID1 identity and protected L4/L7 base, its
closed native syscall loop may use fixed-descriptor operations plus `capget`,
`capset`, `prctl`, and the exact listener operations below only to:

1. drop every bounding capability outside the frozen six;
2. set permitted, effective, and inheritable sets to exactly those six;
3. raise exactly those same six ambient bits while the permitted/inheritable
   invariant holds;
4. set and lock `SECBIT_NOROOT` and `SECBIT_NO_CAP_AMBIENT_RAISE`, lock
   `SECBIT_KEEP_CAPS` and `SECBIT_NO_SETUID_FIXUP` off, set
   `PR_SET_DUMPABLE=0` and `PR_SET_NO_NEW_PRIVS=1`; and
5. create, bind, listen on, and reinspect exactly three nonblocking
   `AF_VSOCK/SOCK_STREAM|SOCK_CLOEXEC` listeners at CID any, fixed ports
   1024/1025/1026, fixed backlogs 64/1/4, and fixed PID1 FDs 12/13/14, then
   clear close-on-exec only for the immediate PID1 target handoff; and
6. read back every UID/GID, capability set, securebit, limit, listener property,
   and hardening property before stacking the exact `launch-base` filter and
   `execve`ing the fixed `hal-guest-init` target in the same PID.

Listener setup uses only native `socket`, `bind`, `listen`, `getsockopt`, and
`getsockname` with compiled structures and no caller input. The bootstrap never
connects, accepts, sends, or receives. A partial listener set is closed and boot
fails. After `launch-base` commits, no PID1 or child role can create or bind an
`AF_VSOCK` socket; only service-agent FDs 5, 6, and 7 can accept after the
agent's steady filter and composition commit.

After native commit and exec, `hal-guest-init` constructs and reinspects the
frozen descriptor table, anonymous seqpacket pairs, sealed config pipes,
workload gate pipes, delegated cgroup root, verified proc root, fixed mount
target, inherited VSOCK listeners, and image-profile-pinned executable identities
before readiness. Go PID1 immediately reinspects FDs 12..14 and restores
`FD_CLOEXEC` before any child launch. Only its exact agent `ForkExec` maps
copies to child FDs 5..7; the native agent retains them through its fixed second
exec and Go agent adds `FD_CLOEXEC` before admission. No credential body or
protocol/job-derived value exists at this point.
The bootstrap is one native thread and allocates no heap, starts no thread,
loads no dynamic object, and reads no external input. `hal-guest-init` starts
under the committed filter with every thread inheriting the same exact six
sets, verifies the state, and never changes a capability or securebit,
widens/replaces its filter, creates an unlisted FD kind, or returns to
`launch-bootstrap`. Failure exits the microVM before readiness.

### Controller bootstrap only

Controller mode of the native role bootstrap permits only the following
operations; after target exec the inherited `launch-base` admits the common Go
runtime family below only until Go main commits `steady-controller` before any
protocol read:

- `getsockopt(3..4, SOL_SOCKET, SO_TYPE|SO_DOMAIN|SO_PROTOCOL|SO_PASSCRED, ...)`
  and `setsockopt(3..4, SOL_SOCKET, SO_PASSCRED, one)`; all returned values are
  checked against the two fixed seqpacket roles;
- `fcntl(3..6, F_GETFD|F_SETFD|F_GETFL|F_DUPFD_CLOEXEC, ...)`, where `F_SETFD`
  may only add `FD_CLOEXEC`, and `dup3`/`close_range` only establish the table
  above and remove unrelated FDs;
- `getuid`, `geteuid`, `getgid`, and `getegid` only to verify the expected
  bootstrap identity, `prlimit64` only to read and confirm `RLIMIT_CORE=0`, and
  `capget`/`capset` only to verify the inherited six-bit launch sets and clear
  every controller permitted/effective/inheritable capability before readiness;
- `prctl` only for `PR_SET_DUMPABLE=0`, exact locked securebits,
  `PR_SET_NO_NEW_PRIVS=1`, `PR_CAPBSET_READ`, exact six-bit
  `PR_CAP_AMBIENT_LOWER`/`PR_CAP_AMBIENT_CLEAR_ALL`, exact bounding-set drops,
  and read-back of those
  properties;
- `fchdir(5)`, one `pivot_root` using the fixed minimal-root staging names,
  `chdir("/")`, one normal `umount2` of the fixed old-root staging mount with
  flags zero, and exact `unlinkat(..., AT_REMOVEDIR)` removal of that empty
  staging directory;
- one Go-main
  `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, steadyProgram)`
  before any receive/send; and
- only after that steady commit, `sendmsg(4, ...)` for the canonical controller
  attestation followed by `sendmsg(3, ...)` for sequence-zero `helper_ready`.

The path pointers used by `pivot_root`, `chdir`, and `umount2` are fixed image
constants, never protocol/config values. Native bootstrap reinspects and
retains sealed config FD 6 through target exec while closing every unrelated
descriptor and requiring FD 7 initially closed. The Go controller
reads/validates then closes FD 6 before readiness; only the later authenticated
PID1 bootstrap may install the received agent pidfd at FD 7. The native
bootstrap performs the pivot, drops all six bounding bits,
clears ambient then permitted/effective/inheritable sets, verifies every set is
empty, and execs the Go controller. Go verifies the empty state and only then
commits `steady-controller`. Any bootstrap failure exits; it cannot continue
with a partial root, capability set, descriptor table, or filter.

After `steady-controller` commits, `pivot_root`, `chdir`, bootstrap
`setsockopt`, `capget`, `capset`, and any seccomp filter replacement are
forbidden to the controller.

### Agent bootstrap only

Agent mode of the native role bootstrap begins as UID/GID 0 with the inherited
exact six-bit bounding/permitted/effective/inheritable/ambient sets. Its
`agent-bootstrap` state admits no external input; after target exec the inherited
`launch-base` admits the common Go runtime family only until Go main commits
`steady-agent`. Neither process can read a job request before authenticated
`composition_accepted`. The native bootstrap permits only:

- native fixed-FD/socket reinspection with no socket I/O, including exact
  listening VSOCK identity at FDs 5, 6, and 7; after Go commits the steady
  filter, FD 4 permits agent-config receive and direct PID1 attestation, while
  FD 3 permits property inspection only and no I/O before accepted;
- `setgroups(0, NULL)`, exact bounding-set drops for all six bits,
  `setresgid(998,998,998)`, and `setresuid(998,998,998)` in that order;
- `capget`/`capset` solely to verify the UID transition cleared
  permitted/effective/ambient sets and then clear the inherited set;
- `prctl` only for the inherited locked-securebits read-back,
  `PR_SET_DUMPABLE=0`, `PR_SET_NO_NEW_PRIVS=1`, capability-set read-back, and
  `PR_CAP_AMBIENT_CLEAR_ALL`; and
- fixed target `execve`; Go main then stacks `steady-agent` with TSYNC before
  the direct PID1 descriptor attestation.

`SECBIT_NO_SETUID_FIXUP` is unset and locked off, so the root-to-998 transition
performs the kernel's normal capability clearing. The native bootstrap verifies
UID/GID 998, no supplementary groups, empty bounding/permitted/effective/
inheritable/ambient sets and `no_new_privs` before exec. Go verifies the same
state, stacks the steady filter, and sends its descriptor directly to PID1 on
FD 4. The steady agent retains FDs 3 through 7 until authenticated
`composition_accepted`, then closes FD 4, performs the controller hello, and
begins accepting on exact listeners 5 through 7. It has no capability, process
clone, mount, cgroup, namespace, pathname exec, raw filesystem, socket creation,
bind, listen, connect, or arbitrary accept authority. Bootstrap failure exits
and forces PID1 whole-VM cleanup; it never releases admission.

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
- `ppoll` watches only recorded control, pipe, pidfd, cgroup-event, inherited
  VSOCK listener/accepted-stream, and Unix relay FDs with a bounded timeout.
  Signal-mask and timespec pointers are
  helper-owned.
- `fcntl` is limited to `F_GETFD`, `F_SETFD` adding `FD_CLOEXEC`, `F_GETFL`,
  `F_SETFL` changing only `O_NONBLOCK`, and `F_DUPFD_CLOEXEC` into 16..255.
  Native launch-bootstrap may clear `FD_CLOEXEC` only on verified listener FDs
  12..14 immediately before its one exec; Go PID1 restores it before creating a
  child. `ForkExec` maps only agent copies to 5..7 without close-on-exec for the
  two fixed role execs, and Go agent adds it before admission.
  The sole clearing exception is shim FD 11 for an already detected and
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

### Native role-bootstrap envelope

`hal-guest-role-bootstrap` is one freestanding static Linux-amd64 ELF `_start`
using reviewed raw syscall stubs. It has no libc, dynamic loader, Go runtime,
allocator, TLS, signal handler, thread creation, plugin, environment lookup,
network client, or filesystem search. Its union is limited to fixed-FD `read`,
`write`, `close`,
`close_range`, `dup3`, `fcntl`, `fstat`, `statx`, `fstatfs`, `getsockopt`,
`getsockname`, `getuid`, `geteuid`, `getgid`, `getegid`, read-only `prlimit64`, `capget`,
`capset`, exact `prctl`, exact
`setgroups`/`setresgid`/`setresuid`, controller-only `fchdir`/`pivot_root`/
`chdir`/`umount2`/`unlinkat`, shim-only `ioctl`/`setns`, PID1-only exact
`socket`/`bind`/`listen`, PID1-mode `seccomp`, exact target `execve`, and
`exit_group`. All pointers address fixed read-only image data or bounded
stack objects; the native source has no mutable global or general path/argv/env
parameter. PID1 mode is entered only as the immutable image init; child modes
are selected only by the supervisor adapter's closed enum. D2 fake decisions
and D4 normalized strace/golden disassembly must make the per-role subsets,
arguments, and instruction bytes exact.

### Pinned Go 1.25.7 runtime envelope

The five L8 production entrypoints are the repository's exact static
`CGO_ENABLED=0` Go 1.25.7 builds, not a generic language runtime. PID1 supplies
the sealed runtime settings `GOMAXPROCS=1` and
`GODEBUG=madvdontneed=1,disablethp=1,decoratemappings=0`; every process confirms
them before readiness or transition and never inherits caller-controlled Go
settings. Each role filter adds only these ordinary runtime calls:

```text
clone arch_prctl tgkill
```

This `clone` rule is only a same-process runtime thread with exactly
`CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_SYSVSEM|CLONE_THREAD` plus
optional `CLONE_SETTLS`; its exit signal, parent-TID pointer, child-TID pointer,
and every namespace/privilege flag are zero. The stack and optional TLS pointer
must fall within the pinned runtime's own noncredential mappings. It cannot
create a process, namespace, pidfd, cgroup placement, or different file table;
PID1 process start instead uses the separately matched exact service/monitor
`clone` and shim `clone3` templates.
`arch_prctl` is only `ARCH_SET_FS` to that runtime-owned TLS pointer.
`tgkill` embeds the already inspected helper TGID in the filter, targets a
thread in that same thread group, and permits only `SIGURG` for Go asynchronous
preemption. Profiling, cgo, plugins, `os/signal`, generic network polling, and
runtime-created application sockets are absent from the service binaries.

Bootstrap may additionally use `sched_getaffinity(0, boundedMaskBytes, ...)`
and `mincore` only while a pinned Go runtime initializes, before capability,
descriptor, and role-filter commit. The committed role policies forbid both.
`decoratemappings=0` is mandatory because the pinned runtime otherwise calls
`prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ...)`, which no steady role admits.
D4's safe normalized strace fixtures must prove this exact runtime envelope for
each locked binary digest; a toolchain or runtime-dependency change is a
contract change, never an automatically learned syscall.

### Authenticated local IPC

The service agent, controller, PID1 supervisor, and monitor may use:

```text
recvmsg sendmsg getsockopt
```

Agent-controller traffic is only agent FD 3/controller FD 3, agent-supervisor
traffic only agent FD 4/PID1's recorded boot endpoint, controller-supervisor
traffic only controller FD 4/PID1 FD 3, monitor bootstrap traffic only monitor
FD 10 to PID1's recorded transient bootstrap peer before readiness commit, and
steady direct monitor traffic only monitor FD 3/controller FD 8. PID1 FD 10
remains the monitor pidfd and is never a protocol endpoint; descriptor numbers
are role-local. The sole PID1 bootstrap relay is the normative HL8M exception:
the
monitor sends sequence-zero `monitor_ready` on FD 10 to the PID1-held recorded
transient bootstrap peer with exactly two rights ordered controller peer
endpoint then inspected mount namespace. PID1 authenticates and reinspects both, transfers those same two
rights in HL8L `job_created`, and closes its duplicates only after successful
atomic transfer. After the ready send the monitor permanently closes FDs 9 and
10, retaining direct FD 3 and namespace FD 7; PID1 closes its bootstrap peer
after relay or failure. Neither side reuses a closed bootstrap descriptor. PID1
neither forwards the ready body nor sends or receives a later HL8M packet. All
credential bodies then travel directly from controller-owned locked
buffers to the authenticated monitor FD 3. The controller begins the inherited
logical monitor receive sequence at one because PID1 consumed monitor sequence
zero on the separate bootstrap pair; its independent send sequence starts at
zero. Receive flags are exactly
`MSG_CMSG_CLOEXEC` plus optional `MSG_DONTWAIT`; send flags are zero or
`MSG_NOSIGNAL`. Each role allocates the fixed bounded control and ancillary
buffers before the call. It rejects truncation and reinspects the complete
`msghdr`, one kernel credentials record, rights cardinality, and every received
FD as required by the architecture. `getsockopt` is limited to read-only
reinspection of those fixed socket properties and accepted Unix peers.

`sendto`, `recvfrom`, `sendmmsg`, `recvmmsg`, and generic `ioctl` are not
substitutes.

### Preopened guest VSOCK acceptance

PID1 preopens the three fixed `AF_VSOCK` listeners in native
`launch-bootstrap`, passes them as service-agent FDs 5, 6, and 7, and closes
its FDs 12, 13, and 14 only after authenticated agent composition. The agent
revalidates `SO_DOMAIN=AF_VSOCK`, `SO_TYPE=SOCK_STREAM`, `SO_ACCEPTCONN=1`,
nonblocking/close-on-exec state, CID any, and exact port before admission.

After `steady-agent` and `composition_accepted`, `accept4` is permitted only on
FDs 5 through 7 with `SOCK_CLOEXEC|SOCK_NONBLOCK`. The returned transient FD
and exact kernel peer `SockaddrVM` are validated before any read: v2 requires
`VMADDR_CID_HOST`, while the listener's revalidated local port and sealed
generation supply the channel identity; v1 retains the existing port-1024 peer
behavior. Port 1025 admits one active control stream and port 1026 at
most four relay streams. Duplicate control, over-cap relay, wrong CID/port,
truncation, or listener replacement closes the accepted FD without protocol
decode. `shutdown` applies only to a recorded accepted VSOCK or D5 Unix relay
FD. Agent loss closes all three listeners and accepted streams; there is no
listener recreation in-place.

### Descriptor-relative monitor filesystem and PID1 cgroup operations

The steady monitor may use:

```text
openat2 mkdirat unlinkat renameat2
fchmod fchown fchownat ftruncate fsync fdatasync
```

PID1 `launch-base` may use only `openat2`, `mkdirat`, and
`unlinkat(..., AT_REMOVEDIR)` from that list, solely for the exact active
cgroup leaf beneath its revalidated delegated-root FD. It cannot use the
monitor's rename, ownership, mode, size, or durability operations.

`open`, `openat`, and `creat` are never permitted. Contained-path `openat2`
begins only at monitor FD 8 or an already revalidated descendant directory.
Every contained-path request uses an exact-size `open_how`, `O_CLOEXEC`, the
minimum access needed, and:

```text
RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV
```

The only exception is monitor bootstrap's namespace-self call:

```c
struct open_how how = {
    .flags = O_RDONLY | O_CLOEXEC,
    .mode = 0,
    .resolve = 0,
};
openat2(verified_proc_root_fd, "self/ns/mnt", &how, OPEN_HOW_SIZE_VER0);
```

`verified_proc_root_fd` is monitor FD 4, revalidated as procfs before this exact
compiled-constant lookup. `O_NOFOLLOW`, `RESOLVE_BENEATH`,
`RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS`, and `RESOLVE_NO_XDEV` are
forbidden for this exception because the namespace handle is a proc magic link.
The result is accepted only after exact monitor credentials/pidfd liveness,
`NSFS_MAGIC`, `NS_GET_NSTYPE == CLONE_NEWNS`, expected device/inode, and
inequality from PID1's namespace are proved. No other exception exists.

`O_CREAT` additionally requires `O_EXCL|O_NOFOLLOW`; every traversed credential
directory is root-owned mode 0711, and credential files are regular, mode 0600,
single-link, fixed UID/GID 1000. A D5 Unix socket entry is mode 0600 and fixed
UID/GID 1000 beneath those non-listable, non-writable directories. PID1 opens cgroup control
files only beneath its active FD 9 with fixed names and expected cgroup-v2
filesystem identity. `mkdirat`, `unlinkat`, and `renameat2` operate only beneath
the monitor credential root or PID1 delegated cgroup root on a canonical safe
generation/component name. `unlinkat` uses zero or `AT_REMOVEDIR` as required;
`renameat2` uses `RENAME_NOREPLACE` for publication. There is no exchange,
whiteout, caller-selected overwrite, hard link, symlink, node, FIFO, or device
creation.

The pinned Linux 6.1.178 guest kernel requires the D5 pathname socket mode to
be fixed at creation. After every required directory and regular-file creation
and immediately before the sole D5 bind, the monitor makes the one-way
`umask(0177)` transition. It never restores the process-wide umask, creates no
later directory, and permits no concurrent creator. The bind therefore creates
the pathname socket at exact mode 0600. The monitor reinspects the root-owned,
mode-0711 parent directory, sealed leaf name, socket FD, local address, mount,
device, and inode before calling
`fchownat(parentDirFD, sealedLeaf, 1000, 1000, AT_SYMLINK_NOFOLLOW)` with
ownership last. The non-writable parent and closed monitor state machine forbid
create, unlink, or rename from bind through the final same-mount/device/inode
reinspection. It sets mode 0600 before changing the D5 socket to fixed UID/GID 1000,
with ownership last. `fchownat` never receives an empty, absolute,
caller-selected, or multi-component path and never changes a directory owner
or mode.

Monitor writes are permitted only to an inspected staging regular file. Each
HL8M `prepare_file` decodes directly into one fixed 64-KiB locked receive slot;
the monitor authenticates metadata before exposure, writes through a borrowed
view, and overwrites the slot through full capacity before another packet or
any return path. No body-owning slice/string, second slot, generic formatter,
PID1 copy, or durable value exists. PID1
writes only `cgroup.kill` or another closed-catalog cgroup control file needed
for the already specified owned leaf. The cgroup kill body is exactly `1`. Reads of
`cgroup.events` are bounded and accept cleanup proof only after parsing the
exact `populated 0` record. `fsync`/`fdatasync`, ownership, mode, size, inode,
link count, mount ID, and filesystem type are reinspected at the architecture's
publication and cleanup boundaries.

### Monitor mount and namespace operations

Only the steady monitor may use:

```text
fsopen fsconfig fsmount open_tree move_mount mount_setattr umount2
```

The monitor is already executing in the job mount namespace created by PID1;
it never calls `setns`. The only filesystem created is `tmpfs`. `fsopen` uses
`FSOPEN_CLOEXEC`; `fsconfig` accepts only `size=4194304`, `nr_inodes=65536`, and
`mode=0711`, followed once by `FSCONFIG_CMD_CREATE`. The tmpfs root remains
root-owned and is searchable but neither listable nor writable by UID 1000. `fsmount` uses
`FSMOUNT_CLOEXEC`; `open_tree` uses `OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC`;
`move_mount` attaches only the inspected tmpfs object to monitor FD 5 in the
monitor's current namespace with the two empty-path flags; and `mount_setattr`
uses `AT_EMPTY_PATH`, the kernel ABI size, zero user/group mappings, and only
`MOUNT_ATTR_NODEV|MOUNT_ATTR_NOSUID|MOUNT_ATTR_NOEXEC` plus private
propagation. No caller supplies filesystem type, option, target, propagation,
or flags.

The monitor retains `CAP_SYS_ADMIN|CAP_CHOWN` through cleanup. `umount2` is a
normal flags-zero unmount of the one compiled fixed target after mount identity
reinspection. It then proves the target has no mounted tmpfs and calls
`exit_group`; it does not attempt a per-thread capability transition inside the
multi-threaded Go process. The controller and PID1 never attach or unmount that
target, and a namespace FD is never treated as a mountpoint FD. `MNT_DETACH`,
recursive attributes, shared/slave propagation, bind mounts from caller paths,
classic `mount`, and arbitrary namespace entry are forbidden. Normal unmount
failure follows bounded retry/stop-VM handling and is never converted to
success by lazy unmount.

### PID1 process creation, supervision, and cleanup

Only PID1's launch adapter may call pinned Go 1.25.7 `syscall.ForkExec`. Using
`os.StartProcess`, `os/exec`, or another wrapper is forbidden because its
implicit pidfd capability probe creates an extra unowned child. The boot-only
controller/agent service launch uses exact `clone` flags
`CLONE_VFORK|CLONE_VM|CLONE_PIDFD|SIGCHLD`, no namespace or cgroup flag, and the
pidfd pointer in the pinned amd64 argument position. The monitor uses exact `clone`
flags `CLONE_VFORK|CLONE_VM|CLONE_NEWNS|CLONE_PIDFD|SIGCHLD`, with the
pidfd pointer in the pinned amd64 argument position. The shim uses exact `clone3`
flags
`CLONE_VFORK|CLONE_VM|CLONE_PIDFD|CLONE_INTO_CGROUP`,
`exit_signal=SIGCHLD`, `cgroup=9`, and every other optional field zero. The
temporary `CLONE_VFORK|CLONE_VM` sharing is the pinned Go pre-exec mechanism;
the parent remains suspended until child exec/exit and no protocol goroutine or
mutable credential buffer is reachable from the child path.

The shim `clone_args` size is the pinned Go 1.25.7 toolchain ABI size. Unknown
tail bytes and fallback sizes are rejected. Zero `Cloneflags`, a non-nil
`PidFD`, and `UseCgroupFD=false` are mandatory for the boot-only controller and
agent starts. `Cloneflags=CLONE_NEWNS`, a non-nil
`PidFD`, and `UseCgroupFD=false` are mandatory for the monitor.
`UseCgroupFD=true`, exact `CgroupFD=9`, zero `Cloneflags`, and a non-nil `PidFD`
are mandatory for the shim. A returned pidfd below zero is failure before any
gate release. The launch adapter validates the exact `syscall.ForkExec` path as
the image-profile-pinned `hal-guest-role-bootstrap` and supplies only the frozen
closed role argv/environment; the controller protocol cannot invoke either
boot-only start and the private launch protocol can select no binary or
argument. There is no process creation by the controller or monitor, arbitrary
command, `fork`, caller-selected clone flag, alternate `clone3` size, or
spawn-then-write-`cgroup.procs` fallback.

Every `ProcAttr` has empty `Dir`, nil `Credential`, exact fixed `Files`, and no
chroot, controlling TTY, session/process-group, parent-death signal, user-ID
mapping, ambient-capability request, or other `SysProcAttr` option. The pinned
pre-exec path may add `prlimit64(0, RLIMIT_NOFILE, ...)` only for Go's cached
limit recheck, fixed-FD `dup3`/`fcntl`/`close`, the exact child `execve`, and an
error-pipe write/exit. If exec fails, PID1 may use
`wait4(exactReturnedPID, ..., 0, NULL)` only inside `ForkExec`'s synchronous
failure cleanup, then closes the returned pidfd and converges through the
owned role cleanup. Normal authority and cleanup use pidfds plus `waitid`; a
PID from this internal failure path is never accepted from a protocol or used
after `ForkExec` returns.

The `ForkExec` pre-exec child may call pathname `execve` only for the compiled
role-bootstrap path. That native bootstrap may perform exactly one second
pathname `execve` to its role's compiled, image-profile-pinned controller,
agent, monitor, or shim target after committing the exact native role state.
The inherited `launch-base` remains the only installed filter until the Go
target commits its steady or transition filter before protocol input. Both
argv/environment sets contain no protocol or job field and are
validated in immutable adapter-owned storage before `clone`; `CLONE_VFORK`
suspends the only mutator until first exec/exit. The sole PID1 launch adapter
admits no other pathname exec request, and every steady child role filter
rejects pathname exec. The agent stacks its existing unprivileged service filter
before admission release; the controller and monitor stack the role filters
above, and the shim is the sole service binary that later uses pinned-FD
`execveat` for a workload.

PID1 and the controller may create only the exact `pipe2` and unnamed
`AF_UNIX/SOCK_SEQPACKET|SOCK_CLOEXEC` pairs required by the closed launch and
stream protocols, with `SO_PASSCRED` on protocol endpoints. Before monitor
launch PID1 creates a temporary PID1-monitor bootstrap pair and a distinct
long-lived controller-monitor pair. The monitor receives the long-lived
monitor endpoint at fixed FD 3, the long-lived controller peer at launch-only
FD 9, and its bootstrap endpoint at launch-only FD 10. PID1 keeps the other
bootstrap peer in a recorded transient slot; PID1 fixed FD 10 remains the
monitor pidfd. The monitor creates no socketpair. It opens and reinspects its
namespace as FD 7 using the exact `verified_proc_root_fd` exception above, then
its sequence-zero `HL8M monitor_ready` sends exactly two rights over FD 10 to
PID1 in this order: FD 9, the long-lived controller peer, then FD 7, the live
namespace capability. It retains fixed FD 3 and FD 7 and closes FD 9 and FD 10
permanently after the authenticated send. The ready body carries the exact
pending revision,
controller-minted job/monitor/mount/cgroup generations, `helper-limits-v1`,
`createJobSHA256`, and canonical `monitorReadySHA256`. PID1 requires exact
equality, recomputes the ready digest, requires the expected monitor
pidfd/PID/UID/GID, and reinspects both rights before relaying them in the same
order through `HL8L job_created` with that same ready digest; it then closes
its bootstrap peer and transferred duplicates. The controller owns the direct
endpoint and namespace authority after that commit. Any discrepancy closes
every transient right,
kills/reaps the monitor, and rolls back.

`pipe2` uses `O_CLOEXEC` plus optional `O_NONBLOCK`; each pair is immediately
type/direction inspected. `waitid(P_PIDFD, ...)` is PID1-only for monitor and
workload processes. The controller proves agent liveness by pidfd polling only;
it lacks signal permission for UID 998 and never calls `pidfd_send_signal`.
PID1 may use `pidfd_send_signal` with signal zero or `SIGKILL`, null siginfo,
and flags zero only for its same-UID-0 monitor. PID1 never signals a UID-1000 workload;
after shim start, every stop path writes exact `1` to the owned job cgroup's
`cgroup.kill`, observes `populated 0`, and reaps each workload pidfd with
`WEXITED`, optional bounded `WNOHANG`, and a final wait without `WNOWAIT`.
PID numbers, process groups, and ambient `/proc` lookups are not authority. The
still-capable monitor remains alive for normal unmount after workload absence.
`setsid` and `setpgid` descendants remain covered by cgroup kill.

### Unix SSH relay extension

Only a D5-enabled monitor may add
`umask socket bind getsockname listen`; only the matching controller extension
may add `accept4 shutdown`:

```text
umask socket bind getsockname listen | accept4 shutdown
```

`socket` is exactly `AF_UNIX`, `SOCK_STREAM|SOCK_CLOEXEC` with optional
`SOCK_NONBLOCK`, protocol zero. `accept4` adds `SOCK_CLOEXEC` and optional
`SOCK_NONBLOCK`. `bind` uses only the monitor-owned job relay address under the
fixed credential root; abstract names, unnamed caller sockets, and
any network or vsock family are rejected. The pointer is copied and validated
before the syscall. `umask` is the exact one-way `0177` transition above and is
permitted only immediately before the sole D5 bind. The monitor-only `getsockname`
rule applies only to its recorded D5 listener, uses a fixed-size
zeroed `sockaddr_un` and initialized length, and after bind must return exact
`AF_UNIX`, length, and sealed canonical pathname bytes. After the exact
parent-FD-relative ownership-last transition, the monitor calls `listen` with
backlog 1 through 4 and repeats `getsockname`; read-only `getsockopt` must prove
the exact domain, type, protocol, and `SO_ACCEPTCONN` listening state. It also
reinspects the same filesystem mount/device/inode, fixed UID/GID 1000, mode
0600, ownership, and generation before publication. A listener has no peer or
connected-state claim. The controller validates accepted peer identity only after `accept4`
on the resulting connected FD. Before rights publication or any stream read,
exact `getsockopt(SOL_SOCKET, SO_PEERCRED)` must return an accepted `struct ucred`
at its exact kernel ABI size with positive PID and fixed UID/GID 1000. The PID is
ephemeral check metadata, never durable identity or authority. A mismatch or
wrong result length closes the connected FD without publication. `shutdown` is
`SHUT_RD`, `SHUT_WR`, or `SHUT_RDWR` on a recorded relay FD only.

D2 owns the policy rule and fake decisions. The monitor sends the one inspected
listener capability to the controller through the exact D5 monitor response:
the normative HL8M `create_ssh_endpoint` accepted response carries exactly one
inspected listening `AF_UNIX` capability from a recorded transient slot. Fixed
FD 9 is never reused for it after the bootstrap handoff. The monitor
then closes its original only after the authenticated atomic send succeeds;
the controller owns
and accepts on the published listener and never binds in another mount
namespace. On revoke the controller closes every published listener and
accepted connection before the monitor unlinks the socket entry. D5 owns live
acceptance, descriptor passing, peer validation, and pumping. D4 alone MUST NOT
enable this extension.

## Monitor and workload transitions

Monitor mode of the native role bootstrap begins already inside the cloned job
mount namespace. Before any Go runtime starts, it clears supplementary groups,
reduces bounding/permitted/effective/inheritable/ambient sets to exactly
`CAP_SYS_ADMIN|CAP_CHOWN`, verifies inherited securebits/`no_new_privs`, and
execs the fixed monitor target. Go verifies that state and fixed FDs, then
stacks `steady-monitor` with TSYNC before the
exact namespace-self `openat2`/`sendmsg` handoff. It performs only the closed
prepare, optional SSH-endpoint, revoke, and absence protocol in its current
namespace. It never clones, performs pathname exec, or enters another
namespace. After successful absence proof it calls `exit_group`; monitor exits
the entire process, so no privileged runtime thread survives.

The handoff and later operations obey the architecture's HL8M FSM rather than
being inferred from syscall success: ready revision is exactly one; one
begin/file/commit transaction is the sole logical outstanding prepare request;
the optional endpoint is created only after commit; cleanup-complete reports
entry/socket/mount absence only. The monitor cannot claim its own process
absence while sending. The controller alone drives revoke over direct FD 3,
receives cleanup-complete, and completes the exact bilateral normal
`close_notify` handshake before monitor FD 3 closes and the monitor exits. The
controller observes the expected EOF, then closes its direct endpoint and
namespace duplicate. Only afterward does it send HL8L `destroy_job`; PID1 never
requests HL8M cleanup and then separately reaps the monitor pidfd and proves
process/cgroup/directory absence. Any non-normal close, wrong-state close,
close-send failure, or EOF before the committed handshake requires stop-VM.

Shim mode of the native role bootstrap verifies the exact six inherited sets,
fixed FDs, securebits, cgroup placement, and `no_new_privs`. The single-threaded
native shim enters the mount namespace before any Go runtime starts: it
revalidates FD 3 as the exact monitor namespace, calls
`setns(3, CLONE_NEWNS)` while holding `CAP_SYS_ADMIN|CAP_SYS_CHROOT`, and closes
FD 3. It then drops `CAP_SYS_ADMIN`, `CAP_SYS_CHROOT`, and `CAP_CHOWN` from the
bounding/permitted/effective/inheritable/ambient sets, verifies the remaining
sets are exactly `CAP_SETUID|CAP_SETGID|CAP_SETPCAP`, and execs the fixed Go
shim without reading the launch block or gate. The child was created without
`CLONE_FS`; native namespace entry therefore cannot share filesystem state with
another process. Go starts inside the job namespace and immediately stacks
`workload-transition` with TSYNC before either read; no transition policy is
learned from input. It later stacks the final existing workload filter.

A workload shim transition may call only:

```text
read close close_range dup3 fcntl fchdir
setgroups setresgid setresuid getresuid getresgid getgroups capget capset prctl
seccomp execveat exit exit_group rt_sigreturn
```

The exact sequence is:

1. validate fixed FDs 0..2 and 4..7, require native FD 3 is closed after
   namespace entry, require FD 8 is closed, and close every unrelated
   descriptor;
2. read and authenticate the bounded launch block from FD 6 directly into
   locked memory, construct the sealed `ExecPlan`/binding, wipe the input slot,
   and close FD 6;
3. revalidate already mapped pipe directions at 0, 1, and 2;
4. `fchdir` to workdir FD 4 and close it;
5. consume gate FD 7 only after PID1 committed cgroup/namespace/FD correlation,
   then close it;
6. drop each of the remaining three bounding bits with `PR_CAPBSET_DROP` while
   `CAP_SETPCAP` remains effective;
7. `setgroups(0, NULL)`, `setresgid(1000,1000,1000)`, and
   `setresuid(1000,1000,1000)`; require the normal UID transition to clear
   permitted/effective/ambient state, clear the inherited set with `capset`,
   use exact `getresuid`, `getresgid`, `getgroups`, `capget`, and bounding/
   ambient `prctl` reads to verify UID/GID 1000, no groups, and all five sets
   empty, set `PR_SET_DUMPABLE=0`, and reconfirm `PR_SET_NO_NEW_PRIVS=1`;
8. stack the existing workload seccomp policy; and
9. move pinned executable FD 5 to FD 11 and call
   `execveat(11, "", argv, envp, AT_EMPTY_PATH)`. FD 11 remains close-on-exec
   for a native executable. For an already detected and pinned interpreter
   script only, the child clears `FD_CLOEXEC` immediately before `execveat` so
   the kernel interpreter handoff can use the same inode, exactly preserving
   the frozen L4 child-only descriptor behavior.

The shim does not use pathname `execve`, ambient `PATH`, `chdir`, or a
request-derived `open*`/`/proc/self/fd` lookup. The monitor namespace constant
and frozen L4 kernel interpreter handoff are the only exceptions. `argv` and
`envp` are constructed solely from the
validated bounded `ExecPlan` plus authenticated prepared bindings; their
pointers are not seccomp-inspectable. Failure at any step wipes private memory,
closes pipes/gate, and exits without a second launch attempt. PID1 kills the
owned job cgroup, reaps the recorded pidfd, and continues cgroup cleanup.

The final workload policy is not broadened here. It MUST retain the existing
L4 execution semantics and L7 network confinement and MUST deny at least the
forbidden process-inspection and privilege syscalls below. A child cannot use
`SECCOMP_FILTER_FLAG_NEW_LISTENER`, `TSYNC`, `LOG`, or a permissive transition.

## Capability and identity invariants

At PID1 launch-supervisor commit, the bounding, permitted, effective,
inheritable, and ambient sets are exactly:

```text
CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_CHOWN
```

PID1 raises the six ambient bits only after proving they are already permitted
and inheritable, then locks `SECBIT_NOROOT` and
`SECBIT_NO_CAP_AMBIENT_RAISE` on. `SECBIT_KEEP_CAPS` and
`SECBIT_NO_SETUID_FIXUP` remain off and are locked off with their companion
locked bits. PID1 is non-dumpable and cannot raise or gain any capability
outside the six-bit bounding set. The ambient set exists solely so an exact
image-profile-pinned nonprivileged controller/agent/monitor/shim exec retains the
six transition capabilities despite `SECBIT_NOROOT`; no file capability or
setuid/setgid bit supplies privilege.
No file capability, setuid/setgid binary, user namespace, keyring, or ambient
raise can restore authority.

The service agent reaches UID/GID 998 with all five capability sets empty
before descriptor hello or admission release. The steady
controller is UID/GID 0 with locked `SECBIT_NOROOT` and every capability set
empty. The monitor is UID/GID 0, has no supplementary groups, and retains only
`CAP_SYS_ADMIN|CAP_CHOWN` until normal unmount/absence, then exits its entire
process. The workload is UID/GID 1000, has no supplementary groups, has every
capability set empty, and has `no_new_privs` before exec. The native workload
shim has the six-bit set only through namespace entry; `CAP_SYS_CHROOT` is
present solely so exact mount-namespace `setns` can succeed. The Go shim starts
with exactly `CAP_SETUID|CAP_SETGID|CAP_SETPCAP` and no namespace FD. Any mismatch blocks
readiness or gate release; it is never downgraded to a warning.

## Forbidden syscall catalog

The following are forbidden except for the exact role rule above and forbidden
to workloads where applicable:

- arbitrary path and mutation: `open`, `openat`, `creat`, `mount`, `chroot`,
  `name_to_handle_at`, `open_by_handle_at`, `link`, `linkat`, `symlink`,
  `symlinkat`, `mknod`, `mknodat`, `mkfifo`, and `pivot_root` after bootstrap;
- arbitrary namespace or privilege: `unshare`, arbitrary `setns`,
  `setuid`, `setgid`, `setreuid`, `setregid`, `setfsuid`, `setfsgid`,
  `personality`, `uselib`, and seccomp listener creation;
- device, kernel, or key authority: every `ioctl` except exact monitor or native
  shim `ioctl(7|3, NS_GET_NSTYPE)`, `iopl`, `ioperm`, `kexec_load`,
  `kexec_file_load`, `init_module`, `finit_module`, `delete_module`,
  `reboot`, `swapon`, `swapoff`, `quotactl`, `syslog`, `acct`,
  `add_key`, `request_key`, and `keyctl`;
- process inspection or cross-process memory: `ptrace`, `process_vm_readv`,
  `process_vm_writev`, `pidfd_getfd`, `kcmp`, `perf_event_open`, `bpf`,
  `userfaultfd`, and `membarrier` registration;
- uncontrolled process/signal authority: `fork`, `vfork`, every `clone` and
  `tgkill` outside the pinned Go-runtime envelope, `kill`, `tkill`, and
  every `clone3` outside PID1's single exact shim template;
- network/vsock authority: every `socket` family except PID1 native bootstrap's
  exact three `AF_VSOCK` listeners and the exact D5 `AF_UNIX` rule, plus
  `socketpair`, `accept`, `connect`, `sendto`, `recvfrom`, `sendmmsg`, `recvmmsg`,
  and `setsockopt` after bootstrap, except the exact local protocols, steady-agent
  `accept4`, and D5 monitor/controller split above; and
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
- pidfds: pidfd type, expected generation/liveness, and poll state; signal
  permission is never inferred from pidfd ownership;
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
allow. A `KILL_PROCESS` outcome in PID1, controller, agent, monitor, or shim is
permanent role loss. The agent invalidates readiness and active proofs; the guest cannot claim local
cleanup complete. D6 stops/reaps the exact microVM and inspects host-owned
absence.

## Kill, reap, and cleanup convergence

Before shim gate release, any authentication, descriptor, private-binding,
policy, or setup failure closes the gate and pipes and wipes buffers. If a shim
has started, PID1 uses the owned cgroup-kill/zero-population path and then reaps
its recorded pidfd; it never relies on signal permission after the UID drop.
Unstarted state rolls back without a kill.

After gate release, cancel, timeout, protocol/session/role loss, malformed
stream, output failure, expiry, or revoke denies new exec and converges through
the exact job cgroup. On the recoverable normal path the controller initiates
each protocol step; PID1 never originates an HL8M cleanup request:

1. the controller denies new exec/accept and sends HL8L `terminate_job`; PID1
   writes exactly `1` to `cgroup.kill` beneath its fixed FD 9;
2. PID1 parses bounded `cgroup.events` until exact `populated 0`;
3. PID1 reaps all recorded workload shims/leaders with `waitid(P_PIDFD, ...)`;
4. PID1 returns `job_terminated`; the controller closes pipes and wipes private
   buffers;
5. the controller closes every published listener and accepted connection;
   through direct monitor FD 3 it drives HL8M revoke/cleanup, and the
   still-capable monitor unlinks files/socket entries, normally unmounts in its
   current namespace, and proves mount/file absence;
6. the monitor returns `cleanup_complete` directly to the controller, calls
   `exit_group` only after bilateral normal HL8M close commits, and the
   controller observes monitor exit before closing its direct endpoint and
   namespace duplicate;
7. only then the controller sends HL8L `destroy_job`; PID1 never contacts the
   monitor, whose bootstrap channel is permanently closed, but confirms/reaps
   the monitor with its FD 10 pidfd; and
8. PID1 performs any still-needed cgroup kill/zero confirmation, removes and
   reinspects the generation directory and cgroup, and returns `job_destroyed`.

An early `destroy_job` before the monitor cleanup/exit precondition returns only
the canonical correlated cleanup retry or stop-VM result; PID1 does not attempt
to recreate a bootstrap link or operate a controller-owned capability.

There are at most three idempotent attempts inside one 30-second total
deadline. A retry begins with reinspection and never recreates a resource.
Process-group signals, leader pidfd death, descriptor closure, and role exit
are not descendant-absence proof. Missing cgroup kill/inspection, unknown
ownership, nonzero population, normal-unmount failure, monitor-reap failure,
PID1/controller/agent/monitor loss, or policy-kill yields `stop_vm_required`. Only D6's exact
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
- launch-base ancestry, capability/securebits/UID/GID, and fixed-FD transition
  matrices, including native pre-Go namespace entry, post-setns three-capability
  shim state, required read-back calls, and the `CAP_SYS_CHROOT` transition;
- exact native VSOCK listener create/bind/listen/CLOEXEC handoff, partial-set
  rollback, fixed agent-FD accept matrix, peer/local identity checks, limits,
  and no service-side socket creation;
- host `HL8C` and helper `0x19 exec_credit` direction/offset/one-outstanding
  matrices, independent stdout/stderr progress, credit digest exclusion,
  host-resupplied comparison-only replay, no agent replay retention, local
  response-loss termination, fixed-slot wiping, and shared-transport stall cleanup;
- partial prepare, child-before-gate, pidfd loss, `setsid` descendant,
  forbidden cross-UID signal, cgroup-kill, nonzero population, root-0711
  traversal, UID-1000 file/socket access and parent non-write, unmount,
  monitor-reap, three-attempt/deadline,
  and `stop_vm_required` state-machine tests; and
- compiler golden tests proving exact `ALLOW`, `ERRNO(EPERM)`, and
  `KILL_PROCESS` decisions, amd64 arch check, x32 rejection, no permissive
  action, and stable syscall-name/number mapping.

D4 owns the Linux implementation and adds:

- subprocess probes for every `KILL_PROCESS` class and representative
  `ERRNO(EPERM)` classes, asserting the process disposition and absence of a
  performed side effect;
- positive kernel tests for fixed-FD bootstrap, filesystem/mount/cgroup,
  VSOCK inherited-listener acceptance, canonical service/monitor `clone` and
  shim `clone3`, native shim setns before any Go thread, shim identity/capability drop, and
  kill/reap ordering through injected syscall fakes before any prepared-host
  test;
- one normalized, committed strace fixture for each bootstrap, prepare,
  exec-success, exec-failure, revoke, and cleanup path. The fixture contains
  syscall names and safe scalar categories only—never paths, payloads,
  arguments, environment values, nonces, socket names, or credentials. The set
  difference `observed - policy` and `policy-required - observed` MUST both be
  empty, except explicitly enumerated state-dependent alternatives already in
  the D2 table; and
- a role-composition regression proving the steady controller cannot launch,
  mount, create network/vsock sockets, or use workload authority; the monitor
  alone mounts/unmounts in its current namespace; the workload is not trapped by
  controller seccomp; and PID1 accepts no general-purpose launch request; and
- a small-`SO_SNDBUF` seqpacket test proving withheld stdout credit does not
  prevent credited stderr progress (and vice versa), while a peer-wide read
  stall reaches the bounded session-loss cleanup path.

Strace is test evidence, not an allowlist generator. An observed extra syscall
fails the test; it is never automatically added. Kernel tests remain behind an
explicit D4 integration tag and prepared prerequisite checks. A skip cannot
become selected live evidence.

## Ownership and non-goals

D2 owns this immutable policy vocabulary, exact tables, fake decisions,
pointer/provenance validators, the pure normative HL8M codec/FSM, supervisor/
monitor protocol contracts, test
fixtures, and source/import guards. D4 owns the live PID1/controller/monitor/shim/agent role composition,
filter compilation and
installation, direct syscalls, namespaces, tmpfs, cgroups, workload launch,
and guest cleanup retries. D5 owns live SSH Unix sockets and relay I/O under the
optional extension. D6 owns role-loss and whole-VM stop/reap composition.

This closure does not add a service binary, syscall wrapper, BPF program,
listener, mount, namespace, cgroup, process, command wiring, guest image, live
test, capability claim, active proof, or cleanup proof. It does not alter v1,
the D2 packet/exec codecs, L4 workload behavior, L7 network enforcement, or the
existing D2/D4/D5/D6 ownership split.
