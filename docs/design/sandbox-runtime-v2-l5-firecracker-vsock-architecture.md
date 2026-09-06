# Sandbox Runtime v2 L5 Firecracker Guest Image and Vsock Architecture

## Authority and phase boundary

This note refines issue #49 phase L5 under locked comments `5068151561`,
`5068157402`, and `5068162708`. The Linux completion architecture and the L4
guest-agent architecture remain authoritative. The exact L5 base is
`762ee1a61d2efc5bb9241a6e87409ca20d68f976`.

L5 owns a reproducible Linux guest kernel/rootfs containing the L4 guest-agent
server, the guest AF_VSOCK listener, the Firecracker host UDS bridge and
framing, machine vsock configuration, readiness evidence bound to one live
runtime, proof-gated exec/copy capability projection, and a prepared-Linux KVM
end-to-end test.

L5 does not implement policy proxying, firewall or network topology, credential
delivery, OCI acquisition, default runtime selection, or strict secure-default
composition. It makes no network, credential, template-trust, or strict-mode
claim.

## 1. Inputs, outputs, states, and failure codes

### Guest asset build

The x86_64 build lock is:

- Buildroot tag `2026.05.1`, annotated tag object
  `de1f9260590a53a7cd8a59addc47c96ecd09f983`, peeled commit
  `cb857ba4c87a93e5265a9e4a3f32071abf39e14a`, official
  `buildroot-2026.05.1.tar.xz` SHA-256
  `ae7f706f087b9ae9083a10a587368dfbf53103c28bf81c2d690198dc4090cb58`,
  and verified signed release message from full fingerprint
  `18C7DF2819C1733D822D599EA500D6EE9CB0E540`;
- Linux `6.1.178` archive SHA-256
  `7d83fa67ca75032b1ac6ef49973722073963c0cb9bc3aa7ef3efa749cf6c720f`;
- BusyBox `1.38.0` archive SHA-256
  `34f9ea6ff8636f2c9241153b9114eefa9e65674a45318ae1ef95bb5f31c53bb2`;
- e2fsprogs `1.47.4` `e2fsprogs-1.47.4.tar.xz` archive SHA-256
  `fd5bf388cbdbe006a3d3b318d983b2948382440acc85a87f1e7d108653e8db0b`;
- Go `1.25.7` Linux x86_64 archive SHA-256
  `12e6d6a191091ae27dc31f6efc630e3a3b8ba409baf3573d955b196fdf086005`,
  matching the repository's `go` directive and official Go download record;
- Firecracker `v1.15.1` x86_64 release archive SHA-256
  `d4a32ab2322d887ca1bc4a4e7afa9cc35393e6362dfc2b3becb389d362e4275a`,
  with extracted executable SHA-256
  `7e8b57e88c459396d4680d83dcdd8c7f72305447cb55b11f4ac98ad70a3f7825`;
  and
- the Buildroot `linux/amd64` build image
  `registry.gitlab.com/buildroot.org/buildroot/base@sha256:f1e7f009dad6b6f44bf5fcb4b0b89c9228e42f9fe689142774b1db802d4c93c6`.

The checked-in manifest also locks every transitive Buildroot download by
exact filename, version, URL, and SHA-256. A checksum establishes integrity;
it is not independent authenticity. The Buildroot signed-release verification
and the Firecracker upstream release origin are recorded separately.

The build entry point consumes:

- a checked-in Buildroot release version and SHA-256 lock;
- checked-in Buildroot, Linux, BusyBox, and filesystem configuration plus the
  SHA-256 lock for every offline Buildroot source dependency;
- a clean Hal source tree whose exact Git tree and commit identities are
  recorded;
- `SOURCE_DATE_EPOCH`; and
- an empty caller-owned output directory.

Network fetch is a separate explicit step. Every official download is accepted
only after its immutable SHA-256 lock matches, and the Buildroot source must
also pass its pinned signed-release verification. The offline build executes
inside a real no-network namespace/container after preflighting the exact
locally installed build-image digest and disabling daemon pulls. It uses
`BR2_PRIMARY_SITE_ONLY=y`, `BR2_DOWNLOAD_FORCE_CHECK_HASHES=y`, no ccache, a
fixed `hal-l5-build` container hostname, and a fresh host/staging/target/download
tree. It consumes only the verified source
archive and exact download manifest, refuses a missing, extra, renamed, or
digest-mismatched dependency, builds a static
`hal-guest-agent`, and emits:

- `vmlinux`;
- `rootfs.ext4`;
- a path-free `distribution-manifest.json`;
- `provenance.json`; and
- `SHA256SUMS`.

The guest binary uses `-trimpath`, `-buildvcs=false`, an empty Go build ID, and
no ambient module download. Canonical cache/output roots require private
owner-controlled mode-`0700` parents. The exact cache set includes hidden
entries, and its expected host UID and contents are rechecked inside the
host-identity container. Guest Go compilation uses `GOPROXY=off`, `GOSUMDB=off`,
and `-mod=readonly` after the exact local module artifacts are populated. All
ephemeral build trees are independently created below the validated private
output parent and removed after restoring only the caller's write bit on
read-only build-cache entries.
The kernel build fixes `KBUILD_BUILD_USER`,
`KBUILD_BUILD_HOST`, `KBUILD_BUILD_TIMESTAMP`, and `KBUILD_BUILD_VERSION`.
The kernel has `CONFIG_MODULES=n` and `CONFIG_HW_RANDOM_VIRTIO=y`.
Filesystem construction uses a fixed ext4 UUID, label, inode count, block
size/count and feature set, sorted population order, normalized
ownership/modes/mtimes, disabled lazy inode-table and journal initialization,
and a final `e2fsck -fn`. The distribution manifest records only stable
relative asset keys, safe IDs, versions, protocol/features, sizes, and SHA-256
digests. It is deliberately distinct from the existing runtime-materialized
`assets.LaunchDescriptor`, whose resolved host paths are created only after
installation and are never a distribution artifact. Provenance never records
source/output paths, hostnames, endpoints, usernames, environment values, or
command lines; any time field is exactly `SOURCE_DATE_EPOCH * 1000`.

Buildroot's reproducibility mode requires the same canonical internal source
and `O=` paths. Therefore the acceptance build uses two independent clean
no-network namespaces/containers that expose identical canonical internal
paths and fresh host/staging/target/download state, export results to distinct
caller directories, then byte-compare `vmlinux`, `rootfs.ext4`,
`distribution-manifest.json`, `provenance.json`, and `SHA256SUMS`. Different
caller export paths must not change any byte or appear in an artifact.
Cross-host equality is a stronger handoff check, not the local L5 acceptance
claim.

The guest agent maps both its host-side workspace root and protocol-visible
guest root to `/workspace`; absolute request paths therefore remain contained
without being prefixed as `/workspace/workspace`.

### Vsock transport

The fixed production guest CID is `3` and the fixed guest-agent port is
`1024`. These are protocol constants, not caller-controlled endpoints.
Firecracker receives a target-owned UDS path inside the private runtime state
directory. The host transport:

1. opens one AF_UNIX stream per request with a bounded dial timeout;
2. writes exactly `CONNECT 1024\n`;
3. reads one bounded newline-terminated Firecracker response without accepting
   pre-acknowledgement protocol bytes;
4. requires the exact `OK <assignedHostPort>\n` shape where the host port is
   canonical unsigned 32-bit decimal without sign or leading zero, is nonzero,
   and is in `1..4294967294`; Linux `VMADDR_PORT_ANY` (`4294967295`) is
   reserved;
5. writes one bounded guest-agent JSON request as a fixed 4-byte big-endian length-prefixed frame;
6. reads exactly one bounded guest-agent JSON response using the same frame;
   and
7. closes the connection on success, cancellation, timeout, or failure.

The guest transport accepts AF_VSOCK streams only for port `1024`, applies
L4 request/response limits before allocation/write, dispatches one request per
connection, writes one framed response, and closes every accepted connection.
They do not rely on an EOF or half-close as a message delimiter: Firecracker
can tear down a forwarded vsock channel after a shutdown signal before a reply
is delivered. The Linux connection watcher
treats `POLLRDHUP` as non-terminal and treats only `POLLHUP`, `POLLERR`, or
`POLLNVAL` as peer loss that cancels the per-request handler context. It never
accepts AF_INET, exposes a shell, or forwards host paths.

The host bridge states are `configured`, `handshaking`, `active`, `failed`, and
`closed`. Only an exact `guest-agent-v1` readiness response from the running
runtime moves proof to `active`. API-socket availability and UDS existence
remain host-process facts only.

### Live runtime and failure codes

The pre-start Firecracker full-config file contains:

```json
{
  "boot-source": {
    "kernel_image_path": "<private>",
    "boot_args": "console=ttyS0 reboot=k panic=1 nomodule devtmpfs.mount=0 ro root=/dev/vda rootfstype=ext4 rootwait init=/sbin/init"
  },
  "drives": [{
    "drive_id": "rootfs",
    "path_on_host": "<private>",
    "is_root_device": true,
    "is_read_only": true
  }],
  "vsock": {
    "guest_cid": 3,
    "uds_path": "<target-owned-private-state>/guest.vsock"
  },
  "entropy": {}
}
```

PID 1 mounts `/proc`, `/dev`, `/sys`, `/run`, and `/tmp`, creates a fixed
non-root UID/GID `1000` with a disabled agent password, and mounts `/workspace`
as a distinct size-bounded tmpfs owned by that identity with mode `0700` before
constructing the L4 backend. It reaps children and forwards termination
signals, then drops privileges and execs the guest agent. The immutable ext4
root drive remains read-only. The privilege transition uses the static util-linux `setpriv`, not
the BusyBox applet: `BR2_PACKAGE_UTIL_LINUX_SETPRIV=y` is locked and the built
binary must expose `--reuid`, `--regid`, `--clear-groups`, and
`--no-new-privs`. The fixed boot arguments, entropy device, and vsock device
must be present in the config before Firecracker starts; no post-start API
mutation is accepted as equivalent proof.

The locked kernel configuration includes `CONFIG_HYPERVISOR_GUEST=y`,
`CONFIG_PARAVIRT=y`, and `CONFIG_KVM_GUEST=y` so the guest obtains KVM clock
support rather than waiting for absent legacy timer devices. It also keeps
`CONFIG_SMP=y` even though L5 starts one vCPU: the x86 APIC topology remains
available for the emulated PCI interrupt path. This is a kernel configuration
requirement, not a claim that L5 starts multiple vCPUs. The Buildroot profile
uses `BR2_ROOTFS_DEVICE_CREATION_STATIC=y` with the explicit
`system/device_table_dev.txt` bootstrap table, preventing Buildroot from
forcing `CONFIG_DEVTMPFS_MOUNT=y` into the generated kernel configuration.
The build rejects an effective kernel configuration that enables that option:
PID 1 owns the one explicit devtmpfs mount with the required `nosuid,noexec`
restrictions, and an automatic mount is not equivalent. The fixed boot
arguments also set `devtmpfs.mount=0` as a redundant runtime guard.

L5 selects Firecracker's ACPI/PCI virtio transport deliberately. The guest
locks `CONFIG_ACPI=y`, `CONFIG_PCI=y`, `CONFIG_BLK_MQ_PCI=y`,
`CONFIG_PCI_MMCONFIG=y`, `CONFIG_PCI_MSI=y`, `CONFIG_PCIEPORTBUS=y`, and
`CONFIG_VIRTIO_PCI=y`; the production start plan contains the exact
`--enable-pci` flag before any path-bearing argument. It disables the legacy
fallback mechanisms with `CONFIG_X86_MPPARSE=n`, `CONFIG_VIRTIO_MMIO=n`, and
`CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=n`, and the fixed boot arguments omit
`pci=off`. Firecracker therefore exposes the read-only root block, vsock, and
entropy devices through its bounded emulated PCI segment and ACPI discovery,
not through guest-supplied `virtio_mmio.device=` command-line metadata. This
does not grant the guest host PCI passthrough or arbitrary device discovery.

Start order is verify private state, render state, start Firecracker, accept the
API socket, correlate the process handle/runtime/state identity, complete the
exact vsock readiness handshake, then return a ready target. Failure before
readiness triggers whole-runtime cleanup. Exec and copy require the target's
active readiness proof and the same runtime identity.

The state directory is opened descriptor-relatively, must be owned by the
current effective UID, have mode `0700`, and be a real directory rather than a
symlink. The vsock path is lstat-checked without following links. Before a new
start, a present symlink, non-socket, wrong-owner socket, group/other-accessible
socket, or socket without the exact runtime ownership marker fails closed. A
stale socket may be removed only when its type, UID, mode, parent descriptor,
runtime ID, prior process handle, and terminal lifecycle record all correlate.
After Firecracker creates the socket, the same checks run again before dial.
A socket swap between verification and dial is detected by comparing the
pinned parent plus pre/post device/inode identity. After connect, Linux
`SO_PEERCRED` must report the exact PID of the accepted live Firecracker process
generation before the host writes `CONNECT`; inode checks without peer
credentials are insufficient. Missing, malformed, stale, or mismatched peer
credentials reject the handshake and readiness.

L5 reuses L4 protocol failures and the existing sanitized microVM operation
codes. New construction failures use fixed safe codes:

- `asset_lock_mismatch`;
- `asset_build_failed`;
- `vsock_configuration_invalid`;
- `vsock_handshake_failed`;
- `vsock_response_invalid`;
- `guest_readiness_failed`; and
- `runtime_teardown_failed`.

Raw paths, socket errors, Firecracker arguments, guest output, and kernel logs
never enter these public summaries.

## 2. Package ownership and import boundaries

```text
cmd/hal-guest-agent
  minimal Linux guest entry point; no command tree or host runtime imports

internal/sandboxruntime/microvm/guestagent/vsock
  guest AF_VSOCK listener implementing server.Transport

internal/sandboxruntime/microvm/guestagent/frame
  data-only bounded length framing shared by the host bridge and guest listener

internal/sandboxruntime/microvm/firecrackerhost
  host UDS CONNECT handshake, bounded protocol transport, readiness composition

internal/sandboxruntime/microvm/firecracker
  deterministic vsock device payload and target-owned socket path rendering

internal/sandboxruntime/microvm/assets/build
  safe build manifest/provenance parsing and digest verification only

tools/microvm/l5
  pinned fetch/build scripts and Buildroot configuration
```

The guest vsock package may import the L4 server boundary, the parent protocol,
standard-library packages, and `golang.org/x/sys/unix`. It must not import
`cmd`, worker, execution, workspace, factory, provider, Firecracker host,
network policy, credential, OCI, cloud, HTTP, or rootless Podman packages.

The Firecracker contract package remains host-adapter independent. The asset
build metadata package is data/digest only and does not download, execute
tools, mount filesystems, or start VMs. Build scripts never run from default
tests or default Hal execution.

## 3. Durable and machine-contract schema changes

L5 does not change manifests, factory records, command JSON versions, worker
protocol versions, or strict-security schemas.

The path-free distribution manifest carries kernel/rootfs SHA-256 locks and
guest-agent metadata (`guest-agent-v1`, `readiness`, `exec`, `copy_in`,
`copy_out`). Asset installation/resolution separately materializes the
existing runtime launch descriptor with local host paths.
The build provenance schema is `hal-microvm-image-v1` with safe fields only:
schema version, source revision, source-date epoch, Buildroot/Linux/BusyBox/Go
versions, architecture, guest-agent protocol/features, and output
digest/size records.

Runtime readiness continues to use
`RuntimeGuestReadinessMetadata`. L5 permits only sanitized
`state=ready`, `transport=vsock`, and the canonical `ready` state label plus
fixed proof labels `protocol_v1`, `runtime_bound`, and `probe_ok` after the
active handshake.
No UDS path, CID, port, process identifier, or handshake bytes are durable
proof.

Worker microVM operations remain lifecycle-only before a target is ready.
The Firecracker backend owns a private in-memory live-session registry shared
by every controller it creates. A session proof is keyed by runtime ID, exact
opaque process generation, verified state-directory identity, socket
device/inode, peer PID, bridge generation, and successful readiness generation.
Start, stop, and delete share one exclusive per-runtime lifecycle reservation;
an overlapping lifecycle request rejects before rendering state, calling the
live process manager, or reporting success. A successful stop or delete
therefore cannot race with an in-flight start that later becomes ready.
Host-process ownership is recorded immediately after launch and survives guest
session or bridge loss. Replacing that generation requires positive,
exact-generation terminal-state verification from the host process owner;
missing verification, unknown handles, and failed cleanup reject the restart.
A production-vsock launch that returns no safe opaque process handle is retained
as unverified ownership and fails closed before guest readiness.
Stale socket cleanup additionally requires every matching path/state generation
to be terminal, so an older terminal record cannot authorize cleanup while a
newer matching process remains active.
Exec/copy authorization consults this registry, not caller-carried
`Target.Runtime.Metadata.GuestReadiness`. Manually constructed, stale, or
cross-runtime `ready` target metadata never authorizes an operation.

Stop, delete, cleanup, observed process exit, bridge loss, readiness failure,
and a new start generation invalidate the session before returning. Every
transport failure invalidates the matching bridge generation without touching
a newer generation. Worker descriptors remain daemon-wide and lifecycle-only;
L5 does not globally advertise exec/copy after one VM becomes ready.
Target-scoped status may project operations only from the same active session.

Existing microVM isolation projection from caller-carried labels is not L5
proof. L5 either projects isolation from the same host-owned active session
identity or leaves strict isolation blocked. It never upgrades synthetic target
metadata; L10 still owns the full strict conjunction/default decision.

## 4. Redaction and containment rules

- Host UDS and asset paths remain private live values and are omitted from
  errors, evidence, runtime metadata, logs, docs, and descriptors.
- Handshake errors expose fixed codes and fields only; they never wrap raw
  `net.OpError` text across the public boundary.
- Frames are bounded before allocation. Handshake lines are ASCII, newline
  terminated, and at most 64 bytes.
- The guest agent runs as a dedicated non-root UID/GID with `/workspace` on a
  distinct size-bounded tmpfs and the image root drive read-only. Live
  acceptance requires UID/GID `1000`, no supplementary groups,
  and `NoNewPrivs: 1` in the guest process status.
- The guest process receives a fixed environment, fixed executable roots, no
  ambient host data, no network configuration, and no credentials.
- Copy paths retain L4 descriptor-relative `openat2` containment. Vsock framing
  cannot select local paths, ports, operations, or protocol versions through
  sideband metadata.
- Rootfs construction installs only the guest binary, fixed init/config files,
  required runtime libraries/devices, and an empty workspace mount point.

## 5. Crash, retry, cancellation, and cleanup semantics

Each host request owns one connection. Cancellation or deadline closes the
connection, preserves `errors.Is` through the private error chain, and yields
the fixed L4 canceled/timeout code. A handshake or response cannot be retried
automatically because copy-in may have crossed its publication point.

Readiness polling creates fresh connections and is bounded by the existing live
driver timeout. Unsupported version, malformed response, wrong operation,
not-ready, connection refusal, or a stale bridge never yields ready metadata.

Start failure cleanup uses a context independent of the canceled start context
and has its own fixed upper bound. Stop/delete send TERM with a bounded grace deadline,
escalate to KILL, wait/reap within an independent final deadline, then invalidate
the live session, close bridge connections, and remove API/vsock sockets and
ownership-proven target state. The immutable master assets are untouched and the
live test always uses a scratch rootfs copy.

Guest exec timeout/cancel first exercises L4 process-group cleanup. Whole-VM
teardown then proves that even a deliberately session-escaping guest process
cannot survive VM deletion. Repeated stop/delete is idempotent. Cleanup failure
or uncertainty is joined with the primary error and cannot be reported as
stopped, deleted, ready, or successful. State is not removed unless process
ownership, path identity, termination, and reap are all proven.

Prepared-Linux acceptance copies the content-locked Firecracker executable,
kernel, and rootfs into one private caller-owned launch directory before
constructing the driver. The copied executable and kernel paths, not the
externally installed distribution paths, are the exact paths passed to the
process runner and Firecracker configuration; all master digests are checked
again after teardown.
After cleanup, a new connection to the former bridge must fail and no stale
readiness/capability proof may survive.

## 6. Red-first fake and live acceptance tests

The first red commit locks:

- deterministic vsock device JSON and state-path containment;
- exact bounded Firecracker `CONNECT` handshake framing;
- partial read/write, malformed/oversized response, timeout, cancellation, EOF,
  pre-acknowledgement data, stale/wrong sockets, private socket permissions,
  and connection cleanup;
- guest AF_VSOCK listener bounds, one-frame dispatch, cancellation, and no
  AF_INET fallback;
- Linux AF_VSOCK construction plus a non-Linux build-tagged stub that fails
  closed, with Darwin and Windows cross-compile gates;
- readiness identity correlation and lifecycle-only behavior for configured,
  stale, wrong-process, wrong-state, wrong-inode, mismatched, malformed, or
  not-ready evidence, including boot/readiness races;
- caller-manufactured and cross-runtime ready targets rejected by the private
  session registry, plus invalidation on stop, delete, restart, process exit,
  bridge loss, and readiness failure;
- daemon-wide worker descriptors remain lifecycle-only and synthetic isolation
  labels remain blocked;
- asset input digest verification, safe provenance, reproducibility contract,
  guest binary/config presence, and default-test no-download/no-build guards;
- public error redaction with path, endpoint, token, argument, and payload
  canaries; and
- start-failure plus stop/delete process/socket/state cleanup;
- independent cleanup timeout, TERM deadline, KILL escalation, wait/reap,
  ownership-proven state deletion, and cleanup-uncertainty projection;
- symlink/socket substitution and post-cleanup reconnect rejection.

The prepared-Linux test is selected only by `l5_firecracker_vsock_integration`.
Once selected it never skips. It requires Linux x86_64, writable KVM,
the pinned Firecracker version, and assets produced by the checked-in pipeline.
`HAL_L5_DISTRIBUTION_DIR` names only the caller-installed distribution
directory for the tagged prerequisite and end-to-end tests; it is never
recorded in distribution artifacts or retained evidence. Before boot, the
tagged prerequisite validates provenance against the distribution manifest,
verifies the exact `SHA256SUMS` entry set and every referenced byte, rejects
unsafe roots/manifests/assets through no-follow opens, and uses read-only
filesystem inspection to prove `/usr/bin/hal-guest-agent` is present in the
built rootfs. The prerequisite creates a private digest-verified rootfs copy
through a no-follow file descriptor, then performs bounded read-only debugfs inspection
through a fixed stat/cat allowlist; it never gives debugfs a
caller-controlled asset pathname or command.
It boots the produced image and proves:

- API acceptance alone is not readiness;
- exact v1 in-guest readiness;
- stdout/stderr and non-zero exec exit;
- copy-in/copy-out byte and digest integrity;
- exec timeout and explicit cancellation;
- fail-closed behavior after guest-agent loss;
- whole-VM containment of an escaped guest process; and
- zero owned processes, sockets, mounts, and runtime state after teardown.

Missing KVM, build dependencies, Firecracker, assets, or required kernel/vsock
behavior is a test failure, never a skip or pass. Default tests remain fake-safe
and make no downloads, KVM calls, mounts, listeners, or process launches.

Cross-platform compile-only gates are:

```sh
GOOS=darwin GOARCH=amd64 go test -exec=true -count=1 -run '^$' ./internal/sandboxruntime/microvm/guestagent/vsock ./internal/sandboxruntime/microvm/firecrackerhost
GOOS=windows GOARCH=amd64 go test -exec=true -count=1 -run '^$' ./internal/sandboxruntime/microvm/guestagent/vsock ./internal/sandboxruntime/microvm/firecrackerhost
```

## 7. Non-goals and L6 handoff

L5 does not add guest networking, HTTP/CONNECT policy proxying, DNS behavior,
Linux firewall rules, rootless topology, credential adapters, OCI registry
resolution, template selection, cloud calls, scheduler defaults, or strict
secure-default composition. VM isolation/readiness proof cannot be projected
as network or credential enforcement.

L6 receives a live, bounded Firecracker guest execution substrate and owns only
the production policy proxy. L7 later owns network topology and inspected Linux
rules for Firecracker and Podman. L8 owns credentials; L9 owns OCI trust; L10
alone may compose strict success.

## Verification commands

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm/assets/build ./internal/sandboxruntime/microvm/guestagent/vsock ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost
go test -race -count=1 -timeout=240s ./internal/sandboxruntime/microvm/guestagent/vsock ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost
go test -count=1 -timeout=180s ./cmd -run '^TestL5'
test "$(go env GOOS)" = linux
go test -count=1 -timeout=60s -tags=l5_firecracker_vsock_integration ./internal/sandboxruntime/microvm/assets/localresolver -run '^TestL5PreparedLinuxImagePrerequisites$'
go test -list '^TestL5PreparedLinuxFirecrackerVsockE2E$' -tags=l5_firecracker_vsock_integration ./internal/sandboxruntime/microvm/firecrackerhost | grep -qx 'TestL5PreparedLinuxFirecrackerVsockE2E'
go test -race -count=1 -timeout=900s -tags=l5_firecracker_vsock_integration ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestL5PreparedLinuxFirecrackerVsockE2E$'
go test -count=1 -timeout=420s ./...
go test -count=1 -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

Run gofmt verification on changed Go files. Run
`golangci-lint run --new-from-rev 762ee1a61d2efc5bb9241a6e87409ca20d68f976 ./...`
only when `command -v golangci-lint` succeeds.
