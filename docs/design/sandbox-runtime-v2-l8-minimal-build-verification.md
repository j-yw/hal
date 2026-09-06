# L8 minimal staged-input artifact producer (B2 partial)

This slice produces a real, inspected ext4 and an exact seven-file
`l8-minimal-credentials-v1` bundle. It is **not completion of B2**, an offline
Node/Pi source builder, a boot test, credential delivery proof, or strict
readiness. Legacy HL8E issuance and all default runtime gates are unchanged.

The implementation is isolated in
`internal/sandboxruntime/microvm/assets/minimalprofile/` and the separate
`tools/microvm/l8-minimal/` executable. It does not modify legacy image tools,
Jailer, guest entrypoints, runtime selection, or L10/L11 admission.

## Producer inputs and remaining source-build dependency

`minimalprofile.PublishRequest` is trusted producer input. The executable
requires its JSON SHA-256 through an independent trusted channel, authenticates
a bounded immutable copy, rejects symlinks/unknown fields/trailing JSON, then
decodes the exact authenticated bytes. Do not compute that pin from a candidate
bundle's own metadata or accept a request supplied by an untrusted workload.

The request currently uses Go's exported field names in JSON:

- `ParentDir`: absolute genuine L7 five-file distribution. The existing
  `VerifyDistributionBundle` must issue its L7 profile and asset lease. Exact
  parent file measurements are re-correlated by the B1 verifier; the child
  kernel is a digest-authenticated copy of that parent's kernel.
- `SourceDir`, `Sources`: absolute offline source directory and independent
  ordered `L8LockedSource` pins. Every required source's size and SHA-256 are
  verified. Existing B1 rules require Node `22.22.0`, Pi
  `@earendil-works/pi-coding-agent@0.82.1`, its shrinkwrap and ordered npm
  archives. This verifies source availability, **not their compilation or
  installation into the staged rootfs**.
- `Archive`, `ArchiveSHA256`: absolute canonical, uncompressed rootfs tar and
  its independent trusted build digest. This is a previously assembled offline
  rootfs, not a host directory copied opportunistically into an image.
- `Pins`: independent `GuestInitSHA256`, `GuestAgentSHA256`, `NodeSHA256`,
  `PiLauncherSHA256`, `InitScriptSHA256`, and `InstalledPiTreeSHA256`. Required
  executable bytes must match the trusted build. The init-script pin must
  identify the selected UID1000/L7-network bootstrap; this tool does not infer
  script behavior from filenames or execute guest binaries on the host.
- `SourceRevision`, `SourceTree`, `Epoch`, `BuildImageDigest`: authenticated
  staged-build provenance. Revision and tree are exact forty-hex identities,
  the tree is prefixed `tree-`, and epoch is positive and within the supported
  ext4 timestamp range. The builder digest is pinned to
  `sha256:f1e7f009dad6b6f44bf5fcb4b0b89c9228e42f9fe689142774b1db802d4c93c6`.
  Requiring this declared identity is not evidence that this executable ran
  that container. Actual Buildroot/Node/Pi source assembly remains separate.
- `OutputDir`: an absent final directory under an existing absolute,
  UID-owned private parent. No existing output is overwritten.

There is intentionally no source installer that pretends the historical L8
build works for this profile. The remaining producer must build untagged
`hal-init` and `hal-guest-agent`, Node22.22.0 and Pi0.82.1 plus its complete
offline dependency closure, retain the selected L7 bootstrap, produce the
canonical staged tar, and independently authenticate the installed-tree pin.
Do not use `l8_production_pid1` or install the four historical role binaries.

## Actual image construction and inspection

The local producer requires `mke2fs`, `debugfs`, `e2fsck` and their EXT2FS library
at version `1.47.4`. These are trusted host build tools; their executable and
dynamic-library provenance belongs to the prepared build environment. No
container pull, privileged operation, filesystem mount, VM, network request,
package install, host chown, or credential synchronization occurs here.

The tar accepts parent-before-child regular files, directories and safe
symlinks only. Names are bounded by the archive size and restricted to the
documented parser's ASCII token alphabet; absolute/traversing names, duplicate
records, symlink parents, hardlinks, devices, sockets, sparse/PAX extensions and
xattrs fail closed. `/` is implicit; do not emit a `.` root record. Archive UID
and GID must both be zero except `/workspace` and `/run/agent`, which must both
be UID/GID1000 directories. Host extraction uses private staging permissions;
the requested inode modes, ownership and fixed timestamps are applied to the
actual ext4 with checked debugfs commands, not to host-owned files.

The image has a fixed UUID/hash seed, explicit ext4 features, fixed inode
capacity, fixed timestamps, no host mke2fs configuration, and a deterministic
size formula. `e2fsck -f -n` must report a clean result before inspection.

The inspector traverses reachable directories from inode2 and rejects malformed
or incomplete records. Bounds are 65,536 unique reachable inodes, 262,144
directory records and 512MiB aggregate regular-file logical content. Reserved
unreachable metadata inodes are not extracted. Every reachable inode's
attributes are inspected (this minimal profile permits no xattrs); every
regular file is read, size-checked, hashed and scanned. Failed or truncated
reads, setuid/setgid bits, capabilities, historical role names, known credential
filenames, private-key markers, npm auth assignments and canary markers reject
publication. This is a bounded known-pattern check, not a proof that arbitrary
opaque bytes can never encode credentials. The trusted offline assembler must
not include credentials at all.

The four measured roles are exact root-owned0755 regular files at
`/sbin/hal-init`, `/usr/bin/hal-guest-agent`, `/usr/bin/node`, `/usr/bin/pi`.
Required parent directories must be root-owned, traversable/readable by UID1000,
and not group/world-writable. Busybox, setpriv, init, network applets, locked
accounts, empty resolver file and UID1000 workspace/run directories are checked.
Safe Busybox symlink resolution is bounded; long/non-fast symlinks fail closed
in this initial profile.

Account checks parse complete passwd/group/shadow records with unique names,
valid field counts, safe names/paths and numeric IDs. Root is UID/GID0 with
`/root` and `/bin/sh`; workload is UID/GID1000 with `/workspace` and `/bin/sh`.
Their UID/GID identities cannot be aliased by another account/group. Passwd
entries require the `x` shadow placeholder, never empty or inline passwords;
each account must have exactly one matching shadow record locked by `!` or `*`.
Missing, duplicate or orphan shadow records and malformed aging fields fail.
Primary groups and group members must resolve consistently; group passwords
are restricted to `x`, `!`, or `*`. Additional coherently locked accounts and
groups are allowed. This does not add a general guest user-policy evaluator.

Pi lives at `/usr/lib/pi`, with its complete dependencies below
`/usr/lib/pi/node_modules`. The inspector checks package name/version and
requires dependency contents, root ownership, workload-readable files and
traversable directories. Symlinks must resolve inside that installed tree.
The installed-tree digest is SHA-256 of records sorted by absolute guest path:

```text
path NUL type NUL octal-mode NUL decimal-uid NUL decimal-gid NUL digest NEWLINE
```

Types are `directory`, `regular`, `symlink`; directory digests are empty,
regular digests hash file bytes, and symlink digests hash target bytes. The
`/usr/lib/pi` directory itself is included. This digest is separate from
`Runtime.PiDependencyTreeSHA256`, whose existing B1 meaning is the canonical
source-archive inventory. A source list alone never substitutes for the
independent installed-tree pin.

## Publication and downstream boundary

Only these seven files are published after B1 validation:

```text
SHA256SUMS
distribution-manifest.json
final-inspection.json
provenance.json
rootfs.ext4
sources.lock.json
vmlinux
```

Inspection records come from the actual scan. Canonical JSON and ordered
checksums are generated from measurements, not supplied inspection assertions.
File inputs are opened nofollow and copied into private digest-authenticated
snapshots. Parent currentness is rechecked. The exact B1 verifier validates the
new bundle against producer-derived expected hashes and resolver-issued parent
authority before atomic no-replace publication. Each output file is synced.
Competing publishers cannot overwrite one another. A filesystem error after
the final rename can leave the complete output present with uncertain directory
durability; callers must treat an error as failure and verify any such output
before manual recovery, never blindly retry with overwrite.

Standalone image cancellation remains active through the final image hash,
publication copy and file sync. Cancellation observed at the final context
check immediately before the no-replace rename aborts publication and releases
its private temporary output. The final context check and filesystem rename
cannot be one atomic operation: cancellation racing after that check may
commit successfully. Once rename commits, there is no retroactive deletion;
directory sync still determines durability. Deterministic CLI-free primitive
tests exercise cancellation during copy and at EOF, while a tagged inotify
regression observes cancellation after inspection and before publication.

The JSON `Receipt` is returned **outside** the seven-file bundle. Retain its
`Expected`, archive digest and installed-tree digest through the trusted
producer channel. Future B1 consumers must use this independently retained
identity, not reconstruct it from a candidate's checksums. No runtime-owned
FD handoff, default selection, VM boot, workload execution or credential
authority is provided by this slice.

## Commands and acceptance evidence

With trusted inputs already prepared (there are no automatic downloads):

```sh
go run ./tools/microvm/l8-minimal -request /absolute/trusted-request.json -request-sha256 TRUSTED_REQUEST_SHA256
```

Default gates are CLI-free. They use fake inspector transcripts, bounded local
archive/file fixtures, request authentication, and receipt round trips. The
source guard selects the actual untagged Linux test files and rejects process
imports or references to image-production/probe helpers; seeded negative cases
keep that guard effective.

```sh
go test -p 2 -count=1 ./internal/sandboxruntime/microvm/assets/minimalprofile ./tools/microvm/l8-minimal
go test -p 2 -race -count=3 ./internal/sandboxruntime/microvm/assets/minimalprofile ./tools/microvm/l8-minimal
go vet ./internal/sandboxruntime/microvm/assets/minimalprofile ./tools/microvm/l8-minimal
go test -p 2 -count=1 ./internal/sandboxruntime/microvm/assets/localresolver -run '^TestL8Minimal'
```

Real ext4 fixtures and all tool/version probes require the explicit
`linux && microvm_assets_integration` build constraint:

```sh
go test -p 2 -tags=microvm_assets_integration -count=1 ./internal/sandboxruntime/microvm/assets/minimalprofile
go test -p 2 -tags=microvm_assets_integration -race -count=3 ./internal/sandboxruntime/microvm/assets/minimalprofile
```

`TestMinimalRealExt4Production` makes and inspects real ext4 twice;
`TestMinimalSevenFilePublisher` repeats all seven files and checks B1 selection
with resolver-issued fixture parent correlation. Other focused tests cover
archive/process/tree tamper, unsafe metadata, credentials, UID/traversal,
incomplete scans, excessive bounds, cancellation, nofollow and competing
publication. **Their executable, kernel and source payloads are fixtures.**
They do not establish that the real Node/Pi closure builds or boots. Selected
tagged real-tool fixtures fail if exact e2fsprogs1.47.4 is unavailable; there is
no availability-based skip that can stand in for artifact acceptance. Untagged
tests do not execute version probes, including when tools happen to be present.

Full B2 artifact acceptance still requires a genuine L7 parent, independently
verified offline cache and pinned builder, genuine staged runtime provenance,
two independent full source builds with identical artifacts, and review of the
installed tree/receipt. At implementation time no L7/cache path was configured,
the pinned builder was absent from local Podman, and Docker image inspection
was permission-denied. No pull or installation was attempted. `/dev/kvm` is
also absent, but it is not needed for these offline fixture tests; live strict
acceptance remains a separate, still blocked gate.
