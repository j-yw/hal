# L8 minimal image profile: bundle verification foundation

This B1 slice implements the distinct `l8-minimal-credentials-v1` metadata and
read-only verifier selected by the L8 contract reset. It does not build an
image, boot a guest, deliver credentials, issue runtime launch authority, or
enable strict selection. L8, L10, and L11 live acceptance remain unavailable.

## Explicit API and ownership

`build.L8MinimalDistributionManifest`, `L8MinimalProvenance`,
`L8MinimalSourceLock`, and `L8MinimalFinalInspection` are separate contracts.
Legacy distribution JSON types and validators are unchanged. The selected
guest protocol remains the currently implemented `guest-agent-v1`; this
foundation does not advertise unimplemented credential transport capabilities.

Call `localresolver.VerifyL8MinimalDistributionBundle` explicitly with a
`L8MinimalDistributionRequest`: the distribution path and lock timestamp, an
existing resolver-issued L7 parent, and `Expected L8MinimalExpectedIdentity`.
The expected source revision, rootfs digest, init/agent digests, Node/Pi runtime
identities, source-lock digest, final-inspection digest, and provenance digest must come from
trusted build/source pins outside the candidate verification operation.
Reading those pins from the untrusted candidate itself defeats this boundary.
There is no trust-on-first-use fallback, signature service, or new publisher.

Pinning provenance also binds the source tree, builder-image digest, source
date epoch, and duplicated profile facts to the trusted producer's record.

The result is an opaque `VerifiedL8MinimalDistribution`. It retains all seven
candidate files, a private L7 asset lease, and the parent metadata files. Copies
share ownership; callers must call `Close`, including on later selection error.
Close is idempotent and serialized with selection. Failed verification closes
its own partially acquired handles. Public metadata mutations cannot alter
retained correlation.

`SelectL8MinimalDistribution` rechecks file bytes, inode identities, directory
identity, exact inventory, and the retained L7 parent before returning a cloned
`l8-minimal-credentials-image` descriptor. This selection is planning-only.
It is not a Jailer, guest-readiness, network, credential, or strict proof.
Neither a legacy L7 nor L8 seal is issued. A later runtime handoff must copy or
duplicate retained verified bytes through a separately reviewed transfer seam;
validating here and blindly reopening descriptor paths during launch is unsafe.

## Exact bundle and measured facts

The bundle contains exactly these seven regular, no-follow files:

- `SHA256SUMS`
- `distribution-manifest.json`
- `final-inspection.json`
- `provenance.json`
- `rootfs.ext4`
- `sources.lock.json`
- `vmlinux`

The checksum file has six ordered entries, excluding itself. Every installed
file is measured through retained descriptors; source and inspection digests
are correlated with the profile and caller pins. The kernel must match the
verified parent kernel exactly. The parent rootfs identifies provenance, not
the child rootfs. The parent five-file measurements are revalidated through
the real L7 lease; stale content, substituted identity, symlinks, and even
byte-identical file replacements after retention fail closed.
Directory enumeration reads at most eight entries to establish the exact
seven-file set, rather than loading every entry from an oversized directory.

Each of the four child JSON documents and `SHA256SUMS` is decoded from a
private byte snapshot bounded to 4 MiB. Its exact size and SHA-256 must match
the retained file pin before any semantic decode or checksum scan. Strict JSON
decoding rejects unknown fields and trailing data. This prevents a file from
being hashed, changed for decoding, and restored before the final currentness
check; later file mutation cannot change the already authenticated buffer.
Retained-file and directory currentness checks still run independently.

This snapshot binding is specific to the new minimal child metadata path.
Existing L7 parent verification and `measureL8ParentEvidence` retain their
pre-existing read/hash behavior and are not repaired or strengthened by this
slice. The minimal verifier continues to require that existing parent
authority; no new parent-verifier or legacy HL8E guarantee is claimed here.

The minimal executable inventory is exactly `hal-init`, `hal-guest-agent`,
`node`, and `pi-launcher`, each a regular root-owned executable with mode 0755
and pinned digest/size. The runtime identity binds Node 22.22.0, Pi 0.82.1, and
the ordered offline dependency inventory. Each npm dependency records its own
version. The source inventory digest reuses the existing canonical algorithm
and pure inventory validation; this does not enter legacy process-policy
validation or issue a legacy image profile.

Final inspection records bounded counts of unique reachable inodes visited,
directory records visited, and logical bytes inspected. These are traversal
measurements, not the ext4 allocated inode capacity; no ordering between inode
and directory-record totals is assumed. It also records an explicitly empty
findings array, non-root agent/workload UID 1000,
and private workspace ownership/mode. The inspector must report credential
markers, filesystem privilege, historical role executables, incomplete scans,
and other forbidden profile findings rather than emit a synthetic pass label.
The verifier rejects missing counts, absent/nonempty findings, unsafe process
metadata, unknown JSON fields, and cross-document mismatches.

The resolver measures the **outer bundle bytes**. It does not parse ext4,
measure the actual binaries inside it, inspect source archives, or establish
that an empty findings list is true. Those are trusted producer/inspector
responsibilities, authenticated here by caller-pinned document/image digests.
Tests use tiny deterministic files, not an accepted guest image. Real image
construction, bounded final-image inspection, and no-skip prepared-Linux tests
are required before this metadata can support a later live handoff.

## Preserved boundaries

The minimal path neither reads nor requires HL8E and has no policy-authority
import. Legacy `VerifyL8DistributionBundle`, `tools/microvm/l8/build.sh`, and
`verify-final-image.sh` retain their existing fail-closed HL8E requirements.
Generic `VerifyDistributionBundle` and `ResolveDistribution` reject the new
schema/profile rather than fall back to L5 or relabel it as legacy L8.
There is no active guest seccomp claim, no process launch, no network action,
no credential access, and no billed provider call in this slice.

## Verification

The first test commit precedes implementation. Focused default tests use real
temporary files with fake image contents and require no live environment:

```sh
go test -count=1 ./internal/sandboxruntime/microvm/assets/build ./internal/sandboxruntime/microvm/assets/localresolver
go test -race -count=10 ./internal/sandboxruntime/microvm/assets/localresolver -run '^TestL8Minimal'
go vet ./internal/sandboxruntime/microvm/assets/build ./internal/sandboxruntime/microvm/assets/localresolver
git diff --check
```

The parent integration must additionally run its broad test, typecheck, vet,
build, and documentation gates. These checks are not build/boot or live L8
acceptance. No selected prepared-Linux command is introduced by B1.
