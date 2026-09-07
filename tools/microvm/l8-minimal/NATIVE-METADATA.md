# Native Buildroot metadata compatibility

Status: the reviewed bounded recipe/path correction is implemented. The frozen
RED tests remain unchanged. This is not acceptance of a new native-built image.

## Observed failure and authority

Native build 3 selected clean source
`99b58782390f0805efbdaf01d4eadbb52f70bb79`. Buildroot completed its filesystem
tar, but host canonicalization failed before ext4 generation. The retained tar
is 274,247,680 bytes, SHA-256
`920d4709395af20e7fa5856f241b805392b59b742b3d32d4058d34d523501f13`.
Its 20,801 headers contain these seven incompatible entries:

- `dev/fb0` through `dev/fb3`: character devices, mode 0640, UID 0, GID 5;
- `usr/bin/[` and `usr/bin/[[`: mode 0777, root-owned symlinks to
  `../../bin/busybox`; and
- `var/www`: directory, mode 0755, UID/GID 33.

The first framebuffer header is rejected before device omission. The applet
names also fail the independent image extractor and directory-record parser.
The final web-directory ownership fails both archive ownership validators.
The empty stdout receipt and absent publication are correct fail-closed results,
not proof that this real build or an ext4 image passed.

These shapes originate in pinned Buildroot 2026.05.1 and BusyBox 1.38.0, not
candidate-selected policy. The unchanged Buildroot source archive SHA-256 is
`ae7f706f087b9ae9083a10a587368dfbf53103c28bf81c2d690198dc4090cb58`.
Its complete `system/device_table_dev.txt` SHA-256 is
`0529745f46720eb083f5c31bcf700a0fb21d09dff750aa41c0cde4ed0b54cc43`.
The committed test fixture records its 52 active rows, preserving order and
fields while omitting comments/normalizing whitespace. It is deterministic test
input, not a new source pin, download, receipt or production authority.

## Smallest selected recipe correction

Keep `BR2_ROOTFS_DEVICE_CREATION_STATIC=y`. Select a committed minimal-only
`static-devices.txt` through the existing `BR2_ROOTFS_STATIC_DEVICE_TABLE` field.
It contains exactly the upstream 51 other active rows, in order, with only
`/dev/fb c 640 0 5 29 0 0 1 4` omitted. Do not change the shared L5/L7 tables,
device mode, default device rows, kernel configuration or runtime mounts.
The selected init already mounts devtmpfs on `/dev`, and the canonicalizer
already omits every admitted character/block entry. Omitting only the unused
framebuffer row avoids its contradictory group ownership without broadening
device admission or silently changing the entire boot-device policy.

Add `/var/www d 0755 0 0 - - - - -` to the existing minimal `permissions.txt`.
The selected configuration applies this table after `system/device_table.txt`;
the explicit override therefore replaces the upstream 33:33 ownership during
fakeroot, not by chowning a host directory. No web server is selected. Preserve
the locked www-data account and directory contents rather than deleting them.
Unexpected nonroot files/directories/devices must remain rejected by the
canonicalizer and image extractor. Do not normalize arbitrary candidate owners.

## Exact BusyBox tuple, not a wider filename alphabet

Preserve shell compatibility by accepting exactly the two canonical image paths
`usr/bin/[` and `usr/bin/[[`, only as symlinks with mode 0777, UID/GID 0, size
zero in tar, and the exact link target `../../bin/busybox`. The measured inode
inspection must additionally resolve them to the already-required BusyBox
inode. Existing regular-file bytes and executable pins stay unchanged.

The assembler may recognize these two paths after its existing optional `./`
normalization, but may not clean traversal into an exception. The independent
extractor accepts only canonical relative paths. The inspector must evaluate
the complete parent/path and tuple, not globally accept a `[` directory leaf.
Pass directory context into its private record parser or apply the equivalent
contextual check before accepting the entry. Keep all existing numeric-inode
queries: no image-controlled name may become a debugfs inspection command.

Do not broaden `guestName`, `safeName`, `safeLeaf`, generic link-target matching,
account locations, public artifact names or unrelated validators. Reject other
bracket names/locations, regular files/directories in either special path,
wrong mode/UID/GID/target, duplicates, symlink parents, traversal, controls,
whitespace and command metacharacters. The ext4 ownership writer already uses
validated canonical paths; a tagged real-ext4 case must prove the two literal
names survive that command parser without aliasing or command injection.

## RED and later verification

`TestNativeMetadataRecipeStaticRows` reads the actual selected config/table and
compares all active rows against the independently recorded upstream fixture.
At RED the configured upstream path resolves explicitly to that fixture, so
missing future files are not the failure. `TestCanonicalNativeRecipeMetadata`
projects the affected rows/permission override into a small tar and calls the
actual canonicalizer: framebuffer-only, web-only and combined cases are
independent. This models the relevant makedevs row effects; it does not execute
Buildroot or fakeroot and is not a successful build claim.

`TestCanonicalNativeBusyboxPaths` independently exercises the actual archive
conversion and unchanged owner/device negatives. Separate extraction and fake
inode-inspection subtests in `TestMinimalBusyboxPaths` reach both downstream
boundaries even when canonicalization rejects first. Baseline controls execute
without the new paths. `TestMinimalBusyboxPublicNamesRemainRestricted` locks
the unrelated validators. The tagged `TestMinimalBusyboxRealExt4` runs the
actual small-image producer/inspector using required e2fsprogs 1.47.4, not guest
execution or a container. At RED its archive-extraction failure leaves later
ext4 assertions unreached; report that honestly.

After reviewed GREEN, run focused/race/default/tagged tools and minimalprofile
tests, relevant source/default guards, vet, formatting and diff checks. The
old tar remains read-only diagnostic evidence: never rewrite/relabel/publish
it as a new selected-source result. Accepted source changes require fresh
clean native builds and unchanged measured-image/reproducibility gates. No
cache, source/dependency pin, receipt, runtime, credential or strict claim changes.

After separate fixed-source review and supervisor approval, a fresh private
diagnostic-only copy of the retained tar may apply only the reviewed metadata
transformations and exercise the full-size ext4 pipeline. Keep the original
tar/stage/source untouched; name all output explicitly diagnostic. Such a probe
can expose later real-image mismatches before another expensive clean build,
but cannot mint a B1 publication request, accepted source identity or receipt.
It never substitutes for the two fresh final-source builds. No such probe has
run for this correction.

## Implemented verification boundary

The actual canonicalizer, extractor and contextual inode inspector now pass
the original recipe/applet regressions. The real small-ext4 baseline and applet
case both pass; the latter retains exactly two additional inodes and directory
records without changing logical file bytes or installed Pi-tree pins. This
exercises real ownership commands and inode inspection, not guest execution.
Additional tests reject raw trailing-slash/dot spellings and verify that a
shared symlink inode cannot bypass the applet's per-path target validation.
The ordinary shared-inode control still passes. Generic archive, public-name,
link-target, account-location and default-test tool guards remain unchanged.

Focused command: `go test -p 2 -race -count=3
./tools/microvm/l8-minimal/assembler
./internal/sandboxruntime/microvm/assets/minimalprofile
-run '^(TestNativeMetadata|TestCanonicalNative|TestMinimalBusybox|TestMinimalDefault)'`.
Run the whole adjacent tools/image suites with `-tags=microvm_assets_integration`
for required real local ext4 and fake runtime/Git checks, plus scoped vet and
format/diff checks. Required image tools must be present, not skipped. Actual
full-size diagnostic inspection, final-source clean builds and live acceptance
remain separate, unperformed gates.
