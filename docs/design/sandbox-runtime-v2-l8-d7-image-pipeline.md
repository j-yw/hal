# L8 D7 image pipeline scripts exist; issuance is not accepted

This slice lands fail-closed L8 Buildroot pipeline scripts under
`tools/microvm/l8/`. The scripts exist. Issuance is not accepted.
`VerifyL8DistributionBundle` remains the sole issuer. This slice does not
call that issuer, does not generate `verified-pinned-callsites.hl8e` from a
fixture, and does not treat an L5 rootfs/vmlinux as an L8 production image.
`fixture-as-strict` is forbidden.

The pipeline is modeled on L7 with an L8-specific profile. It does not rewrite
L5 or L7 digests, descriptors, or image claims. Parent L7 evidence is
required. The parent must be an already produced L7 distribution
(`imageProfile` `l7-firecracker-network-v1`); missing parent L7 fails closed.

HL8E is still unissued. Builds fail closed when HL8E, parent L7, the native
bootstrap path, or required phase-head guest binaries are missing. Native
bootstrap is assembled with `tools/microvm/l8/role-bootstrap/build.sh`
(`as`/`ld` only) from `tools/microvm/l8/role-bootstrap/hal-guest-role-bootstrap.S`.
A Go `cmd/hal-guest-role-bootstrap` package is not an L8 native identity. Node
22.22.0 and `@earendil-works/pi-coding-agent` 0.82.1 are fail-closed required
cache filenames (`node-v22.22.0.tar.xz`, `pi-coding-agent-0.82.1.tgz`,
`pi-shrinkwrap-0.82.1.json`). This slice does not download them.
The exact L8 cache manifest is checked in with the Node, Pi, shrinkwrap, and
transitive npm archive filename, size, and SHA-256 locks. The external cache
directory must contain that exact set; missing, additional, or mismatched cache
content still fails closed, and this pipeline does not download it.

The seven-file bundle layout is:

- `SHA256SUMS`
- `distribution-manifest.json`
- `final-inspection.json`
- `provenance.json`
- `rootfs.ext4`
- `sources.lock.json`
- `vmlinux`

Descriptor identity is `l8-production-credentials-image` with labels
`firecracker`, `reproducible`, `network-profile`,
`production-credentials-profile`. Manifest/provenance protocol is
`guest-agent-v2` with features `copy_in`, `copy_out`,
`credential_delivery_v2`, `exec`, `readiness`, `ssh_agent_relay_v1`.
Image profile is `l8-production-credentials-v1`.

Pinned docker image:
`registry.gitlab.com/buildroot.org/buildroot/base@sha256:f1e7f009dad6b6f44bf5fcb4b0b89c9228e42f9fe689142774b1db802d4c93c6`.
Builds use `--pull=never --network=none`, a clean git tree, absolute
cache/output outside the repo, distinct cache/output, and `0700` parents.
L5 `cache.manifest` remains the source-cache baseline. The L8 verifier requires
a separate exact L8 manifest and never accepts runtime files by filename or
nonempty-file checks alone.

This slice does not claim D7 live, does not claim L8 complete, does not claim
L10, and does not claim L11. It does not change live D7 stub fatals.

## Scripts

```
tools/microvm/l8/build.sh
tools/microvm/l8/build-in-container.sh
tools/microvm/l8/post-build.sh
tools/microvm/l8/verify-reproducible.sh
tools/microvm/l8/verify-final-image.sh
tools/microvm/l8/verify-image-profile.sh
tools/microvm/l8/verify-cache.sh
```

`build-in-container.sh` invokes `verify-image-profile.sh` for immutable rootfs
inspection without using HL8E as an image-layout prerequisite.
`verify-final-image.sh` remains the separate HL8E and parent-L7 gated wrapper;
the profile-only verifier does not issue evidence or accept L8.

The immutable inspection is bounded to the fixed profile's 65,536 inodes,
262,144 parsed directory records, and 512 MiB of aggregate logical
regular-file content. Starting at root inode 2, it visits each reachable
directory once with an independent `debugfs ls -p -r` request. Every request
must complete without a debugfs diagnostic, every nonempty output record must
parse, and every visited directory must contain exactly one matching `.`
record. Reserved metadata and unlinked inodes are not guest-reachable entries
and are not treated as files.

The traversal rejects control-byte filenames (including newline), plus the
existing `.npmrc`, `.npm`, `id_rsa`, `*.pem`, and `npm-session` filename
policy. It deduplicates hard-linked regular inode IDs, sums the logical size
reported by their directory entries, rejects setuid/setgid mode bits, and
checks reachable regular inodes for file capabilities. The batched attribute
query is accepted only when debugfs echoes every requested inode in exact
order. It then extracts each deduplicated regular inode with an independent
debugfs request, requires the extracted size to equal the inventoried logical
size, validates the required setpriv/account content from those bounded
extractions, and searches each file for PEM-style private-key markers. There
is no shared content pipeline whose early consumer exit could hide a producer
failure, and required content is not read before aggregate size validation.

This is defense in depth, not an exhaustive secret detector: it does not
identify DER, PKCS#12, encoded, compressed, archive-contained, or custom key
blobs. It also makes no claim about inaccessible filesystem slack or unlinked
data. Changes to the image size, inode count, directory-record bound, or
secret-pattern policy must update the Buildroot profile, verifier, and tests
together.

Reproducible verification, when a later issuance slice supplies HL8E, parent
L7, native bootstrap, and the locked cache, is:

```sh
tools/microvm/l8/verify-reproducible.sh \
  --cache "$HAL_L8_BUILD_CACHE" \
  --output "$HAL_L8_DISTRIBUTION"
```

`HAL_L8_PARENT_L7` must point at a canonical parent L7 distribution. Two
independent offline builds byte-compare every exported artifact. Unit tests
cover argument and safety gates without running Buildroot.

## Focused verification

```sh
go test ./tools/microvm/l8 -count=1
go test ./cmd -run 'TestL8D7ImagePipeline' -count=1
bash -n tools/microvm/l8/build.sh tools/microvm/l8/build-in-container.sh tools/microvm/l8/post-build.sh tools/microvm/l8/verify-reproducible.sh tools/microvm/l8/verify-final-image.sh tools/microvm/l8/verify-image-profile.sh tools/microvm/l8/verify-cache.sh
go vet ./tools/microvm/l8 ./cmd
```

The profile package includes deterministic, bounded local real-ext4 fixtures
for the image scanner. Those tests require host `mke2fs` and `debugfs` and skip
when either tool is unavailable; the remaining focused tests are fake-only.
This slice does not boot a VM, run a full Buildroot build, call billed APIs, or
select live tags.

## Broad verification

```sh
go test ./...
go vet ./...
make docs-check
make build
git diff --check
```

`golangci-lint` is reported only when `command -v golangci-lint` succeeds.

## Non-goals

This slice does not:

- accept D7 prepared-Linux live proof;
- issue HL8E or accept D7 live proof;
- call `VerifyL8DistributionBundle` with dummy parent L7 as a pass;
- generate `verified-pinned-callsites.hl8e` from a fixture;
- treat L5 rootfs/vmlinux as an L8 production image;
- run a full Buildroot build;
- download Node or Pi sources;
- claim L8, L10, or L11 complete;
- wire sandboxd, `hal run`, `hal auto`, or factory defaults;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`.
