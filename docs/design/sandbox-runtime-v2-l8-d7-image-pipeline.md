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
bootstrap path, or required phase-head guest binaries are missing. Node
22.22.0 and `@earendil-works/pi-coding-agent` 0.82.1 are fail-closed required
cache filenames (`node-v22.22.0.tar.xz`, `pi-coding-agent-0.82.1.tgz`,
`pi-shrinkwrap-0.82.1.json`). This slice does not download them.

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
L5 `cache.manifest` / `verify-cache.sh` remain the source-cache baseline;
L8 adds the required runtime filenames without inventing their digests.

This slice does not claim D7 live, does not claim L8 complete, does not claim
L10, and does not claim L11. It does not change live D7 stub fatals.

## Scripts

```
tools/microvm/l8/build.sh
tools/microvm/l8/build-in-container.sh
tools/microvm/l8/post-build.sh
tools/microvm/l8/verify-reproducible.sh
tools/microvm/l8/verify-final-image.sh
tools/microvm/l8/verify-cache.sh
```

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
bash -n tools/microvm/l8/build.sh tools/microvm/l8/build-in-container.sh tools/microvm/l8/post-build.sh tools/microvm/l8/verify-reproducible.sh tools/microvm/l8/verify-final-image.sh tools/microvm/l8/verify-cache.sh
go vet ./tools/microvm/l8 ./cmd
```

These commands are fake-only. This slice does not boot a VM, run a full
Buildroot build, call billed APIs, or select live tags.

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
