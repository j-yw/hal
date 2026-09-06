# L8 D7 cache source locks are authored from measured archives

This slice authors the exact L8 `cache.manifest` from measured Node, Pi,
shrinkwrap, and transitive npm archive bytes. Digests are not invented.
Tarball bytes stay in the operator cache; only the manifest, tests, and
this document are committed. `VerifyL8DistributionBundle` is not called.
HL8E remains unissued. This slice does not claim D7 live, does not claim
L8 complete, does not claim L10, and does not claim L11. It does not
change live D7 stub fatals.

The lock lives at `tools/microvm/l8/cache.manifest`. Format matches L5:
sorted lines `digest<TAB>size<TAB>filename`, lowercase hex SHA-256, no
extra fields. `LC_ALL=C` sort order is required. Filenames are unique
basename-only entries and must not duplicate any L5
`tools/microvm/l5/cache.manifest` name, especially not `firecracker-*.tgz`.

## Measured required locks

These three names are required by `tools/microvm/l8/verify-cache.sh` and
are locked from real downloaded/extracted files:

- `node-v22.22.0.tar.xz` size `50902788` sha256
  `4c138012bb5352f49822a8f3e6d1db71e00639d0c36d5b6756f91e4c6f30b683`
  from official `https://nodejs.org/dist/v22.22.0/node-v22.22.0.tar.xz`
- `pi-coding-agent-0.82.1.tgz` size `4978133` sha256
  `8343ab95cbab5766f2f5d48844df8db13e772ead2e2976166cbb820a29dacb7d`
  from `npm pack @earendil-works/pi-coding-agent@0.82.1`, renamed from
  `earendil-works-pi-coding-agent-0.82.1.tgz`
- `pi-shrinkwrap-0.82.1.json` size `61545` sha256
  `ac68e6c713a3fa13b56d2e41855dcfce44fe2ca1645ccc90977bea3afbeaf50a`
  extracted from `package/npm-shrinkwrap.json` inside that tarball

## Transitive npm archives

The Pi shrinkwrap is lockfileVersion 3. Every non-root shrinkwrap package
is packed with `npm pack` for each resolved integrity (and `name@version`
when a lockfile record omits integrity). Each resulting unique `.tgz` is
measured for sha256 and size. The authored manifest contains 142 entries:
the three required names plus 139 transitive npm archives. Unit tests do
not download; they lock the committed manifest text and exercise
`verify-cache.sh` with temp caches of copied measured bytes or synthetic
files only where verifying parser errors.

`verify-cache.sh` still fail-closes on missing files, unsorted records,
duplicate L5/L8 filenames, and an absent L8 `cache.manifest`. Exact-set
verification continues to require the combined L5 and L8 manifests. This
slice does not boot a VM and does not issue HL8E.

## Focused fake-only commands

```
go test ./tools/microvm/l8 -count=1
go test ./cmd -run '^TestL8D7CacheSourceLocks' -count=1
bash -n tools/microvm/l8/verify-cache.sh
go vet ./tools/microvm/l8 ./cmd
```

These commands are fake-only. They do not boot a VM, call billed APIs, or
select live tags.

## Broad verification

```
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
- issue HL8E or enable `generateEvidence` success;
- call `VerifyL8DistributionBundle`;
- generate `verified-pinned-callsites.hl8e` from a fixture;
- treat L5 images as L8 proof;
- boot Firecracker or require KVM;
- commit Node/Pi/npm tarball bytes;
- wire sandboxd, `hal run`, `hal auto`, or factory;
- call billed Azure/OpenAI;
- provision Hetzner/Lightsail;
- merge to `develop`.
