#!/usr/bin/env bash
set -euo pipefail

readonly build_image_digest=sha256:f1e7f009dad6b6f44bf5fcb4b0b89c9228e42f9fe689142774b1db802d4c93c6
readonly source_root=/src
readonly cache_root=/cache
readonly buildroot_source=/build/buildroot
readonly buildroot_output=/build/output
readonly download_root=/build/download

export TZ=UTC
export LC_ALL=C
export LANG=C
export SOURCE_DATE_EPOCH
export KBUILD_BUILD_USER=hal
export KBUILD_BUILD_HOST=builder
export KBUILD_BUILD_TIMESTAMP
KBUILD_BUILD_TIMESTAMP=$(date -u -d "@$SOURCE_DATE_EPOCH" '+%a %b %d %H:%M:%S UTC %Y')
export KBUILD_BUILD_VERSION=1
export E2FSPROGS_FAKE_TIME=$SOURCE_DATE_EPOCH

/src/tools/microvm/l5/verify-cache.sh \
	--manifest /src/tools/microvm/l5/cache.manifest \
	--cache "$cache_root"
grep -Fq "lazy_itable_init=0" /src/tools/microvm/l5/buildroot.config
grep -Fq "lazy_journal_init=0" /src/tools/microvm/l5/buildroot.config

mkdir -p /build /build/guest-bin "$download_root" /build/gocache /build/gomodcache /build/goproxy/golang.org/x/sys/@v
tar -C /build -xf /cache/buildroot-2026.05.1.tar.xz
mv /build/buildroot-2026.05.1 "$buildroot_source"
tar -C /build -xf /cache/go1.25.7.linux-amd64.tar.gz
cp /cache/golang.org-x-sys-v0.41.0.info /build/goproxy/golang.org/x/sys/@v/v0.41.0.info
cp /cache/golang.org-x-sys-v0.41.0.mod /build/goproxy/golang.org/x/sys/@v/v0.41.0.mod
cp /cache/golang.org-x-sys-v0.41.0.zip /build/goproxy/golang.org/x/sys/@v/v0.41.0.zip

export PATH=/build/go/bin:/usr/bin:/bin
export GOCACHE=/build/gocache
export GOMODCACHE=/build/gomodcache
export GOTOOLCHAIN=local
export GOSUMDB=off
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64
GOPROXY=file:///build/goproxy go -C "$source_root" mod download golang.org/x/sys
export GOPROXY=off
go -C "$source_root" build -mod=mod -trimpath -buildvcs=false -ldflags=-buildid= \
	-o /build/guest-bin/hal-guest-agent ./cmd/hal-guest-agent
go -C "$source_root" build -mod=mod -trimpath -buildvcs=false -ldflags=-buildid= \
	-o /build/guest-bin/hal-init ./cmd/hal-guest-init

make -C "$buildroot_source" \
	O=/build/output \
	BR2_DEFCONFIG=/src/tools/microvm/l5/buildroot.config \
	BR2_PRIMARY_SITE=file:///cache \
	BR2_PRIMARY_SITE_ONLY=y \
	BR2_DOWNLOAD_FORCE_CHECK_HASHES=y \
	BR2_CCACHE= \
	DL_DIR=/build/download \
	defconfig
make -C "$buildroot_source" \
	-j"$HAL_L5_JOBS" \
	O=/build/output \
	BR2_PRIMARY_SITE=file:///cache \
	BR2_PRIMARY_SITE_ONLY=y \
	BR2_DOWNLOAD_FORCE_CHECK_HASHES=y \
	BR2_CCACHE= \
	DL_DIR=/build/download

test -f "$buildroot_output/images/vmlinux"
test -f "$buildroot_output/images/rootfs.ext4"
PATH="$buildroot_output/host/sbin:$PATH" e2fsck -fn "$buildroot_output/images/rootfs.ext4"

install -m 0644 "$buildroot_output/images/vmlinux" /export/vmlinux
install -m 0644 "$buildroot_output/images/rootfs.ext4" /export/rootfs.ext4

python3 - "$SOURCE_REVISION" "$SOURCE_TREE" "$SOURCE_DATE_EPOCH" <<'PY'
import hashlib
import json
import os
import sys

revision, tree, epoch = sys.argv[1:]
outputs = []
for key, identifier, kind in (
    ("vmlinux", "kernel", "kernel_image"),
    ("rootfs.ext4", "rootfs", "rootfs_image"),
):
    path = os.path.join("/export", key)
    with open(path, "rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    outputs.append({
        "key": key,
        "id": identifier,
        "kind": kind,
        "sizeBytes": os.path.getsize(path),
        "sha256": digest,
    })

versions = {
    "buildroot": "2026.05.1",
    "linux": "6.1.178",
    "busybox": "1.38.0",
    "e2fsprogs": "1.47.4",
    "go": "1.25.7",
    "firecracker": "v1.15.1",
}
agent = {
    "protocol": "guest-agent-v1",
    "features": ["copy_in", "copy_out", "exec", "readiness"],
}
manifest = {
    "schemaVersion": "hal-microvm-image-v1",
    "architecture": "x86_64",
    "versions": versions,
    "guestAgent": agent,
    "assets": outputs,
}
provenance = {
    "schemaVersion": "hal-microvm-image-v1",
    "sourceRevision": revision,
    "sourceTree": tree,
    "sourceDateEpoch": int(epoch),
    "buildImageDigest": "sha256:f1e7f009dad6b6f44bf5fcb4b0b89c9228e42f9fe689142774b1db802d4c93c6",
    "architecture": "x86_64",
    "versions": versions,
    "guestAgent": agent,
    "outputs": outputs,
}
for name, value in (
    ("distribution-manifest.json", manifest),
    ("provenance.json", provenance),
):
    with open(os.path.join("/export", name), "w", encoding="utf-8", newline="\n") as target:
        json.dump(value, target, sort_keys=True, separators=(",", ":"))
        target.write("\n")
PY

(
	cd /export
	sha256sum distribution-manifest.json provenance.json rootfs.ext4 vmlinux >SHA256SUMS
)
