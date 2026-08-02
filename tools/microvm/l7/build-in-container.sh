#!/usr/bin/env bash
set -euo pipefail

readonly build_image_digest=sha256:f1e7f009dad6b6f44bf5fcb4b0b89c9228e42f9fe689142774b1db802d4c93c6
readonly source_root=/src
readonly cache_root=/cache
readonly buildroot_source=/build/buildroot
readonly buildroot_output=/build/output
readonly download_root=/build/download
readonly profile_root=/src/tools/microvm/l7
readonly L7_MAX_JOBS=64

[[ "${HAL_L7_JOBS:-}" =~ ^[1-9][0-9]*$ ]] && ((${#HAL_L7_JOBS} <= 2)) && ((HAL_L7_JOBS <= L7_MAX_JOBS)) || {
	echo "HAL_L7_JOBS must be a positive decimal no greater than $L7_MAX_JOBS" >&2
	exit 1
}

export TZ=UTC LC_ALL=C LANG=C SOURCE_DATE_EPOCH
export KBUILD_BUILD_USER=hal KBUILD_BUILD_HOST=builder KBUILD_BUILD_VERSION=1
export KBUILD_BUILD_TIMESTAMP
KBUILD_BUILD_TIMESTAMP=$(date -u -d "@$SOURCE_DATE_EPOCH" '+%a %b %d %H:%M:%S UTC %Y')
export E2FSPROGS_FAKE_TIME=$SOURCE_DATE_EPOCH

/src/tools/microvm/l5/verify-cache.sh \
	--manifest /src/tools/microvm/l5/cache.manifest \
	--cache "$cache_root" \
	--expected-owner "$EXPECTED_CACHE_UID"

for required in \
	BR2_KERNEL_HEADERS_AS_KERNEL=y BR2_PACKAGE_HOST_LINUX_HEADERS_CUSTOM_6_1=y \
	BR2_LINUX_KERNEL_NEEDS_HOST_LIBELF=y BR2_PACKAGE_UTIL_LINUX=y \
	BR2_PACKAGE_UTIL_LINUX_SETPRIV=y; do
	grep -Fxq "$required" "$profile_root/buildroot.config"
done
grep -Fxq 'BR2_ROOTFS_DEVICE_TABLE="system/device_table.txt /src/tools/microvm/l7/permissions.txt"' "$profile_root/buildroot.config"
grep -Fxq '/bin/busybox f 0755 0 0 - - - - -' "$profile_root/permissions.txt"
for required in \
	CONFIG_HYPERVISOR_GUEST=y CONFIG_PARAVIRT=y CONFIG_KVM_GUEST=y CONFIG_SMP=y \
	CONFIG_ACPI=y CONFIG_BLK_MQ_PCI=y CONFIG_PCI=y CONFIG_PCI_MMCONFIG=y \
	CONFIG_PCI_MSI=y CONFIG_PCIEPORTBUS=y CONFIG_VIRTIO_PCI=y; do
	grep -Fxq "$required" "$profile_root/linux.config"
done
grep -Fxq 'CONFIG_X86_MPPARSE=n' "$profile_root/linux.config"
grep -Fxq 'CONFIG_VIRTIO_MMIO=n' "$profile_root/linux.config"
grep -Fxq 'CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=n' "$profile_root/linux.config"
grep -Fxq '# CONFIG_DEVTMPFS_MOUNT is not set' "$profile_root/linux.config"

for required in \
	CONFIG_NET=y CONFIG_PACKET=y CONFIG_INET=y CONFIG_IPV6=y \
	CONFIG_NETDEVICES=y CONFIG_VIRTIO_NET=y CONFIG_VSOCKETS=y CONFIG_VIRTIO_VSOCKETS=y; do
	grep -Fxq "$required" "$profile_root/linux.config"
done
grep -Fxq 'BR2_SYSTEM_DHCP=""' "$profile_root/buildroot.config"
grep -Fxq 'BR2_PACKAGE_BUSYBOX_CONFIG_FRAGMENT_FILES="/src/tools/microvm/l7/busybox.fragment"' "$profile_root/buildroot.config"
grep -Fq "lazy_itable_init=0" "$profile_root/buildroot.config"
grep -Fq "lazy_journal_init=0" "$profile_root/buildroot.config"

mkdir -p "$HOME" /build/guest-bin "$download_root" /build/gocache /build/gomodcache /build/goproxy/golang.org/x/sys/@v
tar -C /build -xf /cache/buildroot-2026.05.1.tar.xz
mv /build/buildroot-2026.05.1 "$buildroot_source"
tar -C /build -xf /cache/go1.25.7.linux-amd64.tar.gz
cp /cache/golang.org-x-sys-v0.41.0.info /build/goproxy/golang.org/x/sys/@v/v0.41.0.info
cp /cache/golang.org-x-sys-v0.41.0.mod /build/goproxy/golang.org/x/sys/@v/v0.41.0.mod
cp /cache/golang.org-x-sys-v0.41.0.zip /build/goproxy/golang.org/x/sys/@v/v0.41.0.zip

export PATH=/build/go/bin:/usr/bin:/bin
export GOCACHE=/build/gocache GOMODCACHE=/build/gomodcache GOTOOLCHAIN=local GOSUMDB=off
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64
GOPROXY=file:///build/goproxy go -C "$source_root" mod download golang.org/x/sys
export GOPROXY=off
go -C "$source_root" build -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid= \
	-o /build/guest-bin/hal-guest-agent ./cmd/hal-guest-agent
go -C "$source_root" build -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid= \
	-o /build/guest-bin/hal-init ./cmd/hal-guest-init

make -C "$buildroot_source" \
	O="$buildroot_output" \
	BR2_DEFCONFIG="$profile_root/buildroot.config" \
	BR2_PRIMARY_SITE=file:///cache \
	BR2_PRIMARY_SITE_ONLY=y \
	BR2_DOWNLOAD_FORCE_CHECK_HASHES=y \
	BR2_CCACHE= \
	DL_DIR="$download_root" \
	defconfig
make -C "$buildroot_source" \
	-j"$HAL_L7_JOBS" \
	O="$buildroot_output" \
	BR2_PRIMARY_SITE=file:///cache \
	BR2_PRIMARY_SITE_ONLY=y \
	BR2_DOWNLOAD_FORCE_CHECK_HASHES=y \
	BR2_CCACHE= \
	DL_DIR="$download_root"

kernel_config="$buildroot_output/build/linux-6.1.178/.config"
for required in \
	CONFIG_SMP=y CONFIG_ACPI=y CONFIG_BLK_MQ_PCI=y CONFIG_PCI=y \
	CONFIG_PCI_MMCONFIG=y CONFIG_PCI_MSI=y CONFIG_PCIEPORTBUS=y CONFIG_VIRTIO_PCI=y; do
	grep -Fxq "$required" "$kernel_config"
done
grep -Fxq '# CONFIG_X86_MPPARSE is not set' "$kernel_config"
grep -Fxq '# CONFIG_VIRTIO_MMIO is not set' "$kernel_config"
! grep -Eq '^CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=(y|m)$' "$kernel_config"
for required in \
	CONFIG_NET=y CONFIG_PACKET=y CONFIG_INET=y CONFIG_IPV6=y \
	CONFIG_NETDEVICES=y CONFIG_VIRTIO_NET=y CONFIG_VSOCKETS=y CONFIG_VIRTIO_VSOCKETS=y; do
	grep -Fxq "$required" "$kernel_config"
done
busybox_config=$(find "$buildroot_output/build" -maxdepth 2 -path '*/busybox-1.38.0/.config' -print -quit)
test -n "$busybox_config"
for required in \
	CONFIG_IP=y CONFIG_FEATURE_IPV6=y CONFIG_NC=y CONFIG_NC_EXTRA=y \
	CONFIG_PING=y CONFIG_PING6=y CONFIG_NSLOOKUP=y CONFIG_WGET=y; do
	grep -Fxq "$required" "$busybox_config"
done
! grep -Eq '^CONFIG_IP_PNP=(y|m)$' "$kernel_config"
! grep -Eq '^CONFIG_DEVTMPFS_MOUNT=(y|m)$' "$kernel_config"

test -f "$buildroot_output/images/vmlinux"
rootfs_alias="$buildroot_output/images/rootfs.ext4"
rootfs_payload="$buildroot_output/images/rootfs.ext2"
rootfs_stage_dir=/build/verified-rootfs
rootfs_stage="$rootfs_stage_dir/rootfs.ext4"
[[ -L "$rootfs_alias" ]]
[[ "$(readlink -- "$rootfs_alias")" == rootfs.ext2 ]]
[[ -f "$rootfs_payload" && ! -L "$rootfs_payload" ]]
[[ ! -e "$rootfs_stage_dir" && ! -L "$rootfs_stage_dir" ]]
install -d -m 0700 -- "$rootfs_stage_dir"
[[ -d "$rootfs_stage_dir" && ! -L "$rootfs_stage_dir" ]]
[[ "$(stat -c '%a' -- "$rootfs_stage_dir")" == 700 ]]
install -m 0644 -- "$rootfs_payload" "$rootfs_stage"
[[ -f "$rootfs_stage" && ! -L "$rootfs_stage" ]]
PATH="$buildroot_output/host/sbin:$PATH" e2fsck -fn "$rootfs_stage"
PATH="$buildroot_output/host/sbin:$PATH" "$profile_root/verify-final-image.sh" "$rootfs_stage"
install -m 0644 -- "$buildroot_output/images/vmlinux" /export/vmlinux
install -m 0644 -- "$rootfs_stage" /export/rootfs.ext4
[[ -f /export/rootfs.ext4 && ! -L /export/rootfs.ext4 ]]

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
network = {
    "mode": "static_proxy",
    "features": ["ipv4", "ipv6", "proxy_bootstrap", "virtio_net"],
}
common = {
    "schemaVersion": "hal-microvm-image-v1",
    "imageProfile": "l7-firecracker-network-v1",
    "architecture": "x86_64",
    "versions": versions,
    "guestAgent": agent,
    "guestNetwork": network,
}
manifest = dict(common, assets=outputs)
provenance = dict(
    common,
    sourceRevision=revision,
    sourceTree=tree,
    sourceDateEpoch=int(epoch),
    buildImageDigest="sha256:f1e7f009dad6b6f44bf5fcb4b0b89c9228e42f9fe689142774b1db802d4c93c6",
    outputs=outputs,
)
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
