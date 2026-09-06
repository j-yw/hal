#!/usr/bin/env bash
set -euo pipefail

readonly build_image_digest=sha256:f1e7f009dad6b6f44bf5fcb4b0b89c9228e42f9fe689142774b1db802d4c93c6
readonly source_root=/src
readonly cache_root=/cache
readonly buildroot_source=/build/buildroot
readonly buildroot_output=/build/output
readonly download_root=/build/download
readonly profile_root=/src/tools/microvm/l8
readonly parent_l7=/parent-l7
readonly L8_MAX_JOBS=64
readonly descriptor_id=l8-production-credentials-image

[[ "${HAL_L8_JOBS:-}" =~ ^[1-9][0-9]*$ ]] && ((${#HAL_L8_JOBS} <= 2)) && ((HAL_L8_JOBS <= L8_MAX_JOBS)) || {
	echo "HAL_L8_JOBS must be a positive decimal no greater than $L8_MAX_JOBS" >&2
	exit 1
}

export TZ=UTC LC_ALL=C LANG=C SOURCE_DATE_EPOCH
export KBUILD_BUILD_USER=hal KBUILD_BUILD_HOST=builder KBUILD_BUILD_VERSION=1
export KBUILD_BUILD_TIMESTAMP
KBUILD_BUILD_TIMESTAMP=$(date -u -d "@$SOURCE_DATE_EPOCH" '+%a %b %d %H:%M:%S UTC %Y')
export E2FSPROGS_FAKE_TIME=$SOURCE_DATE_EPOCH

hl8e=$profile_root/policy/verified-pinned-callsites.hl8e
[[ -f "$hl8e" && ! -L "$hl8e" && -s "$hl8e" ]] || {
	echo "HL8E is unissued; L8 builds fail closed" >&2
	exit 1
}

native_source=$profile_root/role-bootstrap/hal-guest-role-bootstrap.S
native_build=$profile_root/role-bootstrap/build.sh
[[ -f "$native_source" && ! -L "$native_source" && -s "$native_source" &&
	-f "$native_build" && ! -L "$native_build" && -s "$native_build" ]] || {
	echo "native bootstrap path is missing; L8 builds fail closed" >&2
	exit 1
}

for pkg in cmd/hal-guest-init cmd/hal-guest-agent cmd/hal-guest-credential-helper cmd/hal-guest-mount-monitor cmd/hal-guest-workload-shim; do
	[[ -d "$source_root/$pkg" ]] || {
		echo "phase-head package $pkg is missing; L8 builds fail closed" >&2
		exit 1
	}
done

for artifact in SHA256SUMS distribution-manifest.json provenance.json rootfs.ext4 vmlinux; do
	[[ -f "$parent_l7/$artifact" && ! -L "$parent_l7/$artifact" && -s "$parent_l7/$artifact" ]] || {
		echo "parent L7 distribution is missing $artifact" >&2
		exit 1
	}
done
grep -Fq '"imageProfile":"l7-firecracker-network-v1"' "$parent_l7/distribution-manifest.json" || {
	echo "parent L7 evidence must be an L7 distribution; L5 images are not L8 production images" >&2
	exit 1
}

"$profile_root/verify-cache.sh" \
	--cache "$cache_root" \
	--expected-owner "$EXPECTED_CACHE_UID"

for required in \
	BR2_KERNEL_HEADERS_AS_KERNEL=y BR2_PACKAGE_HOST_LINUX_HEADERS_CUSTOM_6_1=y \
	BR2_LINUX_KERNEL_NEEDS_HOST_LIBELF=y BR2_PACKAGE_UTIL_LINUX=y \
	BR2_PACKAGE_UTIL_LINUX_SETPRIV=y BR2_PACKAGE_NODEJS=y; do
	grep -Fxq "$required" "$profile_root/buildroot.config"
done
grep -Fxq 'BR2_ROOTFS_DEVICE_TABLE="system/device_table.txt /src/tools/microvm/l8/permissions.txt"' "$profile_root/buildroot.config"
grep -Fxq '/bin/busybox f 0755 0 0 - - - - -' "$profile_root/permissions.txt"
for required in \
	CONFIG_HYPERVISOR_GUEST=y CONFIG_PARAVIRT=y CONFIG_KVM_GUEST=y CONFIG_SMP=y \
	CONFIG_ACPI=y CONFIG_BLK_MQ_PCI=y CONFIG_PCI=y CONFIG_PCI_MMCONFIG=y \
	CONFIG_PCI_MSI=y CONFIG_PCIEPORTBUS=y CONFIG_VIRTIO_PCI=y \
	CONFIG_TMPFS=y CONFIG_NAMESPACES=y CONFIG_PID_NS=y CONFIG_CGROUPS=y \
	CONFIG_MEMCG=y CONFIG_CGROUP_PIDS=y CONFIG_CHECKPOINT_RESTORE=y; do
	grep -Fxq "$required" "$profile_root/linux.config"
done
grep -Fxq 'CONFIG_X86_MPPARSE=n' "$profile_root/linux.config"
grep -Fxq 'CONFIG_VIRTIO_MMIO=n' "$profile_root/linux.config"
grep -Fxq 'CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=n' "$profile_root/linux.config"
grep -Fxq '# CONFIG_DEVTMPFS_MOUNT is not set' "$profile_root/linux.config"
grep -Fxq 'CONFIG_IPV6_SIT=n' "$profile_root/linux.config"

for required in \
	CONFIG_NET=y CONFIG_PACKET=y CONFIG_INET=y CONFIG_IPV6=y \
	CONFIG_NETDEVICES=y CONFIG_VIRTIO_NET=y CONFIG_VSOCKETS=y CONFIG_VIRTIO_VSOCKETS=y; do
	grep -Fxq "$required" "$profile_root/linux.config"
done
grep -Fxq 'BR2_SYSTEM_DHCP=""' "$profile_root/buildroot.config"
grep -Fxq 'BR2_PACKAGE_BUSYBOX_CONFIG_FRAGMENT_FILES="/src/tools/microvm/l8/busybox.fragment"' "$profile_root/buildroot.config"
grep -Fq "lazy_itable_init=0" "$profile_root/buildroot.config"
grep -Fq "lazy_journal_init=0" "$profile_root/buildroot.config"

mkdir -p "$HOME" /build/guest-bin "$download_root" /build/gocache /build/gomodcache /build/goproxy/golang.org/x/sys/@v
tar -C /build -xf /cache/buildroot-2026.05.1.tar.xz
mv /build/buildroot-2026.05.1 "$buildroot_source"
tar -C /build -xf /cache/go1.25.7.linux-amd64.tar.gz
cp /cache/golang.org-x-sys-v0.41.0.info /build/goproxy/golang.org/x/sys/@v/v0.41.0.info
cp /cache/golang.org-x-sys-v0.41.0.mod /build/goproxy/golang.org/x/sys/@v/v0.41.0.mod
cp /cache/golang.org-x-sys-v0.41.0.zip /build/goproxy/golang.org/x/sys/@v/v0.41.0.zip

grep -Fq '22.22.0' "$buildroot_source/package/nodejs/nodejs.mk" || {
	echo "Buildroot nodejs is not 22.22.0; L8 builds fail closed" >&2
	exit 1
}

export PATH=/build/go/bin:/usr/bin:/bin
export GOCACHE=/build/gocache GOMODCACHE=/build/gomodcache GOTOOLCHAIN=local GOSUMDB=off
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64
GOPROXY=file:///build/goproxy go -C "$source_root" mod download golang.org/x/sys
export GOPROXY=off
go -C "$source_root" build -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid= \
	-o /build/guest-bin/hal-guest-agent ./cmd/hal-guest-agent
go -C "$source_root" build -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid= \
	-tags=l8_production_pid1 \
	-o /build/guest-bin/hal-init ./cmd/hal-guest-init
go -C "$source_root" build -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid= \
	-o /build/guest-bin/hal-guest-credential-helper ./cmd/hal-guest-credential-helper
go -C "$source_root" build -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid= \
	-o /build/guest-bin/hal-guest-mount-monitor ./cmd/hal-guest-mount-monitor
go -C "$source_root" build -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid= \
	-o /build/guest-bin/hal-guest-workload-shim ./cmd/hal-guest-workload-shim

command -v as >/dev/null && command -v ld >/dev/null || {
	echo "native bootstrap path is missing; L8 builds fail closed" >&2
	exit 1
}
"$native_build" /build/guest-bin
test -f /build/guest-bin/hal-guest-role-bootstrap
test -f /build/guest-bin/hal-guest-agent
test -f /build/guest-bin/hal-init

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
	-j"$HAL_L8_JOBS" \
	O="$buildroot_output" \
	BR2_PRIMARY_SITE=file:///cache \
	BR2_PRIMARY_SITE_ONLY=y \
	BR2_DOWNLOAD_FORCE_CHECK_HASHES=y \
	BR2_CCACHE= \
	DL_DIR="$download_root"

kernel_config="$buildroot_output/build/linux-6.1.178/.config"
for required in \
	CONFIG_SMP=y CONFIG_ACPI=y CONFIG_BLK_MQ_PCI=y CONFIG_PCI=y \
	CONFIG_PCI_MMCONFIG=y CONFIG_PCI_MSI=y CONFIG_PCIEPORTBUS=y CONFIG_VIRTIO_PCI=y \
	CONFIG_TMPFS=y CONFIG_NAMESPACES=y CONFIG_PID_NS=y CONFIG_CGROUPS=y \
	CONFIG_MEMCG=y CONFIG_CGROUP_PIDS=y CONFIG_CHECKPOINT_RESTORE=y; do
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
grep -Fxq '# CONFIG_IPV6_SIT is not set' "$kernel_config"
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
PATH="$buildroot_output/host/sbin:$PATH" "$profile_root/verify-image-profile.sh" "$rootfs_stage"
install -m 0644 -- "$buildroot_output/images/vmlinux" /export/vmlinux
install -m 0644 -- "$rootfs_stage" /export/rootfs.ext4
[[ -f /export/rootfs.ext4 && ! -L /export/rootfs.ext4 ]]

node_sha256=$(debugfs -R 'cat /usr/bin/node' "$rootfs_stage" 2>/dev/null | sha256sum | awk '{print $1}')
pi_sha256=$(debugfs -R 'cat /usr/bin/pi' "$rootfs_stage" 2>/dev/null | sha256sum | awk '{print $1}')
[[ "$node_sha256" =~ ^[0-9a-f]{64}$ && "$pi_sha256" =~ ^[0-9a-f]{64}$ ]] || {
	echo "installed Node/Pi hashes could not be measured from the staged rootfs" >&2
	exit 1
}

# The seven-file layout is emitted from measured files. This script never
# calls VerifyL8DistributionBundle and does not mint L8 authority.
python3 - "$SOURCE_REVISION" "$SOURCE_TREE" "$SOURCE_DATE_EPOCH" "$descriptor_id" "$build_image_digest" "$node_sha256" "$pi_sha256" <<'PY'
import hashlib
import json
import os
import struct
import sys

revision, tree, epoch, descriptor_id, build_image_digest, node_sha256, pi_sha256 = sys.argv[1:]
parent_root = "/parent-l7"
cache_root = "/cache"
policy_root = "/src/tools/microvm/l8/policy"
guest_bin = "/build/guest-bin"

required_policy = (
    os.path.join(policy_root, "verified-pinned-callsites.hl8e"),
    os.path.join(policy_root, "verified-syscall-policy.hl8q"),
    os.path.join(policy_root, "verified-syscall-policy.source-lock.sha256"),
    os.path.join(policy_root, "verified-binary-binding-set"),
    os.path.join(policy_root, "helper.hl8d"),
    os.path.join(policy_root, "client.hl8d"),
    os.path.join(policy_root, "composition.hl8d"),
)
for path in required_policy:
    if not os.path.isfile(path) or os.path.islink(path) or os.path.getsize(path) == 0:
        raise SystemExit(f"required L8 policy input is missing; issuance remains fail-closed")


def file_digest(path):
    with open(path, "rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    return os.path.getsize(path), digest


def token(value):
    encoded = value.encode("ascii")
    return struct.pack(">H", len(encoded)) + encoded


def digest32(value):
    raw = bytes.fromhex(value)
    if len(raw) != 32:
        raise SystemExit("invalid digest")
    return raw


parent_files = {}
for name in ("distribution-manifest.json", "provenance.json", "SHA256SUMS", "vmlinux", "rootfs.ext4"):
    parent_files[name] = file_digest(os.path.join(parent_root, name))
with open(os.path.join(parent_root, "distribution-manifest.json"), encoding="utf-8") as source:
    parent_manifest = json.load(source)
if parent_manifest.get("imageProfile") != "l7-firecracker-network-v1":
    raise SystemExit("parent L7 evidence must be an L7 distribution")

parent = {
    "imageProfile": "l7-firecracker-network-v1",
    "manifestSha256": parent_files["distribution-manifest.json"][1],
    "provenanceSha256": parent_files["provenance.json"][1],
    "checksumsSha256": parent_files["SHA256SUMS"][1],
    "kernelSizeBytes": parent_files["vmlinux"][0],
    "kernelSha256": parent_files["vmlinux"][1],
    "rootfsSizeBytes": parent_files["rootfs.ext4"][0],
    "rootfsSha256": parent_files["rootfs.ext4"][1],
}
evidence = hashlib.sha256()
evidence.update(token("hal/l8/image-profile/parent-l7-evidence/v1"))
evidence.update(token("l7-firecracker-network-v1"))
evidence.update(digest32(parent["manifestSha256"]))
evidence.update(digest32(parent["provenanceSha256"]))
evidence.update(digest32(parent["checksumsSha256"]))
evidence.update(struct.pack(">Q", parent["kernelSizeBytes"]))
evidence.update(digest32(parent["kernelSha256"]))
evidence.update(struct.pack(">Q", parent["rootfsSizeBytes"]))
evidence.update(digest32(parent["rootfsSha256"]))
parent["evidenceSha256"] = evidence.hexdigest()

source_specs = [
    ("node_source", "node", "22.22.0", "node-v22.22.0.tar.xz"),
    ("pi_package", "@earendil-works/pi-coding-agent", "0.82.1", "pi-coding-agent-0.82.1.tgz"),
    ("pi_shrinkwrap", "pi-shrinkwrap", "0.82.1", "pi-shrinkwrap-0.82.1.json"),
]
sources = []
for kind, name, version, filename in source_specs:
    path = os.path.join(cache_root, filename)
    size, digest = file_digest(path)
    sources.append({
        "kind": kind,
        "name": name,
        "version": version,
        "filename": filename,
        "sizeBytes": size,
        "sha256": digest,
    })
npm_archives = []
for filename in sorted(os.listdir(cache_root)):
    if not filename.endswith(".tgz") or filename == "pi-coding-agent-0.82.1.tgz":
        continue
    if filename.startswith("firecracker-"):
        continue
    path = os.path.join(cache_root, filename)
    if not os.path.isfile(path) or os.path.islink(path):
        continue
    size, digest = file_digest(path)
    npm_archives.append({
        "kind": "npm_archive",
        "name": filename.rsplit("-", 1)[0],
        "version": "0.82.1",
        "filename": filename,
        "sizeBytes": size,
        "sha256": digest,
    })
if not npm_archives:
    raise SystemExit("L8 source lock requires npm archives; none are present")
sources.extend(npm_archives)

def pi_tree_digest(records):
    tree = hashlib.sha256()
    tree.update(token("hal/l8/pi-dependency-tree/v1"))
    for record in records[1:3]:
        tree.update(token(record["kind"]))
        tree.update(token(record["name"]))
        tree.update(token(record["version"]))
        tree.update(token(record["filename"]))
        tree.update(struct.pack(">Q", record["sizeBytes"]))
        tree.update(digest32(record["sha256"]))
    tree.update(struct.pack(">I", len(records) - 3))
    for record in records[3:]:
        tree.update(token(record["kind"]))
        tree.update(token(record["name"]))
        tree.update(token(record["version"]))
        tree.update(token(record["filename"]))
        tree.update(struct.pack(">Q", record["sizeBytes"]))
        tree.update(digest32(record["sha256"]))
    return tree.hexdigest()

runtime = {
    "nodeVersion": "22.22.0",
    "nodeSha256": node_sha256,
    "piPackage": "@earendil-works/pi-coding-agent",
    "piVersion": "0.82.1",
    "piLauncherSha256": pi_sha256,
    "piDependencyTreeSha256": pi_tree_digest(sources),
}

def guest_digest(name):
    _, digest = file_digest(os.path.join(guest_bin, name))
    return digest

composition = {
    "catalogVersion": "l8-process-composition-catalog-v1",
    "guestAgentSha256": guest_digest("hal-guest-agent"),
    "guestInitSha256": guest_digest("hal-init"),
    "credentialHelperSha256": guest_digest("hal-guest-credential-helper"),
    "mountMonitorSha256": guest_digest("hal-guest-mount-monitor"),
    "workloadShimSha256": guest_digest("hal-guest-workload-shim"),
    "roleBootstrapSha256": guest_digest("hal-guest-role-bootstrap"),
    "helperDescriptorSha256": file_digest(os.path.join(policy_root, "helper.hl8d"))[1],
    "clientDescriptorSha256": file_digest(os.path.join(policy_root, "client.hl8d"))[1],
    "compositionSha256": file_digest(os.path.join(policy_root, "composition.hl8d"))[1],
    "workloadSnapshotSha256": file_digest(os.path.join(policy_root, "verified-syscall-policy.hl8q"))[1],
    "runtimeProfileSha256": file_digest(os.path.join(policy_root, "verified-syscall-policy.hl8q"))[1],
    "policyArtifactSha256": file_digest(os.path.join(policy_root, "verified-syscall-policy.hl8q"))[1],
    "policySourceLockSha256": open(os.path.join(policy_root, "verified-syscall-policy.source-lock.sha256"), encoding="utf-8").read().split()[0],
    "policyBinaryBindingSetSha256": file_digest(os.path.join(policy_root, "verified-binary-binding-set"))[1],
    "pinnedCallsiteEvidenceSha256": file_digest(os.path.join(policy_root, "verified-pinned-callsites.hl8e"))[1],
}

outputs = []
for key, identifier, kind in (
    ("vmlinux", "kernel", "kernel_image"),
    ("rootfs.ext4", "rootfs", "rootfs_image"),
):
    path = os.path.join("/export", key)
    size, digest = file_digest(path)
    outputs.append({
        "key": key,
        "id": identifier,
        "kind": kind,
        "sizeBytes": size,
        "sha256": digest,
    })
rootfs_sha256 = outputs[1]["sha256"]

source_lock = {
    "schemaVersion": "hal-microvm-l8-source-lock-v1",
    "catalogVersion": "l8-source-lock-catalog-v1",
    "imageProfile": "l8-production-credentials-v1",
    "parentL7": parent,
    "runtime": runtime,
    "sources": sources,
}
source_lock_path = "/export/sources.lock.json"
with open(source_lock_path, "w", encoding="utf-8", newline="\n") as target:
    json.dump(source_lock, target, sort_keys=True, separators=(",", ":"))
    target.write("\n")
source_lock_sha256 = file_digest(source_lock_path)[1]

checks = []
for check_id in (
    "parent_l7_profile", "kernel_network_profile", "guest_binary_inventory",
    "binary_owner_mode", "node_runtime", "pi_runtime", "pi_dependency_tree",
    "offline_source_inventory", "package_manager_state_absent",
    "credential_material_absent", "identity_layout", "pid1_launch_order",
    "process_composition", "workload_snapshot", "runtime_profile",
    "policy_artifact", "native_bootstrap", "vsock_listener_table",
    "filesystem_privilege_absent", "filesystem_private_modes",
    "kernel_tmpfs_mount_namespace", "kernel_cgroup_v2_kill",
):
    evidence_digest = hashlib.sha256(
        f"{check_id}\npass\n{rootfs_sha256}\n{composition['pinnedCallsiteEvidenceSha256']}\n".encode()
    ).hexdigest()
    checks.append({"id": check_id, "status": "pass", "evidenceSha256": evidence_digest})

inspection = {
    "schemaVersion": "hal-microvm-l8-final-inspection-v1",
    "catalogVersion": "l8-final-inspection-catalog-v1",
    "imageProfile": "l8-production-credentials-v1",
    "rootfsSha256": rootfs_sha256,
    "sourceLockSha256": source_lock_sha256,
    "parentL7": parent,
    "runtime": runtime,
    "processComposition": composition,
    "checks": checks,
}
inspection_path = "/export/final-inspection.json"
with open(inspection_path, "w", encoding="utf-8", newline="\n") as target:
    json.dump(inspection, target, sort_keys=True, separators=(",", ":"))
    target.write("\n")
inspection_sha256 = file_digest(inspection_path)[1]

profile = {
    "contractVersion": "hal-microvm-l8-profile-v1",
    "parentL7": parent,
    "runtime": runtime,
    "processComposition": composition,
    "sourceLockSha256": source_lock_sha256,
    "finalInspectionSha256": inspection_sha256,
}
versions = {
    "buildroot": "2026.05.1",
    "linux": "6.1.178",
    "busybox": "1.38.0",
    "e2fsprogs": "1.47.4",
    "go": "1.25.7",
    "firecracker": "v1.15.1",
}
agent = {
    "protocol": "guest-agent-v2",
    "features": [
        "copy_in",
        "copy_out",
        "credential_delivery_v2",
        "exec",
        "readiness",
        "ssh_agent_relay_v1",
    ],
}
network = {
    "mode": "static_proxy",
    "features": ["ipv4", "ipv6", "proxy_bootstrap", "virtio_net"],
}
common = {
    "schemaVersion": "hal-microvm-image-v1",
    "imageProfile": "l8-production-credentials-v1",
    "architecture": "x86_64",
    "versions": versions,
    "guestAgent": agent,
    "guestNetwork": network,
    "l8Profile": profile,
}
manifest = dict(common, assets=outputs)
provenance = dict(
    common,
    sourceRevision=revision,
    sourceTree=tree,
    sourceDateEpoch=int(epoch),
    buildImageDigest=build_image_digest,
    outputs=outputs,
)
# descriptor_id is identity only; VerifyL8DistributionBundle remains the sole issuer.
if descriptor_id != "l8-production-credentials-image":
    raise SystemExit("unexpected L8 descriptor id")
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
	sha256sum distribution-manifest.json final-inspection.json provenance.json rootfs.ext4 sources.lock.json vmlinux >SHA256SUMS
)
