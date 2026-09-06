#!/usr/bin/env bash
set -euo pipefail
readonly profile=/src/tools/microvm/l8-minimal
readonly br=/build/buildroot
readonly output=/build/output
readonly dl=/build/download
[[ "$BR2_PRIMARY_SITE" == file:///nonexistent && "$BR2_PRIMARY_SITE_ONLY" == y ]]
export TZ=UTC LC_ALL=C LANG=C SOURCE_DATE_EPOCH
export KBUILD_BUILD_USER=hal KBUILD_BUILD_HOST=builder KBUILD_BUILD_VERSION=1
export KBUILD_BUILD_TIMESTAMP
KBUILD_BUILD_TIMESTAMP=$(date -u -d "@$SOURCE_DATE_EPOCH" '+%a %b %d %H:%M:%S UTC %Y')
mkdir -p /build/home /build/guest-bin /build/gocache /build/gomodcache /build/goproxy/golang.org/x/sys/@v "$dl"
tar -C /build -xf /cache/buildroot-2026.05.1.tar.xz
mv /build/buildroot-2026.05.1 "$br"
tar -C /build -xf /cache/go1.25.7.linux-amd64.tar.gz
cp /cache/golang.org-x-sys-v0.41.0.info /build/goproxy/golang.org/x/sys/@v/v0.41.0.info
cp /cache/golang.org-x-sys-v0.41.0.mod /build/goproxy/golang.org/x/sys/@v/v0.41.0.mod
cp /cache/golang.org-x-sys-v0.41.0.zip /build/goproxy/golang.org/x/sys/@v/v0.41.0.zip
export PATH=/build/go/bin:/usr/bin:/bin
export GOCACHE=/build/gocache GOMODCACHE=/build/gomodcache GOTOOLCHAIN=local GOSUMDB=off
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOMAXPROCS=3
GOPROXY=file:///build/goproxy go -C /src mod download golang.org/x/sys
export GOPROXY=off
go -C /src build -p 3 -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid= -o /build/guest-bin/hal-init ./cmd/hal-guest-init
go -C /src build -p 3 -mod=readonly -trimpath -buildvcs=false -ldflags=-buildid= -o /build/guest-bin/hal-guest-agent ./cmd/hal-guest-agent
make_args=(-C "$br" O="$output" BR2_PRIMARY_SITE=file:///nonexistent BR2_PRIMARY_SITE_ONLY=y BR2_DOWNLOAD_FORCE_CHECK_HASHES=y BR2_CCACHE= DL_DIR="$dl")
make "${make_args[@]}" BR2_DEFCONFIG="$profile/buildroot.config" defconfig
for selected in BR2_SHARED_LIBS=y BR2_TOOLCHAIN_BUILDROOT_CXX=y BR2_PACKAGE_NODEJS=y BR2_PACKAGE_HOST_NODEJS_SRC=y BR2_PACKAGE_ICU=y BR2_PACKAGE_OPENSSL=y; do
	grep -Fxq "$selected" "$output/.config"
done
! grep -Fxq 'BR2_PACKAGE_HOST_NODEJS_BIN=y' "$output/.config"
make -s "${make_args[@]}" show-info > /build/show-info.json
python3 "$profile/stage-native.py" seed /cache "$dl" /build/show-info.json "$profile/buildroot-downloads.lock.json"
# This selected target produces the actual fakeroot ownership tar without
# building the legacy 64MiB ext4 output. The host inspector builds minimal ext4.
make "${make_args[@]}" -j3 rootfs-tar
test -f "$output/images/rootfs.tar" && test ! -L "$output/images/rootfs.tar"
install -m 0644 "$output/images/rootfs.tar" /export/rootfs.tar
