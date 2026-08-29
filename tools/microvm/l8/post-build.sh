#!/bin/sh
set -eu

target=$1
install -D -m 0755 /build/guest-bin/hal-guest-agent "$target/usr/bin/hal-guest-agent"
install -D -m 0755 /build/guest-bin/hal-init "$target/sbin/hal-init"
install -D -m 0755 /build/guest-bin/hal-guest-credential-helper "$target/usr/bin/hal-guest-credential-helper"
install -D -m 0755 /build/guest-bin/hal-guest-mount-monitor "$target/usr/bin/hal-guest-mount-monitor"
install -D -m 0755 /build/guest-bin/hal-guest-workload-shim "$target/usr/bin/hal-guest-workload-shim"
install -D -m 0755 /build/guest-bin/hal-guest-role-bootstrap "$target/sbin/hal-guest-role-bootstrap"
rm -f -- "$target/etc/resolv.conf"
install -D -m 0644 /dev/null "$target/etc/resolv.conf"
chmod 0755 "$target/bin/busybox"
ln -snf /bin/busybox "$target/bin/sh"
test -x "$target/sbin/ip"
test -x "$target/usr/bin/nc"
test -x "$target/bin/ping"
test -x "$target/bin/ping6"
test -x "$target/usr/bin/nslookup"
test -x "$target/usr/bin/wget"
test -x "$target/usr/bin/setpriv"
test ! -L "$target/usr/bin/setpriv"
test -x "$target/usr/bin/node"
test ! -L "$target/usr/bin/node"
test -x "$target/usr/bin/pi"
test ! -L "$target/usr/bin/pi"
install -d -m 0700 -o 998 -g 998 "$target/run/agent"
install -d -m 0700 -o 1000 -g 1000 "$target/workspace"
rm -rf -- "$target/root/.npm" "$target/root/.npmrc" "$target/root/.config/npm"
rm -rf -- "$target/home" "$target/root/.pi" "$target/root/.cache"
test ! -e "$target/root/.npm"
test ! -e "$target/root/.npmrc"
# Secrets, host keys, npm session material, and fixture profiles stay out of
# the production image.
if find "$target" \( -name '.npmrc' -o -name '.npm' -o -name 'id_rsa' -o -name '*.pem' \) -print | grep -q .; then
	echo "L8 rootfs contains secret or package-manager session material" >&2
	exit 1
fi
