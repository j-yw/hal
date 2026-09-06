#!/bin/sh
set -eu
target=$1
install -D -m 0755 /build/guest-bin/hal-init "$target/sbin/hal-init"
install -D -m 0755 /build/guest-bin/hal-guest-agent "$target/usr/bin/hal-guest-agent"
rm -f -- "$target/etc/resolv.conf"
install -D -m 0644 /dev/null "$target/etc/resolv.conf"
chmod 0755 "$target/bin/busybox" "$target/sbin/init"
ln -snf /bin/busybox "$target/bin/sh"
# Numeric guest ownership is applied by Buildroot fakeroot permissions.txt,
# not a premature host chown from the UID-preserving rootless build user.
install -d -m 0700 "$target/workspace" "$target/run/agent"
python3 /src/tools/microvm/l8-minimal/stage-native.py pi /cache "$target"
for executable in /sbin/hal-init /usr/bin/hal-guest-agent /usr/bin/node /usr/bin/pi /usr/bin/setpriv; do
	test -x "$target$executable" && test ! -L "$target$executable"
done
