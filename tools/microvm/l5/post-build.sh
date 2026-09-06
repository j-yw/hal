#!/bin/sh
set -eu

target=$1
install -D -m 0755 /build/guest-bin/hal-guest-agent "$target/usr/bin/hal-guest-agent"
install -D -m 0755 /build/guest-bin/hal-init "$target/sbin/hal-init"
chmod 0755 "$target/bin/busybox"
ln -snf /bin/busybox "$target/bin/sh"
ln -snf /bin/busybox "$target/usr/bin/env"
test -x "$target/usr/bin/setpriv"
test ! -L "$target/usr/bin/setpriv"
install -d -m 0700 -o 1000 -g 1000 "$target/workspace"
