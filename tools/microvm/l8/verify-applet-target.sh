#!/usr/bin/env bash
set -euo pipefail

[[ $# == 2 ]] || exit 2
applet=$1
target=$2
[[ "$applet" == /* && -n "$target" && "$applet" != *$'\n'* && "$target" != *$'\n'* ]] || exit 1
[[ "$(realpath -m -s -- "$applet")" == "$applet" ]] || exit 1

if [[ "$target" == /* ]]; then
	candidate=$target
else
	candidate=${applet%/*}/$target
fi
[[ "$(realpath -m -s -- "$candidate")" == /bin/busybox ]]
