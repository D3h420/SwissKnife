#!/usr/bin/env bash
# Install a built package over SSH without leaving installer files on the device.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "Usage: $0 PACKAGE.deb [user@host]" >&2
    exit 2
fi

package=$1
target=${2:-one@c0.local}
if [[ ! -f $package ]]; then
    echo "Package not found: $package" >&2
    exit 1
fi

filename=${package##*/}
if [[ ! $filename =~ ^swissknife-cardputer_[A-Za-z0-9.+~_-]+_arm64\.deb$ ]]; then
    echo "Expected a SwissKnife Cardputer ARM64 package" >&2
    exit 1
fi
if [[ $(dpkg-deb -f "$package" Package) != swissknife-cardputer ||
      $(dpkg-deb -f "$package" Architecture) != arm64 ]]; then
    echo "Package metadata does not match SwissKnife Cardputer ARM64" >&2
    exit 1
fi

remote_package=/tmp/$filename
workdir=$(mktemp -d)
trap 'rm -r -- "$workdir"' EXIT
dpkg-deb --raw-extract "$package" "$workdir/stage"
dpkg-deb --root-owner-group --build "$workdir/stage" "$workdir/$filename" >/dev/null
scp "$workdir/$filename" "$target:$remote_package"
ssh -tt "$target" "trap 'rm -f -- $remote_package' EXIT; sudo apt-get install -y -- $remote_package && dpkg-query -W swissknife-cardputer"
