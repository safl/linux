#!/bin/bash
# Install an amdgpu-xnvme DKMS package against a kernel's headers and check
# that DKMS built amdgpu.ko for it with the fixes in, and that a kernel of
# another series is skipped rather than failing the install. Needs no such
# kernel running.
#
#   test-amdgpu-dkms.sh <deb> <kernel release>, e.g. 7.3.0-9-generic
#
# Copyright (c) Simon A. F. Lund <os@safl.dk>
# SPDX-License-Identifier: GPL-2.0
set -euo pipefail
deb=$(realpath "$1")
kver=$2

export DEBIAN_FRONTEND=noninteractive
apt-get -qy update >/dev/null
apt-get -qy install --no-install-recommends dkms kmod binutils zstd xz-utils "linux-headers-$kver" >/dev/null
other=6.6.0-1-other
mkdir -p "/lib/modules/$other"
ln -s "/usr/src/linux-headers-$kver" "/lib/modules/$other/build"

apt-get -qy install --no-install-recommends "$deb" >/dev/null
dkms status
ko=$(compgen -G "/lib/modules/$kver/updates/dkms/amdgpu.ko*" | head -1)
[ -n "$ko" ] || { echo "test-amdgpu-dkms.sh: no DKMS amdgpu for $kver" >&2; exit 1; }
echo "amdgpu: $ko"
case "$ko" in
*.zst) zstd -dq "$ko" -o /tmp/amdgpu.ko ;;
*.xz) xz -dc "$ko" >/tmp/amdgpu.ko ;;
*) cp "$ko" /tmp/amdgpu.ko ;;
esac
# The memory partition setup was compiled in, not left behind its guard
# Captured first: grep -q stops at the first match, and under pipefail the
# SIGPIPE that leaves nm with would read as the symbol missing.
syms=$(nm /tmp/amdgpu.ko)
grep -q ' soc_v1_0_get_xcp_mem_id$' <<<"$syms" ||
	{ echo "test-amdgpu-dkms.sh: soc_v1_0_get_xcp_mem_id is not in the module" >&2; exit 1; }
if compgen -G "/lib/modules/$other/updates/dkms/amdgpu*" >/dev/null; then
	echo "test-amdgpu-dkms.sh: built for $other, outside the series" >&2
	exit 1
fi
apt-get -qy purge "$(dpkg-deb -f "$deb" Package)" >/dev/null
if dkms status | grep -q amdgpu-xnvme; then
	echo "test-amdgpu-dkms.sh: purge left the DKMS module registered" >&2
	exit 1
fi
echo "test-amdgpu-dkms.sh: ok"
