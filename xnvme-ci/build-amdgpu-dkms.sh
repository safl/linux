#!/bin/bash
# Package this tree's amdgpu as a DKMS .deb for one kernel series, for guests
# whose GPU is rocjitsu's GC 12.1.
#
#   build-amdgpu-dkms.sh <output dir> <deb version>
#
# The package carries drivers/gpu/drm/amd from this branch, which is mainline
# plus the GC 12.1 fixes on top of it, and DKMS builds amdgpu.ko from it on
# install for every installed kernel of the tree's series. So a machine gets
# the fixes on its own kernel, without a reboot into ours.
#
# Copyright (c) Simon A. F. Lund <os@safl.dk>
# SPDX-License-Identifier: GPL-2.0
set -euo pipefail
out=$(realpath "$1")
version=$2
tree=$(cd "$(dirname "$0")/.." && pwd)

export DEBIAN_FRONTEND=noninteractive
apt-get -qy update >/dev/null
apt-get -qy install --no-install-recommends ca-certificates git >/dev/null

kv=$(awk -F' = ' '$1=="VERSION"{v=$2} $1=="PATCHLEVEL"{p=$2} $1=="SUBLEVEL"{s=$2}
	END{print v"."p"."s}' "$tree/Makefile")
series=$(echo "$kv" | cut -d. -f1-2)
name=amdgpu-xnvme
pkg=$name-$series-dkms
work=$(mktemp -d)
src=$work/stage/usr/src/$name-$series
mkdir -p "$src/drivers/gpu/drm" "$src/include/trace"
cp -a "$tree/drivers/gpu/drm/amd" "$src/drivers/gpu/drm/"

# The trace headers name themselves relative to include/trace, so that has to
# sit beside drivers/ for them to resolve in this tree rather than the
# kernel's headers.
cat >"$src/dkms.conf" <<CONF
PACKAGE_NAME="$name"
PACKAGE_VERSION="$series"
BUILT_MODULE_NAME[0]="amdgpu"
BUILT_MODULE_LOCATION[0]="drivers/gpu/drm/amd/amdgpu"
DEST_MODULE_LOCATION[0]="/updates/dkms"
BUILD_EXCLUSIVE_KERNEL="^${series//./\\.}[.-]"
AUTOINSTALL="yes"
MAKE[0]="make -C \${kernel_source_dir} M=\${dkms_tree}/\${PACKAGE_NAME}/\${PACKAGE_VERSION}/build/drivers/gpu/drm/amd/amdgpu KCFLAGS=-I\${dkms_tree}/\${PACKAGE_NAME}/\${PACKAGE_VERSION}/build/include/trace -j\$(nproc) modules"
CLEAN="true"
CONF

stage=$work/stage
install -D -m 0644 "$tree/COPYING" "$stage/usr/share/doc/$pkg/copyright"
# The release commit rather than its tag, which a fork's clone may not carry
release=$(git -C "$tree" log -1 --format=%H --grep="^Linux $series\$" HEAD)
[ -n "$release" ]
git -C "$tree" log --format='%h %s' "$release..HEAD" -- drivers/gpu/drm/amd \
	>"$stage/usr/share/doc/$pkg/changes"
mkdir -p "$stage/DEBIAN"
cat >"$stage/DEBIAN/control" <<CONTROL
Package: $pkg
Version: $version
Architecture: all
Maintainer: Simon A. F. Lund <os@safl.dk>
Depends: dkms
Section: kernel
Priority: optional
Homepage: https://github.com/safl/linux/tree/xnvme-ci/artifacts
Description: amdgpu with the GC 12.1 fixes rocjitsu needs, as DKMS, for $series kernels
 amdgpu from Linux $kv with the changes GC 12.1 needs that mainline lacks,
 built by DKMS for every installed $series kernel and installed under
 updates/dkms, so it takes precedence over the kernel's own. The changes
 are listed in /usr/share/doc/$pkg/changes.
CONTROL
cat >"$stage/DEBIAN/postinst" <<POSTINST
#!/bin/sh
set -e
if [ "\$1" = configure ]; then
	dkms add $name/$series >/dev/null 2>&1 || true
	for build in /lib/modules/*/build; do
		[ -e "\$build" ] || continue
		# 77 is DKMS declining a kernel outside BUILD_EXCLUSIVE_KERNEL
		dkms install $name/$series -k "\$(basename "\$(dirname "\$build")")" ||
			[ \$? -eq 77 ]
	done
fi
POSTINST
cat >"$stage/DEBIAN/prerm" <<PRERM
#!/bin/sh
set -e
dkms remove $name/$series --all >/dev/null 2>&1 || true
PRERM
chmod 0755 "$stage/DEBIAN/postinst" "$stage/DEBIAN/prerm"
mkdir -p "$out"
dpkg-deb --root-owner-group -Zxz --build "$stage" "$out" >/dev/null
rm -rf "$work"
ls "$out/${pkg}_"*.deb
