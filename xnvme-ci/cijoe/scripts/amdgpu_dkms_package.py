#!/usr/bin/env python3
"""
Package this tree's amdgpu as a DKMS deb for its kernel series
==============================================================

The package carries drivers/gpu/drm/amd from this tree, which is mainline
plus the GC 12.1 fixes rocjitsu's GPU needs, and DKMS builds amdgpu.ko from
it on install for every installed kernel of the series, ours and Ubuntu's
alike. So a machine gets the fixes on its own kernel, without a reboot into
ours.

The deb is <version>+xnvme<n> for a release, or <version>+xnvme0~g<commit>
for a build of the branch, with 'xnvme_ci.n' as <n>.

Retargetable: true
------------------
"""
import logging as log
import shlex

NAME = "amdgpu-xnvme"
MAINTAINER = "Simon A. F. Lund <os@safl.dk>"


def main(args, cijoe):
    """Stage and build the amdgpu-xnvme-<series>-dkms deb into 'xnvme_ci.out'"""

    src = cijoe.getconf("xnvme_ci.src")
    out = cijoe.getconf("xnvme_ci.out")
    n = int(cijoe.getconf("xnvme_ci.n"))

    err, state = cijoe.run(
        "awk -F' = ' '$1==\"VERSION\"{v=$2} $1==\"PATCHLEVEL\"{p=$2} "
        "$1==\"SUBLEVEL\"{s=$2} END{print v\".\"p\".\"s}' Makefile && "
        "git rev-parse --short HEAD",
        cwd=src,
    )
    if err:
        return err
    kv, sha = state.output().split()[-2:]
    series = ".".join(kv.split(".")[:2])
    version = f"{kv}+xnvme{n}" if n else f"{kv}+xnvme0~g{sha}"
    pkg = f"{NAME}-{series}-dkms"
    exclusive = "^" + series.replace(".", r"\.") + "[.-]"
    log.info(f"packaging {pkg} {version}")

    # The trace headers name themselves relative to include/trace, so that has
    # to sit beside drivers/ for them to resolve in this tree rather than the
    # kernel's headers.
    dkms_conf = f"""PACKAGE_NAME="{NAME}"
PACKAGE_VERSION="{series}"
BUILT_MODULE_NAME[0]="amdgpu"
BUILT_MODULE_LOCATION[0]="drivers/gpu/drm/amd/amdgpu"
DEST_MODULE_LOCATION[0]="/updates/dkms"
BUILD_EXCLUSIVE_KERNEL="{exclusive}"
AUTOINSTALL="yes"
MAKE[0]="make -C ${{kernel_source_dir}} M=${{dkms_tree}}/${{PACKAGE_NAME}}/${{PACKAGE_VERSION}}/build/drivers/gpu/drm/amd/amdgpu KCFLAGS=-I${{dkms_tree}}/${{PACKAGE_NAME}}/${{PACKAGE_VERSION}}/build/include/trace -j$(nproc) modules"
CLEAN="true"
"""
    control = f"""Package: {pkg}
Version: {version}
Architecture: all
Maintainer: {MAINTAINER}
Depends: dkms
Section: kernel
Priority: optional
Homepage: https://github.com/safl/linux/tree/xnvme-ci/artifacts
Description: amdgpu with the GC 12.1 fixes rocjitsu needs, as DKMS, for {series} kernels
 amdgpu from Linux {kv} with the changes GC 12.1 needs that mainline lacks,
 built by DKMS for every installed {series} kernel and installed under
 updates/dkms, so it takes precedence over the kernel's own. The changes
 are listed in /usr/share/doc/{pkg}/changes.
"""
    # 77 is DKMS declining a kernel outside BUILD_EXCLUSIVE_KERNEL
    postinst = f"""#!/bin/sh
set -e
if [ "$1" = configure ]; then
	dkms add {NAME}/{series} >/dev/null 2>&1 || true
	for build in /lib/modules/*/build; do
		[ -e "$build" ] || continue
		dkms install {NAME}/{series} -k "$(basename "$(dirname "$build")")" || [ $? -eq 77 ]
	done
fi
"""
    prerm = f"""#!/bin/sh
set -e
dkms remove {NAME}/{series} --all >/dev/null 2>&1 || true
"""

    stage = "$work/stage"
    usr_src = f"{stage}/usr/src/{NAME}-{series}"
    doc = f"{stage}/usr/share/doc/{pkg}"
    files = {
        f"{usr_src}/dkms.conf": dkms_conf,
        f"{stage}/DEBIAN/control": control,
        f"{stage}/DEBIAN/postinst": postinst,
        f"{stage}/DEBIAN/prerm": prerm,
    }
    writes = " && ".join(
        f"printf '%s' {shlex.quote(body)} > {path}" for path, body in files.items()
    )
    # The release commit rather than its tag, which a fork's clone may not carry
    err, _ = cijoe.run(
        f"work=$(mktemp -d) && mkdir -p {usr_src}/drivers/gpu/drm {usr_src}/include/trace "
        f"{doc} {stage}/DEBIAN && cp -a drivers/gpu/drm/amd {usr_src}/drivers/gpu/drm/ && "
        f"{writes} && chmod 0755 {stage}/DEBIAN/postinst {stage}/DEBIAN/prerm && "
        f"install -m 0644 COPYING {doc}/copyright && "
        f"release=$(git log -1 --format=%H --grep='^Linux {series}$' HEAD) && "
        f'[ -n "$release" ] && '
        f'git log --format="%h %s" "$release..HEAD" -- drivers/gpu/drm/amd > {doc}/changes && '
        f"mkdir -p {out} && dpkg-deb --root-owner-group -Zxz --build {stage} {out} && "
        f"rm -rf $work && ls {out}/{pkg}_*.deb",
        cwd=src,
    )
    return err
