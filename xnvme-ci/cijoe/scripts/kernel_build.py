#!/usr/bin/env python3
"""
Build this tree as the kernel of xNVMe's test guests
=====================================================

Builds linux-image and linux-headers debs for the release 7.3.0-xnvme<n>,
configured as Ubuntu's own 'xnvme_ci.ubuntu_kernel', which the guests run
otherwise, so the two differ only in the patches this tree carries.

Ubuntu's config is changed only where it cannot be built outside Canonical,
or for nothing: its certificates are Canonical's, so modules are signed with
a key of the build's own; Rust needs a toolchain the archive does not carry;
and debug info nobody reads in these guests would triple the build.

Retargetable: true
------------------
"""
import errno
import logging as log


def main(args, cijoe):
    """Build the kernel debs into 'xnvme_ci.out'"""

    src = cijoe.getconf("xnvme_ci.src")
    out = cijoe.getconf("xnvme_ci.out")
    n = cijoe.getconf("xnvme_ci.n")
    ubuntu = cijoe.getconf("xnvme_ci.ubuntu_kernel")
    release = f"7.3.0-xnvme{n}"
    if not (src and out and str(n).isdigit()):
        log.error("set XNVME_CI_SRC, XNVME_CI_OUT and XNVME_CI_N")
        return errno.EINVAL

    err, _ = cijoe.run(
        f"work=$(mktemp -d) && cd $work && apt-get download linux-modules-{ubuntu} && "
        f"dpkg-deb --fsys-tarfile linux-modules-*.deb | "
        f"tar -xOf - ./boot/config-{ubuntu} > {src}/.config && rm -rf $work"
    )
    if err:
        log.error(f"could not take the config from linux-modules-{ubuntu}")
        return err

    err, _ = cijoe.run(
        "scripts/config --set-str SYSTEM_TRUSTED_KEYS '' --set-str SYSTEM_REVOCATION_KEYS '' "
        "--set-str LOCALVERSION '' --disable LOCALVERSION_AUTO "
        "--disable DEBUG_INFO_DWARF5 --disable DEBUG_INFO_DWARF4 "
        "--disable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT --enable DEBUG_INFO_NONE "
        "--disable DEBUG_INFO_BTF --disable RUST && make olddefconfig",
        cwd=src,
    )
    if err:
        return err

    # The build's output is long and goes to the report as a log of its own
    err, _ = cijoe.run(
        f"make -j$(nproc) bindeb-pkg LOCALVERSION=-xnvme{n} KDEB_PKGVERSION={release} "
        f"> {out}.build.log 2>&1 || {{ tail -n 80 {out}.build.log; exit 1; }}",
        cwd=src,
    )
    if err:
        log.error(f"the kernel build failed; see {out}.build.log")
        return err

    return cijoe.run(
        f"mkdir -p {out} && mv {src}/../linux-image-{release}_*.deb "
        f"{src}/../linux-headers-{release}_*.deb {out}/ && ls -l {out}"
    )[0]
