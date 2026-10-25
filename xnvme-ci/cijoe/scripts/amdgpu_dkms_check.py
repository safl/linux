#!/usr/bin/env python3
"""
Install the amdgpu DKMS deb against a kernel's headers and check the build
==========================================================================

Installs the amdgpu-xnvme deb from 'xnvme_ci.out' with the headers of
'--kernel' and checks that DKMS built amdgpu.ko for it with the fixes in, and
that a kernel of another series is skipped rather than failing the install.
Then purges it and checks DKMS forgot it. Needs no such kernel running.

'--kernel' is 'ubuntu' for 'xnvme_ci.ubuntu_kernel', whose headers come from
the archive, or 'xnvme' for ours, whose headers kernel_check installed.

Retargetable: true
------------------
"""
import errno
import logging as log
from argparse import ArgumentParser

OTHER = "6.6.0-1-other"


def add_args(parser: ArgumentParser):
    parser.add_argument("--kernel", choices=["ubuntu", "xnvme"], default="ubuntu")


def main(args, cijoe):
    """Check the amdgpu DKMS build for one kernel"""

    out = cijoe.getconf("xnvme_ci.out")
    if args.kernel == "ubuntu":
        kver = cijoe.getconf("xnvme_ci.ubuntu_kernel")
    else:
        kver = f"7.3.0-xnvme{cijoe.getconf('xnvme_ci.n')}"

    err, _ = cijoe.run(
        "export DEBIAN_FRONTEND=noninteractive && apt-get -qy update && "
        f"apt-get -qy install --no-install-recommends dkms kmod binutils zstd xz-utils "
        f"linux-headers-{kver} && mkdir -p /lib/modules/{OTHER} && "
        f"ln -sfn /usr/src/linux-headers-{kver} /lib/modules/{OTHER}/build && "
        f"apt-get -qy install --no-install-recommends {out}/amdgpu-xnvme-*-dkms_*.deb && "
        "dkms status"
    )
    if err:
        log.error(f"the DKMS package did not install against {kver}")
        return err

    # The memory partition setup was compiled in, not left behind its guard
    err, _ = cijoe.run(
        f"ko=$(ls /lib/modules/{kver}/updates/dkms/amdgpu.ko* | head -n 1) && echo $ko && "
        'case "$ko" in *.zst) zstd -dqf "$ko" -o /tmp/amdgpu.ko ;; '
        '*.xz) xz -dc "$ko" > /tmp/amdgpu.ko ;; *) cp "$ko" /tmp/amdgpu.ko ;; esac && '
        "nm /tmp/amdgpu.ko > /tmp/amdgpu.syms && grep ' soc_v1_0_get_xcp_mem_id$' /tmp/amdgpu.syms"
    )
    if err:
        log.error(f"no DKMS amdgpu with the GC 12.1 fixes for {kver}")
        return err

    err, _ = cijoe.run(f"ls /lib/modules/{OTHER}/updates/dkms/amdgpu*")
    if not err:
        log.error(f"DKMS built amdgpu for {OTHER}, outside the series")
        return errno.EINVAL

    err, _ = cijoe.run(
        "apt-get -qy purge $(dpkg-deb -f $(ls " + out + "/amdgpu-xnvme-*-dkms_*.deb) Package) && "
        "! dkms status | grep amdgpu-xnvme"
    )
    if err:
        log.error("the purge left the DKMS module registered")
        return err

    return 0
