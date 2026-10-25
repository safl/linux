#!/usr/bin/env python3
"""
Install the guests' kernel debs and check what DKMS and the guests rely on
==========================================================================

Installs linux-image and linux-headers 7.3.0-xnvme<n> from 'xnvme_ci.out'
and checks that the kernel and its modules land under that release and that
its headers carry the io_uring dma-buf uAPI the guests test. Booting it is
xnvme-images' to check, in the guest.

The headers ship objtool built against libelf, which the debs the kernel's
own packaging makes do not depend on, so it is installed here as Ubuntu's
headers would pull it in.

Retargetable: true
------------------
"""
import errno
import logging as log


def main(args, cijoe):
    """Install and check the kernel debs"""

    out = cijoe.getconf("xnvme_ci.out")
    release = f"7.3.0-xnvme{cijoe.getconf('xnvme_ci.n')}"

    err, _ = cijoe.run(
        "export DEBIAN_FRONTEND=noninteractive && apt-get -qy update && "
        "apt-get -qy install --no-install-recommends kmod libelf1t64 "
        f"{out}/linux-image-{release}_*.deb {out}/linux-headers-{release}_*.deb"
    )
    if err:
        return err

    err, _ = cijoe.run(
        f"test -s /boot/vmlinuz-{release} && test -s /lib/modules/{release}/modules.dep"
    )
    if err:
        log.error(f"the image did not install {release}'s kernel and modules")
        return err

    err, _ = cijoe.run(
        "grep -n IO_REGBUF_TYPE_DMABUF "
        f"/usr/src/linux-headers-{release}/include/uapi/linux/io_uring.h"
    )
    if err:
        log.error(f"{release}'s headers lack the io_uring dma-buf uAPI")
        return errno.ENOENT

    return 0
