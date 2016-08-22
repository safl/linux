/*
 * Copyright (C) 2015 CNEX Labs. All rights reserved.
 * Initial release:
 *	- Javier González <javier@cnexlabs.com>
 *	- Matias Bjorling <matias@cnexlabs.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139,
 * USA.
 */

#ifndef DFLASH_H_
#define DFLASH_H_

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>
#include <linux/blk_types.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>

#include <linux/lightnvm.h>
#include <uapi/linux/lightnvm.h>

#define dflash_SECTOR (512)
#define dflash_EXPOSED_PAGE_SIZE (4096)

#define NR_PHY_IN_LOG (dflash_EXPOSED_PAGE_SIZE / dflash_SECTOR)

struct dflash {
	struct nvm_tgt_instance instance;
	unsigned long nr_luns;
	struct nvm_lun **luns;
	unsigned long nr_blocks;
	unsigned long nr_pages;
	mempool_t *rq_pool;
	struct nvm_dev *dev;
	struct gendisk *disk;
};

#endif /* DFLASH_H_ */
