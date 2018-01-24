/* Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#ifndef __HAB_GHS_H
#define __HAB_GHS_H
#ifdef __INTEGRITY
#include <gipc/gipc_integrity.h>
#include <gipc/gipc.h>
#include <util/devtree_user_import.h>
#include <util/devtree_gipc_user_import.h>
#include <util/devtree_core.h>
#include <util/devtree_user.h>
#elif __linux__
#include <ghs_vmm/kgipc.h>
#endif
#define GIPC_RECV_BUFF_SIZE_BYTES   (32*1024)

struct ghs_vdev {
	int be;
	void *read_data; /* buffer to receive from gipc */
	size_t read_size;
	int read_offset;
	GIPC_Endpoint endpoint;
	spinlock_t io_lock;
	char name[32];
#ifdef __INTEGRITY
	MemoryRegion pmr_send;
	MemoryRegion pmr_recv;
	GIPC_Channel channel;
	Task task;
#elif __linux__
	struct tasklet_struct task;
#endif
};

#ifdef __INTEGRITY
Value ghs_hyp_rx_dispatch(Address data);
#endif

#endif /* __HAB_GHS_H */
