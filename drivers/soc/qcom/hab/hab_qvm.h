/* Copyright (c) 2016-2017, The Linux Foundation. All rights reserved.
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
#ifndef __HAB_QNX_H
#define __HAB_QNX_H
#include "hab.h"
#include "hab_pipe.h"

#if defined(ENABLE_HOST_VM) || defined(ENABLE_GUEST_VM)
#include <hyp_shm.h>
#include <guest_shm.h>
#include <sys/mman.h>
#include <sys/iomgr.h>
#include <sys/neutrino.h>
#include <stdlib.h>
#include <errno.h>
#include <stddef.h>
#include <inttypes.h>
#else /* AGL guest */
#include <guest_shm.h>
#include <linux/stddef.h>
#endif

#define PULSE_CODE_NOTIFY 0
#define PULSE_CODE_INPUT 1

struct qvm_channel {
	int be;

	struct hab_pipe *pipe;
	struct hab_pipe_endpoint *pipe_ep;
	spinlock_t io_lock;
#if defined(__linux__)
	struct tasklet_struct task;
#endif

#ifdef ENABLE_HOST_VM
	struct hyp_shm *host_hsp;
	unsigned int host_idx;
#endif
	volatile struct guest_shm_factory *guest_factory;
	volatile struct guest_shm_control *guest_ctrl;
	uint32_t idx; /* cached guest ctrl idx value to prevent trap when accessed */

	int channel;
	int coid;

/** Host VM */

/** Guest VM */
	unsigned int guest_intr;
	unsigned int guest_iid;
	unsigned int factory_addr;
	unsigned int irq;

#if defined(ENABLE_HOST_VM) || defined(ENABLE_GUEST_VM) /* QNX host or guest */
	pthread_t thread_id;
#endif
};

/* Shared mem size in each direction for communication pipe */
#define PIPE_SHMEM_SIZE (128 * 1024)

void *qnx_hyp_rx_dispatch(void *data);
void hab_pipe_reset(struct physical_channel *pchan);
#endif /* __HAB_QNX_H */
