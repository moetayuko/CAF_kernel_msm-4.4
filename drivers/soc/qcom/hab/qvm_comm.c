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
#include "hab.h"
#include "hab_qvm.h"

static inline void habhyp_notify(void *commdev)
{
	struct qvm_channel *dev = (struct qvm_channel *)commdev;

#ifdef ENABLE_HOST_VM
	if (dev)
		hyp_shm_poke(dev->host_hsp, HYP_SHM_POKE_ALL_BUT_ME);
#else
	if (dev && dev->guest_ctrl)
		dev->guest_ctrl->notify = ~0;
#endif
}

/* this is only used to read payload, never the head! */
int physical_channel_read(struct physical_channel *pchan,
		void *payload,
		size_t read_size)
{
	struct qvm_channel *dev  = (struct qvm_channel *)pchan->hyp_data;

	if (dev)
		return hab_pipe_read(dev->pipe_ep, payload, read_size);
	else
		return 0;
}

#define HAB_HEAD_SIGNATURE 0xBEE1BEE1

int physical_channel_send(struct physical_channel *pchan,
		struct hab_header *header,
		void *payload)
{
	int sizebytes = HAB_HEADER_GET_SIZE(*header);
	struct qvm_channel *dev  = (struct qvm_channel *)pchan->hyp_data;
	int write_size;
	int total_size = sizeof(*header) + sizebytes;

	if (total_size > dev->pipe_ep->tx_info.sh_buf->size)
		return -EINVAL; /* too much data for ring */

	spin_lock_bh(&dev->io_lock);

	if ((dev->pipe_ep->tx_info.sh_buf->size -
		(dev->pipe_ep->tx_info.wr_count -
		dev->pipe_ep->tx_info.sh_buf->rd_count)) < total_size) {
		spin_unlock_bh(&dev->io_lock);
		return -EAGAIN; /* not enough free space */
	}
	
#ifdef _DEBUG
	header->sequence = ++pchan->sequence_tx;
#endif
	header->signature = HAB_HEAD_SIGNATURE;

	if (hab_pipe_write(dev->pipe_ep,
		(unsigned char *)header,
		sizeof(*header)) != sizeof(*header)) {
		spin_unlock_bh(&dev->io_lock);
		return -EIO;
	}

	if (HAB_PAYLOAD_TYPE_PROFILE == HAB_HEADER_GET_TYPE(*header)) {
		struct timeval tv;
#ifdef __QNXNTO__
		gettimeofday(&tv, NULL);
#else
		do_gettimeofday(&tv);
#endif
		((uint64_t*)payload)[0] = tv.tv_sec;
		((uint64_t*)payload)[1] = tv.tv_usec;
	}

	if (sizebytes) {
		if (hab_pipe_write(dev->pipe_ep,
			(unsigned char *)payload,
			sizebytes) != sizebytes) {
			spin_unlock_bh(&dev->io_lock);
			return -EIO;
		}
	}

	hab_pipe_write_commit(dev->pipe_ep);
	spin_unlock_bh(&dev->io_lock);
	habhyp_notify(dev);

	return 0;
}

void physical_channel_rx_dispatch(unsigned long data)
{
	struct hab_header header;
	struct physical_channel *pchan = (struct physical_channel *)data;
	struct qvm_channel *dev = (struct qvm_channel *)pchan->hyp_data;

	spin_lock_bh(&pchan->rxbuf_lock);
	while (1) {
		if (hab_pipe_read(dev->pipe_ep,
			(unsigned char *)&header,
			sizeof(header)) != sizeof(header))
			break; /* no data available */

		if (header.signature != HAB_HEAD_SIGNATURE) {
		  HAB_LOG_ERR("HAB signature mismatch expect %X, received %X, %X %X %X %X\n",
					  HAB_HEAD_SIGNATURE, header.signature, header.id_type_size,
					  header.session_id, header.signature, header.sequence);
		}
#ifdef _DEBUG
		if (header.sequence != pchan->sequence_rx + 1) {
		  HAB_LOG_ERR("HAB sequence mismatch expect %X, received %X, %X %X %X %X\n",
					  pchan->sequence_rx + 1, header.sequence, header.id_type_size,
					  header.session_id, header.signature, header.sequence);
		}

		pchan->sequence_rx = header.sequence;
#endif

		hab_msg_recv(pchan, &header);
	}
	spin_unlock_bh(&pchan->rxbuf_lock);
}

#if defined(ENABLE_HOST_VM) || defined(ENABLE_GUEST_VM) /* QNX host or guest */

void *qnx_hyp_rx_dispatch(void *data)
{
	struct physical_channel *pchan = (struct physical_channel *)data;
	struct qvm_channel *dev = (struct qvm_channel *)pchan->hyp_data;

	struct _pulse pulse;
	struct hab_header header;
	int channel = dev->channel;

#ifdef ENABLE_HOST_VM
	uint32_t attach_list = hyp_shm_status(dev->host_hsp) >> 16;
	HAB_LOG_INFO("attach_list=%x\n", attach_list);
#endif

	HAB_LOG_INFO("qnx_hyp_rx_dispatch channel=%d", channel);

	for ( ;; ) {
		int ret = 0;
		/* one channel for all client can be used. Whenever pulse comes,
		 * we can check all the Queues and read all available
		 */
		ret = MsgReceivePulse(channel, &pulse, sizeof(pulse), NULL);
		if ((EFAULT == ret) || (ESRCH == ret)) {
			HAB_LOG_ERR("failed to recv pulse for pchannel %d(%d)", pchan->habdev->id, ret);
			break;
		}

		spin_lock_bh(&pchan->rxbuf_lock);
		switch (pulse.code) {
		case PULSE_CODE_INPUT:
			break;
		case PULSE_CODE_NOTIFY:
		{
			uint32_t status = 0;
			uint32_t condition = 1;
#ifdef ENABLE_HOST_VM
			uint32_t attach_list_new;
			status = hyp_shm_status(dev->host_hsp);

			//HAB_LOG_INFO("Host status:%x, attach_list %x\n", status, attach_list); // read back 0x30002

			attach_list_new = status >> 16;
			if(attach_list_new != attach_list) {
				if (attach_list > attach_list_new) {
					HAB_LOG_ERR("detach %4x => %4x", attach_list, attach_list_new);
					/* detach notification is used for awareness of GVM termination */
					if (habhyp_read(dev, (char *)&header,
							sizeof(header)) == sizeof(header)) {
						/* Just a catcher here and do nothing more now */
						HAB_LOG_WARN("Data available when handling remote's detach!");
					}

					hab_vchans_stop(pchan);
					hab_pipe_reset(pchan);
				} else {
					HAB_LOG_INFO("attach %4x => %4x", attach_list, attach_list_new);
				}

				attach_list = attach_list_new;
				break;
			}

#else
			status = dev->guest_ctrl->status;
			condition = (status & /*(1<<dev->idx)*/0xffff);/*bitmask is for source*/
#endif
			while ((pchan != NULL) && condition) {
				if (hab_pipe_read(dev->pipe_ep,
					(unsigned char *)&header,
					sizeof(header)) != sizeof(header))
					break; /* no data available */

				if (header.signature != HAB_HEAD_SIGNATURE) {
				  HAB_LOG_ERR("HAB signature mismatch expect %X, received %X, %X %X %X %X\n",
							  HAB_HEAD_SIGNATURE, header.signature, header.id_type_size,
							  header.session_id, header.signature, header.sequence);
				}
#ifdef _DEBUG
				if (header.sequence != pchan->sequence_rx + 1) {
				  HAB_LOG_ERR("HAB sequence mismatch expect %X, received %X, %X %X %X %X\n",
							  pchan->sequence_rx + 1, header.sequence, header.id_type_size,
							  header.session_id, header.signature, header.sequence);
				}

				pchan->sequence_rx = header.sequence;
#endif

				hab_msg_recv(pchan, &header);
			}
#ifndef ENABLE_HOST_VM
			InterruptUnmask(dev->guest_intr, dev->guest_iid);
#endif
			break;
		}
		default:
			HAB_LOG_ERR("unexpected pulse %d", pulse.code);
			break;
		}
		spin_unlock_bh(&pchan->rxbuf_lock);
	}

#ifdef ENABLE_HOST_VM
	hyp_shm_detach(dev->host_hsp);
#endif

	HAB_LOG_ERR("rx dispatcher destroyed!");
	return NULL;
}
#endif
