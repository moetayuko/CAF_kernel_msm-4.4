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
#include "hab.h"
#include "hab_ghs.h"

int physical_channel_read(struct physical_channel *pchan,
		void *payload,
		size_t read_size)
{
	struct ghs_vdev *dev  = (struct ghs_vdev *)pchan->hyp_data;

	/* size in header is only for payload excluding the header itself */
	if (dev->read_size < read_size + sizeof(struct hab_header)) {
		pr_warn("read %d is less than requested %d plus header %d\n",
			dev->read_size, read_size, sizeof(struct hab_header));
		read_size = dev->read_size;
	}

	/* always skip the header */
	memcpy(payload, (unsigned char *)dev->read_data +
		sizeof(struct hab_header) + dev->read_offset, read_size);
	dev->read_offset += read_size;
	return read_size;
}

int physical_channel_send(struct physical_channel *pchan,
		struct hab_header *header,
		void *payload)
{
	int sizebytes = HAB_HEADER_GET_SIZE(*header);
	struct ghs_vdev *dev  = (struct ghs_vdev *)pchan->hyp_data;
	GIPC_Result result;
	uint8_t *msg;

	spin_lock_bh(&dev->io_lock);

#ifdef __INTEGRITY
	result = GIPC_WaitToSend(dev->endpoint);
	if (result != GIPC_Success) {
		spin_unlock_bh(&dev->io_lock);
		pr_err("failed to wait to send %d!\n", result);
		return -EBUSY;
	}
#endif
	result = GIPC_PrepareMessage(dev->endpoint, sizebytes+sizeof(*header),
		(void **)&msg);
	if (result == GIPC_Full) {
		spin_unlock_bh(&dev->io_lock);
		/* need to wait for space! */
		pr_err("failed to reserve send msg for %zd bytes!\n",
			sizebytes+sizeof(*header));
		return -EBUSY;
	} else if (result != GIPC_Success) {
		spin_unlock_bh(&dev->io_lock);
		pr_err("failed to send %d due to error!\n", result);
		return -ENOMEM;
	}

	if (HAB_HEADER_GET_TYPE(*header) == HAB_PAYLOAD_TYPE_PROFILE) {
		struct timeval tv;
		struct habmm_xing_vm_stat *pstat =
					(struct habmm_xing_vm_stat *)payload;
#ifdef __INTEGRITY
		gettimeofday(&tv, NULL);
#else
		do_gettimeofday(&tv);
#endif
		pstat->tx_sec = tv.tv_sec;
		pstat->tx_usec = tv.tv_usec;
	}

	memcpy(msg, header, sizeof(*header));

	if (sizebytes)
		memcpy(msg+sizeof(*header), payload, sizebytes);

	result = GIPC_IssueMessage(dev->endpoint, sizebytes+sizeof(*header),
		header->id_type_size);
	spin_unlock_bh(&dev->io_lock);
	if (result != GIPC_Success) {
		pr_err("failed to send %d, ep %p, msg %p, sz %zd, prot %x\n",
			result, dev->endpoint, msg, sizebytes+sizeof(*header),
			   header->id_type_size);
		return -EAGAIN;
	}

	return 0;
}

void physical_channel_rx_dispatch(unsigned long physical_channel)
{
	struct hab_header header;
	struct physical_channel *pchan =
		(struct physical_channel *)physical_channel;
	struct ghs_vdev *dev = (struct ghs_vdev *)pchan->hyp_data;
	GIPC_Result result;

#if defined(__linux__)
	uint32_t events;
	unsigned long flags;

	spin_lock_irqsave(&pchan->rxbuf_lock, flags);
	events = kgipc_dequeue_events(dev->endpoint);
	spin_unlock_irqrestore(&pchan->rxbuf_lock, flags);

	if (events & (GIPC_EVENT_RESET))
		pr_info("hab gipc RESET\n");
	if (events & (GIPC_EVENT_RESETINPROGRESS))
		pr_info("hab gipc RESETINPROGRESS\n");

	if (events & (GIPC_EVENT_RECEIVEREADY)) {
#endif
		spin_lock_bh(&pchan->rxbuf_lock);
		while (1) {
			dev->read_size = 0;
			dev->read_offset = 0;
			result = GIPC_ReceiveMessage(dev->endpoint,
					dev->read_data,
					GIPC_RECV_BUFF_SIZE_BYTES,
					&dev->read_size,
					&header.id_type_size);

			if (result == GIPC_Success || dev->read_size > 0) {
				 /* handle corrupted msg? */
				hab_msg_recv(pchan, dev->read_data);
			} else if (result == GIPC_Empty) {
				/* no more pending msg */
				break;
			} else {
				pr_warn("recv unhandled result %d, size %d\n",
					result, dev->read_size);
				break;
			}
		}
		spin_unlock_bh(&pchan->rxbuf_lock);
#if defined(__linux__)
	}

	if (events & (GIPC_EVENT_SENDREADY))
		pr_info("kgipc send ready\n");
#endif
}

#ifdef __INTEGRITY
Value ghs_hyp_rx_dispatch(Address data)
{
	struct physical_channel *pchan =
		(struct physical_channel *)data;
	struct ghs_vdev *dev = (struct ghs_vdev *)pchan->hyp_data;
	GIPC_Result result;

#if 0
	/* for native gipc doing synchronized mode */
	if (dev->be)
		GIPC_ExtractEndpoint(dev->channel, 1, &dev->endpoint);
#else
	/*
	 * INTEGRITY endpoint is synchronized by choice, the Linux kernel side
		is asynchronized as limitation from GHS
	 */
	result = GIPC_ModifyEndpoint(dev->endpoint, false, NULL, NULL);
	if (result != GIPC_Success) {
		HAB_LOG_ERR("endpoint switch to sync mode failed! ret %d, %s\n",
			result, dev->name);
	} else {
		HAB_LOG_INFO("endpoint switch to sync mode passes for id %s!\n",
			dev->name);
	}
#endif

	while (1) {
		result = GIPC_WaitToReceive(dev->endpoint);
		if (result == GIPC_Reset) {
			GIPC_ClearReset(dev->endpoint);
		} else if (result == GIPC_Success) {
			physical_channel_rx_dispatch((unsigned long) pchan);
		} else {
			pr_err("Unknown error: %d\n", result);
			/* do not leave this loop for next events */
		}
	}

	return 0;
}
#endif
