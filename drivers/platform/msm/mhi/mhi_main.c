/* Copyright (c) 2014-2017, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <linux/completion.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>
#include <linux/of_gpio.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/cpu.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/completion.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/iommu.h>
#include <linux/termios.h>
#include <linux/skbuff.h>
#include "mhi.h"

void *mhi_to_virtual(struct mhi_ring *ring, dma_addr_t addr)
{
	return (addr - ring->phys_base) + ring->base;
}

void mhi_add_ring_element(struct mhi_device *mhi_dev,
				 struct mhi_ring *ring)
{
	ring->wp += ring->el_size;
	if (ring->wp >= (ring->base + ring->len))
		ring->wp = ring->base;
	smp_wmb();
}

void mhi_del_ring_element(struct mhi_device *mhi_dev,
				 struct mhi_ring *ring)
{
	ring->rp += ring->el_size;
	if (ring->rp >= (ring->base + ring->len))
		ring->rp = ring->base;
	smp_wmb();
}

int get_nr_avail_ring_elements(struct mhi_device *mhi_dev,
				      struct mhi_ring *ring)
{
	int nr_el;

	if (ring->wp < ring->rp)
		nr_el = ((ring->rp - ring->wp) / ring->el_size) - 1;
	else {
		nr_el = (ring->rp - ring->base) / ring->el_size;
		nr_el += ((ring->base + ring->len - ring->wp) /
			  ring->el_size) - 1;
	}
	return nr_el;
}

static bool mhi_is_ring_full(struct mhi_device *mhi_dev, struct mhi_ring *ring)
{
	void *tmp = ring->wp + ring->el_size;

	if (tmp >= (ring->base + ring->len))
		tmp = ring->base;

	return (tmp == ring->rp);
}

static void mhi_recycle_ev_ring_element(struct mhi_device *mhi_dev,
					struct mhi_ring *ring)
{
	/* Update the WP */
	ring->wp += ring->el_size;
	if (ring->wp >= (ring->base + ring->len))
		ring->wp = ring->base;

	/* Update the RP */
	ring->rp += ring->el_size;
	if (ring->rp >= (ring->base + ring->len))
		ring->rp = ring->base;

	/* visible to other cores */
	smp_wmb();
}



/*
 * allocate coherent buffers
 * Memory leak debug tools such as kmemleak does not catch CMA memory
 * allocations such as from dma_alloc_coherent.  Track all coherent memory
 * allocations coming from MHI to catch any potential memory leaks.
*/
void *mhi_alloc_coherent(struct mhi_device *mhi_dev, size_t size,
			 dma_addr_t *dma_handle, gfp_t gfp)
{
	void *buf = dma_alloc_coherent(mhi_dev->dev, size, dma_handle, gfp);
	if (buf)
		atomic_add(size, &mhi_dev->alloc_size);

	return buf;
}

void mhi_free_coherent(struct mhi_device *mhi_dev, size_t size,
		       void *vaddr, dma_addr_t dma_handle)
{
	atomic_sub(size, &mhi_dev->alloc_size);
	dma_free_coherent(mhi_dev->dev, size, vaddr, dma_handle);
}

void mhi_notify_client(struct mhi_device *mhi_dev,
		       struct mhi_chan *mhi_chan,
		       enum MHI_CB_REASON reason)
{
	struct mhi_cb_info cb_info;
	struct mhi_client_data *cldata = mhi_chan->cldata;

	if (!cldata)
		return;
	mhi_log(mhi_dev, MHI_MSG_INFO, "chan:%u notify_reason:0x%x\n",
		mhi_chan->chan, reason);

	cb_info.user_data = cldata->user_data;
	cb_info.cb_reason = reason;
	cb_info.chan = mhi_chan->chan;
	cldata->mhi_client_cb(&cb_info);
};

void mhi_reset_chan(struct mhi_device *mhi_dev, struct mhi_chan *mhi_chan)
{
	struct __packed mhi_tre *dev_rp, *local_rp;
	struct __packed mhi_event_ctxt *er_ctxt;
	struct mhi_event *mhi_event;
	struct mhi_ring *ev_ring, *buf_ring, *tre_ring;
	unsigned long flags;
	int chan = mhi_chan->chan;

	mhi_event = &mhi_dev->mhi_event[mhi_chan->er_index];
	ev_ring = &mhi_event->ring;
	er_ctxt = &mhi_dev->mhi_ctxt.er_ctxt[mhi_chan->er_index];

	mhi_log(mhi_dev, MHI_MSG_INFO,
		"Marking all events for chan:%d as stale\n", chan);

	/* Clear all stale events related to Channel */
	spin_lock_irqsave(&mhi_event->lock, flags);
	dev_rp = mhi_to_virtual(ev_ring, er_ctxt->rp);;
	local_rp = ev_ring->rp;

	while (dev_rp != local_rp) {
		if (MHI_TRE_GET_EV_TYPE(local_rp) == MHI_PKT_TYPE_TX_EVENT) {
			/* Mark as stale event */
			if (chan == MHI_TRE_GET_EV_CHID(local_rp))
				local_rp->dword[1] =
					MHI_TRE_EV_DWORD1(chan, MHI_PKT_TYPE_STALE_EVENT);
		}

		local_rp++;
		if (local_rp == (ev_ring->base + ev_ring->len))
			local_rp = ev_ring->base;
	}

	mhi_log(mhi_dev, MHI_MSG_INFO, "Finish with data\n");
	spin_unlock_irqrestore(&mhi_event->lock, flags);

	/* reset any pending buffers */
	read_lock_bh(&mhi_dev->pm_lock);
	buf_ring = &mhi_chan->buf_ring;
	tre_ring = &mhi_chan->tre_ring;
	while(tre_ring->rp != tre_ring->wp) {
		struct mhi_buf_info *buf_info = buf_ring->rp;

		if (mhi_chan->dir == DMA_TO_DEVICE) {
			atomic_dec(&mhi_dev->pending_acks);
			mhi_dev->deassert_wake(mhi_dev, false);
			mhi_dev->runtime_put(mhi_dev);
		}
		dma_unmap_single(mhi_dev->dev, buf_info->p_addr, buf_info->len,
				 buf_info->dir);
		mhi_del_ring_element(mhi_dev, buf_ring);
		mhi_del_ring_element(mhi_dev, tre_ring);
	}

	read_unlock_bh(&mhi_dev->pm_lock);
	mhi_log(mhi_dev, MHI_MSG_INFO, "Reset complete.\n");
}

static int mhi_process_event_ring(struct mhi_device *mhi_dev, u32 er_index,
				  u32 event_quota)
{
	struct __packed mhi_tre *dev_rp, *local_rp;
	struct mhi_event *mhi_event = &mhi_dev->mhi_event[er_index];
	struct mhi_ring *ev_ring = &mhi_event->ring;
	struct __packed mhi_event_ctxt *er_ctxt =
		&mhi_dev->mhi_ctxt.er_ctxt[er_index];
	int count = 0;
	unsigned long flags;

	mhi_log(mhi_dev, MHI_MSG_VERBOSE, "Enter ev_index:%u\n", er_index);
	read_lock_bh(&mhi_dev->pm_lock);
	if (unlikely(MHI_EVENT_ACCESS_INVALID(mhi_dev->pm_state))) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"No event access, PM_STATE:0x%x\n",mhi_dev->pm_state);
		read_unlock_bh(&mhi_dev->pm_lock);
		return -EIO;
	}
	mhi_dev->assert_wake(mhi_dev, false);
	read_unlock_bh(&mhi_dev->pm_lock);

	dev_rp = mhi_to_virtual(ev_ring, er_ctxt->rp);
	local_rp = ev_ring->rp;

	while (dev_rp != local_rp && event_quota > 0) {
		enum MHI_PKT_TYPE type = MHI_TRE_GET_EV_TYPE(local_rp);

		mhi_log(mhi_dev, MHI_MSG_VERBOSE,
			"Processing Event:0x%llx 0x%08x 0x%08x\n",
			local_rp->ptr, local_rp->dword[0], local_rp->dword[1]);

		switch (type) {
		case MHI_PKT_TYPE_TX_EVENT:
		{
			u32 chan;
			struct mhi_chan *mhi_chan;

			chan = MHI_TRE_GET_EV_CHID(local_rp);
			mhi_chan = &mhi_dev->mhi_chan[chan];
			parse_xfer_event(mhi_dev, local_rp, mhi_chan);
			event_quota--;
			break;
		}
		case MHI_PKT_TYPE_CMD_COMPLETION_EVENT:
		{
			dma_addr_t ptr = MHI_TRE_GET_EV_PTR(local_rp);
			struct mhi_ring *cmd_ring =
				&mhi_dev->mhi_cmd[PRIMARY_CMD_RING];
			struct __packed mhi_tre *cmd_pkt;
			struct mhi_chan *mhi_chan;
			u32 chan;

			cmd_pkt = mhi_to_virtual(cmd_ring, ptr);

			/* out of order completion received */
			BUG_ON(cmd_pkt != cmd_ring->rp);
			chan = MHI_TRE_GET_CMD_CHID(cmd_pkt);
			mhi_chan = &mhi_dev->mhi_chan[chan];
			write_lock_bh(&mhi_chan->lock);
			mhi_chan->cmd_tre = *cmd_pkt;
			mhi_chan->ev_tre = *local_rp;
			complete(&mhi_chan->completion);
			write_unlock_bh(&mhi_chan->lock);
			mhi_del_ring_element(mhi_dev, cmd_ring);
			break;
		}
		case MHI_PKT_TYPE_STATE_CHANGE_EVENT:
		{
			enum STATE_TRANSITION new_state;
			unsigned long flags;
			new_state = MHI_TRE_GET_EV_STATE(local_rp);

			mhi_log(mhi_dev, MHI_MSG_INFO,
				"MHI state change event to state:%s\n",
				state_transition_str(new_state));

			switch (new_state) {
			case STATE_TRANSITION_M0:
				process_m0_transition(mhi_dev);
				break;
			case STATE_TRANSITION_M1:
				write_lock_irqsave(&mhi_dev->pm_lock, flags);
				mhi_dev->dev_state = mhi_get_m_state(mhi_dev);
				if (mhi_dev->dev_state == MHI_STATE_M1) {
					enum MHI_PM_STATE state;

					state = mhi_tryset_pm_state(mhi_dev,
								    MHI_PM_M1);
					if (state == MHI_PM_M1)
						schedule_work(&mhi_dev->
							      m1_worker);
				}
				write_unlock_irqrestore(&mhi_dev->pm_lock,
							flags);
				break;
			case STATE_TRANSITION_M3:
				process_m3_transition(mhi_dev);
				break;
			case STATE_TRANSITION_SYS_ERR:
			{
				enum MHI_PM_STATE new_state;
				unsigned long flags;

				mhi_log(mhi_dev, MHI_MSG_INFO,
					"MHI System Error Detected\n");
				write_lock_irqsave(&mhi_dev->pm_lock, flags);
				new_state = mhi_tryset_pm_state(mhi_dev,
							MHI_PM_SYS_ERR_DETECT);
				write_unlock_irqrestore(&mhi_dev->pm_lock,
							flags);
				if (new_state == MHI_PM_SYS_ERR_DETECT)
					schedule_work(&mhi_dev->sys_err_worker);
				break;
			}
			default:
				mhi_log(mhi_dev, MHI_MSG_ERROR,
					"Unsupported STE received ring State:%s\n",
					state_transition_str(new_state));
			}
			break;
		}
		case MHI_PKT_TYPE_EE_EVENT:
		{
			enum STATE_TRANSITION new_state = 0;
			enum MHI_EXEC_ENV event = MHI_TRE_GET_EV_EXECENV
				(local_rp);

			mhi_log(mhi_dev, MHI_MSG_INFO,
				"MHI EE received event:0x%x\n", event);

			switch (event) {
			case MHI_EXEC_ENV_SBL:
				new_state = STATE_TRANSITION_SBL;
				break;
			case MHI_EXEC_ENV_AMSS:
				new_state = STATE_TRANSITION_AMSS;
				break;
			case MHI_EXEC_ENV_BHIE:
				new_state = STATE_TRANSITION_BHIE;
				break;
			case MHI_EXEC_ENV_RDDM:
				new_state = STATE_TRANSITION_RDDM;
				break;
			default:
				mhi_log(mhi_dev, MHI_MSG_INFO,
					"Invalid EE Event 0x%x received\n",
					event);
			}
			if (new_state)
				mhi_queue_state_transition(mhi_dev, new_state);
			break;
		}
		case MHI_PKT_TYPE_STALE_EVENT:
			mhi_log(mhi_dev, MHI_MSG_INFO,
				"Stale Event received for chan:%u\n",
				MHI_TRE_GET_EV_CHID(local_rp));
			break;
		default:
			mhi_log(mhi_dev, MHI_MSG_ERROR,
				"Unsupported packet type code 0x%x\n",type);
			break;
		}

		mhi_recycle_ev_ring_element(mhi_dev, ev_ring);
		local_rp = ev_ring->rp;
		dev_rp = mhi_to_virtual(ev_ring, er_ctxt->rp);
		count++;
	}
	read_lock_bh(&mhi_dev->pm_lock);
	if (likely(MHI_DB_ACCESS_VALID(mhi_dev->pm_state))) {
		spin_lock_irqsave(&mhi_event->lock, flags);
		mhi_ring_er_db(mhi_event);
		spin_unlock_irqrestore(&mhi_event->lock, flags);
	}
	mhi_dev->deassert_wake(mhi_dev, false);
	read_unlock_bh(&mhi_dev->pm_lock);
	mhi_log(mhi_dev, MHI_MSG_VERBOSE, "exit er_index:%u\n", er_index);
	return count;
}

void mhi_ev_task(unsigned long data)
{
	int ret;
	struct mhi_event *mhi_event = (struct mhi_event *)data;
	struct mhi_device *mhi_dev = mhi_event->mhi_dev;
	const int CTRL_EV = 0; /* event ring for ctrl events */

	mhi_log(mhi_dev, MHI_MSG_VERBOSE, "Enter for event index:%d\n",
		mhi_event->index);

	/* Process event ring */
	ret = mhi_process_event_ring(mhi_dev, mhi_event->index, U32_MAX);
	/*
	 * If we received MSI for primary event ring with no events to process
	 * check status register to see if device enter SYSERR status
	 */
	if (mhi_event->index == CTRL_EV && !ret) {
		bool in_sys_err = false;
		unsigned long flags;
		enum MHI_PM_STATE new_state;

		read_lock_bh(&mhi_dev->pm_lock);
		if (MHI_REG_ACCESS_VALID(mhi_dev->pm_state))
			in_sys_err = mhi_in_sys_err(mhi_dev);
		read_unlock_bh(&mhi_dev->pm_lock);

		if (in_sys_err) {
			mhi_log(mhi_dev, MHI_MSG_INFO,
				"MHI System Error Detected\n");
			write_lock_irqsave(&mhi_dev->pm_lock, flags);
			new_state = mhi_tryset_pm_state(mhi_dev,
							MHI_PM_SYS_ERR_DETECT);
			write_unlock_irqrestore(&mhi_dev->pm_lock, flags);
			if (new_state == MHI_PM_SYS_ERR_DETECT)
				schedule_work(&mhi_dev->sys_err_worker);
		}
	}

	mhi_log(mhi_dev, MHI_MSG_VERBOSE, "Exit\n");
}

void process_event_ring(struct work_struct *work)
{
	struct mhi_event *mhi_event =
		container_of(work, struct mhi_event, worker);
	struct mhi_device *mhi_dev = mhi_event->mhi_dev;

	mhi_log(mhi_dev, MHI_MSG_VERBOSE, "Enter for event:%d\n",
		mhi_event->index);
	/* Process event ring */
	mhi_process_event_ring(mhi_dev, mhi_event->index, U32_MAX);

	mhi_log(mhi_dev, MHI_MSG_VERBOSE, "Exit\n");
}

irqreturn_t mhi_msi_handlr(int irq_number, void *dev)
{
	struct mhi_event *mhi_event = dev;

	/* client manges this MSI, notify the client */
	if (mhi_event->client_manage)
		mhi_notify_client(mhi_event->mhi_dev, mhi_event->chan,
				  MHI_CB_PENDING_DATA);
	else {
		if (mhi_event->priority <= MHI_EV_PRIORITY_TASKLET)
			tasklet_schedule(&mhi_event->task);
		else
			schedule_work(&mhi_event->worker);
	}

	return IRQ_HANDLED;
}

int parse_xfer_event(struct mhi_device *mhi_dev,
		     struct __packed mhi_tre *event,
		     struct mhi_chan *mhi_chan)
{
	int chan;
	struct mhi_ring *buf_ring, *tre_ring;
	u32 ev_code;
	struct mhi_client_data *cldata = mhi_chan->cldata;
	struct mhi_result *result;
	struct mhi_cb_info cb_info;
	bool ev_managed;
	unsigned long flags = 0;

	cb_info.user_data = cldata->user_data;
	result = &cb_info.result;
	ev_code = MHI_TRE_GET_EV_CODE(event);
	chan = mhi_chan->chan;
	buf_ring = &mhi_chan->buf_ring;
	tre_ring = &mhi_chan->tre_ring;
	ev_managed = !mhi_dev->mhi_event[mhi_chan->er_index].client_manage;

	result->transaction_status = (ev_code == MHI_EVENT_CC_OVERFLOW) ?
		-EOVERFLOW : 0;

	/*
	 * if it's a DB Event then we need to grab the lock
	 * with premption disable and as a write because we
	 * have to update db register and another thread could
	 * be doing same.
	 */
	if (ev_code >= MHI_EVENT_CC_OOB)
		write_lock_irqsave(&mhi_chan->lock, flags);
	else
		read_lock_bh(&mhi_chan->lock);

	if (mhi_chan->ch_state != MHI_CHAN_STATE_ENABLED)
		goto end_process_tx_event;

	switch (ev_code) {
	case MHI_EVENT_CC_OVERFLOW:
	case MHI_EVENT_CC_EOB:
	case MHI_EVENT_CC_EOT:
	{
		dma_addr_t ptr = MHI_TRE_GET_EV_PTR(event);
		struct __packed mhi_tre *local_rp, *ev_tre;
		void *dev_rp;
		struct mhi_buf_info *buf_info;
		u16 xfer_len;

		/* Get the TRB this event points to */
		ev_tre = mhi_to_virtual(tre_ring, ptr);

		/* device rp after servicing the TREs */
		dev_rp = ev_tre + 1;
		if (dev_rp >= (tre_ring->base + tre_ring->len))
			dev_rp = tre_ring->base;

		cb_info.cb_reason = MHI_CB_XFER;
		cb_info.chan = mhi_chan->chan;

		/* local rp */
		local_rp = tre_ring->rp;
		while (local_rp != dev_rp) {
			buf_info = buf_ring->rp;
			/* if it's last tre get len from the event */
			if (local_rp == ev_tre)
				xfer_len = MHI_TRE_GET_EV_LEN(event);
			else
				xfer_len = buf_info->len;
			dma_unmap_single(mhi_dev->dev, buf_info->p_addr,
					 buf_info->len, buf_info->dir);

			result->buf_addr = buf_info->cb_buf;
			result->bytes_xferd = xfer_len;
			buf_info->len = xfer_len;
			mhi_del_ring_element(mhi_dev, buf_ring);
			mhi_del_ring_element(mhi_dev, tre_ring);
			local_rp = tre_ring->rp;

			/* Notify client */
			cldata->mhi_xfer_cb(&cb_info);

			if (mhi_chan->dir == DMA_TO_DEVICE) {
				atomic_dec(&mhi_dev->pending_acks);
				read_lock_bh(&mhi_dev->pm_lock);
				mhi_dev->runtime_put(mhi_dev);
				mhi_dev->deassert_wake(mhi_dev, false);
				read_unlock_bh(&mhi_dev->pm_lock);
			}

		};
		break;
	} /* CC_EOT */
	case MHI_EVENT_CC_OOB:
	case MHI_EVENT_CC_DB_MODE:
	{
		unsigned long flags;

		mhi_log(mhi_dev, MHI_MSG_VERBOSE,
			"DB_MODE/OOB Detected chan %d.\n", chan);
		mhi_chan->db_mode.db_mode = 1;
		read_lock_irqsave(&mhi_dev->pm_lock, flags);
		if (tre_ring->wp != tre_ring->rp &&
		    MHI_DB_ACCESS_VALID(mhi_dev->pm_state)) {
			mhi_ring_chan_db(mhi_dev, mhi_chan);
		}
		read_unlock_irqrestore(&mhi_dev->pm_lock, flags);
		break;
	}
	case MHI_EVENT_CC_BAD_TRE:
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Received BAD TRE event for ring\n");
		BUG();
	break;
	default:
		mhi_log(mhi_dev, MHI_MSG_ERROR, "Unknown TX completion.\n");

		break;
	} /*switch(MHI_EV_READ_CODE(EV_TRB_CODE,event)) */

end_process_tx_event:
	if (ev_code >= MHI_EVENT_CC_OOB)
		write_unlock_irqrestore(&mhi_chan->lock, flags);
	else
		read_unlock_bh(&mhi_chan->lock);

	return 0;
}

int mhi_get_epid(struct mhi_client_handle *client_handle)
{
	return MHI_EPID;
}

void mhi_write_reg(struct mhi_device *mhi_dev,
		   void __iomem *base,
		   u32 offset,
		   u32 val)
{
	writel_relaxed(val, base + offset);
}

u32 __must_check mhi_read_reg(struct mhi_device *mhi_dev, void __iomem *base, u32 offset)
{
	return readl_relaxed(base + offset);
}

void mhi_write_reg_field(struct mhi_device *mhi_dev,
			 void __iomem *base,
			 u32 offset,
			 u32 mask,
			 u32 shift,
			 u32 val)
{
	u32 reg;

	reg = mhi_read_reg(mhi_dev, base, offset);
	if (unlikely(PCI_INVALID_READ(reg))) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Invalid read from pcie bus\n");
		return;
	}
	reg &= ~mask;
	reg = reg | (val << shift);
	mhi_write_reg(mhi_dev, base, offset, reg);
}

u32 __must_check mhi_read_reg_field(struct mhi_device *mhi_dev,
		       void __iomem *base,
		       u32 offset,
		       u32 mask,
		       u32 shift)
{
	u32 val = mhi_read_reg(mhi_dev, base, offset);

	if (PCI_INVALID_READ(val))
		return val;

	return (val & mask) >> shift;
}

static void mhi_write_db(struct mhi_device *mhi_dev,
			 void __iomem *db_addr,
			 dma_addr_t wp)
{

	mhi_write_reg(mhi_dev, db_addr, 4, upper_32_bits(wp));
	mhi_write_reg(mhi_dev, db_addr, 0, lower_32_bits(wp));
}

void mhi_process_db_brstmode(struct mhi_device *mhi_dev,
			     struct db_mode *db_mode,
			     void __iomem *db_addr,
			     dma_addr_t wp)
{

	if (db_mode->db_mode) {
		db_mode->db = wp;
		mhi_write_db(mhi_dev, db_addr, wp);
		db_mode->db_mode = 0;
	}
}

void mhi_process_db_brstmode_disable(struct mhi_device *mhi_dev,
				     struct db_mode *db_mode,
				     void __iomem *db_addr,
				     dma_addr_t wp)
{
	db_mode->db = wp;
	mhi_write_db(mhi_dev, db_addr, wp);
}

void mhi_ring_chan_db(struct mhi_device *mhi_dev, struct mhi_chan *mhi_chan)
{
	struct mhi_ring *ring = &mhi_chan->tre_ring;
	dma_addr_t db;

	db = ring->phys_base + (ring->wp - ring->base);
	*ring->ctxt_wp = db;
	mhi_chan->db_mode.process_db(mhi_dev, &mhi_chan->db_mode, ring->db_addr,
				     db);
}

void mhi_ring_er_db(struct mhi_event *mhi_event)
{
	struct mhi_ring *ring = &mhi_event->ring;
	dma_addr_t db;
	db = ring->phys_base + (ring->wp - ring->base);
	*ring->ctxt_wp = db;
	mhi_event->db_mode.process_db(mhi_event->mhi_dev, &mhi_event->db_mode,
				      ring->db_addr, db);
}

void mhi_ring_cmd_db(struct mhi_device *mhi_dev)
{
	dma_addr_t db;
	struct mhi_ring *ring = &mhi_dev->mhi_cmd[PRIMARY_CMD_RING];
	struct db_mode db_mode;

	db = ring->phys_base + (ring->wp - ring->base);
	*ring->ctxt_wp = db;
	mhi_process_db_brstmode_disable(mhi_dev, &db_mode, ring->db_addr, db);
}

/*
 * mhi_assert_device_wake - Set WAKE_DB register
 * force_set - if true, will set bit regardless of counts
 */
void mhi_assert_device_wake(struct mhi_device *mhi_dev, bool force_set)
{
	unsigned long flags;

	if (unlikely(force_set)) {
		spin_lock_irqsave(&mhi_dev->wake_lock, flags);
		atomic_inc(&mhi_dev->dev_wake);
		if (MHI_WAKE_DB_ACCESS_VALID(mhi_dev->pm_state) &&
		    !mhi_dev->wake_set) {
			mhi_write_db(mhi_dev, mhi_dev->wake_db, 1);
			mhi_dev->wake_set = true;
		}
		spin_unlock_irqrestore(&mhi_dev->wake_lock, flags);
	} else {
		if (likely(atomic_add_unless(&mhi_dev->dev_wake, 1, 0)))
			return;

		spin_lock_irqsave(&mhi_dev->wake_lock, flags);
		if ((atomic_inc_return(&mhi_dev->dev_wake) == 1) &&
		    MHI_WAKE_DB_ACCESS_VALID(mhi_dev->pm_state) &&
		    !mhi_dev->wake_set) {
			mhi_write_db(mhi_dev, mhi_dev->wake_db, 1);
			mhi_dev->wake_set = true;
		}
		spin_unlock_irqrestore(&mhi_dev->wake_lock, flags);
	}
}

void mhi_deassert_device_wake(struct mhi_device *mhi_dev, bool override)
{
	unsigned long flags;

	WARN_ON(atomic_read(&mhi_dev->dev_wake) == 0);

	if (likely(atomic_add_unless
		   (&mhi_dev->dev_wake, -1, 1)))
		return;

	spin_lock_irqsave(&mhi_dev->wake_lock, flags);
	if ((atomic_dec_return(&mhi_dev->dev_wake) == 0) &&
	    MHI_WAKE_DB_ACCESS_VALID(mhi_dev->pm_state) && !override &&
	    mhi_dev->wake_set) {
		mhi_write_db(mhi_dev, mhi_dev->wake_db, 0);
		mhi_dev->wake_set = false;
	}
	spin_unlock_irqrestore(&mhi_dev->wake_lock, flags);
}

int mhi_send_cmd(struct mhi_device *mhi_dev,
			enum MHI_COMMAND cmd,
			u32 chan)
{
	struct __packed  mhi_tre *cmd_tre = NULL;
	struct mhi_ring *ring = &mhi_dev->mhi_cmd[PRIMARY_CMD_RING];

	mhi_log(mhi_dev, MHI_MSG_INFO,
		"Entered, MHI state:%s dev_exec_env:%s chan:%d cmd:%d\n",
		TO_MHI_STATE_STR(mhi_dev->dev_state),
		TO_MHI_EXEC_STR(mhi_dev->dev_exec_env), chan, cmd);

	/* MHI host only support RESET and START commands */
	if (cmd != MHI_COMMAND_START_CHAN && cmd != MHI_COMMAND_RESET_CHAN)
		return -EINVAL;

	spin_lock_bh(&mhi_dev->cmd_lock);
	if (!get_nr_avail_ring_elements(mhi_dev, ring)) {
		spin_unlock_bh(&mhi_dev->cmd_lock);
		return -ENOMEM;
	}

	cmd_tre = ring->wp;
	if (cmd == MHI_COMMAND_START_CHAN) {
		cmd_tre->ptr = MHI_TRE_CMD_START_PTR;
		cmd_tre->dword[0] = MHI_TRE_CMD_START_DWORD0;
		cmd_tre->dword[1] = MHI_TRE_CMD_START_DWORD1(chan);
	} else {
		cmd_tre->ptr = MHI_TRE_CMD_RESET_PTR;
		cmd_tre->dword[0] = MHI_TRE_CMD_RESET_DWORD0;
		cmd_tre->dword[1] = MHI_TRE_CMD_RESET_DWORD1(chan);
	}

	mhi_log(mhi_dev, MHI_MSG_VERBOSE, "TRE: 0x%llx 0x%08x 0x%08x\n",
		cmd_tre->ptr, cmd_tre->dword[0], cmd_tre->dword[1]);

	mhi_add_ring_element(mhi_dev, ring);
	read_lock_bh(&mhi_dev->pm_lock);
	mhi_ring_cmd_db(mhi_dev);
	read_unlock_bh(&mhi_dev->pm_lock);
	spin_unlock_bh(&mhi_dev->cmd_lock);
	mhi_log(mhi_dev, MHI_MSG_VERBOSE,
		"Sent command 0x%x for chan %d\n", cmd, chan);
	return 0;
}

int mhi_queue_buf_tre(struct mhi_device *mhi_dev,
		      struct mhi_chan *mhi_chan,
		      void *buf,
		      void *cb,
		      size_t buf_len,
		      enum MHI_FLAGS flags)
{
	struct mhi_ring *buf_ring, *tre_ring;
	struct __packed mhi_tre *mhi_tre;
	struct mhi_buf_info *buf_info;
	struct mhi_event *mhi_event = &mhi_dev->mhi_event[mhi_chan->er_index];
	int eot, eob, chain, bei;

	buf_ring = &mhi_chan->buf_ring;
	tre_ring = &mhi_chan->tre_ring;

	buf_info = buf_ring->wp;
	buf_info->v_addr = buf;
	buf_info->cb_buf = cb;
	buf_info->wp = tre_ring->wp;
	buf_info->dir = mhi_chan->dir;
	buf_info->len = buf_len;
	buf_info->p_addr = dma_map_single(mhi_dev->dev, buf_info->v_addr,
					  buf_info->len, buf_info->dir);
	if (dma_mapping_error(mhi_dev->dev, buf_info->p_addr))
		return -ENOMEM;

	eob = !!(flags & MHI_EOB);
	eot = !!(flags & MHI_EOT);
	chain = !!(flags & MHI_CHAIN);
	bei = !!mhi_event->intmod;
	mhi_tre = tre_ring->wp;
	mhi_tre->ptr = MHI_TRE_DATA_PTR(buf_info->p_addr);
	mhi_tre->dword[0] = MHI_TRE_DATA_DWORD0(buf_info->len);
	mhi_tre->dword[1] = MHI_TRE_DATA_DWORD1(bei,eot, eob, chain);

	mhi_log(mhi_dev, MHI_MSG_VERBOSE, "chan:%d TRE: 0x%llx 0x%08x 0x%08x\n",
		mhi_chan->chan, mhi_tre->ptr, mhi_tre->dword[0],
		mhi_tre->dword[1]);

	/* Increment WP */
	mhi_add_ring_element(mhi_dev, tre_ring);
	mhi_add_ring_element(mhi_dev, buf_ring);

	return 0;
}

int mhi_open_channel(struct mhi_client_handle *client_handle)
{
	int ret;
	struct mhi_device *mhi_dev;
	struct mhi_chan *mhi_chan;
	int chan;
	enum MHI_EVENT_CCS ev_code;
	struct mhi_client_data *cldata = client_handle->cldata;

	mhi_dev = cldata->mhi_dev;
	chan = cldata->chan;;
	mhi_chan = &mhi_dev->mhi_chan[chan];

	mutex_lock(&mhi_chan->mutex);
	mhi_log(mhi_dev, MHI_MSG_INFO,
		"Entered: Client opening chan 0x%x\n", chan);
	if (mhi_dev->dev_exec_env != mhi_chan->exec_env) {
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Chan:%d, MHI exec_env:%s, not ready!\n",
			chan, TO_MHI_EXEC_STR(mhi_dev->dev_exec_env));
		mutex_unlock(&mhi_chan->mutex);
		return -ENOTCONN;
	}

	ret = mhi_init_chan_ctxt(mhi_dev, mhi_chan);
	if (ret) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Failed to initialize tre ring chan %d\n",
			chan);
		goto error_tre_ring;
	}

	reinit_completion(&mhi_chan->completion);
	read_lock_bh(&mhi_dev->pm_lock);
	if (unlikely(mhi_dev->pm_state == MHI_PM_DISABLE)) {
		mhi_log(mhi_dev, MHI_MSG_ERROR, "MHI State is disabled\n");
		read_unlock_bh(&mhi_dev->pm_lock);
		ret = -EIO;
		goto error_pm_state;
	}
	mhi_dev->assert_wake(mhi_dev, false);
	read_unlock_bh(&mhi_dev->pm_lock);
	mhi_dev->runtime_get(mhi_dev);

	ret = mhi_send_cmd(mhi_dev, MHI_COMMAND_START_CHAN, chan);
	if (ret) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Failed to send start cmd for chan %d\n", chan);
		goto error_completion;
	}
	ret = wait_for_completion_timeout(&mhi_chan->completion,
				msecs_to_jiffies(mhi_dev->poll_timeout));
	if (!ret) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Failed to receive cmd completion for %d\n", chan);
		ret = -EIO;
		goto error_completion;
	} else
		ret = 0;

	/* check the event result */
	ev_code = MHI_TRE_GET_EV_CODE(&mhi_chan->ev_tre);
	if (ev_code != MHI_EVENT_CC_SUCCESS) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Error to receive event comp. ev_code:0x%x\n", ev_code);
		ret = -EIO;
		goto error_completion;
	}

	write_lock_irq(&mhi_chan->lock);
	mhi_chan->ch_state = MHI_CHAN_STATE_ENABLED;
	write_unlock_irq(&mhi_chan->lock);

	read_lock_bh(&mhi_dev->pm_lock);
	mhi_dev->deassert_wake(mhi_dev, false);
	read_unlock_bh(&mhi_dev->pm_lock);
	mhi_dev->runtime_put(mhi_dev);
	mutex_unlock(&mhi_chan->mutex);

	mhi_log(mhi_dev, MHI_MSG_INFO, "chan:%d opened successfully\n", chan);
	return 0;

error_completion:
	read_lock_bh(&mhi_dev->pm_lock);
	mhi_dev->deassert_wake(mhi_dev, false);
	read_unlock_bh(&mhi_dev->pm_lock);
	mhi_dev->runtime_put(mhi_dev);
error_pm_state:
	mhi_deinit_chan_ctxt(mhi_dev, mhi_chan);
error_tre_ring:
	mutex_unlock(&mhi_chan->mutex);
	mhi_log(mhi_dev, MHI_MSG_INFO, "Exited chan 0x%x ret:%d\n", chan, ret);
	return ret;
}
EXPORT_SYMBOL(mhi_open_channel);

bool mhi_is_device_ready(const struct device_node *of_node,
			 const char *node_name)
{
	struct mhi_device *itr;
	bool match_found = false;

	of_node = of_parse_phandle(of_node, node_name, 0);
	if (!of_node)
		return false;

	mutex_lock(&mhi_device_drv.lock);
	list_for_each_entry(itr, &mhi_device_drv.head, node) {
		struct platform_device *pdev = itr->pdev;

		if (pdev->dev.of_node == of_node) {
			match_found = true;
			break;
		}
	}
	mutex_unlock(&mhi_device_drv.lock);
	return match_found;
}
EXPORT_SYMBOL(mhi_is_device_ready);

struct mhi_client_handle *mhi_register_channel(
				struct mhi_client_info_t *client_info)
{
	struct mhi_device *mhi_dev = NULL, *itr;
	struct mhi_chan *mhi_chan;
	struct mhi_client_data *cldata;
	struct mhi_client_handle *handle;
	const struct device_node *of_node;
	const char *node_name;
	int chan;

	if (!client_info || client_info->of_node == NULL)
		return ERR_PTR(-EINVAL);

	node_name = client_info->node_name;
	of_node = of_parse_phandle(client_info->of_node, node_name, 0);
	if (!of_node)
		return ERR_PTR(-EINVAL);

	/* traverse thru the list */
	mutex_lock(&mhi_device_drv.lock);
	list_for_each_entry(itr, &mhi_device_drv.head, node) {
		struct platform_device *pdev = itr->pdev;

		if (pdev->dev.of_node == of_node) {
			mhi_dev = itr;
			break;
		}
	}
	mutex_unlock(&mhi_device_drv.lock);

	if (!mhi_dev)
		return ERR_PTR(-EINVAL);

	mhi_chan = mhi_dev->mhi_chan;
	for (chan = 0; chan < MHI_MAX_CHANNELS; chan++, mhi_chan++) {
		if (!mhi_chan->supported)
			continue;
		if (!strncmp(mhi_chan->name, client_info->chan_name,
			     strlen(mhi_chan->name)))
			break;
	}

	if (chan >= MHI_MAX_CHANNELS)
		return ERR_PTR(-EINVAL);

	mhi_log(mhi_dev, MHI_MSG_INFO,
		"Registering chan %s (%d) for client\n", mhi_chan->name, chan);

	mhi_chan = &mhi_dev->mhi_chan[chan];
	cldata = vmalloc(sizeof(*cldata));
	if (!cldata)
		return ERR_PTR(-ENOMEM);

	handle = &cldata->client_handle;
	handle->dev_id = mhi_dev->dev_id;
	handle->domain = mhi_dev->domain;
	handle->bus = mhi_dev->bus;
	handle->slot = mhi_dev->slot;
	handle->enabled = false;
	handle->chan_id = chan;
	handle->xfer_func = mhi_chan->queue_xfer;
	cldata->chan = chan;
	cldata->mhi_dev = mhi_dev;
	cldata->mhi_client_cb = client_info->mhi_client_cb;
	cldata->mhi_xfer_cb = (client_info->mhi_xfer_cb) ? :
		cldata->mhi_client_cb;
	cldata->user_data = client_info->user_data;
	handle->cldata = cldata;

	if (mhi_dev->dev_exec_env == MHI_EXEC_ENV_AMSS)
		handle->enabled = true;
	mhi_chan->cldata = cldata;

	mhi_log(mhi_dev, MHI_MSG_VERBOSE,
		"Successfuly registered chan:%s (%d)\n", mhi_chan->name, chan);

	return handle;
}
EXPORT_SYMBOL(mhi_register_channel);

void mhi_close_channel(struct mhi_client_handle *client_handle)
{
	u32 chan;
	int ret;
	struct mhi_device *mhi_dev;
	enum MHI_EVENT_CCS ev_code;
	struct mhi_client_data *cldata = client_handle->cldata;
	struct mhi_chan *mhi_chan;

	mhi_dev = cldata->mhi_dev;
	chan = cldata->chan;
	mhi_chan = &mhi_dev->mhi_chan[chan];

	mhi_log(mhi_dev, MHI_MSG_INFO,
		"Client attempting to close chan 0x%x\n", chan);

	mutex_lock(&mhi_chan->mutex);

	/* No more processing events for this channel */
	write_lock_irq(&mhi_chan->lock);
	if (mhi_chan->ch_state != MHI_CHAN_STATE_ENABLED) {
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Chan %d is not enabled, cur state:0x%x\n",
			chan, mhi_chan->ch_state);
		write_unlock_irq(&mhi_chan->lock);
		mutex_unlock(&mhi_chan->mutex);
		return;
	}

	mhi_chan->ch_state = MHI_CHAN_STATE_DISABLED;
	write_unlock_irq(&mhi_chan->lock);
	reinit_completion(&mhi_chan->completion);
	read_lock_bh(&mhi_dev->pm_lock);
	WARN_ON(mhi_dev->pm_state == MHI_PM_DISABLE);
	mhi_dev->assert_wake(mhi_dev, false);
	read_unlock_bh(&mhi_dev->pm_lock);
	mhi_dev->runtime_get(mhi_dev);
	ret = mhi_send_cmd(mhi_dev, MHI_COMMAND_RESET_CHAN, chan);
	if (ret) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Failed to send reset cmd for chan %d ret %d\n",
			chan, ret);
		goto error_completion;
	}
	ret = wait_for_completion_timeout(&mhi_chan->completion,
				msecs_to_jiffies(mhi_dev->poll_timeout));
	if (!ret) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Failed to receive cmd completion for %d\n", chan);
		goto error_completion;
	}

	ev_code = MHI_TRE_GET_EV_CODE(&mhi_chan->ev_tre);
	if (ev_code != MHI_EVENT_CC_SUCCESS) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Error to receive event completion ev_cod:0x%x\n",
			ev_code);
	}

error_completion:
	mhi_reset_chan(mhi_dev, mhi_chan);

	read_lock_bh(&mhi_dev->pm_lock);
	mhi_dev->deassert_wake(mhi_dev, false);
	read_unlock_bh(&mhi_dev->pm_lock);
	mhi_dev->runtime_put(mhi_dev);
	mhi_log(mhi_dev, MHI_MSG_INFO, "Freeing ring for chan 0x%x\n", chan);
	mhi_deinit_chan_ctxt(mhi_dev, mhi_chan);
	mutex_unlock(&mhi_chan->mutex);
}
EXPORT_SYMBOL(mhi_close_channel);

int mhi_queue_scatterlist(struct mhi_client_handle *handle,
			  void *buf,
			  size_t len,
			  enum MHI_FLAGS mhi_flags)
{
	struct scatterlist *sg, *sgl = buf;
	struct mhi_client_data *cldata = handle->cldata;
	struct mhi_device *mhi_dev = cldata->mhi_dev;
	u32 chan = cldata->chan;
	struct mhi_chan *mhi_chan = &mhi_dev->mhi_chan[chan];
	unsigned long flags;
	int i = 0, j, ret;

	if (mhi_get_free_desc(handle) < len)
		return -ENOMEM;


	read_lock_irqsave(&mhi_dev->pm_lock, flags);
	if (mhi_dev->pm_state == MHI_PM_DISABLE) {
		read_unlock_irqrestore(&mhi_dev->pm_lock, flags);
		return -EINVAL;
	}

	for (i = 0; i < len; i++) {
		mhi_dev->runtime_get(mhi_dev);
		mhi_dev->assert_wake(mhi_dev, false);
	}
	read_unlock_irqrestore(&mhi_dev->pm_lock, flags);

	for_each_sg(sgl, sg, len, i) {
		ret = mhi_chan->gen_tre(mhi_dev, mhi_chan, sg_virt(sg), sg,
					sg->length, mhi_flags);
		if (unlikely(ret)) {
			mhi_log(mhi_dev, MHI_MSG_ERROR,
				"Error with dma_mapping for chan:%d\n", chan);
			goto error_queue;
		}

		if (mhi_chan->dir == DMA_TO_DEVICE)
			atomic_inc(&mhi_dev->pending_acks);
	}

	read_lock_irqsave(&mhi_dev->pm_lock, flags);
	if (likely(MHI_DB_ACCESS_VALID(mhi_dev->pm_state))) {
		unsigned long flags;

		read_lock_irqsave(&mhi_chan->lock, flags);
		mhi_ring_chan_db(mhi_dev, mhi_chan);
		read_unlock_irqrestore(&mhi_chan->lock, flags);
	}

	if (mhi_chan->dir == DMA_FROM_DEVICE) {
		bool override = (mhi_dev->pm_state != MHI_PM_M0);

		for (i = 0; i < len; i++) {
			mhi_dev->runtime_put(mhi_dev);
			mhi_dev->deassert_wake(mhi_dev, override);
		}
	}
	read_unlock_irqrestore(&mhi_dev->pm_lock, flags);

	return 0;

error_queue:
	/*
	 * this is unexpected error, there is really no way to clean the ring
	 * buffers, client expect to reset the channel to clean the ring.
	 */
	read_lock_irqsave(&mhi_dev->pm_lock, flags);
	i--;
	for (j = 0; j < len; j++, i--) {
		/*
		 * if we queue the packet already, decrement only if it's
		 * DL TRE.  Channel reset will reset the counters,
		 * otherwise always decrement it
		 */
		if ((i >= 0 && mhi_chan->dir == DMA_FROM_DEVICE) || i < 0) {
			mhi_dev->runtime_put(mhi_dev);
			mhi_dev->deassert_wake(mhi_dev, false);
		}
	}
	read_unlock_irqrestore(&mhi_dev->pm_lock, flags);
	return -EIO;
}

int mhi_queue_skb(struct mhi_client_handle *handle,
		  void *buf,
		  size_t len,
		  enum MHI_FLAGS flags)
{
	struct sk_buff *skb = buf;
	struct mhi_client_data *cldata = handle->cldata;
	struct mhi_device *mhi_dev = cldata->mhi_dev;
	u32 chan = cldata->chan;
	struct mhi_chan *mhi_chan = &mhi_dev->mhi_chan[chan];
	struct mhi_ring *tre_ring = &mhi_chan->tre_ring;
	struct mhi_ring *buf_ring = &mhi_chan->buf_ring;
	struct __packed mhi_tre *mhi_tre;
	struct mhi_buf_info *buf_info;

	if (mhi_is_ring_full(mhi_dev, tre_ring))
		return -ENOMEM;

	read_lock_bh(&mhi_dev->pm_lock);
	mhi_dev->runtime_get(mhi_dev);
	mhi_dev->assert_wake(mhi_dev, false);

	buf_info = buf_ring->wp;
	buf_info->v_addr = skb->data;
	buf_info->cb_buf = skb;
	buf_info->wp = tre_ring->wp;
	buf_info->dir = mhi_chan->dir;
	buf_info->len = len;
	buf_info->p_addr = dma_map_single(mhi_dev->dev, buf_info->v_addr,
					  buf_info->len, buf_info->dir);
	if (dma_mapping_error(mhi_dev->dev, buf_info->p_addr))
		goto error_queue_skb;

	mhi_tre = tre_ring->wp;
	mhi_tre->ptr = MHI_TRE_DATA_PTR(buf_info->p_addr);
	mhi_tre->dword[0] = MHI_TRE_DATA_DWORD0(buf_info->len);
	mhi_tre->dword[1] = MHI_TRE_DATA_DWORD1(1, 1, 0, 0);
	mhi_log(mhi_dev, MHI_MSG_VERBOSE, "chain:%d TRE:0x%llx 0x%08x 0x%08x\n",
		chan, mhi_tre->ptr, mhi_tre->dword[0], mhi_tre->dword[1]);

	/* increment the wp */
	mhi_add_ring_element(mhi_dev, buf_ring);
	mhi_add_ring_element(mhi_dev, tre_ring);

	if (mhi_chan->dir == DMA_TO_DEVICE)
		atomic_inc(&mhi_dev->pending_acks);

	if (likely(MHI_DB_ACCESS_VALID(mhi_dev->pm_state))) {
		read_lock_bh(&mhi_chan->lock);
		mhi_ring_chan_db(mhi_dev, mhi_chan);
		read_unlock_bh(&mhi_chan->lock);
	}

	if (mhi_chan->dir == DMA_FROM_DEVICE) {
		bool override = (mhi_dev->pm_state != MHI_PM_M0);

		mhi_dev->runtime_put(mhi_dev);
		mhi_dev->deassert_wake(mhi_dev, override);
	}

	read_unlock_bh(&mhi_dev->pm_lock);

	return 0;
error_queue_skb:
	mhi_dev->runtime_put(mhi_dev);
	mhi_dev->deassert_wake(mhi_dev, false);
	read_unlock_bh(&mhi_dev->pm_lock);
	return -ENOMEM;
}

int mhi_queue_buffer(struct mhi_client_handle *client_handle,
		     void *buf,
		     size_t len,
		     enum MHI_FLAGS mhi_flags)
{
	int ret;
	struct mhi_device *mhi_dev;
	u32 chan;
	unsigned long flags;
	struct mhi_client_data *cldata;
	struct mhi_ring *tre_ring;
	struct mhi_chan *mhi_chan;

	if (!buf || !len)
		return -EINVAL;

	cldata = client_handle->cldata;
	mhi_dev = cldata->mhi_dev;
	chan = cldata->chan;
	mhi_chan = &mhi_dev->mhi_chan[chan];

	read_lock_irqsave(&mhi_dev->pm_lock, flags);
	if (mhi_dev->pm_state == MHI_PM_DISABLE) {
		read_unlock_irqrestore(&mhi_dev->pm_lock, flags);
		mhi_log(mhi_dev, MHI_MSG_ERROR, "MHI is not in active state\n");
		return -EINVAL;
	}
	mhi_dev->runtime_get(mhi_dev);
	mhi_dev->assert_wake(mhi_dev, false);
	read_unlock_irqrestore(&mhi_dev->pm_lock, flags);

	tre_ring = &mhi_chan->tre_ring;
	if (mhi_is_ring_full(mhi_dev, tre_ring)) {
		mhi_log(mhi_dev, MHI_MSG_VERBOSE,
			"transfer ring for chan:%d is full\n", chan);
		goto error_queue;
	}

	ret = mhi_chan->gen_tre(mhi_dev, mhi_chan, buf, buf, len, mhi_flags);
	if (unlikely(ret)) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Error with dma_mapping for chan:%d\n", chan);
		goto error_queue;
	}

	if (mhi_chan->dir == DMA_TO_DEVICE)
		atomic_inc(&mhi_dev->pending_acks);

	read_lock_irqsave(&mhi_dev->pm_lock, flags);
	if (likely(MHI_DB_ACCESS_VALID(mhi_dev->pm_state))) {
		unsigned long flags;

		read_lock_irqsave(&mhi_chan->lock, flags);
		mhi_ring_chan_db(mhi_dev, mhi_chan);
		read_unlock_irqrestore(&mhi_chan->lock, flags);
	}

	if (mhi_chan->dir == DMA_FROM_DEVICE) {
		bool override = (mhi_dev->pm_state != MHI_PM_M0);

		mhi_dev->runtime_put(mhi_dev);
		mhi_dev->deassert_wake(mhi_dev, override);
	}
	read_unlock_irqrestore(&mhi_dev->pm_lock, flags);

	return 0;
error_queue:
	mhi_dev->runtime_put(mhi_dev);
	read_lock_irqsave(&mhi_dev->pm_lock, flags);
	mhi_dev->deassert_wake(mhi_dev, false);
	read_unlock_irqrestore(&mhi_dev->pm_lock, flags);
	return -ENOMEM;
}

int mhi_debugfs_mhi_states_show(struct seq_file *m, void *d)
{
	struct mhi_device *mhi_dev = m->private;

	seq_printf(m,
		   "pm_state:0x%04x dev_state:%s exec_env:%s wake:%d dev_wake:%u acks:%u alloc_size:%u\n",
		   mhi_dev->pm_state, TO_MHI_STATE_STR(mhi_dev->dev_state),
		   TO_MHI_EXEC_STR(mhi_dev->dev_exec_env),
		   mhi_dev->wake,
		   atomic_read(&mhi_dev->dev_wake),
		   atomic_read(&mhi_dev->pending_acks),
		   atomic_read(&mhi_dev->alloc_size));
	return 0;
}

int mhi_debugfs_mhi_event_show(struct seq_file *m, void *d)
{
	struct mhi_device *mhi_dev = m->private;
	struct mhi_event *mhi_event;
	struct __packed mhi_event_ctxt *er_ctxt;
	int i;

	er_ctxt = mhi_dev->mhi_ctxt.er_ctxt;
	mhi_event = mhi_dev->mhi_event;
	for (i = 0; i < mhi_dev->ev_rings; i++, er_ctxt++, mhi_event++) {
		struct mhi_ring *ring = &mhi_event->ring;

		seq_printf(m,
			   "Index:%d modc:%d modt:%d base:0x%0llx len:0x%llx",
			   i, er_ctxt->intmodc, er_ctxt->intmodt,
			   er_ctxt->rbase, er_ctxt->rlen);
		seq_printf(m,
			   " rp:0x%llx wp:0x%llx local_rp:0x%llx db:0x%llx\n",
			   er_ctxt->rp, er_ctxt->wp,
			   ring->phys_base + (ring->rp - ring->base),
			   mhi_event->db_mode.db);;
	}

	return 0;
}

int mhi_debugfs_mhi_chan_show(struct seq_file *m, void *d)
{
	struct mhi_device *mhi_dev = m->private;
	struct mhi_chan *mhi_chan;
	struct __packed mhi_chan_ctxt *chan_ctxt;
	int i;

	mhi_chan = mhi_dev->mhi_chan;
	chan_ctxt = mhi_dev->mhi_ctxt.chan_ctxt;
	for (i = 0; i < MHI_MAX_CHANNELS; i++, chan_ctxt++, mhi_chan++) {
		struct mhi_ring *ring = &mhi_chan->tre_ring;

		if (!mhi_chan->cldata)
			continue;
		seq_printf(m,
			   "%s(%u) state:0x%x brstmode:0x%x pllcfg:0x%x type:0x%x erindex:%u\n",
			   mhi_chan->name, mhi_chan->chan, chan_ctxt->chstate,
			   chan_ctxt->brstmode, chan_ctxt->pollcfg,
			   chan_ctxt->chtype, chan_ctxt->erindex);

		seq_printf(m,
			   "%s(%u) base:0x%llx len:0x%llx wp:0x%llx local_rp:0x%llx local_wp:0x%llx db:0x%llx\n",
			   mhi_chan->name, mhi_chan->chan, chan_ctxt->rbase,
			   chan_ctxt->rlen, chan_ctxt->wp,
			   ring->phys_base + (ring->rp - ring->base),
			   ring->phys_base + (ring->wp - ring->base),
			   mhi_chan->db_mode.db);
	}

	return 0;
}
int mhi_get_max_desc(struct mhi_client_handle *client_handle)
{
	struct mhi_client_data *cldata = client_handle->cldata;
	struct mhi_device *mhi_dev = cldata->mhi_dev;
	struct mhi_chan *mhi_chan = &mhi_dev->mhi_chan[cldata->chan];

	return mhi_chan->tre_ring.elements - 1;
}
EXPORT_SYMBOL(mhi_get_max_desc);

int mhi_set_lpm(struct mhi_client_handle *client_handle, bool enable_lpm)
{
	struct mhi_client_data *cldata = client_handle->cldata;
	struct mhi_device *mhi_dev = cldata->mhi_dev;
	unsigned long flags;

	read_lock_irqsave(&mhi_dev->pm_lock, flags);

	/* Disable low power mode by asserting Wake */
	if (enable_lpm == false)
		mhi_dev->assert_wake(mhi_dev, false);
	else
		mhi_dev->deassert_wake(mhi_dev, false);

	read_unlock_irqrestore(&mhi_dev->pm_lock, flags);

	return 0;
}
EXPORT_SYMBOL(mhi_set_lpm);

int mhi_get_free_desc(struct mhi_client_handle *client_handle)
{
	struct mhi_client_data *cldata = client_handle->cldata;
	struct mhi_device *mhi_dev = cldata->mhi_dev;
	struct mhi_chan *mhi_chan = &mhi_dev->mhi_chan[cldata->chan];
	struct mhi_ring *tre_ring = &mhi_chan->tre_ring;

	return get_nr_avail_ring_elements(mhi_dev, tre_ring);
}
EXPORT_SYMBOL(mhi_get_free_desc);

int mhi_deregister_channel(struct mhi_client_handle *client_handle)
{
	struct mhi_client_data *cldata = client_handle->cldata;
	struct mhi_device *mhi_dev = cldata->mhi_dev;
	struct mhi_chan *mhi_chan = &mhi_dev->mhi_chan[cldata->chan];

	mutex_lock(&mhi_chan->mutex);
	if (mhi_chan->ch_state != MHI_CHAN_STATE_DISABLED) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"chan:%d still in active state\n", mhi_chan->chan);
		mutex_unlock(&mhi_chan->mutex);
		return -EACCES;
	}

	vfree(cldata);
	mhi_chan->cldata = NULL;
	mutex_unlock(&mhi_chan->mutex);
	return 0;
}
EXPORT_SYMBOL(mhi_deregister_channel);

int mhi_poll(struct mhi_client_handle *client_handle, u32 budget)
{
	struct mhi_client_data *cldata = client_handle->cldata;
	int chan = cldata->chan;
	struct mhi_device *mhi_dev = cldata->mhi_dev;
	struct mhi_chan *mhi_chan = &mhi_dev->mhi_chan[chan];

	return mhi_process_event_ring(mhi_dev, mhi_chan->er_index, budget);
}
EXPORT_SYMBOL(mhi_poll);

long mhi_ioctl(struct mhi_client_handle *handle,
	      unsigned int cmd,
	      unsigned long arg)
{
	struct mhi_client_data *cldata = handle->cldata;
	struct mhi_device *mhi_dev = cldata->mhi_dev;
	struct mhi_chan *mhi_chan = &mhi_dev->mhi_chan[cldata->chan];
	int ret;

	switch (cmd) {
	case TIOCMGET:
		return mhi_chan->tiocm;
	case TIOCMSET:
	{
		u32 tiocm;

		ret = get_user(tiocm, (uint32_t *)arg);
		if (ret)
			return ret;
		if (mhi_dev->tiocmset)
			return mhi_dev->tiocmset(mhi_dev, cldata->chan, tiocm);
		break;
	}
	default:
		break;
	}
	return -EINVAL;
}
EXPORT_SYMBOL(mhi_ioctl);

#ifdef CONFIG_MHI_SLAVEMODE

int mhi_xfer_rddm(struct mhi_master *mhi_master, enum mhi_rddm_segment seg,
		  struct scatterlist **sg_list)
{
	struct mhi_device_ctxt *mhi_dev_ctxt = mhi_device->mhi_dev_ctxt;
	struct bhi_ctxt_t *bhi_ctxt = &mhi_dev_ctxt->bhi_ctxt;
	int segments = 0;

	*sg_list = NULL;
	switch (seg) {
	case MHI_RDDM_FW_SEGMENT:
		*sg_list = bhi_ctxt->fw_table.sg_list;
		segments = bhi_ctxt->fw_table.segment_count;
		break;
	case MHI_RDDM_RD_SEGMENT:
		*sg_list = bhi_ctxt->rddm_table.sg_list;
		segments = bhi_ctxt->rddm_table.segment_count;
		break;
	}
	return segments;

}
EXPORT_SYMBOL(mhi_xfer_rddm);
#endif
