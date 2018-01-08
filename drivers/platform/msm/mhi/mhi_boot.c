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

#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include "mhi.h"

static int bhi_load_firmware(struct mhi_device *mhi_dev,
			     const struct bhie_mem_info  *const mem_info)
{
	u32 word;
	u32 tx_db_val = 0;
	unsigned long timeout;
	rwlock_t *pm_lock = &mhi_dev->pm_lock;
	void __iomem *base = mhi_dev->bhi;

	/* program sbl image into pbl */
	read_lock_bh(pm_lock);
	if (!MHI_REG_ACCESS_VALID(mhi_dev->pm_state)) {
		read_unlock_bh(pm_lock);
		return -EIO;
	}

	/* clear BHI status before ringing txdb */
	mhi_write_reg(mhi_dev, base,  BHI_STATUS, 0);

	word = upper_32_bits(mem_info->phys_addr);
	mhi_write_reg(mhi_dev, base, BHI_IMGADDR_HIGH, word);

	word = lower_32_bits(mem_info->phys_addr);
	mhi_write_reg(mhi_dev, base, BHI_IMGADDR_LOW, word);

	mhi_write_reg(mhi_dev, base, BHI_IMGSIZE, mem_info->size);

	word = mhi_read_reg(mhi_dev, base, BHI_IMGTXDB);
	if (unlikely(PCI_INVALID_READ(word))) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Read invalid data from pci bus\n");
		read_unlock_bh(pm_lock);
		return -EIO;
	}
	word += 1;
	mhi_write_reg(mhi_dev, base, BHI_IMGTXDB, word);
	read_unlock_bh(pm_lock);

	/* poll for completion */
	timeout = jiffies + msecs_to_jiffies(mhi_dev->poll_timeout);
	while (time_before(jiffies, timeout)) {
		u32 err = 0, errdbg1 = 0, errdbg2 = 0, errdbg3 = 0;

		read_lock_bh(pm_lock);
		if (!MHI_REG_ACCESS_VALID(mhi_dev->pm_state)) {
			read_unlock_bh(pm_lock);
			return -EIO;
		}
		err = mhi_read_reg(mhi_dev, base, BHI_ERRCODE);
		errdbg1 = mhi_read_reg(mhi_dev, base, BHI_ERRDBG1);
		errdbg2 = mhi_read_reg(mhi_dev, base, BHI_ERRDBG2);
		errdbg3 = mhi_read_reg(mhi_dev, base, BHI_ERRDBG3);
		tx_db_val = mhi_read_reg_field(mhi_dev, base, BHI_STATUS,
					BHI_STATUS_MASK, BHI_STATUS_SHIFT);
		read_unlock_bh(pm_lock);
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"%s 0x%x %s:0x%x %s:0x%x %s:0x%x %s:0x%x\n",
			"BHI STATUS", tx_db_val, "err", err, "errdbg1", errdbg1,
			"errdbg2", errdbg2, "errdbg3", errdbg3);

		if (unlikely(PCI_INVALID_READ(tx_db_val)))
			return -EIO;
		if (tx_db_val == BHI_STATUS_SUCCESS ||
		    tx_db_val == BHI_STATUS_ERROR)
			break;
		msleep(BHI_POLL_SLEEP_TIME_MS);
	}

	return (tx_db_val == BHI_STATUS_SUCCESS) ? 0 : -EIO;
}

static int bhi_alloc_pbl_xfer(struct mhi_device *mhi_dev,
			      struct bhie_mem_info *const mem_info,
			      size_t size)
{
	mem_info->size = size;
	mem_info->alloc_size = size;
	mem_info->pre_aligned =
		mhi_alloc_coherent(mhi_dev, mem_info->alloc_size,
				   &mem_info->dma_handle, GFP_KERNEL);
	if (mem_info->pre_aligned == NULL)
		return -ENOMEM;

	mem_info->phys_addr = mem_info->dma_handle;
	mem_info->aligned = mem_info->pre_aligned;
	mhi_log(mhi_dev, MHI_MSG_INFO,
		"alloc_size:%lu image_size:%lu unal_addr:0x%llx al_addr:0x%llx\n",
		mem_info->alloc_size, mem_info->size,
		mem_info->dma_handle, mem_info->phys_addr);

	return 0;
}

void bhi_load_worker(struct work_struct *work)
{
	struct mhi_device *mhi_dev;
	const struct firmware *firmware;
	struct bhie_mem_info mem_info;
	int ret = -EIO;
	enum MHI_PM_STATE pm_state;

	mhi_dev = container_of(work, struct mhi_device, fw_load_worker);

	mhi_log(mhi_dev, MHI_MSG_INFO, "Enter\n");

	/*
	 * If MHI host operating on master mode then try to read image
	 * now, on slave mode we read image thru different code path
	 */

	if (mhi_dev->pci_master && mhi_dev->dl_fw) {
		unsigned long timeout = jiffies +
			msecs_to_jiffies(mhi_dev->fw_timeout);

		while (time_before(jiffies, timeout)) {
			ret = request_firmware(&firmware, mhi_dev->fw_image,
					       mhi_dev->dev);
			if (!ret)
				break;
			mhi_log(mhi_dev, MHI_MSG_VERBOSE,
				"fw not ready, sleeping\n");
			msleep(FW_POLL_SLEEP_TIME_MS);
		}

		if (ret) {
			mhi_log(mhi_dev, MHI_MSG_ERROR,
				"Error requesting firmware image:%s ret:%d\n",
				mhi_dev->fw_image, ret);
			return;
		}

		/* allocate memory and copy the image */
		ret = bhi_alloc_pbl_xfer(mhi_dev, &mem_info, firmware->size);
		if (ret) {
			mhi_log(mhi_dev, MHI_MSG_ERROR,
				"Error allocating memory for sbl image\n");
			release_firmware(firmware);
			return;
		}

		memcpy(mem_info.aligned, firmware->data, firmware->size);
		release_firmware(firmware);
	}

	ret = wait_event_timeout(mhi_dev->state_event,
			mhi_dev->dev_exec_env == MHI_EXEC_ENV_PBL ||
			mhi_dev->pm_state ==
			(MHI_PM_LD_ERR_FATAL_DETECT | MHI_PM_FW_DL_ERR),
			msecs_to_jiffies(MHI_MAX_STATE_TRANSITION_TIMEOUT));
	if (!ret || mhi_dev->pm_state ==
	    (MHI_PM_LD_ERR_FATAL_DETECT | MHI_PM_FW_DL_ERR)) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"MHI is not in valid state for firmware download\n");
		if (mhi_dev->pci_master)
			mhi_free_coherent(mhi_dev, mem_info.alloc_size,
					  mem_info.pre_aligned,
					  mem_info.dma_handle);
		return;
	}

	/*
	 * if we're not bus master, PBL image stored in the first segment
	 * in firmware vector table
	 */
	if (!mhi_dev->pci_master) {
		mem_info = *mhi_dev->fw_table.bhie_mem_info;
		mem_info.size = mhi_dev->sbl_len;
	}
	ret = bhi_load_firmware(mhi_dev, &mem_info);

	if (mhi_dev->pci_master)
		mhi_free_coherent(mhi_dev, mem_info.alloc_size,
				  mem_info.pre_aligned, mem_info.dma_handle);
	if (ret) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Failed to load sbl firmware\n");
		goto transfer_error;
	}

	/* wait for device to go into RESET -> READY Transition */
	ret = process_reset_transition(mhi_dev);
	if (ret) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Device failed to enter READY state\n");
		goto transfer_error;
	}

	/* if we're master mode we're finish loading firmware */
	if (mhi_dev->pci_master)
		return;

#ifdef CONFIG_MHI_SLAVEMODE
	/* wait for device to enter bhie event */
	wait_event_timeout(mhi_dev->state_event,
			   mhi_dev->dev_exec_env == MHI_EXEC_ENV_BHIE ||
			   mhi_dev->pm_state >= MHI_PM_SYS_ERR_DETECT,
			   msecs_to_jiffies(bhi_ctxt->poll_timeout));
	if (mhi_dev->pm_state >= MHI_PM_SYS_ERR_DETECT ||
	    mhi_dev->dev_exec_env != MHI_EXEC_ENV_BHIE) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Failed to Enter EXEC_ENV_BHIE\n");
		goto transfer_error;
	}

	ret = bhi_bhie_transfer(mhi_dev_ctxt, &mhi_dev_ctxt->bhi_ctxt.fw_table,
				true);
	if (ret) {
		mhi_log(mhi_dev_ctxt, MHI_MSG_ERROR,
			"Failed to Load amss firmware\n");
		goto transfer_error;
	}

	return;
#endif
transfer_error:
	write_lock_irq(&mhi_dev->pm_lock);
	pm_state = mhi_tryset_pm_state(mhi_dev, MHI_PM_FW_DL_ERR);
	write_unlock_irq(&mhi_dev->pm_lock);
	mhi_log(mhi_dev, MHI_MSG_INFO, "PM_State:0x%x\n", pm_state);
}

#ifdef CONFIG_MHI_SLAVEMODE
static int bhi_alloc_bhie_xfer(struct mhi_device *mhi_dev, size_t size,
			       struct bhie_vec_table *vec_table)
{
	size_t seg_size = mhi_dev->seg_len;
	/* We need one additional entry for Vector Table */
	int segments = DIV_ROUND_UP(size, seg_size) + 1;
	int i;
	struct scatterlist *sg_list;
	struct bhie_mem_info *bhie_mem_info, *info;

	mhi_log(mhi_dev, MHI_MSG_INFO,
		"Total size:%lu total_seg:%d seg_size:%lu\n",
		size, segments, seg_size);

	sg_list = kcalloc(segments, sizeof(*sg_list), GFP_KERNEL);
	if (!sg_list)
		return -ENOMEM;

	bhie_mem_info = kcalloc(segments, sizeof(*bhie_mem_info), GFP_KERNEL);
	if (!bhie_mem_info)
		goto alloc_bhi_mem_info_error;

	/* Allocate buffers for bhi/e vector table */
	for (i = 0; i < segments; i++) {
		size_t size = seg_size;

		/* Last entry if for vector table */
		if (i == segments - 1)
			size = sizeof(struct bhi_vec_entry) * i;
		info = &bhie_mem_info[i];
		info->size = size;
		info->alloc_size = info->size;
		info->pre_aligned =
			mhi_alloc_coherent(mhi_dev, info->alloc_size,
					   &info->dma_handle, GFP_KERNEL);
		if (!info->pre_aligned)
			goto alloc_dma_error;

		info->phys_addr = info->dma_handle;
		info->aligned = info->pre_aligned;
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Seg:%d unaligned Img: 0x%llx aligned:0x%llx\n",
			i, info->dma_handle, info->phys_addr);
	}

	sg_init_table(sg_list, segments);
	sg_set_buf(sg_list, info->aligned, info->size);
	sg_dma_address(sg_list) = info->phys_addr;
	sg_dma_len(sg_list) = info->size;
	vec_table->sg_list = sg_list;
	vec_table->bhie_mem_info = bhie_mem_info;
	vec_table->bhi_vec_entry = info->aligned;
	vec_table->segment_count = segments;

	mhi_log(mhi_dev, MHI_MSG_INFO, "BHI/E table successfully allocated\n");
	return 0;

alloc_dma_error:
	for (i = i - 1; i >= 0; i--)
		mhi_free_coherent(mhi_dev, bhie_mem_info[i].alloc_size,
				  bhie_mem_info[i].pre_aligned,
				  bhie_mem_info[i].dma_handle);
	kfree(bhie_mem_info);
alloc_bhi_mem_info_error:
	kfree(sg_list);
	return -ENOMEM;
}
#endif

#ifdef CONFIG_MHI_SLAVEMODE

/* transfer firmware or ramdump via bhie protocol */
static int bhi_bhie_transfer(struct mhi_device *mhi_dev,
			     struct bhie_vec_table *vec_table,
			     bool tx_vec_table)
{
	struct bhi_ctxt_t *bhi_ctxt = &mhi_dev_ctxt->bhi_ctxt;
	/* last element is the vector table */
	const struct bhie_mem_info *bhie_mem_info =
		&vec_table->bhie_mem_info[vec_table->segment_count - 1];
	u32 val;
	const u32 tx_sequence = vec_table->sequence++;
	unsigned long timeout;
	rwlock_t *pm_xfer_lock = &mhi_dev_ctxt->pm_xfer_lock;
	unsigned bhie_vecaddr_high_offs, bhie_vecaddr_low_offs,
		bhie_vecsize_offs, bhie_vecdb_offs,
		bhie_vecstatus_offs;

	if (tx_vec_table) {
		bhie_vecaddr_high_offs = BHIE_TXVECADDR_HIGH_OFFS;
		bhie_vecaddr_low_offs = BHIE_TXVECADDR_LOW_OFFS;
		bhie_vecsize_offs = BHIE_TXVECSIZE_OFFS;
		bhie_vecdb_offs = BHIE_TXVECDB_OFFS;
		bhie_vecstatus_offs = BHIE_TXVECSTATUS_OFFS;
	} else {
		bhie_vecaddr_high_offs = BHIE_RXVECADDR_HIGH_OFFS;
		bhie_vecaddr_low_offs = BHIE_RXVECADDR_LOW_OFFS;
		bhie_vecsize_offs = BHIE_RXVECSIZE_OFFS;
		bhie_vecdb_offs = BHIE_RXVECDB_OFFS;
		bhie_vecstatus_offs = BHIE_RXVECSTATUS_OFFS;
	}

	/* Program TX/RX Vector table */
	read_lock_bh(pm_xfer_lock);
	if (!MHI_REG_ACCESS_VALID(mhi_dev_ctxt->mhi_pm_state)) {
		read_unlock_bh(pm_xfer_lock);
		return -EIO;
	}

	val = HIGH_WORD(bhie_mem_info->phys_addr);
	mhi_reg_write(mhi_dev_ctxt, bhi_ctxt->bhi_base,
		      bhie_vecaddr_high_offs, val);
	val = LOW_WORD(bhie_mem_info->phys_addr);
	mhi_reg_write(mhi_dev_ctxt, bhi_ctxt->bhi_base,
		      bhie_vecaddr_low_offs, val);
	val = (u32)bhie_mem_info->size;
	mhi_reg_write(mhi_dev_ctxt, bhi_ctxt->bhi_base, bhie_vecsize_offs, val);

	/* Ring DB to begin Xfer */
	mhi_reg_write_field(mhi_dev_ctxt, bhi_ctxt->bhi_base, bhie_vecdb_offs,
			    BHIE_TXVECDB_SEQNUM_BMSK, BHIE_TXVECDB_SEQNUM_SHFT,
			    tx_sequence);
	read_unlock_bh(pm_xfer_lock);

	timeout = jiffies + msecs_to_jiffies(bhi_ctxt->poll_timeout);
	while (time_before(jiffies, timeout)) {
		u32 current_seq, status;

		read_lock_bh(pm_xfer_lock);
		if (!MHI_REG_ACCESS_VALID(mhi_dev_ctxt->mhi_pm_state) ||
		    mhi_dev_ctxt->mhi_pm_state >= MHI_PM_SYS_ERR_DETECT) {
			read_unlock_bh(pm_xfer_lock);
			return -EIO;
		}
		val = mhi_reg_read(bhi_ctxt->bhi_base, bhie_vecstatus_offs);
		read_unlock_bh(pm_xfer_lock);
		mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
			"%sVEC_STATUS:0x%x\n", tx_vec_table ? "TX" : "RX", val);
		current_seq = (val & BHIE_TXVECSTATUS_SEQNUM_BMSK) >>
			BHIE_TXVECSTATUS_SEQNUM_SHFT;
		status = (val & BHIE_TXVECSTATUS_STATUS_BMSK) >>
			BHIE_TXVECSTATUS_STATUS_SHFT;
		if ((status == BHIE_TXVECSTATUS_STATUS_XFER_COMPL) &&
		    (current_seq == tx_sequence)) {
			mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
				"%s transfer complete\n",
				tx_vec_table ? "image" : "rddm");
			return 0;
		}

		if (status == BHIE_TXVECSTATUS_STATUS_ERROR) {
			u32 err, errdb1, errdb2, errdb3;

			mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
				"%s transfer error\n",
				tx_vec_table ? "image" : "rddm");
			read_lock_bh(pm_xfer_lock);
			if (!MHI_REG_ACCESS_VALID(mhi_dev_ctxt->mhi_pm_state)) {
				read_unlock_bh(pm_xfer_lock);
				return -EIO;
			}
			err = mhi_reg_read(bhi_ctxt->bhi_base, BHI_ERRCODE);
			errdb1 = mhi_reg_read(bhi_ctxt->bhi_base, BHI_ERRDBG1);
			errdb2 = mhi_reg_read(bhi_ctxt->bhi_base, BHI_ERRDBG2);
			errdb3 = mhi_reg_read(bhi_ctxt->bhi_base, BHI_ERRDBG3);
			read_unlock_bh(pm_xfer_lock);
			mhi_log(mhi_dev_ctxt, MHI_MSG_ERROR,
				"%s: 0x%x, %s: 0x%x, %s: 0x%x, %s: 0x%x, %s: 0x%x\n",
				"VEC_STATUS", status,
				"BHI_ERRCODE", err,
				"BHI_ERRDBG1", errdb1,
				"BHI_ERRDBG2", errdb2,
				"BHI_ERRDBG3", errdb3);
			return -EIO;
		}
		msleep(BHI_POLL_SLEEP_TIME_MS);
	}

	mhi_log(mhi_dev_ctxt, MHI_MSG_ERROR,
		"Error xfer %s via BHIE\n", tx_vec_table ? "image" : "rddm");

	return -EIO;
}
#endif

#ifdef CONFIG_MHI_SLAVEMODE
static int bhi_rddm_graceful(struct mhi_device *mhi_dev)
{
	int ret = 0;

	struct bhi_ctxt_t *bhi_ctxt = &mhi_dev_ctxt->bhi_ctxt;
	struct bhie_vec_table *rddm_table = &bhi_ctxt->rddm_table;
	enum MHI_EXEC_ENV exec_env = mhi_dev_ctxt->dev_exec_env;

	mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
		"Entered with pm_state:0x%x exec_env:%s mhi_state:%s\n",
		mhi_dev_ctxt->mhi_pm_state, TO_MHI_EXEC_STR(exec_env),
		TO_MHI_STATE_STR(mhi_dev_ctxt->mhi_state));

	if (exec_env != MHI_EXEC_ENV_RDDM) {
		mhi_log(mhi_dev_ctxt, MHI_MSG_ERROR,
			"Not in RDDM exec env, exec_env:%s\n", TO_MHI_STATE_STR(exec_env));
		return -EIO;
	}

	ret = bhi_bhie_transfer(mhi_dev_ctxt, rddm_table, false);
	mhi_log(mhi_dev_ctxt, MHI_MSG_INFO, "rddm transfer status:%d\n", ret);

	return ret;
}
#endif

#ifdef CONFIG_MHI_SLAVEMODE

/* collect ramdump from device using bhie protocol */
int bhi_rddm(struct mhi_device *mhi_dev, bool in_panic)
{
	struct bhi_ctxt_t *bhi_ctxt = &mhi_dev_ctxt->bhi_ctxt;
	struct bhie_vec_table *rddm_table = &bhi_ctxt->rddm_table;
	struct bhie_mem_info *bhie_mem_info;
	u32 rx_sequence, val, current_seq;
	u32 timeout = (bhi_ctxt->poll_timeout * 1000) / BHIE_RDDM_DELAY_TIME_US;
	int i;
	u32 cur_exec, prev_exec = 0;
	u32 state, prev_state = 0;
	u32 rx_status, prev_status = 0;

	if (!rddm_table->bhie_mem_info) {
		mhi_log(mhi_dev_ctxt, MHI_MSG_INFO, "RDDM table == NULL\n");
		return -ENOMEM;
	}

	if (!in_panic)
		return bhi_rddm_graceful(mhi_dev_ctxt);

	/*
	 * Below code should only be executed during kernel panic,
	 * we expect other cores to be shutting down while we're
	 * executing rddm transfer. After returning from this function,
	 * we expect device to reset.
	 */

	/* Trigger device into RDDM */
	mhi_log(mhi_dev_ctxt, MHI_MSG_INFO, "pm_state:0x%x mhi_state:%s\n",
		mhi_dev_ctxt->mhi_pm_state,
		TO_MHI_STATE_STR(mhi_dev_ctxt->mhi_state));
	if (!MHI_REG_ACCESS_VALID(mhi_dev_ctxt->mhi_pm_state)) {
		mhi_log(mhi_dev_ctxt, MHI_MSG_ERROR,
			"Register access not allowed\n");
		return -EIO;
	}

	/*
	 * Normally we only set mhi_pm_state after grabbing pm_xfer_lock as a
	 * write, by function mhi_tryset_pm_state. Since we're in a kernel
	 * panic, we will set pm state w/o grabbing xfer lock. We're setting
	 * pm_state to LD as a safety precautions. If another core in middle
	 * of register access this should deter it. However, there is no
	 * no gurantee change will take effect.
	 */
	mhi_dev_ctxt->mhi_pm_state = MHI_PM_LD_ERR_FATAL_DETECT;
	/* change should take effect immediately */
	smp_wmb();

	bhie_mem_info = &rddm_table->
		bhie_mem_info[rddm_table->segment_count - 1];
	rx_sequence = rddm_table->sequence++;

	/* program the vector table */
	mhi_log(mhi_dev_ctxt, MHI_MSG_INFO, "Programming RXVEC table\n");
	val = HIGH_WORD(bhie_mem_info->phys_addr);
	mhi_reg_write(mhi_dev_ctxt, bhi_ctxt->bhi_base,
		      BHIE_RXVECADDR_HIGH_OFFS, val);
	val = LOW_WORD(bhie_mem_info->phys_addr);
	mhi_reg_write(mhi_dev_ctxt, bhi_ctxt->bhi_base, BHIE_RXVECADDR_LOW_OFFS,
		      val);
	val = (u32)bhie_mem_info->size;
	mhi_reg_write(mhi_dev_ctxt, bhi_ctxt->bhi_base, BHIE_RXVECSIZE_OFFS,
		      val);
	mhi_reg_write_field(mhi_dev_ctxt, bhi_ctxt->bhi_base, BHIE_RXVECDB_OFFS,
			    BHIE_TXVECDB_SEQNUM_BMSK, BHIE_TXVECDB_SEQNUM_SHFT,
			    rx_sequence);

	/* trigger device into rddm */
	mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
		"Triggering Device into RDDM mode\n");
	mhi_set_m_state(mhi_dev_ctxt, MHI_STATE_SYS_ERR);
	i = 0;

	while (timeout--) {
		cur_exec = mhi_reg_read(bhi_ctxt->bhi_base, BHI_EXECENV);
		state = mhi_get_m_state(mhi_dev_ctxt);
		rx_status = mhi_reg_read(bhi_ctxt->bhi_base,
					 BHIE_RXVECSTATUS_OFFS);
		/* if reg. values changed or each sec (udelay(1000)) log it */
		if (cur_exec != prev_exec || state != prev_state ||
		    rx_status != prev_status || !(i & (SZ_1K - 1))) {
			mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
				"EXECENV:0x%x MHISTATE:0x%x RXSTATUS:0x%x\n",
				cur_exec, state, rx_status);
			prev_exec = cur_exec;
			prev_state = state;
			prev_status = rx_status;
		};
		current_seq = (rx_status & BHIE_TXVECSTATUS_SEQNUM_BMSK) >>
			BHIE_TXVECSTATUS_SEQNUM_SHFT;
		rx_status = (rx_status & BHIE_TXVECSTATUS_STATUS_BMSK) >>
			BHIE_TXVECSTATUS_STATUS_SHFT;

		if ((rx_status == BHIE_TXVECSTATUS_STATUS_XFER_COMPL) &&
		    (current_seq == rx_sequence)) {
			mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
				"rddm transfer completed\n");
			return 0;
		}
		udelay(BHIE_RDDM_DELAY_TIME_US);
		i++;
	}

	mhi_log(mhi_dev_ctxt, MHI_MSG_ERROR, "rddm transfer timeout\n");
	return -EIO;
}

#endif

#ifdef CONFIG_MHI_SLAVEMODE
int bhi_probe(struct mhi_device *mhi_dev, const char *fw_image)
{
	struct bhie_vec_table *fw_table = &mhi_dev->fw_table;
	struct bhie_vec_table *rddm_table = &mhi_dev->rddm_table;
	const struct firmware *firmware;
	struct scatterlist *itr;
	int ret, i;
	size_t remainder;
	const u8 *image;

	/* expose dev node to userspace */
	if (mhi_dev->dl_fw == false)
		return bhi_expose_dev_bhi(mhi_dev);

	if (!fw_image)
		return -EINVAL;

	/* Make sure minimum  buffer we allocate for BHI/E is >= sbl image */
	while (fw_info->segment_size < fw_info->max_sbl_len)
		fw_info->segment_size <<= 1;

	mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
		"max sbl image size:%lu segment size:%lu\n",
		fw_info->max_sbl_len, fw_info->segment_size);

	/* Read the fw image */
	ret = request_firmware(&firmware, fw_image, mhi_dev_ctxt->dev);
	if (ret) {
		mhi_log(mhi_dev_ctxt, MHI_MSG_ERROR,
			"Error request firmware for:%s ret:%d\n",
			fw_image, ret);
		return ret;
	}

	ret = bhi_alloc_bhie_xfer(mhi_dev_ctxt, firmware->size, fw_table);
	if (ret) {
		mhi_log(mhi_dev_ctxt, MHI_MSG_ERROR,
			"Error Allocating memory for firmware image\n");
		release_firmware(firmware);
		return ret;
	}

	/* Copy the fw image to vector table */
	remainder = firmware->size;
	image = firmware->data;
	for (i = 0, itr = &fw_table->sg_list[1];
	     i < fw_table->segment_count - 1; i++, itr++) {
		size_t to_copy = min(remainder, fw_info->segment_size);

		memcpy(fw_table->bhie_mem_info[i].aligned, image, to_copy);
		fw_table->bhi_vec_entry[i].phys_addr =
			fw_table->bhie_mem_info[i].phys_addr;
		fw_table->bhi_vec_entry[i].size = to_copy;
		sg_set_buf(itr, fw_table->bhie_mem_info[i].aligned, to_copy);
		sg_dma_address(itr) = fw_table->bhie_mem_info[i].phys_addr;
		sg_dma_len(itr) = to_copy;
		remainder -= to_copy;
		image += to_copy;
	}

	fw_table->sequence++;
	release_firmware(firmware);

	/* allocate memory and setup rddm table */
	if (bhi_ctxt->support_rddm) {
		ret = bhi_alloc_bhie_xfer(mhi_dev_ctxt, bhi_ctxt->rddm_size,
					  rddm_table);
		if (!ret) {
			for (i = 0, itr = &rddm_table->sg_list[1];
			     i < rddm_table->segment_count - 1; i++, itr++) {
				size_t size = rddm_table->bhie_mem_info[i].size;

				rddm_table->bhi_vec_entry[i].phys_addr =
					rddm_table->bhie_mem_info[i].phys_addr;
				rddm_table->bhi_vec_entry[i].size = size;
				sg_set_buf(itr, rddm_table->
					   bhie_mem_info[i].aligned, size);
				sg_dma_address(itr) =
					rddm_table->bhie_mem_info[i].phys_addr;
				sg_dma_len(itr) = size;
			}
			rddm_table->sequence++;
		} else {
			/* out of memory for rddm, not fatal error */
			mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
				"Could not successfully allocate mem for rddm\n");
		}
	}

	/* Schedule a worker thread and wait for BHI Event */
	schedule_work(&bhi_ctxt->fw_load_work);
	return 0;

}
#endif

#ifdef CONFIG_MHI_SLAVEMODE
void bhi_exit(struct mhi_device *mhi_dev)
{
	struct bhi_ctxt_t *bhi_ctxt = &mhi_dev_ctxt->bhi_ctxt;
	struct bhie_vec_table *fw_table = &bhi_ctxt->fw_table;
	struct bhie_vec_table *rddm_table = &bhi_ctxt->rddm_table;
	struct bhie_mem_info *bhie_mem_info;
	int i;

	if (bhi_ctxt->manage_boot == false)
		return;

	mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
		"freeing firmware and rddm memory\n");

	/* free memory allocated for firmware */
	kfree(fw_table->sg_list);
	fw_table->sg_list = NULL;
	bhie_mem_info = fw_table->bhie_mem_info;
	for (i = 0; i < fw_table->segment_count; i++, bhie_mem_info++)
		mhi_free_coherent(mhi_dev_ctxt, bhie_mem_info->alloc_size,
				  bhie_mem_info->pre_aligned,
				  bhie_mem_info->dma_handle);
	kfree(fw_table->bhie_mem_info);
	fw_table->bhie_mem_info = NULL;
	/* vector table is the last entry in bhie_mem_info */
	fw_table->bhi_vec_entry = NULL;

	if (!rddm_table->bhie_mem_info)
		return;

	/* free memory allocated for rddm */
	kfree(rddm_table->sg_list);
	rddm_table->sg_list = NULL;
	bhie_mem_info = rddm_table->bhie_mem_info;
	for (i = 0; i < rddm_table->segment_count; i++, bhie_mem_info++)
		mhi_free_coherent(mhi_dev_ctxt, bhie_mem_info->alloc_size,
				  bhie_mem_info->pre_aligned,
				  bhie_mem_info->dma_handle);
	kfree(rddm_table->bhie_mem_info);
	rddm_table->bhie_mem_info = NULL;
	rddm_table->bhi_vec_entry = NULL;

	mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
		"Number of bytes still allocated to MHI: %d\n",
		atomic_read(&mhi_dev_ctxt->counters.alloc_size));
}
#endif
