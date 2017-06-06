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


#include <linux/pci.h>
#include <linux/gpio.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/pm_runtime.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/hrtimer.h>
#include <linux/cpu.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/completion.h>
#include <linux/platform_device.h>
#include <linux/iommu.h>
#include <linux/dma-iommu.h>
#include <linux/dma-mapping.h>
#include <linux/uaccess.h>
#include "mhi.h"

struct mhi_device_driver mhi_device_drv;
enum MHI_DEBUG_LEVEL mhi_msg_lvl = MHI_MSG_ERROR;

#ifdef CONFIG_MHI_SLAVEMODE
/* populate smmu cfg from dev node */
static void mhi_get_iommu_mapping(struct mhi_device *mhi_dev,
				  struct device *dev)
{
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);
	struct dma_iommu_mapping *mapping = dev->archdata.mapping;
	int s1_bypass = 0;
	int ret;

	if (!domain || !mapping)
		return;

	/* If it's s1 bypass, skip iova address */
	ret = iommu_domain_get_attr(domain, DOMAIN_ATTR_S1_BYPASS, &s1_bypass);
	if (ret)
		return;

	if (s1_bypass)
		mhi_dev->smmu_cfg = MHI_SMMU_ATTACH | MHI_SMMU_S1_BYPASS;
	else {
		mhi_dev->smmu_cfg = MHI_SMMU_ATTACH;
		mhi_dev->iova_start = mapping->base;
		/* get size, check arm_iommu_create_mapping() for more info */
		mhi_dev->iova_end = mapping->base +
			(mapping->bits << PAGE_SHIFT) - 1;
	}
	mhi_log(mhi_dev, MHI_MSG_INFO,
		"smmu_cfg:0x%x iova_start:0x%llx iova_end:0x%llx\n",
		mhi_dev->smmu_cfg, mhi_dev->iova_start, mhi_dev->iova_end);
}
#endif

void mhi_deinit_chan_ctxt(struct mhi_device *mhi_dev, struct mhi_chan *mhi_chan)
{
	struct mhi_ring *buf_ring = &mhi_chan->buf_ring;
	struct mhi_ring *tre_ring = &mhi_chan->tre_ring;
	int chan = mhi_chan->chan;
	struct mhi_chan_ctxt *chan_ctxt = &mhi_dev->mhi_ctxt.chan_ctxt[chan];

	mhi_free_coherent(mhi_dev, tre_ring->alloc_size, tre_ring->pre_aligned,
			  tre_ring->dma_handle);
	kfree(buf_ring->base);

	buf_ring->base = tre_ring->base = NULL;
	chan_ctxt->rbase = 0;
}

static int mhi_alloc_aligned_ring(struct mhi_device *mhi_dev,
				  struct mhi_ring *ring,
				  u64 len)
{
	ring->alloc_size = len + (len - 1);
	ring->pre_aligned = mhi_alloc_coherent(mhi_dev, ring->alloc_size,
					       &ring->dma_handle, GFP_KERNEL);
	if (!ring->pre_aligned)
		return -ENOMEM;

	ring->phys_base = (ring->dma_handle + (len - 1)) & ~(len - 1);
	ring->base = ring->pre_aligned + (ring->phys_base - ring->dma_handle);
	return 0;
}

int mhi_init_chan_ctxt(struct mhi_device *mhi_dev, struct mhi_chan *mhi_chan)
{
	struct mhi_ring *buf_ring = &mhi_chan->buf_ring;
	struct mhi_ring *tre_ring = &mhi_chan->tre_ring;
	int chan = mhi_chan->chan;
	struct mhi_chan_ctxt *chan_ctxt = &mhi_dev->mhi_ctxt.chan_ctxt[chan];
	int ret;

	tre_ring->el_size = sizeof(struct __packed mhi_tre);
	tre_ring->len = tre_ring->el_size * tre_ring->elements;
	ret = mhi_alloc_aligned_ring(mhi_dev, tre_ring, tre_ring->len);
	if (ret)
		return -ENOMEM;

	buf_ring->el_size = sizeof(struct mhi_buf_info);
	buf_ring->len = buf_ring->el_size * buf_ring->elements;
	buf_ring->base = kmalloc(buf_ring->len, GFP_KERNEL);

	if (!buf_ring->base) {
		mhi_free_coherent(mhi_dev, tre_ring->alloc_size,
				  tre_ring->pre_aligned, tre_ring->dma_handle);
		return -ENOMEM;
	}

	chan_ctxt->chstate = MHI_CHAN_STATE_ENABLED;
	chan_ctxt->rbase = tre_ring->phys_base;
	chan_ctxt->rp = chan_ctxt->wp = chan_ctxt->rbase;
	chan_ctxt->rlen = tre_ring->len;
	tre_ring->ctxt_wp = &chan_ctxt->wp;

	tre_ring->rp = tre_ring->wp = tre_ring->base;
	buf_ring->ack_rp = buf_ring->rp = buf_ring->wp = buf_ring->base;

	/* update to all cores */
	smp_wmb();

	return 0;
}

int mhi_init_mmio(struct mhi_device *mhi_dev)
{
	u32 val;
	int i;
	struct mhi_chan *mhi_chan;
	void __iomem *base = mhi_dev->regs;
	struct {
		u32 offset;
		u32 mask;
		u32 shift;
		u32 val;
	} reg_info [] = {
		{
			CCABAP_HIGHER, U32_MAX, 0,
			upper_32_bits(mhi_dev->mhi_ctxt.chan_addr),
		},
		{
			CCABAP_LOWER, U32_MAX, 0,
			lower_32_bits(mhi_dev->mhi_ctxt.chan_addr),
		},
		{
			ECABAP_HIGHER, U32_MAX, 0,
			upper_32_bits(mhi_dev->mhi_ctxt.er_addr),
		},
		{
			ECABAP_LOWER, U32_MAX, 0,
			lower_32_bits(mhi_dev->mhi_ctxt.er_addr),
		},
		{
			CRCBAP_HIGHER, U32_MAX, 0,
			upper_32_bits(mhi_dev->mhi_ctxt.cmd_addr),
		},
		{
			CRCBAP_LOWER, U32_MAX, 0,
			lower_32_bits(mhi_dev->mhi_ctxt.cmd_addr),
		},
		{
			MHICFG, MHICFG_NER_MASK, MHICFG_NER_SHIFT,
			mhi_dev->ev_rings,
		},
		{
			MHICFG, MHICFG_NHWER_MASK, MHICFG_NHWER_SHIFT,
			mhi_dev->hw_ev_rings,
		},
		{
			MHICTRLBASE_HIGHER, U32_MAX, 0,
			upper_32_bits(mhi_dev->iova_start),
		},
		{
			MHICTRLBASE_LOWER, U32_MAX, 0,
			lower_32_bits(mhi_dev->iova_start),
		},
		{
			MHIDATABASE_HIGHER, U32_MAX, 0,
			upper_32_bits(mhi_dev->iova_start),
		},
		{
			MHIDATABASE_LOWER, U32_MAX, 0,
			lower_32_bits(mhi_dev->iova_start),
		},
		{
			MHICTRLLIMIT_HIGHER, U32_MAX, 0,
			upper_32_bits(mhi_dev->iova_end),
		},
		{
			MHICTRLLIMIT_LOWER, U32_MAX, 0,
			lower_32_bits(mhi_dev->iova_end),
		},
		{
			MHIDATALIMIT_HIGHER, U32_MAX, 0,
			upper_32_bits(mhi_dev->iova_end),
		},
		{
			MHIDATALIMIT_LOWER, U32_MAX, 0,
			lower_32_bits(mhi_dev->iova_end),
		},
		{ 0, 0, 0 }
	};

	mhi_log(mhi_dev, MHI_MSG_INFO, "~~~ Initializing MMIO ~~~\n");

	/* set up DB register for all the chan rings */
	val = mhi_read_reg_field(mhi_dev, base, CHDBOFF, CHDBOFF_CHDBOFF_MASK,
				 CHDBOFF_CHDBOFF_SHIFT);
	mhi_log(mhi_dev, MHI_MSG_INFO, "CHDBOFF:0x%x\n", val);

	if (unlikely(PCI_INVALID_READ(val)))
		return -EIO;

	mhi_dev->wake_db = base + (8 * MHI_DEV_WAKE_DB);
	mhi_chan = mhi_dev->mhi_chan;
	for (i = 0; i < MHI_MAX_CHANNELS; i++, val+=8, mhi_chan++)
		mhi_chan->tre_ring.db_addr = base + val;

	/* set up DB registers for all the event rings */
	val = mhi_read_reg_field(mhi_dev, base, ERDBOFF, ERDBOFF_ERDBOFF_MASK,
				 ERDBOFF_ERDBOFF_SHIFT);
	mhi_log(mhi_dev, MHI_MSG_INFO, "ERDBOFF:0x%x\n", val);
	if (unlikely(PCI_INVALID_READ(val)))
		return -EIO;
	for (i = 0; i < mhi_dev->ev_rings; i++, val +=8) {
		struct mhi_event *mhi_event = &mhi_dev->mhi_event[i];

		mhi_event->ring.db_addr = base + val;
	}

	/* set up DB register for primary CMD rings */
	mhi_dev->mhi_cmd[PRIMARY_CMD_RING].db_addr = base + CRDB_LOWER;

	mhi_log(mhi_dev, MHI_MSG_INFO, "Setting all MMIO values.\n");
	for (i = 0; reg_info[i].offset; i++)
		mhi_write_reg_field(mhi_dev, base, reg_info[i].offset,
				    reg_info[i].mask, reg_info[i].shift,
				    reg_info[i].val);

	mhi_log(mhi_dev, MHI_MSG_INFO, "Done..\n");

	return 0;
}

#ifdef CONFIG_MHI_SLAVEMODE
int mhi_register_device(struct mhi_master *mhi_master,
			const char *node_name,
			void *user_data)
{
	const struct device_node *of_node;
	struct mhi_device_ctxt *mhi_dev_ctxt = NULL, *itr;
	struct pcie_core_info *core_info;
	struct pci_dev *pci_dev = mhi_device->pci_dev;
	u32 domain = pci_domain_nr(pci_dev->bus);
	u32 bus = pci_dev->bus->number;
	u32 dev_id = pci_dev->device;
	u32 slot = PCI_SLOT(pci_dev->devfn);
	u32 reg;
	int ret, i;
	char node[32];
	struct pcie_core_info *core;

	of_node = of_parse_phandle(mhi_device->of_node, node_name, 0);
	if (!of_node)
		return -EINVAL;

	if (!mhi_device_drv)
		return -EPROBE_DEFER;

	/* Traverse thru the list */
	mutex_lock(&mhi_device_drv->lock);
	list_for_each_entry(itr, &mhi_device_drv->head, node) {
		struct platform_device *pdev = itr->plat_dev;

		core = &itr->core;
		if (pdev->dev.of_node == of_node && core->domain == domain &&
		    core->bus == bus && core->slot == slot &&
		    (core->dev_id == PCI_ANY_ID || (core->dev_id == dev_id))) {
			/* change default dev_id to current dev_id */
			core->dev_id = dev_id;
			mhi_dev_ctxt = itr;
			break;
		}
	}
	mutex_unlock(&mhi_device_drv->lock);

	/* perhaps we've not probed yet */
	if (!mhi_dev_ctxt)
		return -EPROBE_DEFER;

	snprintf(node, sizeof(node), "mhi_%04x_%02u.%02u.%02u",
		 core->dev_id, core->domain, core->bus, core->slot);
	mhi_dev_ctxt->mhi_ipc_log =
		ipc_log_context_create(MHI_IPC_LOG_PAGES, node, 0);

	mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
		"Registering Domain:%02u Bus:%04u dev:0x%04x slot:%04u\n",
		domain, bus, dev_id, slot);

	/* Set up pcie dev info */
	mhi_dev_ctxt->pcie_device = pci_dev;
	mhi_dev_ctxt->mhi_pm_state = MHI_PM_DISABLE;
	INIT_WORK(&mhi_dev_ctxt->process_m1_worker, process_m1_transition);
	INIT_WORK(&mhi_dev_ctxt->st_thread_worker, mhi_state_change_worker);
	INIT_WORK(&mhi_dev_ctxt->process_sys_err_worker, mhi_sys_err_worker);
	mutex_init(&mhi_dev_ctxt->pm_lock);
	rwlock_init(&mhi_dev_ctxt->pm_xfer_lock);
	spin_lock_init(&mhi_dev_ctxt->dev_wake_lock);
	init_completion(&mhi_dev_ctxt->cmd_complete);
	mhi_dev_ctxt->flags.link_up = 1;
	core_info = &mhi_dev_ctxt->core;
	core_info->manufact_id = pci_dev->vendor;
	core_info->pci_master = false;

	/* Go thru resources and set up */
	for (i = 0; i < ARRAY_SIZE(mhi_device->resources); i++) {
		const struct resource *res = &mhi_device->resources[i];

		switch (resource_type(res)) {
		case IORESOURCE_MEM:
			/* bus master already mapped it */
			core_info->bar0_base = (void __iomem *)res->start;
			core_info->bar0_end = (void __iomem *)res->end;
			mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
				"bar mapped to:0x%llx - 0x%llx (virtual)\n",
				res->start, res->end);
			break;
		case IORESOURCE_IRQ:
			core_info->irq_base = (u32)res->start;
			core_info->max_nr_msis = (u32)resource_size(res);
			mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
				"irq mapped to: %u size:%u\n",
				core_info->irq_base,
				core_info->max_nr_msis);
			break;
		};
	}

	if (!core_info->bar0_base || !core_info->irq_base)
		return -EINVAL;
	if (mhi_device->support_rddm && !mhi_device->rddm_size)
		return -EINVAL;

	mhi_dev_ctxt->bus_master_rt_get = mhi_device->pm_runtime_get;
	mhi_dev_ctxt->bus_master_rt_put = mhi_device->pm_runtime_put_noidle;
	mhi_dev_ctxt->status_cb = mhi_device->status_cb;
	mhi_dev_ctxt->priv_data = user_data;
	if (!mhi_dev_ctxt->bus_master_rt_get || !mhi_dev_ctxt->bus_master_rt_put
	    || !mhi_dev_ctxt->status_cb)
		return -EINVAL;

	mhi_get_iommu_mapping(mhi_dev_ctxt, &pci_dev->dev);
	ret = mhi_init_smmu(mhi_dev_ctxt);
	if (ret) {
		mhi_log(mhi_dev_ctxt, MHI_MSG_ERROR,
			"Failed to initialize smmu, ret:%d\n", ret);
		return ret;
	}

	ret = mhi_ctxt_init(mhi_dev_ctxt);
	if (ret) {
		mhi_log(mhi_dev_ctxt, MHI_MSG_ERROR,
			"MHI Initialization failed, ret %d\n", ret);
		return ret;
	}
	mhi_init_debugfs(mhi_dev_ctxt);

	/* setup shadow pm functions */
	mhi_dev_ctxt->assert_wake = mhi_assert_device_wake;
	mhi_dev_ctxt->deassert_wake = mhi_deassert_device_wake;
	mhi_dev_ctxt->runtime_get = mhi_slave_mode_runtime_get;
	mhi_dev_ctxt->runtime_put = mhi_slave_mode_runtime_put;
	mhi_device->mhi_dev_ctxt = mhi_dev_ctxt;

	/* Store RDDM information */
	if (mhi_device->support_rddm) {
		mhi_dev_ctxt->bhi_ctxt.support_rddm = true;
		mhi_dev_ctxt->bhi_ctxt.rddm_size = mhi_device->rddm_size;

		mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
			"Device support rddm of size:0x%lx bytes\n",
			mhi_dev_ctxt->bhi_ctxt.rddm_size);
	}

	/* get device version */
	mutex_lock(&mhi_dev_ctxt->pm_lock);
	write_lock_irq(&mhi_dev_ctxt->pm_xfer_lock);
	mhi_dev_ctxt->mhi_pm_state = MHI_PM_POR;
	reg = mhi_reg_read(mhi_dev_ctxt->core.bar0_base, BHIOFF);
	if (unlikely(reg == U32_MAX)) {
		mhi_log(mhi_dev_ctxt, MHI_MSG_ERROR,
			"Invalid BHI offset:0x%x\n", reg);
		write_unlock_irq(&mhi_dev_ctxt->pm_xfer_lock);
		mutex_unlock(&mhi_dev_ctxt->pm_lock);
		return -EIO;
	}
	mhi_dev_ctxt->bhi_ctxt.bhi_base = mhi_dev_ctxt->core.bar0_base + reg;
	reg = mhi_reg_read(mhi_dev_ctxt->bhi_ctxt.bhi_base, BHIE_MSMSOCID_OFFS);
	write_unlock_irq(&mhi_dev_ctxt->pm_xfer_lock);
	mhi_device->version = *((struct __packed soc_id *)&reg);
	mutex_unlock(&mhi_dev_ctxt->pm_lock);
	mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
		"Registered dev:0x%04x version: [0x%x, 0x%x, 0x%x, 0x%x]\n",
		core->dev_id, mhi_device->version.minor_version,
		mhi_device->version.major_version,
		mhi_device->version.device_number,
		mhi_device->version.family_number);

	/* notify all the registered clients we probed */
	for (i = 0; i < MHI_MAX_CHANNELS; i++) {
		struct mhi_client_handle *client_handle =
			mhi_dev_ctxt->client_handle_list[i];

		if (!client_handle)
			continue;
		client_handle->dev_id = core->dev_id;
		mhi_notify_client(client_handle, MHI_CB_MHI_PROBED);
	}

	mhi_log(mhi_dev_ctxt, MHI_MSG_INFO, "Exit success\n");

	return 0;
}
EXPORT_SYMBOL(mhi_register_device);

#endif

static int mhi_init_dev_ctxt(struct mhi_device *mhi_dev)
{
	struct mhi_ctxt *mhi_ctxt = &mhi_dev->mhi_ctxt;
	struct mhi_chan *mhi_chan;
	struct mhi_event *mhi_event;
	struct mhi_ring *cmd_ring;
	struct __packed mhi_chan_ctxt *chan_ctxt;
	struct __packed mhi_event_ctxt *er_ctxt;
	struct __packed mhi_cmd_ctxt *cmd_ctxt;
	int i, ret;

	/* set up the channel context */
	mhi_ctxt->chan_ctxt = mhi_alloc_coherent(mhi_dev,
				sizeof(*mhi_ctxt->chan_ctxt) * MHI_MAX_CHANNELS,
				&mhi_ctxt->chan_addr, GFP_KERNEL);
	if (!mhi_ctxt->chan_ctxt)
		return -ENOMEM;
	mhi_chan = mhi_dev->mhi_chan;
	chan_ctxt = mhi_ctxt->chan_ctxt;
	for (i = 0; i < MHI_MAX_CHANNELS; i++, chan_ctxt++, mhi_chan++) {
		chan_ctxt->chstate = MHI_CHAN_STATE_DISABLED;
		chan_ctxt->brstmode = mhi_chan->db_mode.brstmode;
		chan_ctxt->pollcfg = mhi_chan->db_mode.pollcfg;
		chan_ctxt->chtype = mhi_chan->dir;
		chan_ctxt->erindex = mhi_chan->er_index;

		mhi_chan->ch_state = MHI_CHAN_STATE_DISABLED;
		mhi_chan->db_mode.db_mode = 1;
		mhi_chan->db_mode.process_db =
			(chan_ctxt->brstmode == MHI_BRSTMODE_ENABLE) ?
			mhi_process_db_brstmode : mhi_process_db_brstmode_disable;
		mhi_chan->tre_ring.db_addr = &chan_ctxt->wp;
		mutex_init(&mhi_chan->mutex);
		rwlock_init(&mhi_chan->lock);
		init_completion(&mhi_chan->completion);
	}

	/* setup event context */
	mhi_ctxt->er_ctxt = mhi_alloc_coherent(mhi_dev,
				sizeof(*mhi_ctxt->er_ctxt) * mhi_dev->ev_rings,
				&mhi_ctxt->er_addr, GFP_KERNEL);
	if (!mhi_ctxt->er_ctxt)
		goto error_ev_ctxt;

	er_ctxt = mhi_ctxt->er_ctxt;
	mhi_event = mhi_dev->mhi_event;
	for (i = 0; i < mhi_dev->ev_rings; i++, er_ctxt++, mhi_event++) {
		struct mhi_ring *ring = &mhi_event->ring;

		er_ctxt->intmodc = 0;
		er_ctxt->intmodt = mhi_event->intmod;
		er_ctxt->ertype = MHI_EVENT_RING_TYPE_VALID;
		er_ctxt->msivec = mhi_event->msi;

		mhi_event->db_mode.db_mode = true;
		mhi_event->db_mode.process_db =
			(mhi_event->db_mode.brstmode == MHI_BRSTMODE_ENABLE) ?
			mhi_process_db_brstmode : mhi_process_db_brstmode_disable;
		mhi_event->mhi_dev = mhi_dev;

		/* allocate mem for all event rings */
		ring->el_size = sizeof(struct __packed mhi_tre);
		ring->len = ring->el_size * ring->elements;
		ret = mhi_alloc_aligned_ring(mhi_dev, ring, ring->len);
		if (ret)
			goto error_alloc_er;

		ring->rp = ring->wp = ring->base;
		er_ctxt->rbase = ring->phys_base;
		er_ctxt->rp = er_ctxt->wp = er_ctxt->rbase;
		er_ctxt->rlen = ring->len;
		ring->ctxt_wp = &er_ctxt->wp;

		mutex_init(&mhi_event->mutex);
		spin_lock_init(&mhi_event->lock);
		tasklet_init(&mhi_event->task, mhi_ev_task,
			     (unsigned long)mhi_event);
		INIT_WORK(&mhi_event->worker, process_event_ring);
	}

	/* setup cmd context */
	mhi_ctxt->cmd_ctxt = mhi_alloc_coherent(mhi_dev,
				sizeof(*mhi_ctxt->cmd_ctxt) * NR_OF_CMD_RINGS,
				&mhi_ctxt->cmd_addr, GFP_KERNEL);
	if (!mhi_ctxt->cmd_ctxt)
		goto error_alloc_er;

	cmd_ring = mhi_dev->mhi_cmd;
	cmd_ctxt = mhi_ctxt->cmd_ctxt;
	for (i = 0; i < NR_OF_CMD_RINGS; i++, cmd_ring++, cmd_ctxt++) {
		/* allocate mem for all event rings */
		cmd_ring->el_size = sizeof(struct __packed mhi_tre);
		cmd_ring->elements = CMD_EL_PER_RING;
		cmd_ring->len = cmd_ring->el_size * cmd_ring->elements;
		ret = mhi_alloc_aligned_ring(mhi_dev, cmd_ring, cmd_ring->len);
		if (ret)
			goto error_alloc_cmd;
		cmd_ring->rp = cmd_ring->wp = cmd_ring->base;
		cmd_ctxt->rbase = cmd_ring->phys_base;
		cmd_ctxt->rp = cmd_ctxt->wp = cmd_ctxt->rbase;
		cmd_ctxt->rlen = cmd_ring->len;
		cmd_ring->ctxt_wp = &cmd_ctxt->wp;
	}

	spin_lock_init(&mhi_dev->cmd_lock);

	/* allocate state transition ring */
	mhi_dev->work_ring.el_size = sizeof(enum STATE_TRANSITION);
	mhi_dev->work_ring.elements = SZ_1K;
	mhi_dev->work_ring.len = mhi_dev->work_ring.elements *
		mhi_dev->work_ring.el_size;
	mhi_dev->work_ring.base = vmalloc(mhi_dev->work_ring.len);
	if (!mhi_dev->work_ring.base)
		goto error_alloc_cmd;

	mhi_dev->work_ring.rp = mhi_dev->work_ring.wp = mhi_dev->work_ring.base;

	return 0;

error_alloc_cmd:
	for (i = i - 1;i >= 0; i--) {
		struct mhi_ring *ring = &mhi_dev->mhi_cmd[i];

		mhi_free_coherent(mhi_dev, ring->alloc_size, ring->pre_aligned,
				  ring->dma_handle);
	}
	i = mhi_dev->ev_rings;
error_alloc_er:
	for (i = i - 1; i >= 0; i--) {
		struct mhi_ring *ring = &mhi_event[i].ring;

		mhi_free_coherent(mhi_dev, ring->alloc_size, ring->pre_aligned,
				  ring->dma_handle);
	}
error_ev_ctxt:
	mhi_free_coherent(mhi_dev,
			  sizeof(*mhi_ctxt->chan_ctxt) * MHI_MAX_CHANNELS,
			  mhi_ctxt->chan_ctxt, mhi_ctxt->chan_addr);
	return -ENOMEM;
}

int mhi_dma_mask(struct mhi_device *mhi_dev)
{
	int mask = 0;
	u32 config = mhi_dev->smmu_cfg;

	if (mhi_dev->pci_master) {
		/* Not using iova space, set mask to max */
		if (!config)
			mask = 64;
		else {
			unsigned long size = mhi_dev->iova_end + 1;

			/* S1 bypass, iova not used, set to max */
			mask = (config & MHI_SMMU_S1_BYPASS) ?
				64 : find_last_bit(&size, 64);
		}
	} else {
		/*
		 * if MHI not bus master, only time we set dma mask is if iova
		 * not configured by bus master
		 */
		mask = 64;
	}

	mhi_log(mhi_dev, MHI_MSG_INFO, "Set dma mask to %d\n", mask);

	return dma_set_mask_and_coherent(mhi_dev->dev, DMA_BIT_MASK(mask));
}

/* default iommu configuration, for arch specific set MHI_IOMMU_INIT */
int mhi_default_iommu_init( struct mhi_device *mhi_dev)
{
	mhi_dev->dev = &mhi_dev->pci_dev->dev;
	return mhi_dma_mask(mhi_dev);
}

static int mhi_init_debugfs_mhi_states_open(struct inode *inode, struct file *fp)
{
	return single_open(fp, mhi_debugfs_mhi_states_show,
			   inode->i_private);
}

static int mhi_init_debugfs_mhi_event_open(struct inode *inode, struct file *fp)
{
	return single_open(fp, mhi_debugfs_mhi_event_show,
			   inode->i_private);
}

static int mhi_init_debugfs_mhi_chan_open(struct inode *inode, struct file *fp)
{
	return single_open(fp, mhi_debugfs_mhi_chan_show,
			   inode->i_private);
}

static const struct file_operations debugfs_state_ops = {
	.open = mhi_init_debugfs_mhi_states_open,
	.release = single_release,
	.read = seq_read,
};

static const struct file_operations debugfs_ev_ops = {
	.open = mhi_init_debugfs_mhi_event_open,
	.release = single_release,
	.read = seq_read,
};

static const struct file_operations debugfs_chan_ops = {
	.open = mhi_init_debugfs_mhi_chan_open,
	.release = single_release,
	.read = seq_read,
};

static int mhi_init_mhi_device(struct mhi_device *mhi_dev)
{
	int ret;
	int i;
	u32 bhi_offset;
	const int PCI_BAR_NUM = 0;

	/* initialize device locks and grab it */
	mutex_init(&mhi_dev->mutex);
	spin_lock_init(&mhi_dev->wake_lock);
	rwlock_init(&mhi_dev->pm_lock);
	spin_lock_init(&mhi_dev->work_lock);
	atomic_set(&mhi_dev->dev_wake, 0);
	atomic_set(&mhi_dev->pending_acks, 0);
	atomic_set(&mhi_dev->alloc_size, 0);

	mutex_lock(&mhi_dev->mutex);

	/* setup smmu configuration */
	ret = MHI_IOMMU_INIT(mhi_dev);
	if (ret) {
		mhi_log(mhi_dev, MHI_MSG_ERROR, "Error with SMMU init\n");
		goto error_init;
	}

	/* setup pcie bus */
	if (mhi_dev->pci_master) {
		struct pci_dev *pci_dev = mhi_dev->pci_dev;
		resource_size_t start, len;
		unsigned long msi_req;

		ret = pci_assign_resource(pci_dev, PCI_BAR_NUM);
		if (unlikely(ret)) {
			mhi_log(mhi_dev, MHI_MSG_ERROR,
				"Error with pci_assign_resource ret:%d\n", ret);
			goto error_init;
		}
		ret = pci_enable_device(pci_dev);
		if (unlikely(ret)) {
			mhi_log(mhi_dev, MHI_MSG_ERROR,
				"Error with pci_enable_device ret:%d\n", ret);
			goto error_init;
		}
		ret = pci_request_region(pci_dev, PCI_BAR_NUM, "mhi");
		if (unlikely(ret)) {
			mhi_log(mhi_dev, MHI_MSG_ERROR,
				"Error with pci request region ret:%d\n", ret);
		}

		pci_set_master(pci_dev);

		start = pci_resource_start(pci_dev, PCI_BAR_NUM);
		len = pci_resource_len(pci_dev, PCI_BAR_NUM);
		mhi_dev->regs = ioremap_nocache(start, len);
		if (unlikely(!mhi_dev->regs)) {
			mhi_log(mhi_dev, MHI_MSG_ERROR, "Error with ioremap\n");
			goto error_init;
		}

		device_disable_async_suspend(&pci_dev->dev);

		/* # of MSI requested must be power of 2 */
		msi_req = 1 << find_last_bit((ulong *)&mhi_dev->ev_rings, 32);
		if (msi_req < mhi_dev->ev_rings)
			msi_req <<= 1;
		ret = pci_enable_msi_range(pci_dev, msi_req, msi_req);

		if (IS_ERR_VALUE((ulong)ret) || (ret < mhi_dev->ev_rings)) {
			mhi_log(mhi_dev, MHI_MSG_ERROR,
				"Failed to enable MSI ret:%d\n", ret);
			goto error_init;
		}

		mhi_dev->irq = pci_dev->irq;
		dev_set_drvdata(&pci_dev->dev, mhi_dev);
		mhi_init_pm_sysfs(&pci_dev->dev);

		mhi_log(mhi_dev, MHI_MSG_INFO,
			"msi_req:%u returned:%u ev_rings:%u\n",
			(u32)msi_req, (u32)ret, (u32)mhi_dev->ev_rings);

		/* configure runtime pm */
		pm_runtime_set_autosuspend_delay(&pci_dev->dev,
						MHI_RPM_AUTOSUSPEND_TMR_VAL_MS);
		pm_runtime_use_autosuspend(&pci_dev->dev);
		pm_suspend_ignore_children(&pci_dev->dev, true);


		/*
		 * pci framework will increment usage count (twice) before
		 * calling local device driver probe function.
		 * 1st pci.c pci_pm_init() calls pm_runtime_forbid
		 * 2nd pci-driver.c local_pci_probe calls pm_runtime_get_sync
		 * Framework expect pci device driver to call
		 * pm_runtime_put_noidle to decrement usage count after
		 * successful probe and and call pm_runtime_allow to enable
		 * runtime suspend. MHI will allow runtime after entering AMSS
		 * state.
		 */
		pm_runtime_mark_last_busy(&pci_dev->dev);
		pm_runtime_put_noidle(&pci_dev->dev);
	}

	ret = mhi_init_dev_ctxt(mhi_dev);
	if (ret) {
		mhi_log(mhi_dev, MHI_MSG_ERROR, "Failed to setup dev ctxt\n");
		goto error_init;
	}

	mhi_dev->pm_state = MHI_PM_DISABLE;
	INIT_WORK(&mhi_dev->m1_worker, process_m1_transition);
	INIT_WORK(&mhi_dev->st_worker, mhi_state_change_worker);
	INIT_WORK(&mhi_dev->sys_err_worker, mhi_sys_err_worker);
	INIT_WORK(&mhi_dev->fw_load_worker, bhi_load_worker);
	init_completion(&mhi_dev->completion);
	init_waitqueue_head(&mhi_dev->state_event);

	/* setup isr handlers */
	for (i = 0; i < mhi_dev->ev_rings; i++) {
		struct mhi_event *mhi_event = &mhi_dev->mhi_event[i];

		ret = request_irq(mhi_dev->irq + mhi_event->msi, mhi_msi_handlr,
				  IRQF_SHARED, "mhi", mhi_event);
		if (ret) {
			mhi_log(mhi_dev, MHI_MSG_ERROR,
				"Error requesting offset:%d irq:%d ret:%d\n",
				mhi_event->msi, mhi_dev->irq + mhi_event->msi,
				ret);
			goto error_init;
		}
	}

	ret = mhi_arch_post_init(mhi_dev);

	/* setup debug fs for channel context and state context */
	if (mhi_device_drv.dentry) {
		char node[32];

		snprintf(node, sizeof(node), "%04x_%02u:%02u.%02u",
			 mhi_dev->dev_id, mhi_dev->domain, mhi_dev->bus,
			 mhi_dev->slot);
		mhi_dev->dentry = debugfs_create_dir(node,
						     mhi_device_drv.dentry);
		if (!IS_ERR_OR_NULL(mhi_dev->dentry)) {
			debugfs_create_file("states", 0444, mhi_dev->dentry,
					    mhi_dev, &debugfs_state_ops);
			debugfs_create_file("events", 0444, mhi_dev->dentry,
					    mhi_dev, &debugfs_ev_ops);
			debugfs_create_file("chan", 0444, mhi_dev->dentry,
					    mhi_dev, &debugfs_chan_ops);
		}
	}

	/* setup shadow functions for power management */
	mhi_dev->assert_wake = mhi_assert_device_wake;
	mhi_dev->deassert_wake = mhi_deassert_device_wake;

	if (mhi_dev->pci_master) {
		mhi_dev->runtime_get = mhi_master_mode_runtime_get;
		mhi_dev->runtime_put = mhi_master_mode_runtime_put;
	} else {
		mhi_dev->runtime_get = mhi_slave_mode_runtime_get;
		mhi_dev->runtime_put = mhi_slave_mode_runtime_put;
	}

	/* setup bhi offset */
	write_lock_irq(&mhi_dev->pm_lock);
	bhi_offset = mhi_read_reg(mhi_dev, mhi_dev->regs, BHIOFF);
	write_unlock_irq(&mhi_dev->pm_lock);

	if (unlikely(PCI_INVALID_READ(bhi_offset))) {
		ret = -EIO;
		mhi_log(mhi_dev, MHI_MSG_ERROR, "Error read reg BHIOFF\n");
	}
	mhi_dev->bhi = mhi_dev->regs + bhi_offset;
	mhi_dev->pm_state = MHI_PM_POR; //FIXME: see if I need it
error_init:
	mutex_unlock(&mhi_dev->mutex);
	return ret;
}

#define MHI_PCIE_VENDOR_ID 0x17CB
#define MHI_PCIE_DEBUG_ID 0xffff

static struct pci_device_id mhi_pcie_device_id[] = {
		{ PCI_DEVICE(MHI_PCIE_VENDOR_ID, 0x0300)},
		{ PCI_DEVICE(MHI_PCIE_VENDOR_ID, 0x0301)},
		{ PCI_DEVICE(MHI_PCIE_VENDOR_ID, 0x0302)},
		{ PCI_DEVICE(MHI_PCIE_VENDOR_ID, 0x0303)},
		{ PCI_DEVICE(MHI_PCIE_VENDOR_ID, 0x0304)},
		{ PCI_DEVICE(MHI_PCIE_VENDOR_ID, 0x0305)},
		{ PCI_DEVICE(MHI_PCIE_VENDOR_ID, MHI_PCIE_DEBUG_ID)},
		{ 0 },
};

static int mhi_pci_probe(struct pci_dev *pci_dev,
			 const struct pci_device_id *mhi_device_id)
{
	int ret, i;
	struct mhi_device *mhi_dev = NULL, *itr;
	u32 domain = pci_domain_nr(pci_dev->bus);
	u32 bus = pci_dev->bus->number;
	u32 dev_id = pci_dev->device;
	u32 slot = PCI_SLOT(pci_dev->devfn);
	enum STATE_TRANSITION transition;
	enum MHI_EXEC_ENV dev_exec_env;
	struct mhi_chan *mhi_chan;

	/* Find correct device context based on bdf & dev_id */
	mutex_lock(&mhi_device_drv.lock);
	list_for_each_entry(itr, &mhi_device_drv.head, node) {
		if (itr->domain == domain && itr->bus == bus &&
		    (itr->dev_id == PCI_ANY_ID || (itr->dev_id == dev_id)) &&
		    itr->slot == slot) {
			/* change default dev_id to actual dev_id */
			itr->dev_id = dev_id;
			mhi_dev= itr;
			break;
		}
	}
	mutex_unlock(&mhi_device_drv.lock);
	if (!mhi_dev)
		return -EPROBE_DEFER;

	mhi_dev->pci_dev = pci_dev;
	mhi_dev->pci_master = true;
	ret = mhi_arch_pcie_init(mhi_dev);
	if (ret)
		return ret;

	mhi_log(mhi_dev, MHI_MSG_INFO,
		"Processing Domain:%02u Bus:%04u dev:0x%04x slot:%04u\n",
		domain, bus, dev_id, slot);
	ret = mhi_init_mhi_device(mhi_dev);
	if (ret) {
		mhi_log(mhi_dev, MHI_MSG_ERROR, "Error with init mhi device\n");
		return ret;
	}

	mutex_lock(&mhi_dev->mutex);

	/* notify all registered clients we probed */
	mhi_chan = mhi_dev->mhi_chan;
	for (i = 0; i < MHI_MAX_CHANNELS; i++, mhi_chan++) {
		if (!mhi_chan->cldata)
			continue;
		mhi_chan->cldata->client_handle.dev_id = mhi_dev->dev_id;
		mhi_notify_client(mhi_dev, mhi_chan, MHI_CB_MHI_PROBED);
	}

	write_lock_irq(&mhi_dev->pm_lock);
	mhi_dev->dev_exec_env = MHI_EXEC_INVALID;
	dev_exec_env = mhi_get_exec_env(mhi_dev);
	write_unlock_irq(&mhi_dev->pm_lock);

	if (dev_exec_env != MHI_EXEC_ENV_PBL &&
	    dev_exec_env != MHI_EXEC_ENV_AMSS) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Unsupported exec during boot, cur:%s\n",
			TO_MHI_EXEC_STR(dev_exec_env));
		ret = -EIO;
		goto error_probe;
	}

	/* start background thread to load firmware */
	if (dev_exec_env == MHI_EXEC_ENV_PBL)
		schedule_work(&mhi_dev->fw_load_worker);

	/* Start initial state transition */
	transition = (dev_exec_env == MHI_EXEC_ENV_PBL) ?
		STATE_TRANSITION_BHI : STATE_TRANSITION_AMSS;
	mhi_queue_state_transition(mhi_dev, transition);

	/*
	 * Keep the MHI state in Active (M0) state until AMSS because EP
	 * would error fatal if we try to enter M1 before entering
	 * AMSS state.
	 */
	read_lock_irq(&mhi_dev->pm_lock);
	mhi_assert_device_wake(mhi_dev, false);
	read_unlock_irq(&mhi_dev->pm_lock);

	mutex_unlock(&mhi_dev->mutex);

	return 0;

error_probe:
	mutex_unlock(&mhi_dev->mutex);
	return ret;
}

static const struct dev_pm_ops pm_ops = {
	SET_RUNTIME_PM_OPS(mhi_runtime_suspend,
			   mhi_runtime_resume,
			   mhi_runtime_idle)
	SET_SYSTEM_SLEEP_PM_OPS(mhi_system_suspend, mhi_system_resume)
};

static struct pci_driver mhi_pcie_driver = {
	.name = "mhi_pcie_drv",
	.id_table = mhi_pcie_device_id,
	.probe = mhi_pci_probe,
	.driver = {
		.pm = &pm_ops
	}
};

static int mhi_parse_dt(struct mhi_device *mhi_dev, struct device_node *of_node)
{
	int ret, num, i;
	struct mhi_event *mhi_event;
	u64 addr_win[2];
	struct {
		u32 chan_cfg[8];
	} *chan_cfg = NULL;
	struct {
		u32 ev_cfg[7];
	} *ev_cfg = NULL;

	/* Get PCIe bus topology for this node */
	ret = of_property_read_u32(of_node, "pci,pci-dev-id",
				   &mhi_dev->dev_id);
	if (ret)
		mhi_dev->dev_id = PCI_ANY_ID;
	ret = of_property_read_u32(of_node, "pci,pci-domain", &mhi_dev->domain);
	if (ret)
		return ret;
	ret = of_property_read_u32(of_node, "pci,pci-bus", &mhi_dev->bus);
	if (ret)
		return ret;
	ret = of_property_read_u32(of_node, "pci,pci-slot", &mhi_dev->slot);
	if (ret)
		return ret;

	/* firmware image information */
	mhi_dev->dl_fw = of_property_read_bool(of_node, "mhi,dl-fw");
	if (mhi_dev->dl_fw) {
		ret = of_property_read_string(of_node, "mhi,fw-image",
					      &mhi_dev->fw_image);
		if (ret)
			return ret;

		ret = of_property_read_u32(of_node, "mhi,fw-req-timeout",
				   &mhi_dev->fw_timeout);
		if (ret)
			return ret;
	}

	ret = of_property_count_elems_of_size(of_node, "mhi,addr-win",
					      sizeof(addr_win));
	if (ret != 1)
		return ret;
	ret = of_property_read_u64_array(of_node, "mhi,addr-win", addr_win, 2);
	if (ret)
		return ret;
	mhi_dev->iova_start = addr_win[0];
	mhi_dev->iova_end = addr_win[1];

	/* read channel configuration */
	num =  of_property_count_elems_of_size(of_node, "mhi,chan-cfg",
					       sizeof(*chan_cfg));
	if (num <= 0)
		return -EINVAL;
	if (of_property_count_strings(of_node, "mhi,chan-names") != num)
		return -EINVAL;

	chan_cfg = kmalloc_array(num, sizeof(*chan_cfg), GFP_KERNEL);
	if (!chan_cfg)
		return -ENOMEM;
	ret = of_property_read_u32_array(of_node, "mhi,chan-cfg", (u32 *)chan_cfg,
					 num * sizeof(*chan_cfg) / sizeof(u32));
	if (ret)
		goto error_chan_cfg;
	for (i = 0; i < num; i++) {
		struct mhi_chan *mhi_chan;
		int chan = chan_cfg[i].chan_cfg[0];

		if (chan >= MHI_MAX_CHANNELS)
			goto error_chan_cfg;
		mhi_chan = &mhi_dev->mhi_chan[chan];
		mhi_chan->chan = chan;
		mhi_chan->buf_ring.elements = chan_cfg[i].chan_cfg[1];
		mhi_chan->tre_ring.elements = chan_cfg[i].chan_cfg[1];
		mhi_chan->er_index = chan_cfg[i].chan_cfg[2];
		mhi_chan->dir = chan_cfg[i].chan_cfg[3];
		mhi_chan->db_mode.brstmode = chan_cfg[i].chan_cfg[4];
		mhi_chan->db_mode.pollcfg = chan_cfg[i].chan_cfg[5];
		mhi_chan->exec_env = chan_cfg[i].chan_cfg[6];
		switch (chan_cfg[i].chan_cfg[7]) {
		case MHI_XFER_BUFFER:
			mhi_chan->gen_tre = mhi_queue_buf_tre;
			mhi_chan->queue_xfer = mhi_queue_buffer;
			break;
		case MHI_XFER_SKB:
			mhi_chan->queue_xfer = mhi_queue_skb;
			break;
		case MHI_XFER_SCATTERLIST:
			mhi_chan->gen_tre = mhi_queue_buf_tre;
			mhi_chan->queue_xfer = mhi_queue_scatterlist;
			break;
		default:
			ret = -EINVAL;
			goto error_chan_cfg;
		}
		ret = of_property_read_string_index(of_node,
					"mhi,chan-names", i, &mhi_chan->name);
		if (ret)
			goto error_chan_cfg;
		mhi_chan->supported = true;
	}
	kfree(chan_cfg);

	/* read event configuration */
	num = of_property_count_elems_of_size(of_node, "mhi,ev-cfg",
					      sizeof(*ev_cfg));
	if (num <= 0)
		return -EINVAL;
	ev_cfg = kmalloc_array(num, sizeof(*ev_cfg), GFP_KERNEL);
	if (!ev_cfg)
		return -ENOMEM;
	ret = of_property_read_u32_array(of_node, "mhi,ev-cfg", (u32 *)ev_cfg,
					 num * sizeof(*ev_cfg) / sizeof(u32));
	if (ret)
		goto error_ev_cfg;

	mhi_dev->ev_rings = num;
	mhi_dev->mhi_event = kcalloc(num, sizeof(*mhi_dev->mhi_event),
				     GFP_KERNEL);
	if (!mhi_dev->mhi_event)
		goto error_ev_cfg;

	mhi_event = mhi_dev->mhi_event;
	for (i = 0; i < mhi_dev->ev_rings; i++, mhi_event++) {
		u32 mask, chan;

		mhi_event->index = i;
		mhi_event->ring.elements = ev_cfg[i].ev_cfg[0];
		mhi_event->intmod = ev_cfg[i].ev_cfg[1];
		mhi_event->msi = ev_cfg[i].ev_cfg[2];
		chan = ev_cfg[i].ev_cfg[3];
		if (chan)
			mhi_event->chan = &mhi_dev->mhi_chan[chan];
		mhi_event->priority = ev_cfg[i].ev_cfg[4];
		mhi_event->db_mode.brstmode = ev_cfg[i].ev_cfg[5];
		mask = ev_cfg[i].ev_cfg[6];
		if (mask & MHI_EV_CFG_HW_EV) {
			mhi_dev->hw_ev_rings++;
			mhi_event->class = MHI_HW_RING;
		} else {
			mhi_dev->sw_ev_rings++;
			mhi_event->class = MHI_SW_RING;
		}
		mhi_event->client_manage = !!(mask & MHI_EV_CFG_CL_MANAGE);
	}
	kfree(ev_cfg);
	ev_cfg = NULL;

	ret = of_property_read_u32(of_node, "mhi,smmu-cfg", &mhi_dev->smmu_cfg);
	if (ret)
		goto error_ev_cfg;

	ret = of_property_read_u32(of_node, "mhi,poll-timeout",
				   &mhi_dev->poll_timeout);
	if (ret)
		goto error_ev_cfg;

	return 0;

error_chan_cfg:
	kfree(chan_cfg);

error_ev_cfg:
	if (ev_cfg)
		kfree(ev_cfg);
	if (mhi_dev->mhi_event)
		kfree(mhi_dev->mhi_event);

	return -EINVAL;
}

static int mhi_plat_probe(struct platform_device *pdev)
{
	int ret;
	struct mhi_device *mhi_dev;
	struct device_node *of_node = pdev->dev.of_node;

	if (of_node == NULL)
		return -ENODEV;

	pdev->id = of_alias_get_id(of_node, "mhi");
	if (pdev->id < 0)
		return -ENODEV;

	mhi_dev = devm_kzalloc(&pdev->dev, sizeof(*mhi_dev), GFP_KERNEL);
	if (!mhi_dev)
		return -ENOMEM;

	ret = mhi_parse_dt(mhi_dev, of_node);
	if (ret)
		return ret;

	mhi_dev->pdev = pdev;
	ret = mhi_arch_platform_init(mhi_dev);
	if (ret)
		return ret;

	mutex_lock(&mhi_device_drv.lock);
	list_add_tail(&mhi_dev->node, &mhi_device_drv.head);
	mutex_unlock(&mhi_device_drv.lock);

	return 0;
}

static const struct of_device_id mhi_plat_match[] = {
	{ .compatible = "qcom,mhi" },
	{},
};

static struct platform_driver mhi_plat_driver = {
	.probe	= mhi_plat_probe,
	.driver	= {
		.name		= "mhi",
		.owner		= THIS_MODULE,
		.of_match_table	= mhi_plat_match,
	},
};

int mhi_init_debugfs_debug_show(struct seq_file *m, void *d)
{
	seq_printf(m, "Enable debug mode to debug  external soc\n");
	seq_printf(m,
		   "Usage:  echo 'devid,fw_timeout,timeout,domain,smmu_cfg' > debug_mode\n");
	seq_printf(m, "No spaces between parameters\n");
	seq_printf(m, "\t1.  devid : 0 or pci device id to register\n");
	seq_printf(m, "\t2.  fw_timeout : Timout in ms to search for firmware\n");
	seq_printf(m, "\t3.  timeout: mhi cmd/state transition timeout\n");
	seq_printf(m, "\t4.  domain: Rootcomplex\n");
	seq_printf(m, "\t5.  smmu_cfg: smmu configuration mask:\n");
	seq_printf(m, "\t\t- BIT0: ATTACH\n");
	seq_printf(m, "\t\t- BIT1: S1 BYPASS\n");
	seq_printf(m, "\t\t-BIT2: FAST_MAP\n");
	seq_printf(m, "\t\t-BIT3: ATOMIC\n");
	seq_printf(m, "\t\t-BIT4: GEOMETRY\n");
	seq_printf(m, "\t\t-BIT5: FORCE_COHERENT\n");
	seq_printf(m, "\tAll timeout are in ms, enter 0 to keep default\n");
	seq_printf(m, "Examples inputs: '0x307,10000,1000'\n");
	seq_printf(m, "\techo '0,10000,1000'\n");
	seq_printf(m, "\techo '0x307,1000,1000,0,0x3d'\n");
	seq_printf(m, "firmware image name will be changed to debug.mbn\n");

	return 0;
}

static int mhi_init_debugfs_debug_open(struct inode *node, struct file *file)
{
	return single_open(file, mhi_init_debugfs_debug_show, NULL);
}

static ssize_t mhi_init_debugfs_debug_write(struct file *fp,
					    const char __user *ubuf,
					    size_t count,
					    loff_t *pos)
{
	char *buf = kmalloc(count + 1, GFP_KERNEL);
	/*#,devid,fw_timeout,timout,domain,smmu-cfg*/
	int args[6] = {0};
	static const char const *dbf_fw = "debug.mbn";
	int ret;
	struct mhi_device *mhi_dev = NULL, *itr;
	struct pci_device_id *id;

	if (!buf)
		return -ENOMEM;

	ret = copy_from_user(buf, ubuf, count);
	if (ret)
		goto error_write;
	buf[count] = 0;
	get_options(buf, ARRAY_SIZE(args), args);
	kfree(buf);

	/* Find correct device context based on bdf & dev_id */
	mutex_lock(&mhi_device_drv.lock);
	list_for_each_entry(itr, &mhi_device_drv.head, node) {
		if (itr->dev_id == PCI_ANY_ID) {
			mhi_dev= itr;
			break;
		}
	}
	mutex_unlock(&mhi_device_drv.lock);

	if (!mhi_dev) {
		pr_info("%s: no free device found\n", __func__);
		return -EIO;
	}

	/* override default parameters */
	mhi_dev->fw_image = dbf_fw;
	if (args[0] >= 2 && args[2])
		mhi_dev->fw_timeout = args[2];

	if (args[0] >= 3 && args[3])
		mhi_dev->poll_timeout = args[3];

	if (args[0] >= 4 && args[4])
		mhi_dev->domain = args[4];

	if (args[5] >= 4 && args[5])
		mhi_dev->smmu_cfg = args[5];

	/* If it's a new device id register it */
	if (args[0] && args[1]) {
		/* find the debug_id  and overwrite it */
		for (id = mhi_pcie_device_id; id->vendor; id++)
			if (id->device == MHI_PCIE_DEBUG_ID) {
				id->device = args[1];
				pci_unregister_driver(&mhi_pcie_driver);
				ret = pci_register_driver(&mhi_pcie_driver);
			}
	}

	pr_info(
		"%s: ret:%d pcidev:0x%x fw_timeout:%u ms smm_cfg:%u poll_timeout:%u\n",
		__func__, ret, args[1], mhi_dev->fw_timeout, mhi_dev->smmu_cfg,
		mhi_dev->poll_timeout);
	return count;

error_write:
	kfree(buf);
	return ret;
}

static const struct file_operations debugfs_debug_ops = {
	.open = mhi_init_debugfs_debug_open,
	.release = single_release,
	.read = seq_read,
	.write = mhi_init_debugfs_debug_write,
};

static int __init mhi_init(void)
{
	int ret;

	mutex_init(&mhi_device_drv.lock);
	INIT_LIST_HEAD(&mhi_device_drv.head);

	ret = platform_driver_register(&mhi_plat_driver);
	if (ret) {
		pr_err("%s: Failed to probe platform ret %d\n", __func__, ret);
		return ret;
	}

	mhi_device_drv.dentry = debugfs_create_dir("mhi", NULL);
	ret = pci_register_driver(&mhi_pcie_driver);
	if (ret) {
		pr_err("%s: Failed to register pcie drv ret %d\n", __func__, ret);
		goto pci_error;
	}

	debugfs_create_file("debug_mode", 0444, mhi_device_drv.dentry,
			    NULL, &debugfs_debug_ops);

	return 0;

pci_error:
	if (!IS_ERR_OR_NULL(mhi_device_drv.dentry))
		debugfs_remove(mhi_device_drv.dentry);
	platform_driver_unregister(&mhi_plat_driver);
	return ret;
}

subsys_initcall(mhi_init);

MODULE_LICENSE("GPL v2");
MODULE_ALIAS("MHI_CORE");
MODULE_DESCRIPTION("MHI Host Driver");
