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
#include <linux/msm-bus.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/pm_runtime.h>
#include <linux/interrupt.h>
#include <linux/ipc_logging.h>
#include <soc/qcom/subsystem_restart.h>
#include <soc/qcom/subsystem_notif.h>
#include <linux/esoc_client.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/msm_pcie.h>
#include <asm/dma-iommu.h>
#include <linux/iommu.h>
#include <linux/dma-iommu.h>
#include <linux/dma-mapping.h>
#include <linux/termios.h>
#include "mhi.h"

#define MHI_IPC_LOG_PAGES (100)
#ifdef CONFIG_MSM_MHI_DEBUG
enum MHI_DEBUG_LEVEL  mhi_qcom_log_lvl = MHI_MSG_VERBOSE;
#else
enum MHI_DEBUG_LEVEL  mhi_qcom_log_lvl = MHI_MSG_ERROR;
#endif

module_param(mhi_qcom_log_lvl, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(mhi_qcom_log_lvl, "dbg lvl");

struct arch_info {
	struct mhi_device *mhi_dev;
	struct notifier_block notifier_block;
	struct esoc_desc *esoc_client;
	void *subsys_notif;
	u32 bus_client;
	struct msm_bus_scale_pdata *msm_bus_pdata;
	struct msm_pcie_register_event pcie_reg_event;
	struct pci_saved_state *pcie_state;
	struct pci_saved_state *ref_pci_state;
	int dtr_chan; /* dtr/dsr signaling chan */
	struct mhi_client_handle *dtr_handle;
};

struct __packed dtr_ctrl_msg {
	u32 preamble;
	u32 msg_id;
	u32 dest_id;
	u32 size;
	u32 msg;

};

#define CTRL_MAGIC (0x4C525443)
#define CTRL_MSG_DTR BIT(0)
#define CTRL_MSG_ID (0x10)

static void mhi_pci_link_state_cb(struct msm_pcie_notify *notify)
{
	struct mhi_device *mhi_dev = NULL;

	if (!notify || !notify->data) {
		pr_err("%s: incomplete handle received\n", __func__);
		return;
	}

	mhi_dev = notify->data;
	switch (notify->event) {
	case MSM_PCIE_EVENT_LINKDOWN:
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Received MSM_PCIE_EVENT_LINKDOWN\n");
		break;
	case MSM_PCIE_EVENT_LINKUP:
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Received MSM_PCIE_EVENT_LINKUP\n");
		break;
	case MSM_PCIE_EVENT_WAKEUP:
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Received MSM_PCIE_EVENT_WAKE\n");
		if (mhi_dev->dev_exec_env == MHI_EXEC_ENV_AMSS) {
			mhi_dev->runtime_get(mhi_dev);
			mhi_dev->runtime_put(mhi_dev);
		}
		break;
	default:
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Received bad link event\n");
		return;
	}
}

void mhi_dtr_xfer_cb(struct mhi_cb_info *cb_info)
{
	struct arch_info *arch_info = cb_info->user_data;
	struct mhi_device *mhi_dev = arch_info->mhi_dev;
	struct mhi_client_handle *handle = arch_info->dtr_handle;
	struct mhi_result *result;
	struct mhi_chan *dtr_chan;

	mhi_log(mhi_dev, MHI_MSG_VERBOSE, "cb reason: 0x%x\n",
		cb_info->cb_reason);

	switch (cb_info->cb_reason) {
	case MHI_CB_MHI_ENABLED:
		/*
		 * ignoring return status, we always check for channel
		 * status before data transfer
		 */
		mhi_open_channel(handle);
		break;
	case MHI_CB_XFER:
		dtr_chan = &mhi_dev->mhi_chan[arch_info->dtr_chan];
		result = &cb_info->result;
		if (!result->transaction_status)
			complete(&dtr_chan->completion);
		break;
	default:
		break;
	}
}

static long mhi_arch_tiocmset(struct mhi_device *mhi_dev, int chan, u32 tiocm)
{
	struct arch_info *arch_info = mhi_dev->arch_info;
	struct mhi_chan *dtr_chan = &mhi_dev->mhi_chan[arch_info->dtr_chan];
	struct mhi_chan *mhi_chan = &mhi_dev->mhi_chan[chan];
	struct __packed dtr_ctrl_msg *dtr_msg = NULL;
	long ret = 0;

	mutex_lock(&dtr_chan->mutex);
	if (mhi_chan->ch_state != MHI_CHAN_STATE_ENABLED) {
		ret = -EIO;
		goto tiocmset_exit;
	}

	tiocm &= TIOCM_DTR;

	/* update only if it's a new setting */
	if (mhi_chan->tiocm == tiocm)
		goto tiocmset_exit;

	dtr_msg = kzalloc(sizeof(*dtr_msg), GFP_KERNEL);
	if (!dtr_msg) {
		ret = -ENOMEM;
		goto tiocmset_exit;
	}

	dtr_msg->preamble = CTRL_MAGIC;
	dtr_msg->msg_id = CTRL_MSG_ID;
	dtr_msg->dest_id = chan;
	dtr_msg->size = sizeof(u32);
	if (tiocm & TIOCM_DTR)
		dtr_msg->msg |= CTRL_MSG_DTR;
	reinit_completion(&dtr_chan->completion);
	ret = mhi_queue_xfer(arch_info->dtr_handle, dtr_msg, sizeof(*dtr_msg),
			     MHI_EOT);
	if (ret)
		goto tiocmset_exit;
	ret = wait_for_completion_timeout(&dtr_chan->completion,
				msecs_to_jiffies(mhi_dev->poll_timeout));

	if (!ret) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Failed to receive xfer completion cb\n");
		ret = EIO;
		goto tiocmset_exit;
	}
	ret = 0;
	mhi_chan->tiocm = tiocm;
 tiocmset_exit:
	if (dtr_msg)
		kfree(dtr_msg);
	mutex_unlock(&dtr_chan->mutex);
	return ret;
}

int mhi_arch_platform_init(struct mhi_device *mhi_dev)
{
	struct device_node *of_node = mhi_dev->pdev->dev.of_node;
	struct arch_info *arch_info;
	struct mhi_chan *mhi_chan;
	struct mhi_client_data *cldata;
	int ret;

	arch_info = kzalloc(sizeof(*arch_info), GFP_KERNEL);
	if (!arch_info)
		return -ENOMEM;

	arch_info->mhi_dev = mhi_dev;
	mhi_dev->arch_info = arch_info;

	/* register for DTR channel if supported */
	ret = of_property_read_u32(of_node, "qcom,dtr-ctrl",
				   &arch_info->dtr_chan);
	if (ret) {
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"DTR/DSR signaling not supported\n");
		return 0;
	}

	/* register for ctrl channel */
	mhi_chan = &mhi_dev->mhi_chan[arch_info->dtr_chan];
	if (!mhi_chan->supported) {
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Selected DTR/DSR chan %d is not supported\n",
			arch_info->dtr_chan);
		return 0;
	}

	cldata = vmalloc(sizeof(*cldata));
	if (!cldata) {
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Out of memory to setup DTR/DSR chan\n");
		return 0;
	}

	cldata->chan = arch_info->dtr_chan;
	cldata->mhi_dev = mhi_dev;
	cldata->mhi_client_cb = mhi_dtr_xfer_cb;
	cldata->mhi_xfer_cb = mhi_dtr_xfer_cb;
	cldata->user_data = arch_info;
	cldata->client_handle.cldata = cldata;
	mhi_chan->cldata =cldata;
	mhi_dev->tiocmset = mhi_arch_tiocmset;
	arch_info->dtr_handle = &cldata->client_handle;

	return 0;
};

static int mhi_ssr_notify_cb(struct notifier_block *nb,
			unsigned long action, void *data)
{
	enum MHI_PM_STATE cur_state;
	struct arch_info *arch_info =
		container_of(nb, struct arch_info, notifier_block);
	struct notif_data *notif_data = (struct notif_data *)data;
	bool crashed = notif_data->crashed;
	struct mhi_device *mhi_dev = arch_info->mhi_dev;

	mhi_log(mhi_dev, MHI_MSG_INFO,
		"Received ESOC notifcation:%lu crashed:%d\n", action, crashed);
	switch (action) {
	case SUBSYS_AFTER_SHUTDOWN:

		/* Disable internal state, no more communication */
		write_lock_irq(&mhi_dev->pm_lock);
		cur_state = mhi_tryset_pm_state(mhi_dev,
						MHI_PM_LD_ERR_FATAL_DETECT);
		write_unlock_irq(&mhi_dev->pm_lock);
		if (unlikely(cur_state != MHI_PM_LD_ERR_FATAL_DETECT))
			mhi_log(mhi_dev, MHI_MSG_INFO,
				"Failed to transition to state 0x%x from 0x%x\n",
				MHI_PM_LD_ERR_FATAL_DETECT, cur_state);
		if (mhi_dev->pm_state != MHI_PM_DISABLE)
			process_disable_transition(MHI_PM_SHUTDOWN_PROCESS,
						   mhi_dev);
		mutex_lock(&mhi_dev->mutex);
		write_lock_irq(&mhi_dev->pm_lock);
		cur_state = mhi_tryset_pm_state(mhi_dev, MHI_PM_SSR_PENDING);
		write_unlock_irq(&mhi_dev->pm_lock);
		mutex_unlock(&mhi_dev->mutex);
		if (unlikely(cur_state != MHI_PM_SSR_PENDING))
			mhi_log(mhi_dev, MHI_MSG_INFO,
				"Failed to transition to state 0x%x from 0x%x\n",
				MHI_PM_SSR_PENDING, cur_state);
		break;
	default:
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Not handling esoc notification:%lu\n", action);
		break;
	}
	return NOTIFY_OK;
}

int mhi_set_bus_request(struct mhi_device *mhi_dev, int index)
{
	mhi_log(mhi_dev, MHI_MSG_INFO,
		"Setting bus request to index %d\n", index);
	return msm_bus_scale_client_update_request(
				mhi_dev->arch_info->bus_client, index);
}

int mhi_arch_pcie_init(struct mhi_device *mhi_dev)
{
	char node[32];
	struct arch_info *arch_info = mhi_dev->arch_info;
	struct msm_pcie_register_event *reg_event;
	int ret;

	snprintf(node, sizeof(node), "mhi_%04x_%02u.%02u.%02u", mhi_dev->dev_id,
		 mhi_dev->domain, mhi_dev->bus, mhi_dev->slot);
	mhi_dev->log = ipc_log_context_create(MHI_IPC_LOG_PAGES, node, 0);

	arch_info->msm_bus_pdata = msm_bus_cl_get_pdata(mhi_dev->pdev);
	if (!arch_info->msm_bus_pdata)
		goto error_pci_init;
	arch_info->bus_client = msm_bus_scale_register_client(
						arch_info->msm_bus_pdata);
	if (!arch_info->bus_client)
		goto error_pci_init;

	reg_event = &arch_info->pcie_reg_event;
	reg_event->events = MSM_PCIE_EVENT_WAKEUP;
	reg_event->user = mhi_dev->pci_dev;
	reg_event->callback = mhi_pci_link_state_cb;
	reg_event->notify.data = mhi_dev;
	ret = msm_pcie_register_event(reg_event);
	if (ret) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Failed to register for link notification\n");
		goto error_pci_init;
	}

	arch_info->esoc_client = devm_register_esoc_client(&mhi_dev->pdev->dev,
							   "mdm");
	if (IS_ERR_OR_NULL(arch_info->esoc_client))
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Failed to register for esoc client\n");
	else {
		arch_info->notifier_block.notifier_call = mhi_ssr_notify_cb;
		arch_info->subsys_notif = subsys_notif_register_notifier(
					        arch_info->esoc_client->name,
						&arch_info->notifier_block);
	}

	return mhi_set_bus_request(mhi_dev, 1);

error_pci_init:
	return -EINVAL;
}

int mhi_arch_post_init(struct mhi_device *mhi_dev)
{
	mhi_log(mhi_dev, MHI_MSG_INFO, "mhi arch post init\n");
	return 0;
}

int mhi_arch_link_off(struct mhi_device *mhi_dev, bool graceful)
{
	int ret = 0;
	struct pci_dev *pci_dev = mhi_dev->pci_dev;
	struct arch_info *arch_info = mhi_dev->arch_info;

	mhi_log(mhi_dev, MHI_MSG_INFO, "Entered...\n");

	if (graceful) {
		ret = pci_save_state(pci_dev);
		if (ret) {
			mhi_log(mhi_dev, MHI_MSG_ERROR,
				"Failed to save pcie state ret: %d\n", ret);
			return ret;
		}

		arch_info->pcie_state = pci_store_saved_state(pci_dev);
		pci_disable_device(pci_dev);
		ret = pci_set_power_state(pci_dev, PCI_D3hot);
		if (ret) {
			mhi_log(mhi_dev, MHI_MSG_ERROR,
				"Failed to set pcie power state to D3hot ret:%d\n",
				ret);
			return ret;
		}
	}

	ret = msm_pcie_pm_control(MSM_PCIE_SUSPEND, pci_dev->bus->number,
				  pci_dev, NULL, 0);
	if (ret)
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Failed to suspend pcie bus ret 0x%x\n", ret);

	ret = mhi_set_bus_request(mhi_dev, 0);
	if (ret)
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Failed to set bus freq ret %d\n", ret);

	mhi_log(mhi_dev, MHI_MSG_INFO, "Exited...\n");

	return 0;
}

int mhi_arch_link_on(struct mhi_device *mhi_dev)
{
	int ret = 0;
	struct pci_dev *pci_dev = mhi_dev->pci_dev;
	struct arch_info *arch_info = mhi_dev->arch_info;

	mhi_log(mhi_dev, MHI_MSG_INFO, "Entered...\n");

	ret  = mhi_set_bus_request(mhi_dev, 1);
	if (ret)
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Could not set bus frequency ret: %d\n", ret);

	ret = msm_pcie_pm_control(MSM_PCIE_RESUME, pci_dev->bus->number,
				  pci_dev, NULL, 0);
	if (ret) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Failed to resume pcie bus ret %d\n", ret);
		goto exit;
	}

	ret = pci_set_power_state(pci_dev, PCI_D0);
	if (ret) {
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Failed to set PCI_D0 state ret:%d\n", ret);
		goto exit;
	}
	ret = pci_enable_device(pci_dev);
	if (ret) {
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Failed to enable device ret:%d\n", ret);
		goto exit;
	}

	pci_load_and_free_saved_state(pci_dev, &arch_info->pcie_state);
	pci_restore_state(pci_dev);
	pci_set_master(pci_dev);

exit:
	mhi_log(mhi_dev, MHI_MSG_INFO, "Exited...\n");
	return ret;
}

static struct dma_iommu_mapping *mhi_create_iommu_mapping(
						struct mhi_device *mhi_dev)
{
	dma_addr_t base;
	size_t size;

	/*
	 * If S1_BYPASS enabled then iommu space is not used, however framework
	 * still require clients to create a mapping space before attaching. So
	 * set to smallest size required by iommu framework.
	 */
	if (mhi_dev->smmu_cfg & MHI_SMMU_S1_BYPASS) {
		base = 0;
		size = PAGE_SIZE;
	} else {
		base = mhi_dev->iova_start;
		size = (mhi_dev->iova_end - base) + 1;
	}

	mhi_log(mhi_dev, MHI_MSG_INFO,
		"Create iommu mapping of base:0x%llx size:%lu\n",
		base, size);
	return arm_iommu_create_mapping(&pci_bus_type, base, size);
}

int mhi_arch_qcom_init_smmu(struct mhi_device *mhi_dev)
{
	struct dma_iommu_mapping *mapping;
	u32 config = mhi_dev->smmu_cfg;
	int ret = 0;

	/* configure SMMU if we're bus master */
	if (mhi_dev->pci_master && config) {
		/* Create a mapping table */
		mapping = mhi_create_iommu_mapping(mhi_dev);
		if (IS_ERR(mapping)) {
			mhi_log(mhi_dev, MHI_MSG_ERROR,
				"Failed to create iommu mapping, ret:%ld\n",
				PTR_ERR(mapping));
			return PTR_ERR(mapping);
		}

		if (config & MHI_SMMU_S1_BYPASS) {
			int s1_bypass = 1;

			ret = iommu_domain_set_attr(mapping->domain,
					DOMAIN_ATTR_S1_BYPASS, &s1_bypass);
			if (ret) {
				mhi_log(mhi_dev, MHI_MSG_ERROR,
					"Failed to set attribute S1_BYPASS, ret:%d\n",
					ret);
				goto release_mapping;
			}
		}

		if (config & MHI_SMMU_FAST) {
			int fast = 1;

			ret = iommu_domain_set_attr(mapping->domain,
						    DOMAIN_ATTR_FAST, &fast);
			if (ret) {
				mhi_log(mhi_dev, MHI_MSG_ERROR,
					"Failed to set attribute FAST, ret:%d\n",
					ret);
				goto release_mapping;
			}
		}

		if (config & MHI_SMMU_ATOMIC) {
			int atomic = 1;

			ret = iommu_domain_set_attr(mapping->domain,
						DOMAIN_ATTR_ATOMIC, &atomic);
			if (ret) {
				mhi_log(mhi_dev, MHI_MSG_ERROR,
					"Failed to set attribute ATOMIC, ret:%d\n",
					ret);
				goto release_mapping;
			}
		}

		if (config & MHI_SMMU_GEOMETRY) {
			struct iommu_domain_geometry geometry;
			dma_addr_t end;

			/*
			 * RC driver will map one page for MSI from
			 * geometry.aperture_start.  Set start to 0
			 * to avoid any alignment issues
			 */
			end = mhi_dev->iova_end;
			geometry.aperture_start = 0;
			geometry.aperture_end = end;
			geometry.force_aperture = false;
			ret = iommu_domain_set_attr(mapping->domain,
					DOMAIN_ATTR_GEOMETRY, &geometry);
			if (ret) {
				mhi_log(mhi_dev, MHI_MSG_ERROR,
					"Failed to set attribute GEOMETRY, ret:%d\n",
					ret);
				goto release_mapping;
			}
		}

               if (config & MHI_SMMU_FORCE_COHERENT) {
                       int force_coherent = 1;
                       ret = iommu_domain_set_attr(mapping->domain,
					DOMAIN_ATTR_PAGE_TABLE_FORCE_COHERENT,
					&force_coherent);
                       if (ret) {
                               mhi_log(mhi_dev, MHI_MSG_ERROR,
                                       "Failed to set attribute FORCE_COHERENT, ret:%d\n",
                                       ret);
                               goto release_mapping;
                       }
               }

		ret = arm_iommu_attach_device(&mhi_dev->pci_dev->dev,
					      mapping);
		if (ret) {
			mhi_log(mhi_dev, MHI_MSG_ERROR,
				"Error with iommu_attach, ret:%d\n", ret);
			goto release_mapping;
		}
	}

	if (config) {
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Using pci_dev node for memory allocation and mapping\n");
		mhi_dev->dev = &mhi_dev->pci_dev->dev;
	} else {
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Using plat_dev node for memory allocation and mapping\n");
		mhi_dev->dev = &mhi_dev->pdev->dev;
	}

	if (mhi_dev->pci_master || !config) {
		ret = mhi_dma_mask(mhi_dev);
		if (ret) {
			mhi_log(mhi_dev, MHI_MSG_ERROR,
				"Failed to set dma_mask, ret:%d\n", ret);
		}
	}

	return ret;

release_mapping:
	arm_iommu_release_mapping(mapping);
	return ret;
}
