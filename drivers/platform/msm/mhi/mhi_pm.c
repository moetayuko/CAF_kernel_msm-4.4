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

#include <linux/msm_mhi.h>
#include <linux/workqueue.h>
#include <linux/pm.h>
#include <linux/fs.h>
#include <linux/hrtimer.h>
#include <linux/pm_runtime.h>
#include <linux/pci.h>
#include "mhi.h"

static const char *const mhi_dev_ctrl_str[MHI_DEV_CTRL_MAXCMD] = {
	[MHI_DEV_CTRL_INIT] = "INIT",
	[MHI_DEV_CTRL_DE_INIT] = "DE-INIT",
	[MHI_DEV_CTRL_SUSPEND] = "SUSPEND",
	[MHI_DEV_CTRL_RESUME] = "RESUME",
	[MHI_DEV_CTRL_POWER_OFF] = "OFF",
	[MHI_DEV_CTRL_POWER_ON] = "ON",
	[MHI_DEV_CTRL_TRIGGER_RDDM] = "TRIGGER RDDM",
	[MHI_DEV_CTRL_RDDM] = "RDDM",
	[MHI_DEV_CTRL_RDDM_KERNEL_PANIC] = "RDDM IN PANIC",
	[MHI_DEV_CTRL_NOTIFY_LINK_ERROR] = "LD",
};

#define TO_MHI_DEV_CTRL_STR(cmd) ((cmd >= MHI_DEV_CTRL_MAXCMD) ? "INVALID" : \
				  mhi_dev_ctrl_str[cmd])

ssize_t sysfs_init_m0(struct device *dev,
		      struct device_attribute *attr,
		      const char *buf,
		      size_t count)
{
	struct mhi_device *mhi_dev = dev_get_drvdata(dev);

	pm_runtime_get(&mhi_dev->pci_dev->dev);
	pm_runtime_mark_last_busy(&mhi_dev->pci_dev->dev);
	pm_runtime_put_noidle(&mhi_dev->pci_dev->dev);

	return count;
}

ssize_t sysfs_init_m3(struct device *dev,
		      struct device_attribute *attr,
		      const char *buf,
		      size_t count)
{
	struct mhi_device *mhi_dev = dev_get_drvdata(dev);


	if (atomic_read(&mhi_dev->dev_wake) == 0) {
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Schedule RPM suspend");
		pm_runtime_mark_last_busy(&mhi_dev->pci_dev->dev);
		pm_request_autosuspend(&mhi_dev->pci_dev->dev);
	}
	return count;
}


static DEVICE_ATTR(MHI_M0, S_IWUSR, NULL, sysfs_init_m0);
static DEVICE_ATTR(MHI_M3, S_IWUSR, NULL, sysfs_init_m3);
static struct attribute *mhi_attributes[] = {
	&dev_attr_MHI_M0.attr,
	&dev_attr_MHI_M3.attr,
	NULL,
};
static struct attribute_group mhi_attribute_group = {
	.attrs = mhi_attributes,
};

int mhi_system_suspend(struct device *dev)
{
	int ret = 0;
	struct mhi_device *mhi_dev = dev_get_drvdata(dev);

	mhi_log(mhi_dev, MHI_MSG_INFO, "Entered\n");

	/* if rpm status still active then force suspend */
	if (!pm_runtime_status_suspended(dev)) {
		ret = mhi_runtime_suspend(dev);
		if (ret)
			return ret;
	}

	pm_runtime_set_suspended(dev);
	pm_runtime_disable(dev);

	mhi_log(mhi_dev, MHI_MSG_INFO, "Exit\n");
	return ret;
}

static int mhi_pm_initiate_m3(struct mhi_device *mhi_dev)
{
	int ret = 0;
	enum MHI_PM_STATE new_state;

	read_lock_bh(&mhi_dev->pm_lock);
	mhi_log(mhi_dev, MHI_MSG_INFO, "Entered with State:0x%x %s\n",
		mhi_dev->pm_state, TO_MHI_STATE_STR(mhi_dev->dev_state));

	/* Link is already disabled */
	if (mhi_dev->pm_state == MHI_PM_DISABLE ||
	    mhi_dev->pm_state == MHI_PM_M3) {
		mhi_log(mhi_dev, MHI_MSG_INFO, "Already in M3 State\n");
		read_unlock_bh(&mhi_dev->pm_lock);
		return 0;
	}

	if (unlikely(atomic_read(&mhi_dev->dev_wake))) {
		mhi_log(mhi_dev, MHI_MSG_INFO, "Busy, Aborting M3\n");
		read_unlock_bh(&mhi_dev->pm_lock);
		return -EBUSY;
	}

	if (unlikely(!MHI_REG_ACCESS_VALID(mhi_dev->pm_state))) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Error, no register access, PM_STATE:0x%x\n",
			mhi_dev->pm_state);
		read_unlock_bh(&mhi_dev->pm_lock);
		return -EIO;
	}

	mhi_dev->assert_wake(mhi_dev, false);
	read_unlock_bh(&mhi_dev->pm_lock);
	ret = wait_event_timeout(mhi_dev->state_event,
			mhi_dev->dev_state == MHI_STATE_M0 ||
			mhi_dev->dev_state == MHI_STATE_M1 ||
			mhi_dev->pm_state == MHI_PM_LD_ERR_FATAL_DETECT,
			msecs_to_jiffies(MHI_MAX_STATE_TRANSITION_TIMEOUT));
	if (!ret || mhi_dev->pm_state == MHI_PM_LD_ERR_FATAL_DETECT) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Failed to get M0||M1 event or LD pm_state:0x%x state:%s\n",
			mhi_dev->pm_state,
			TO_MHI_STATE_STR(mhi_dev->dev_state));
		return -EIO;
	}

	mhi_log(mhi_dev, MHI_MSG_INFO, "Allowing M3 State\n");
	write_lock_irq(&mhi_dev->pm_lock);
	mhi_dev->deassert_wake(mhi_dev, false);
	new_state = mhi_tryset_pm_state(mhi_dev, MHI_PM_M3_ENTER);
	if (unlikely(new_state != MHI_PM_M3_ENTER)) {
		write_unlock_irq(&mhi_dev->pm_lock);
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Error setting PM_STATE from 0x%x to 0x%x\n",
			new_state, MHI_PM_M3_ENTER);
		return -EIO;
	}
	mhi_set_m_state(mhi_dev, MHI_STATE_M3);
	write_unlock_irq(&mhi_dev->pm_lock);
	mhi_log(mhi_dev, MHI_MSG_INFO, "Waiting for M3 completion.\n");
	ret = wait_event_timeout(mhi_dev->state_event,
			mhi_dev->dev_state == MHI_STATE_M3 ||
			mhi_dev->pm_state == MHI_PM_LD_ERR_FATAL_DETECT,
			msecs_to_jiffies(MHI_MAX_STATE_TRANSITION_TIMEOUT));
	if (!ret || mhi_dev->pm_state == MHI_PM_LD_ERR_FATAL_DETECT) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Failed to get M3 event, timeout, current state:%s\n",
			TO_MHI_STATE_STR(mhi_dev->dev_state));
		return -EIO;
	}

	return 0;
}

static int mhi_pm_initiate_m0(struct mhi_device *mhi_dev)
{
	int ret;
	enum MHI_PM_STATE cur_state;

	mhi_log(mhi_dev, MHI_MSG_INFO, "Entered with State:0x%x %s\n",
		mhi_dev->pm_state, TO_MHI_STATE_STR(mhi_dev->dev_state));

	write_lock_irq(&mhi_dev->pm_lock);
	cur_state = mhi_tryset_pm_state(mhi_dev, MHI_PM_M3_EXIT);
	if (unlikely(cur_state != MHI_PM_M3_EXIT)) {
		write_unlock_irq(&mhi_dev->pm_lock);
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Error setting PM_STATE from 0x%x to 0x%x\n",
			cur_state, MHI_PM_M3_EXIT);
		return -EAGAIN;
	}

	/* Set and wait for M0 Event */
	mhi_set_m_state(mhi_dev, MHI_STATE_M0);
	write_unlock_irq(&mhi_dev->pm_lock);
	ret = wait_event_timeout(mhi_dev->state_event,
			mhi_dev->dev_state == MHI_STATE_M0 ||
			mhi_dev->dev_state == MHI_STATE_M1 ||
			mhi_dev->pm_state == MHI_PM_LD_ERR_FATAL_DETECT,
			msecs_to_jiffies(MHI_MAX_STATE_TRANSITION_TIMEOUT));
	if (!ret || mhi_dev->pm_state == MHI_PM_LD_ERR_FATAL_DETECT) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Failed to get M0 event, timeout or LD\n");
		ret = -EIO;
	} else
		ret = 0;

	return ret;
}

int mhi_runtime_suspend(struct device *dev)
{
	int ret = 0;
	struct mhi_device *mhi_dev = dev_get_drvdata(dev);

	mhi_log(mhi_dev, MHI_MSG_INFO, "Enter\n");

	mutex_lock(&mhi_dev->mutex);
	ret = mhi_pm_initiate_m3(mhi_dev);
	if (ret) {
		mhi_log(mhi_dev, MHI_MSG_INFO, "abort due to ret:%d\n", ret);
		mutex_unlock(&mhi_dev->mutex);
		return ret;
	}
	ret = mhi_arch_link_off(mhi_dev, true);
	if (ret) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Failed to Turn off link ret:%d\n", ret);
	}

	mutex_unlock(&mhi_dev->mutex);
	mhi_log(mhi_dev, MHI_MSG_INFO, "Exited with ret:%d\n", ret);

	return ret;
}

int mhi_runtime_idle(struct device *dev)
{
	struct mhi_device *mhi_dev = dev_get_drvdata(dev);

	mhi_log(mhi_dev, MHI_MSG_INFO, "Entered returning -EBUSY\n");

	/*
	 * RPM framework during runtime resume always calls
	 * rpm_idle to see if device ready to suspend.
	 * If dev.power usage_count count is 0, rpm fw will call
	 * rpm_idle cb to see if device is ready to suspend.
	 * if cb return 0, or cb not defined the framework will
	 * assume device driver is ready to suspend;
	 * therefore, fw will schedule runtime suspend.
	 * In MHI power management, MHI host shall go to
	 * runtime suspend only after entering MHI State M2, even if
	 * usage count is 0.  Return -EBUSY to disable automatic suspend.
	 */
	return -EBUSY;
}

int mhi_runtime_resume(struct device *dev)
{
	int ret = 0;
	struct mhi_device *mhi_dev = dev_get_drvdata(dev);

	mutex_lock(&mhi_dev->mutex);
	read_lock_bh(&mhi_dev->pm_lock);
	WARN_ON(mhi_dev->pm_state != MHI_PM_M3);
	read_unlock_bh(&mhi_dev->pm_lock);

	/* turn on link */
	ret = mhi_arch_link_on(mhi_dev);;
	if (ret)
		goto rpm_resume_exit;

	ret = mhi_pm_initiate_m0(mhi_dev);
rpm_resume_exit:
	mutex_unlock(&mhi_dev->mutex);
	mhi_log(mhi_dev, MHI_MSG_INFO, "Exited with :%d\n", ret);
	return ret;
}

int mhi_system_resume(struct device *dev)
{
	int ret = 0;
	struct mhi_device *mhi_dev = dev_get_drvdata(dev);

	ret = mhi_runtime_resume(dev);
	if (ret)
		mhi_log(mhi_dev, MHI_MSG_ERROR, "Failed to resume link\n");
	else {
		pm_runtime_set_active(dev);
		pm_runtime_enable(dev);
	}

	return ret;
}

void mhi_master_mode_runtime_get(struct mhi_device *mhi_dev)
{
	pm_runtime_get(&mhi_dev->pci_dev->dev);
}

void mhi_master_mode_runtime_put(struct mhi_device *mhi_dev)
{
	pm_runtime_mark_last_busy(&mhi_dev->pci_dev->dev);
	pm_runtime_put_noidle(&mhi_dev->pci_dev->dev);
}

void mhi_slave_mode_runtime_get(struct mhi_device *mhi_dev)
{
	mhi_dev->bus_master_rt_get(mhi_dev->pci_dev);
}

void mhi_slave_mode_runtime_put(struct mhi_device *mhi_dev)
{
	mhi_dev->bus_master_rt_put(mhi_dev->pci_dev);
}

#ifdef CONFIG_MHI_SLAVEMODE
static int mhi_pm_slave_mode_power_on(struct mhi_device_ctxt *mhi_dev_ctxt)
{
	int ret_val;
	u32 timeout = mhi_dev_ctxt->poll_reset_timeout_ms;

	mhi_log(mhi_dev_ctxt, MHI_MSG_INFO, "Entered\n");
	mutex_lock(&mhi_dev_ctxt->pm_lock);
	write_lock_irq(&mhi_dev_ctxt->pm_xfer_lock);
	mhi_dev_ctxt->mhi_pm_state = MHI_PM_POR;
	ret_val = set_mhi_base_state(mhi_dev_ctxt);
	write_unlock_irq(&mhi_dev_ctxt->pm_xfer_lock);

	if (ret_val) {
		mhi_log(mhi_dev_ctxt, MHI_MSG_ERROR,
			"Error Setting MHI Base State %d\n", ret_val);
		goto unlock_pm_lock;
	}

	if (mhi_dev_ctxt->base_state != STATE_TRANSITION_BHI) {
		ret_val = -EIO;
		mhi_log(mhi_dev_ctxt, MHI_MSG_ERROR,
			"Invalid Base State, cur_state:%s\n",
			state_transition_str(mhi_dev_ctxt->base_state));
		goto unlock_pm_lock;
	}

	reinit_completion(&mhi_dev_ctxt->cmd_complete);
	init_mhi_base_state(mhi_dev_ctxt);

	/*
	 * Keep wake in Active until AMSS, @ AMSS we will
	 * decrement counts
	 */
	read_lock_irq(&mhi_dev_ctxt->pm_xfer_lock);
	mhi_dev_ctxt->assert_wake(mhi_dev_ctxt, false);
	read_unlock_irq(&mhi_dev_ctxt->pm_xfer_lock);

	wait_for_completion_timeout(&mhi_dev_ctxt->cmd_complete,
				    msecs_to_jiffies(timeout));
	if (mhi_dev_ctxt->dev_exec_env != MHI_EXEC_ENV_AMSS)
		ret_val = -EIO;
	else
		ret_val = 0;

	if (ret_val) {
		read_lock_irq(&mhi_dev_ctxt->pm_xfer_lock);
		mhi_dev_ctxt->deassert_wake(mhi_dev_ctxt, false);
		read_unlock_irq(&mhi_dev_ctxt->pm_xfer_lock);
	}

unlock_pm_lock:

	if (ret_val) {
		enum MHI_PM_STATE state;

		write_lock_irq(&mhi_dev_ctxt->pm_xfer_lock);
		state = mhi_tryset_pm_state(mhi_dev_ctxt, MHI_PM_FW_DL_ERR);
		write_unlock_irq(&mhi_dev_ctxt->pm_xfer_lock);
		mhi_log(mhi_dev_ctxt, MHI_MSG_INFO, "PM_State:0x%x\n", state);
		wake_up_interruptible(mhi_dev_ctxt->mhi_ev_wq.bhi_event);
	}

	/* wait for firmware download to complete */
	flush_work(&mhi_dev_ctxt->bhi_ctxt.fw_load_work);

	mhi_log(mhi_dev_ctxt, MHI_MSG_INFO, "Exit with ret:%d\n", ret_val);
	mutex_unlock(&mhi_dev_ctxt->pm_lock);
	return ret_val;
}

static void mhi_pm_slave_mode_power_off(struct mhi_device_ctxt *mhi_dev_ctxt)
{
	mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
		"Entered with pm_state:0x%x MHI_STATE:%s\n",
		mhi_dev_ctxt->mhi_pm_state,
		TO_MHI_STATE_STR(mhi_dev_ctxt->mhi_state));

	if (mhi_dev_ctxt->mhi_pm_state == MHI_PM_DISABLE) {
		mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
			"MHI already in disabled state\n");
		return;
	}
	process_disable_transition(MHI_PM_SHUTDOWN_PROCESS, mhi_dev_ctxt);
}

static int mhi_pm_slave_mode_suspend(struct mhi_device_ctxt *mhi_dev_ctxt)
{
	int r;

	mhi_log(mhi_dev_ctxt, MHI_MSG_INFO, "Entered\n");
	mutex_lock(&mhi_dev_ctxt->pm_lock);

	r = mhi_pm_initiate_m3(mhi_dev_ctxt, false);
	if (r)
		mhi_log(mhi_dev_ctxt, MHI_MSG_INFO, "abort due to ret:%d\n", r);
	mutex_unlock(&mhi_dev_ctxt->pm_lock);

	mhi_log(mhi_dev_ctxt, MHI_MSG_INFO, "Exit with ret:%d\n", r);

	return r;
}

static int mhi_pm_slave_mode_resume(struct mhi_device_ctxt *mhi_dev_ctxt)
{
	int r;

	mhi_log(mhi_dev_ctxt, MHI_MSG_INFO, "Entered\n");
	mutex_lock(&mhi_dev_ctxt->pm_lock);

	r = mhi_pm_initiate_m0(mhi_dev_ctxt);
	if (r)
		mhi_log(mhi_dev_ctxt, MHI_MSG_ERROR,
			"M3 exit failed ret:%d\n", r);
	mutex_unlock(&mhi_dev_ctxt->pm_lock);
	mhi_log(mhi_dev_ctxt, MHI_MSG_INFO, "Exit with ret:%d\n", r);

	return r;
}
#endif

int mhi_init_pm_sysfs(struct device *dev)
{
	return sysfs_create_group(&dev->kobj, &mhi_attribute_group);
}

void mhi_rem_pm_sysfs(struct device *dev)
{
	return sysfs_remove_group(&dev->kobj, &mhi_attribute_group);
}

#ifdef CONFIG_MHI_SLAVEMODE
int mhi_pm_control_device(struct mhi_master *mhi_master, enum mhi_dev_ctrl ctrl,
			  void *param)
{
	struct mhi_device_ctxt *mhi_dev_ctxt = mhi_device->mhi_dev_ctxt;
	unsigned long flags;

	if (!mhi_dev_ctxt)
		return -EINVAL;

	mhi_log(mhi_dev_ctxt, MHI_MSG_INFO, "Entered with cmd:%s\n",
		TO_MHI_DEV_CTRL_STR(ctrl));

	switch (ctrl) {
	case MHI_DEV_CTRL_INIT:
	{
		const char *fw_image = param;
		struct bhi_ctxt_t *bhi_ctxt = &mhi_dev_ctxt->bhi_ctxt;

		if (!fw_image)
			fw_image = mhi_device->fw_image;
		if (!fw_image)
			fw_image = bhi_ctxt->firmware_info.fw_image;
		return bhi_probe(mhi_dev_ctxt, fw_image);
	}
	case MHI_DEV_CTRL_POWER_ON:
		return mhi_pm_slave_mode_power_on(mhi_dev_ctxt);
	case MHI_DEV_CTRL_SUSPEND:
		return mhi_pm_slave_mode_suspend(mhi_dev_ctxt);
	case MHI_DEV_CTRL_RESUME:
		return mhi_pm_slave_mode_resume(mhi_dev_ctxt);
	case MHI_DEV_CTRL_POWER_OFF:
		mhi_pm_slave_mode_power_off(mhi_dev_ctxt);
		break;
	case MHI_DEV_CTRL_TRIGGER_RDDM:
		write_lock_irqsave(&mhi_dev_ctxt->pm_xfer_lock, flags);
		if (!MHI_REG_ACCESS_VALID(mhi_dev_ctxt->mhi_pm_state)) {
			write_unlock_irqrestore(&mhi_dev_ctxt->pm_xfer_lock,
						flags);
			mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
				"failed to trigger rddm, no register access in state:0x%x\n",
				mhi_dev_ctxt->mhi_pm_state);
			return -EIO;
		}
		mhi_set_m_state(mhi_dev_ctxt, MHI_STATE_SYS_ERR);
		write_unlock_irqrestore(&mhi_dev_ctxt->pm_xfer_lock, flags);
		break;
	case MHI_DEV_CTRL_RDDM:
		return bhi_rddm(mhi_dev_ctxt, false);
	case MHI_DEV_CTRL_RDDM_KERNEL_PANIC:
		return bhi_rddm(mhi_dev_ctxt, true);
	case MHI_DEV_CTRL_DE_INIT:
		if (mhi_dev_ctxt->mhi_pm_state != MHI_PM_DISABLE) {
			enum MHI_PM_STATE cur_state;
			/*
			 * If bus master calls DE_INIT before calling POWER_OFF
			 * means a critical failure occurred during POWER_ON
			 * state transition and external PCIe device may not
			 * respond to host.  Force PM state to PCIe linkdown
			 * state prior to starting shutdown process to avoid
			 * accessing PCIe link.
			 */
			write_lock_irq(&mhi_dev_ctxt->pm_xfer_lock);
			cur_state = mhi_tryset_pm_state(mhi_dev_ctxt,
						MHI_PM_LD_ERR_FATAL_DETECT);
			write_unlock_irq(&mhi_dev_ctxt->pm_xfer_lock);
			if (unlikely(cur_state != MHI_PM_LD_ERR_FATAL_DETECT)) {
				mhi_log(mhi_dev_ctxt, MHI_MSG_ERROR,
					"Failed to transition to state 0x%x from 0x%x\n",
					MHI_PM_LD_ERR_FATAL_DETECT, cur_state);
			}
			process_disable_transition(MHI_PM_SHUTDOWN_PROCESS,
						   mhi_dev_ctxt);
		}
		bhi_exit(mhi_dev_ctxt);
		break;
	case MHI_DEV_CTRL_NOTIFY_LINK_ERROR:
	{
		enum MHI_PM_STATE cur_state;

		write_lock_irq(&mhi_dev_ctxt->pm_xfer_lock);
		cur_state = mhi_tryset_pm_state(mhi_dev_ctxt,
						MHI_PM_LD_ERR_FATAL_DETECT);
		write_unlock_irq(&mhi_dev_ctxt->pm_xfer_lock);
		if (unlikely(cur_state != MHI_PM_LD_ERR_FATAL_DETECT))
			mhi_log(mhi_dev_ctxt, MHI_MSG_INFO,
				"Failed to transition to state 0x%x from 0x%x\n",
				MHI_PM_LD_ERR_FATAL_DETECT, cur_state);

		/* wake up all threads that's waiting for state change events */
		complete(&mhi_dev_ctxt->cmd_complete);
		wake_up_interruptible(mhi_dev_ctxt->mhi_ev_wq.bhi_event);
		wake_up(mhi_dev_ctxt->mhi_ev_wq.m0_event);
		wake_up(mhi_dev_ctxt->mhi_ev_wq.m3_event);
		break;
	}
	default:
		return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL(mhi_pm_control_device);
#endif
