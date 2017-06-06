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
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include "mhi.h"

static const char * const mhi_states_transition_str[STATE_TRANSITION_MAX] = {
	[STATE_TRANSITION_RESET] = "RESET",
	[STATE_TRANSITION_READY] = "READY",
	[STATE_TRANSITION_M0] = "M0",
	[STATE_TRANSITION_M1] = "M1",
	[STATE_TRANSITION_M2] = "M2",
	[STATE_TRANSITION_M3] = "M3",
	[STATE_TRANSITION_BHI] = "BHI",
	[STATE_TRANSITION_SBL] = "SBL",
	[STATE_TRANSITION_AMSS] = "AMSS",
	[STATE_TRANSITION_LINK_DOWN] = "LINK_DOWN",
	[STATE_TRANSITION_WAKE] = "WAKE",
	[STATE_TRANSITION_BHIE] = "BHIE",
	[STATE_TRANSITION_RDDM] = "RDDM",
	[STATE_TRANSITION_SYS_ERR] = "SYS_ERR",
};

const char * const mhi_states_str[MHI_STATE_LIMIT] = {
	[MHI_STATE_RESET] = "RESET",
	[MHI_STATE_READY] = "READY",
	[MHI_STATE_M0] = "M0",
	[MHI_STATE_M1] = "M1",
	[MHI_STATE_M2] = "M2",
	[MHI_STATE_M3] = "M3",
	"Reserved: 0x06",
	[MHI_STATE_BHI] = "BHI",
	[MHI_STATE_SYS_ERR] = "SYS_ERR",
};

const char * const mhi_exec_env_str[MHI_EXEC_LIMIT] = {
	[MHI_EXEC_ENV_PBL] = "PBL",
	[MHI_EXEC_ENV_SBL] = "SBL",
	[MHI_EXEC_ENV_AMSS] = "AMSS",
	[MHI_EXEC_ENV_RDDM] = "RDDM",
	[MHI_EXEC_ENV_DISABLE_TRANSITION] = "DISABLE",
	[MHI_EXEC_INVALID] = "INVALID"
};

const char *state_transition_str(enum STATE_TRANSITION state)
{
	static const char * const
		mhi_states_transition_str[STATE_TRANSITION_MAX] = {
		[STATE_TRANSITION_RESET] = "RESET",
		[STATE_TRANSITION_READY] = "READY",
		[STATE_TRANSITION_M0] = "M0",
		[STATE_TRANSITION_M1] = "M1",
		[STATE_TRANSITION_M2] = "M2",
		[STATE_TRANSITION_M3] = "M3",
		[STATE_TRANSITION_BHI] = "BHI",
		[STATE_TRANSITION_SBL] = "SBL",
		[STATE_TRANSITION_AMSS] = "AMSS",
		[STATE_TRANSITION_LINK_DOWN] = "LINK_DOWN",
		[STATE_TRANSITION_WAKE] = "WAKE",
		[STATE_TRANSITION_BHIE] = "BHIE",
		[STATE_TRANSITION_RDDM] = "RDDM",
		[STATE_TRANSITION_SYS_ERR] = "SYS_ERR",
	};

	return (state < STATE_TRANSITION_MAX) ?
		mhi_states_transition_str[state] : "Invalid";
}

enum MHI_STATE mhi_get_m_state(struct mhi_device *mhi_dev)
{
	u32 val = mhi_read_reg_field(mhi_dev, mhi_dev->regs, MHISTATUS,
			MHISTATUS_MHISTATE_MASK, MHISTATUS_MHISTATE_SHIFT);
	return PCI_INVALID_READ(val) ? MHI_STATE_INVALID : val;
}

bool mhi_in_sys_err(struct mhi_device *mhi_dev)
{
	u32 state = mhi_read_reg_field(mhi_dev, mhi_dev->regs, MHISTATUS,
				       MHISTATUS_SYSERR_MASK,
				       MHISTATUS_SYSERR_SHIFT);

	return (state || PCI_INVALID_READ(state)) ? true : false;
}

void mhi_set_m_state(struct mhi_device *mhi_dev, enum MHI_STATE new_state)
{
	if (MHI_STATE_RESET == new_state) {
		mhi_write_reg_field(mhi_dev, mhi_dev->regs, MHICTRL,
				    MHICTRL_RESET_MASK, MHICTRL_RESET_SHIFT, 1);
	} else {
		mhi_write_reg_field(mhi_dev, mhi_dev->regs, MHICTRL,
			MHICTRL_MHISTATE_MASK, MHICTRL_MHISTATE_SHIFT,
			new_state);
	}
}

/*
 * Not all MHI states transitions are sync transitions. Linkdown, SSR, and
 * shutdown can happen anytime asynchronously. This function will transition to
 * new state only if it's a valid transitions.
 *
 * Priority increase as we go down, example while in any states from L0, start
 * state from L1, L2, or L3 can be set.  Notable exception to this rule is state
 * DISABLE.  From DISABLE state we can transition to only POR or SSR_PENDING
 * state.  Also for example while in L2 state, user cannot jump back to L1 or
 * L0 states.
 * Valid transitions:
 * L0: DISABLE <--> POR
 *     DISABLE <--> SSR_PENDING
 *     POR <--> POR
 *     POR -> M0 -> M1 -> M1_M2 -> M2 --> M0
 *     POR -> FW_DL_ERR
 *     FW_DL_ERR <--> FW_DL_ERR
 *     M0 -> FW_DL_ERR
 *     M1_M2 -> M0 (Device can trigger it)
 *     M0 -> M3_ENTER -> M3 -> M3_EXIT --> M0
 *     M1 -> M3_ENTER --> M3
 * L1: SYS_ERR_DETECT -> SYS_ERR_PROCESS --> POR
 * L2: SHUTDOWN_PROCESS -> DISABLE -> SSR_PENDING (via SSR Notification only)
 * L3: LD_ERR_FATAL_DETECT <--> LD_ERR_FATAL_DETECT
 *     LD_ERR_FATAL_DETECT -> SHUTDOWN_PROCESS
 */
static const struct mhi_pm_transitions const mhi_state_transitions[] = {
	/* L0 States */
	{
		MHI_PM_DISABLE,
		MHI_PM_POR | MHI_PM_SSR_PENDING
	},
	{
		MHI_PM_POR,
		MHI_PM_POR | MHI_PM_DISABLE | MHI_PM_M0 |
		MHI_PM_SYS_ERR_DETECT | MHI_PM_SHUTDOWN_PROCESS |
		MHI_PM_LD_ERR_FATAL_DETECT | MHI_PM_FW_DL_ERR
	},
	{
		MHI_PM_M0,
		MHI_PM_M1 | MHI_PM_M3_ENTER | MHI_PM_SYS_ERR_DETECT |
		MHI_PM_SHUTDOWN_PROCESS | MHI_PM_LD_ERR_FATAL_DETECT |
		MHI_PM_FW_DL_ERR
	},
	{
		MHI_PM_M1,
		MHI_PM_M1_M2_TRANSITION | MHI_PM_M3_ENTER |
		MHI_PM_SYS_ERR_DETECT | MHI_PM_SHUTDOWN_PROCESS |
		MHI_PM_LD_ERR_FATAL_DETECT
	},
	{
		MHI_PM_M1_M2_TRANSITION,
		MHI_PM_M2 | MHI_PM_M0 | MHI_PM_SYS_ERR_DETECT |
		MHI_PM_SHUTDOWN_PROCESS | MHI_PM_LD_ERR_FATAL_DETECT
	},
	{
		MHI_PM_M2,
		MHI_PM_M0 | MHI_PM_SYS_ERR_DETECT | MHI_PM_SHUTDOWN_PROCESS |
		MHI_PM_LD_ERR_FATAL_DETECT
	},
	{
		MHI_PM_M3_ENTER,
		MHI_PM_M3 | MHI_PM_SYS_ERR_DETECT | MHI_PM_SHUTDOWN_PROCESS |
		MHI_PM_LD_ERR_FATAL_DETECT
	},
	{
		MHI_PM_M3,
		MHI_PM_M3_EXIT | MHI_PM_SYS_ERR_DETECT |
		MHI_PM_SHUTDOWN_PROCESS | MHI_PM_LD_ERR_FATAL_DETECT
	},
	{
		MHI_PM_M3_EXIT,
		MHI_PM_M0 | MHI_PM_SYS_ERR_DETECT | MHI_PM_SHUTDOWN_PROCESS |
		MHI_PM_LD_ERR_FATAL_DETECT
	},
	{
		MHI_PM_FW_DL_ERR,
		MHI_PM_FW_DL_ERR | MHI_PM_SYS_ERR_DETECT |
		MHI_PM_SHUTDOWN_PROCESS | MHI_PM_LD_ERR_FATAL_DETECT
	},
	/* L1 States */
	{
		MHI_PM_SYS_ERR_DETECT,
		MHI_PM_SYS_ERR_PROCESS | MHI_PM_SHUTDOWN_PROCESS |
		MHI_PM_LD_ERR_FATAL_DETECT
	},
	{
		MHI_PM_SYS_ERR_PROCESS,
		MHI_PM_POR | MHI_PM_SHUTDOWN_PROCESS |
		MHI_PM_LD_ERR_FATAL_DETECT
	},
	/* L2 States */
	{
		MHI_PM_SHUTDOWN_PROCESS,
		MHI_PM_DISABLE | MHI_PM_LD_ERR_FATAL_DETECT
	},
	/* L3 States */
	{
		MHI_PM_LD_ERR_FATAL_DETECT,
		MHI_PM_LD_ERR_FATAL_DETECT | MHI_PM_SHUTDOWN_PROCESS
	},
	/* From SSR notification only */
	{
		MHI_PM_SSR_PENDING,
		MHI_PM_DISABLE
	}
};

enum MHI_PM_STATE __must_check mhi_tryset_pm_state(
				struct mhi_device *mhi_dev,
				enum MHI_PM_STATE state)
{
	unsigned long cur_state = mhi_dev->pm_state;
	int index = find_last_bit(&cur_state, 32);

	if (unlikely(index >= ARRAY_SIZE(mhi_state_transitions))) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"cur_state:0x%lx out side of mhi_state_transitions\n",
			cur_state);
		return cur_state;
	}

	if (unlikely(mhi_state_transitions[index].from_state != cur_state)) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"index:%u cur_state:0x%lx != actual_state: 0x%x\n",
			index, cur_state,
			mhi_state_transitions[index].from_state);
		return cur_state;
	}

	if (unlikely(!(mhi_state_transitions[index].to_states & state))) {
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Not allowing pm state transition from:0x%lx to:0x%x state\n",
			cur_state, state);
		return cur_state;
	}

	mhi_log(mhi_dev, MHI_MSG_VERBOSE,
		"Transition to pm state from:0x%lx to:0x%x\n",
		cur_state, state);
	mhi_dev->pm_state = state;
	return mhi_dev->pm_state;
}

int process_m0_transition(struct mhi_device *mhi_dev)
{
	unsigned long flags;
	enum MHI_PM_STATE cur_state;
	struct mhi_chan *mhi_chan;
	int i;

	mhi_log(mhi_dev, MHI_MSG_INFO, "Entered With State %s\n",
		TO_MHI_STATE_STR(mhi_dev->dev_state));

	write_lock_irqsave(&mhi_dev->pm_lock, flags);
	mhi_dev->dev_state = MHI_STATE_M0;
	cur_state = mhi_tryset_pm_state(mhi_dev, MHI_PM_M0);
	write_unlock_irqrestore(&mhi_dev->pm_lock, flags);
	if (unlikely(cur_state != MHI_PM_M0)) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Failed to transition to state 0x%x from 0x%x\n",
			MHI_PM_M0, cur_state);
		return -EIO;
	}
	read_lock_bh(&mhi_dev->pm_lock);
	mhi_dev->assert_wake(mhi_dev, true);

	/* ring all event rings and CMD ring only if we're in AMSS */
	if (mhi_dev->dev_exec_env == MHI_EXEC_ENV_AMSS) {
		struct mhi_event *mhi_event = mhi_dev->mhi_event;
		struct mhi_ring *cmd_ring = &mhi_dev->mhi_cmd[PRIMARY_CMD_RING];

		for (i = 0; i < mhi_dev->ev_rings; i++, mhi_event++) {
			spin_lock_irqsave(&mhi_event->lock, flags);
			mhi_ring_er_db(mhi_event);
			spin_unlock_irqrestore(&mhi_event->lock, flags);
		}

		/* only ring primary cmd ring */
		spin_lock_irqsave(&mhi_dev->cmd_lock, flags);
		if (cmd_ring->rp != cmd_ring->wp)
			mhi_ring_cmd_db(mhi_dev);
		spin_unlock_irqrestore(&mhi_dev->cmd_lock, flags);
	}

	/* ring channel db registers */
	mhi_chan = mhi_dev->mhi_chan;
	for (i = 0; i < MHI_MAX_CHANNELS; i++, mhi_chan++) {
		struct mhi_ring *tre_ring = &mhi_chan->tre_ring;

		write_lock_irqsave(&mhi_chan->lock, flags);
		/* only ring DB if ring is not empty */
		if (tre_ring->base && tre_ring->wp  != tre_ring->rp)
			mhi_ring_chan_db(mhi_dev, mhi_chan);
		write_unlock_irqrestore(&mhi_chan->lock, flags);

	}

	mhi_dev->deassert_wake(mhi_dev, false);
	read_unlock_bh(&mhi_dev->pm_lock);
	wake_up(&mhi_dev->state_event);
	mhi_log(mhi_dev, MHI_MSG_INFO, "Exited\n");

	return 0;
}

void process_m1_transition(struct work_struct *work)
{
	struct mhi_device *mhi_dev;
	enum MHI_PM_STATE cur_state;

	mhi_dev = container_of(work, struct mhi_device, m1_worker);

	mhi_log(mhi_dev, MHI_MSG_INFO,
		"Processing M1 state transition from state %s\n",
		TO_MHI_STATE_STR(mhi_dev->dev_state));

	mutex_lock(&mhi_dev->mutex);
	write_lock_irq(&mhi_dev->pm_lock);

	/* We either Entered M3 or we did M3->M0 Exit */
	if (mhi_dev->pm_state != MHI_PM_M1)
		goto invalid_pm_state;

	mhi_log(mhi_dev, MHI_MSG_INFO, "Transitioning to M2 Transition\n");
	cur_state = mhi_tryset_pm_state(mhi_dev, MHI_PM_M1_M2_TRANSITION);
	if (unlikely(cur_state != MHI_PM_M1_M2_TRANSITION)) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Failed to transition to state 0x%x from 0x%x\n",
			MHI_PM_M1_M2_TRANSITION, cur_state);
		goto invalid_pm_state;
	}

	mhi_dev->dev_state = MHI_STATE_M2;
	mhi_set_m_state(mhi_dev, MHI_STATE_M2);
	write_unlock_irq(&mhi_dev->pm_lock);

	usleep_range(MHI_M2_DEBOUNCE_TMR_US, MHI_M2_DEBOUNCE_TMR_US + 50);
	write_lock_irq(&mhi_dev->pm_lock);

	/* During DEBOUNCE Time We could be receiving M0 Event */
	if (mhi_dev->pm_state == MHI_PM_M1_M2_TRANSITION) {
		mhi_log(mhi_dev, MHI_MSG_INFO, "Entered M2 State\n");
		cur_state = mhi_tryset_pm_state(mhi_dev, MHI_PM_M2);
		if (unlikely(cur_state != MHI_PM_M2)) {
			mhi_log(mhi_dev, MHI_MSG_ERROR,
				"Failed to transition to state 0x%x from 0x%x\n",
				MHI_PM_M2, cur_state);
			goto invalid_pm_state;
		}
	}
	write_unlock_irq(&mhi_dev->pm_lock);

	if (unlikely(atomic_read(&mhi_dev->dev_wake))) {
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Exiting M2 Immediately, count:%d\n",
			atomic_read(&mhi_dev->dev_wake));
		read_lock_bh(&mhi_dev->pm_lock);
		mhi_dev->assert_wake(mhi_dev, true);
		mhi_dev->deassert_wake(mhi_dev, false);
		read_unlock_bh(&mhi_dev->pm_lock);
	} else if (mhi_dev->pci_master) {
		mhi_log(mhi_dev, MHI_MSG_INFO, "Schedule RPM suspend");
		pm_runtime_mark_last_busy(&mhi_dev->pci_dev->dev);
		pm_request_autosuspend(&mhi_dev->pci_dev->dev);
	}

	mutex_unlock(&mhi_dev->mutex);
	return;

invalid_pm_state:
	write_unlock_irq(&mhi_dev->pm_lock);
	mutex_unlock(&mhi_dev->mutex);
}

int process_m3_transition(struct mhi_device *mhi_dev)
{
	unsigned long flags;
	enum MHI_PM_STATE cur_state;

	mhi_log(mhi_dev, MHI_MSG_INFO, "Entered with State %s\n",
		TO_MHI_STATE_STR(mhi_dev->dev_state));

	write_lock_irqsave(&mhi_dev->pm_lock, flags);
	mhi_dev->dev_state = MHI_STATE_M3;
	cur_state = mhi_tryset_pm_state(mhi_dev, MHI_PM_M3);
	write_unlock_irqrestore(&mhi_dev->pm_lock, flags);
	if (unlikely(cur_state != MHI_PM_M3)) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Failed to transition to state 0x%x from 0x%x\n",
			MHI_PM_M3, cur_state);
		return -EIO;
	}
	wake_up(&mhi_dev->state_event);
	return 0;
}

int process_reset_transition(struct mhi_device *mhi_dev)
{
	int ret = 0;
	int i;
	enum MHI_PM_STATE cur_state;
	struct mhi_event *mhi_event;

	mhi_log(mhi_dev, MHI_MSG_INFO, "Processing RESET state transition\n");
	write_lock_irq(&mhi_dev->pm_lock);
	mhi_dev->dev_state = MHI_STATE_RESET;
	cur_state = mhi_tryset_pm_state(mhi_dev, MHI_PM_POR);
	write_unlock_irq(&mhi_dev->pm_lock);
	if (unlikely(cur_state != MHI_PM_POR)) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Error transitining from state:0x%x to:0x%x\n",
			cur_state, MHI_PM_POR);
		return -EIO;
	}

	/* wait till device exit reset state */
	ret = mhi_test_for_device_reset(mhi_dev, false);
	if (ret) {
		mhi_log(mhi_dev, MHI_MSG_ERROR, "Device still in reset\n");
		return -EIO;

	}

	/* wait till device enter ready state */
	ret = mhi_test_for_device_ready(mhi_dev);
	if (ret) {
		mhi_log(mhi_dev, MHI_MSG_ERROR,
			"Timed out waiting for ready\n");
		return ret;
	}

	/* device in ready, program MMIO register */
 	write_lock_irq(&mhi_dev->pm_lock);
	mhi_dev->dev_state = MHI_STATE_READY;
	write_unlock_irq(&mhi_dev->pm_lock);

	read_lock_bh(&mhi_dev->pm_lock);
	if (!MHI_REG_ACCESS_VALID(mhi_dev->pm_state)) {
		read_unlock_bh(&mhi_dev->pm_lock);
		return -EIO;
	}

	/* init device mmio space */
	ret = mhi_init_mmio(mhi_dev);
	if (ret) {
		mhi_log(mhi_dev, MHI_MSG_ERROR, "Error init dev mmio\n");
		read_unlock_bh(&mhi_dev->pm_lock);
		return -EIO;
	}

	/* add elements to all SW event rings */
	for (i = 0; i < mhi_dev->ev_rings; i++) {
		struct mhi_ring *ring;

		mhi_event = &mhi_dev->mhi_event[i];
		if (mhi_event->class == MHI_HW_RING)
			continue;

		ring = &mhi_event->ring;
		ring->wp = ring->base + ring->len - ring->el_size;
		smp_wmb();
		spin_lock_irq(&mhi_event->lock);
		mhi_ring_er_db(mhi_event);
		spin_unlock_irq(&mhi_event->lock);
	}

	/* put device into M0 state */
	mhi_write_reg_field(mhi_dev, mhi_dev->regs, MHICTRL,
			    MHICTRL_MHISTATE_MASK, MHICTRL_MHISTATE_SHIFT,
			    MHI_STATE_M0);
	read_unlock_bh(&mhi_dev->pm_lock);

	return 0;
}

static void enable_clients(struct mhi_device *mhi_dev)
{
	int i = 0;
	struct mhi_chan *mhi_chan;

	mhi_log(mhi_dev, MHI_MSG_INFO, "Enabling Clients, exec env:%s.\n",
		TO_MHI_EXEC_STR(mhi_dev->dev_exec_env));

	mhi_chan = mhi_dev->mhi_chan;
	for (i = 0; i < MHI_MAX_CHANNELS; i++, mhi_chan++) {
		if (!mhi_chan->cldata)
			continue;
		if (mhi_chan->exec_env == mhi_dev->dev_exec_env)
			mhi_notify_client(mhi_dev, mhi_chan,
					  MHI_CB_MHI_ENABLED);
	}

	mhi_log(mhi_dev, MHI_MSG_INFO, "Done.\n");
}

static int process_amss_transition(struct mhi_device *mhi_dev)
{
	struct mhi_event *mhi_event;
	struct mhi_ring *ring;
	int i;

	mhi_log(mhi_dev, MHI_MSG_INFO, "Processing AMSS state transition\n");

	write_lock_irq(&mhi_dev->pm_lock);
	mhi_dev->dev_exec_env = MHI_EXEC_ENV_AMSS;
	write_unlock_irq(&mhi_dev->pm_lock);
	wake_up_interruptible(&mhi_dev->state_event);

	/* add elements to all HW event rings */
	read_lock_bh(&mhi_dev->pm_lock);
	if (!MHI_REG_ACCESS_VALID(mhi_dev->pm_state)) {
		read_unlock_bh(&mhi_dev->pm_lock);
		return -EIO;
	}

	for (i = 0; i < mhi_dev->ev_rings; i++) {
		mhi_event = &mhi_dev->mhi_event[i];
		ring = &mhi_event->ring;

		if (mhi_event->class == MHI_SW_RING)
			continue;

		ring->wp = ring->base + ring->len - ring->el_size;
		smp_wmb();
		spin_lock_irq(&mhi_event->lock);
		mhi_ring_er_db(mhi_event);
		spin_unlock_irq(&mhi_event->lock);

	}
	read_unlock_bh(&mhi_dev->pm_lock);

	enable_clients(mhi_dev);

	/*
	 * runtime_allow will decrement usage_count, counts were
	 * incremented by pci fw pci_pm_init() or by
	 * mhi shutdown/ssr apis.
	 */
	if (mhi_dev->pci_master) {
		mhi_log(mhi_dev, MHI_MSG_INFO, "Allow runtime suspend\n");

		pm_runtime_mark_last_busy(&mhi_dev->pci_dev->dev);
		pm_runtime_allow(&mhi_dev->pci_dev->dev);
	}

	/* during probe we incremented, releasing that count */
	read_lock_bh(&mhi_dev->pm_lock);
	mhi_dev->deassert_wake(mhi_dev, false);
	read_unlock_bh(&mhi_dev->pm_lock);

	mhi_log(mhi_dev, MHI_MSG_INFO, "Exited\n");
	return 0;
}

//FIXME: change argument so mhi_device is first argument

/* handles sys_err, and shutdown transition */
void process_disable_transition(enum MHI_PM_STATE transition_state,
				struct mhi_device *mhi_dev)
{
	enum MHI_PM_STATE cur_state, prev_state;
	struct mhi_chan *mhi_chan;
	struct mhi_event *mhi_event;
	struct mhi_event_ctxt *er_ctxt;
	enum MHI_CB_REASON reason;
	int i;
	int ret;
	rwlock_t *pm_lock = &mhi_dev->pm_lock;
	u32 timeout = mhi_dev->poll_timeout;

	mhi_log(mhi_dev, MHI_MSG_INFO,
		"Enter with pm_state:0x%x MHI_STATE:%s transition_state:0x%x\n",
		mhi_dev->pm_state, TO_MHI_STATE_STR(mhi_dev->dev_state),
		transition_state);

	mutex_lock(&mhi_dev->mutex);
	write_lock_irq(pm_lock);
	prev_state = mhi_dev->pm_state;
	cur_state = mhi_tryset_pm_state(mhi_dev, transition_state);
	if (cur_state == transition_state)
		mhi_dev->dev_exec_env = MHI_EXEC_ENV_DISABLE_TRANSITION;
	write_unlock_irq(pm_lock);

	/* Not handling sys_err, could be middle of shut down */
	if (unlikely(cur_state != transition_state)) {
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Failed to transition to state 0x%x from 0x%x\n",
			transition_state, cur_state);
		mutex_unlock(&mhi_dev->mutex);
		return;
	}

	/*
	 * If we're shutting down trigger device into MHI reset
	 * so we can gurantee device will not access host DDR
	 * during reset
	 */
	if (cur_state == MHI_PM_SHUTDOWN_PROCESS &&
	    MHI_REG_ACCESS_VALID(prev_state)) {
		read_lock_bh(pm_lock);
		mhi_set_m_state(mhi_dev, MHI_STATE_RESET);
		read_unlock_bh(pm_lock);
		mhi_test_for_device_reset(mhi_dev, true);
	}

	mhi_log(mhi_dev, MHI_MSG_INFO,
		"Waiting for all pending event ring processing to complete\n");
	mhi_event = mhi_dev->mhi_event;
	for (i = 0; i < mhi_dev->ev_rings; i++, mhi_event++) {
		tasklet_kill(&mhi_event->task);
		flush_work(&mhi_event->worker);
	}
	mhi_log(mhi_dev, MHI_MSG_INFO,
		"Notifying all clients and resetting channels\n");

	if (cur_state == MHI_PM_SHUTDOWN_PROCESS)
		reason = MHI_CB_MHI_SHUTDOWN;
	else
		reason = MHI_CB_SYS_ERROR;

	mhi_chan = mhi_dev->mhi_chan;
	for (i = 0; i < MHI_MAX_CHANNELS; i++, mhi_chan++) {
		enum MHI_CHAN_STATE ch_state;

       		if (mhi_chan->cldata)
			mhi_notify_client(mhi_dev, mhi_chan, reason);

		mutex_lock(&mhi_chan->mutex);
		write_lock_irq(&mhi_chan->lock);
		ch_state = mhi_chan->ch_state;
		mhi_chan->ch_state = MHI_CHAN_STATE_DISABLED;
		write_unlock_irq(&mhi_chan->lock);

		/* reset channel and free ring */
		if (ch_state == MHI_CHAN_STATE_ENABLED) {
			mhi_reset_chan(mhi_dev, mhi_chan);
			mhi_deinit_chan_ctxt(mhi_dev, mhi_chan);
		}
		mutex_unlock(&mhi_chan->mutex);
	}
	mhi_log(mhi_dev, MHI_MSG_INFO, "Finished notifying clients\n");

	/* Release lock and wait for all pending threads to complete */
	mutex_unlock(&mhi_dev->mutex);
	mhi_log(mhi_dev, MHI_MSG_INFO,
		"Waiting for all pending threads to complete\n");
	flush_work(&mhi_dev->m1_worker);
	flush_work(&mhi_dev->st_worker);
	//if (mhi_dev->dl_fw)
	//	flush_work(&mhi_dev_ctxt->bhi_ctxt.fw_load_work);
	if (cur_state == MHI_PM_SHUTDOWN_PROCESS)
		flush_work(&mhi_dev->sys_err_worker);

	mutex_lock(&mhi_dev->mutex);

	/*
	 * Shutdown has higher priority than sys_err and can be called
	 * middle of sys error, check current state to confirm state
	 * was not changed.
	 */
	if (mhi_dev->pm_state != cur_state) {
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"PM State transitioned to 0x%x while processing 0x%x\n",
			mhi_dev->pm_state, transition_state);
		mutex_unlock(&mhi_dev->mutex);
		return;
	}

	/* Check all counts to make sure 0 */
	WARN_ON(atomic_read(&mhi_dev->dev_wake));
	WARN_ON(atomic_read(&mhi_dev->pending_acks));
	if (mhi_dev->pci_master)
		WARN_ON(atomic_read(&mhi_dev->pci_dev->dev.power.usage_count));

	/* Reset Event rings and CMD rings  */
	mhi_log(mhi_dev, MHI_MSG_INFO, "Resetting ev ctxt and cmd ctxt\n");

	for (i = 0; i < NR_OF_CMD_RINGS; i++) {
		struct __packed mhi_cmd_ctxt *cmd_ctxt =
			&mhi_dev->mhi_ctxt.cmd_ctxt[i];
		struct mhi_ring *ring = &mhi_dev->mhi_cmd[i];

		cmd_ctxt->rp = cmd_ctxt->wp = cmd_ctxt->rbase;
		ring->rp = ring->wp = ring->base;
	}

	er_ctxt = mhi_dev->mhi_ctxt.er_ctxt;
	mhi_event = mhi_dev->mhi_event;
	for (i = 0; i < mhi_dev->ev_rings; i++, er_ctxt++, mhi_event++) {
		mhi_event->ring.rp = mhi_event->ring.wp = mhi_event->ring.base;
		er_ctxt->rp = er_ctxt->wp = er_ctxt->rbase;
	}

	/*
	 * If we're the bus master disable runtime suspend
	 * we will enable it back again during AMSS transition
	 */
	if (mhi_dev->pci_master)
		pm_runtime_forbid(&mhi_dev->pci_dev->dev);

	if (cur_state == MHI_PM_SYS_ERR_PROCESS) {
		bool trigger_reset = false;

		mhi_log(mhi_dev, MHI_MSG_INFO, "Triggering device reset\n");
		write_lock_irq(pm_lock);
		/* Link can go down while processing SYS_ERR */
		if (MHI_REG_ACCESS_VALID(mhi_dev->pm_state)) {
			mhi_set_m_state(mhi_dev, MHI_STATE_RESET);
			mhi_queue_state_transition(mhi_dev,
						   STATE_TRANSITION_RESET);
			trigger_reset = true;
		}
		write_unlock_irq(pm_lock);

		if (trigger_reset) {
			/*
			 * Keep the MHI state in Active (M0) state until host
			 * enter AMSS/RDDM state.  Otherwise modem would error
			 * fatal if host try to enter M1 before reaching
			 * AMSS\RDDM state.
			 */
			read_lock_bh(pm_lock);
			mhi_assert_device_wake(mhi_dev, false);
			read_unlock_bh(pm_lock);

			/* Wait till we enter AMSS/RDDM Exec env.*/
			ret = wait_event_timeout(mhi_dev->state_event,
				mhi_dev->dev_exec_env == MHI_EXEC_ENV_AMSS ||
				mhi_dev->dev_exec_env == MHI_EXEC_ENV_RDDM,
				msecs_to_jiffies(timeout));
			if (mhi_dev->dev_exec_env != MHI_EXEC_ENV_AMSS &&
			    mhi_dev->dev_exec_env != MHI_EXEC_ENV_RDDM) {

				/*
				 * device did not reset properly, notify bus
				 * master
				 */
				if (!mhi_dev->pci_master) {
					mhi_log(mhi_dev, MHI_MSG_INFO,
						"Notifying bus master Sys Error Status\n");
					mhi_dev->status_cb(MHI_CB_SYS_ERROR,
							   mhi_dev->priv_data);
				}
				mhi_dev->deassert_wake(mhi_dev, false);
			}
		}
	} else {
		/* shutdown process */
		write_lock_irq(pm_lock);
		cur_state = mhi_tryset_pm_state(mhi_dev, MHI_PM_DISABLE);
		write_unlock_irq(pm_lock);
		if (unlikely(cur_state != MHI_PM_DISABLE))
			mhi_log(mhi_dev, MHI_MSG_ERROR,
				"Error transition from state:0x%x to 0x%x\n",
				cur_state, MHI_PM_DISABLE);

		if (mhi_dev->pci_master &&
		    cur_state == MHI_PM_DISABLE)
			mhi_arch_link_off(mhi_dev,
					  MHI_REG_ACCESS_VALID(prev_state));
	}

	mhi_log(mhi_dev, MHI_MSG_INFO,
		"Exit with pm_state:0x%x exec_env:%s mhi_state:%s\n",
		mhi_dev->pm_state, TO_MHI_EXEC_STR(mhi_dev->dev_exec_env),
		TO_MHI_STATE_STR(mhi_dev->dev_state));

	mutex_unlock(&mhi_dev->mutex);
}

void mhi_sys_err_worker(struct work_struct *work)
{
	struct mhi_device *mhi_dev = container_of(work, struct mhi_device,
						  sys_err_worker);

	mhi_log(mhi_dev, MHI_MSG_INFO,
		"Enter with pm_state:0x%x MHI_STATE:%s\n",
		mhi_dev->pm_state, TO_MHI_STATE_STR(mhi_dev->dev_state));

	process_disable_transition(MHI_PM_SYS_ERR_PROCESS, mhi_dev);
}


void mhi_state_change_worker(struct work_struct *work)
{
	enum STATE_TRANSITION cur_work_item;
	struct mhi_device *mhi_dev = container_of(work, struct mhi_device,
						  st_worker);
	struct mhi_ring *ring = &mhi_dev->work_ring;;

	while (ring->rp != ring->wp) {
		cur_work_item = *(enum STATE_TRANSITION *)(ring->rp);
		mhi_del_ring_element(mhi_dev, ring);

		mhi_log(mhi_dev, MHI_MSG_INFO, "Transitioning to state :%s\n",
			state_transition_str(cur_work_item));

		switch (cur_work_item) {
		case STATE_TRANSITION_BHI:
			write_lock_irq(&mhi_dev->pm_lock);
			mhi_dev->dev_exec_env = MHI_EXEC_ENV_PBL;
			write_unlock_irq(&mhi_dev->pm_lock);
			wake_up(&mhi_dev->state_event);
			break;
		case STATE_TRANSITION_RESET:
			process_reset_transition(mhi_dev);
			break;
		case STATE_TRANSITION_SBL:
			write_lock_irq(&mhi_dev->pm_lock);
			mhi_dev->dev_exec_env = MHI_EXEC_ENV_SBL;
			write_unlock_irq(&mhi_dev->pm_lock);
			enable_clients(mhi_dev);
			break;
		case STATE_TRANSITION_AMSS:
			process_amss_transition(mhi_dev);
			break;
		case STATE_TRANSITION_BHIE:
			write_lock_irq(&mhi_dev->pm_lock);
			mhi_dev->dev_exec_env = MHI_EXEC_ENV_BHIE;
			write_unlock_irq(&mhi_dev->pm_lock);
			wake_up(&mhi_dev->state_event);
			break;
		case STATE_TRANSITION_RDDM:
			write_lock_irq(&mhi_dev->pm_lock);
			mhi_dev->dev_exec_env = MHI_EXEC_ENV_RDDM;
			mhi_dev->deassert_wake(mhi_dev, false);
			write_unlock_irq(&mhi_dev->pm_lock);

			/* Notify bus master device entered rddm mode */
			if (!mhi_dev->pci_master) {
				mhi_log(mhi_dev, MHI_MSG_INFO,
					"Notifying bus master RDDM Status\n");
				mhi_dev->status_cb(MHI_CB_RDDM, mhi_dev->priv_data);
			}
			break;
		default:
			mhi_log(mhi_dev, MHI_MSG_ERROR,
				"Unrecongized state: %s\n",
				state_transition_str(cur_work_item));
		}
	}
}

int mhi_test_for_device_ready(struct mhi_device *mhi_dev)
{
	u32 val = 0;
	rwlock_t *pm_lock = &mhi_dev->pm_lock;
	unsigned long timeout;

	mhi_log(mhi_dev, MHI_MSG_INFO, "Waiting for Ready bit to be set\n");

	timeout = jiffies +
		msecs_to_jiffies(mhi_dev->poll_timeout);
	while (time_before(jiffies, timeout)) {
		/* poll for READY bit to be set */
		read_lock_bh(pm_lock);
		if (!MHI_REG_ACCESS_VALID(mhi_dev->pm_state)) {
			read_unlock_bh(pm_lock);
			return -EIO;
		}

		val = mhi_read_reg_field(mhi_dev, mhi_dev->regs, MHISTATUS,
					 MHISTATUS_READY_MASK,
					 MHISTATUS_READY_SHIFT);
		read_unlock_bh(pm_lock);
		if (PCI_INVALID_READ(val)) {
			mhi_log(mhi_dev, MHI_MSG_ERROR,
				"Invalid value read from pci bus\n");
			return -EIO;
		}

		if (val == MHI_STATE_READY)
			return 0;
		mhi_log(mhi_dev, MHI_MSG_INFO,
			"Device is not ready, sleeping and retrying.\n");
		msleep(MHI_THREAD_SLEEP_TIMEOUT_MS);
	}
	mhi_log(mhi_dev, MHI_MSG_ERROR, "Device timed out waiting for ready\n");

	return -ETIMEDOUT;
}

int mhi_test_for_device_reset(struct mhi_device *mhi_dev, bool frm_shutdown)
{
	u32 val = 0;
	rwlock_t *pm_lock = &mhi_dev->pm_lock;
	unsigned long timeout;

	mhi_log(mhi_dev, MHI_MSG_INFO,
		"Waiting for MMIO RESET bit to be cleared.\n");

	timeout = jiffies +
		msecs_to_jiffies(mhi_dev->poll_timeout);
	while (time_before(jiffies, timeout)) {
		read_lock_bh(pm_lock);
		if (!MHI_REG_ACCESS_VALID(mhi_dev->pm_state)) {
			read_unlock_bh(pm_lock);
			return -EIO;
		}

		/*
		 * If we're not calling from shutdown path check to see
		 * if we transition to error state while polling.
		 */
		if (!frm_shutdown &&
		    mhi_dev->pm_state >= MHI_PM_SYS_ERR_DETECT) {
			read_unlock_bh(pm_lock);
			return -EIO;
		}
		val = mhi_read_reg_field(mhi_dev, mhi_dev->regs, MHICTRL,
					 MHICTRL_RESET_MASK,
					 MHICTRL_RESET_SHIFT);
		read_unlock_bh(pm_lock);

		if (PCI_INVALID_READ(val)) {
			mhi_log(mhi_dev, MHI_MSG_ERROR,
				"Invalid value read from pcie bus\n");
			return -EIO;
		}

		if (!val)
			return 0;

		mhi_log(mhi_dev, MHI_MSG_INFO, "MHI still in Reset sleeping\n");
		msleep(MHI_THREAD_SLEEP_TIMEOUT_MS);
	}

	mhi_log(mhi_dev, MHI_MSG_ERROR,
		"Timeout waiting for reset to be cleared\n");
	return -ETIMEDOUT;
}

enum MHI_EXEC_ENV mhi_get_exec_env(struct mhi_device *mhi_dev)
{
	u32 exec = mhi_read_reg(mhi_dev, mhi_dev->bhi, BHI_EXECENV);

	if (PCI_INVALID_READ(exec))
		return MHI_EXEC_INVALID;

	return (exec > MHI_EXEC_MAX_SUPPORTED) ? MHI_EXEC_INVALID : exec;
}

void mhi_queue_state_transition(struct mhi_device *mhi_dev,
				enum STATE_TRANSITION transition)
{
	struct mhi_ring *ring = &mhi_dev->work_ring;

	//FIXME: Add  a lock
	if (likely(get_nr_avail_ring_elements(mhi_dev, ring))) {
		*(enum STATE_TRANSITION *)ring->wp = transition;
		mhi_add_ring_element(mhi_dev, ring);
		schedule_work(&mhi_dev->st_worker);
	}
}
