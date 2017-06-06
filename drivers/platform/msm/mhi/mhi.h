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

#ifndef _H_MHI
#define _H_MHI

#include <linux/msm_mhi.h>
#include <linux/types.h>
#include <linux/pm.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/irqreturn.h>
#include <linux/list.h>
#include <linux/dma-mapping.h>

/* MHI MMIO Register Mapping */
#define MHIREGLEN (0x0)
#define MHIREGLEN_MHIREGLEN_MASK 0xffffffff
#define MHIREGLEN_MHIREGLEN_SHIFT 0x0

#define MHIVER (0x8)
#define MHIVER_MHIVER_MASK 0xffffffff
#define MHIVER_MHIVER_SHIFT 0x0

#define MHICFG (0x10)
#define MHICFG_NHWER_MASK (0xff000000)
#define MHICFG_NHWER_SHIFT (24)
#define MHICFG_NER_MASK (0xff0000)
#define MHICFG_NER_SHIFT (16)
#define MHICFG_NHWCH_MASK (0xff00)
#define MHICFG_NHWCH_SHIFT (8)
#define MHICFG_NCH_MASK (0xff)
#define MHICFG_NCH_SHIFT (0)

#define CHDBOFF (0x18)
#define CHDBOFF_CHDBOFF_MASK 0xffffffff
#define CHDBOFF_CHDBOFF_SHIFT 0x0

#define ERDBOFF (0x20)
#define ERDBOFF_ERDBOFF_MASK 0xffffffff
#define ERDBOFF_ERDBOFF_SHIFT 0x0

#define BHIOFF (0x28)
#define BHIOFF_BHIOFF_MASK 0xffffffff
#define BHIOFF_BHIOFF_SHIFT 0x0

#define DEBUGOFF (0x30)
#define DEBUGOFF_DEBUGOFF_MASK 0xffffffff
#define DEBUGOFF_DEBUGOFF_SHIFT 0x0

#define MHICTRL (0x38)
#define MHICTRL_MHISTATE_MASK 0x0000FF00
#define MHICTRL_MHISTATE_SHIFT 0x8
#define MHICTRL_RESET_MASK 0x2
#define MHICTRL_RESET_SHIFT 0x1

#define MHISTATUS (0x48)
#define MHISTATUS_MHISTATE_MASK 0x0000ff00
#define MHISTATUS_MHISTATE_SHIFT 0x8
#define MHISTATUS_SYSERR_MASK 0x4
#define MHISTATUS_SYSERR_SHIFT 0x2
#define MHISTATUS_READY_MASK 0x1
#define MHISTATUS_READY_SHIFT 0x0

#define CCABAP_LOWER (0x58)
#define CCABAP_LOWER_CCABAP_LOWER_MASK 0xffffffff
#define CCABAP_LOWER_CCABAP_LOWER_SHIFT 0x0

#define CCABAP_HIGHER (0x5c)
#define CCABAP_HIGHER_CCABAP_HIGHER_MASK 0xffffffff
#define CCABAP_HIGHER_CCABAP_HIGHER_SHIFT 0x0

#define ECABAP_LOWER (0x60)
#define ECABAP_LOWER_ECABAP_LOWER_MASK 0xffffffff
#define ECABAP_LOWER_ECABAP_LOWER_SHIFT 0x0

#define ECABAP_HIGHER (0x64)
#define ECABAP_HIGHER_ECABAP_HIGHER_MASK 0xffffffff
#define ECABAP_HIGHER_ECABAP_HIGHER_SHIFT 0x0

#define CRCBAP_LOWER (0x68)
#define CRCBAP_LOWER_CRCBAP_LOWER_MASK 0xffffffff
#define CRCBAP_LOWER_CRCBAP_LOWER_SHIFT 0x0

#define CRCBAP_HIGHER (0x6c)
#define CRCBAP_HIGHER_CRCBAP_HIGHER_MASK 0xffffffff
#define CRCBAP_HIGHER_CRCBAP_HIGHER_SHIFT 0x0

#define CRDB_LOWER (0x70)
#define CRDB_LOWER_CRDB_LOWER_MASK 0xffffffff
#define CRDB_LOWER_CRDB_LOWER_SHIFT 0x0

#define CRDB_HIGHER (0x74)
#define CRDB_HIGHER_CRDB_HIGHER_MASK 0xffffffff
#define CRDB_HIGHER_CRDB_HIGHER_SHIFT 0x0

#define MHICTRLBASE_LOWER (0x80)
#define MHICTRLBASE_LOWER_MHICTRLBASE_LOWER_MASK 0xffffffff
#define MHICTRLBASE_LOWER_MHICTRLBASE_LOWER_SHIFT 0x0

#define MHICTRLBASE_HIGHER (0x84)
#define MHICTRLBASE_HIGHER_MHICTRLBASE_HIGHER_MASK 0xffffffff
#define MHICTRLBASE_HIGHER_MHICTRLBASE_HIGHER_SHIFT 0x0

#define MHICTRLLIMIT_LOWER (0x88)
#define MHICTRLLIMIT_LOWER_MHICTRLLIMIT_LOWER_MASK 0xffffffff
#define MHICTRLLIMIT_LOWER_MHICTRLLIMIT_LOWER_SHIFT 0x0

#define MHICTRLLIMIT_HIGHER (0x8c)
#define MHICTRLLIMIT_HIGHER_MHICTRLLIMIT_HIGHER_MASK 0xffffffff
#define MHICTRLLIMIT_HIGHER_MHICTRLLIMIT_HIGHER_SHIFT 0x0

#define MHIDATABASE_LOWER (0x98)
#define MHIDATABASE_LOWER_MHIDATABASE_LOWER_MASK 0xffffffff
#define MHIDATABASE_LOWER_MHIDATABASE_LOWER_SHIFT 0x0

#define MHIDATABASE_HIGHER (0x9c)
#define MHIDATABASE_HIGHER_MHIDATABASE_HIGHER_MASK 0xffffffff
#define MHIDATABASE_HIGHER_MHIDATABASE_HIGHER_SHIFT 0x0

#define MHIDATALIMIT_LOWER (0xa0)
#define MHIDATALIMIT_LOWER_MHIDATALIMIT_LOWER_MASK 0xffffffff
#define MHIDATALIMIT_LOWER_MHIDATALIMIT_LOWER_SHIFT 0x0

#define MHIDATALIMIT_HIGHER (0xa4)
#define MHIDATALIMIT_HIGHER_MHIDATALIMIT_HIGHER_MASK 0xffffffff
#define MHIDATALIMIT_HIGHER_MHIDATALIMIT_HIGHER_SHIFT 0x0

#define CHDB_LOWER_n(n) (0x0400 + 0x8 * (n))
#define CHDB_LOWER_n_CHDB_LOWER_MASK 0xffffffff
#define CHDB_LOWER_n_CHDB_LOWER_SHIFT 0x0

#define CHDB_HIGHER_n(n) (0x0404 + 0x8 * (n))
#define CHDB_HIGHER_n_CHDB_HIGHER_MASK 0xffffffff
#define CHDB_HIGHER_n_CHDB_HIGHER_SHIFT 0x0

#define ERDB_LOWER_n(n) (0x0800 + 0x8 * (n))
#define ERDB_LOWER_n_ERDB_LOWER_MASK 0xffffffff
#define ERDB_LOWER_n_ERDB_LOWER_SHIFT 0x0

#define ERDB_HIGHER_n(n) (0x0804 + 0x8 * (n))
#define ERDB_HIGHER_n_ERDB_HIGHER_MASK 0xffffffff
#define ERDB_HIGHER_n_ERDB_HIGHER_SHIFT 0x0

/* BHI Offsets */
#define BHI_BHIVERSION_MINOR                               (0x00)
#define BHI_BHIVERSION_MAJOR                               (0x04)
#define BHI_IMGADDR_LOW                                    (0x08)
#define BHI_IMGADDR_HIGH                                   (0x0C)
#define BHI_IMGSIZE                                        (0x10)
#define BHI_RSVD1                                          (0x14)
#define BHI_IMGTXDB                                        (0x18)
#define BHI_RSVD2                                          (0x1C)
#define BHI_INTVEC                                         (0x20)
#define BHI_RSVD3                                          (0x24)
#define BHI_EXECENV                                        (0x28)
#define BHI_STATUS                                         (0x2C)
#define BHI_ERRCODE                                        (0x30)
#define BHI_ERRDBG1                                        (0x34)
#define BHI_ERRDBG2                                        (0x38)
#define BHI_ERRDBG3                                        (0x3C)
#define BHI_SERIALNUM                                      (0x40)
#define BHI_SBLANTIROLLVER                                 (0x44)
#define BHI_NUMSEG                                         (0x48)
#define BHI_MSMHWID(n)                                     (0x4C + 0x4 * (n))
#define BHI_OEMPKHASH(n)                                   (0x64 + 0x4 * (n))
#define BHI_RSVD5                                          (0xC4)
#define BHI_STATUS_MASK					   (0xC0000000)
#define BHI_STATUS_SHIFT				   (30)
#define BHI_STATUS_ERROR				   (3)
#define BHI_STATUS_SUCCESS				   (2)
#define BHI_STATUS_RESET				   (0)

/* BHIE Offsets */
#define BHIE_OFFSET (0x0124) /* BHIE register space offset from BHI base */
#define BHIE_MSMSOCID_OFFS (BHIE_OFFSET + 0x0000)
#define BHIE_TXVECADDR_LOW_OFFS (BHIE_OFFSET + 0x002C)
#define BHIE_TXVECADDR_HIGH_OFFS (BHIE_OFFSET + 0x0030)
#define BHIE_TXVECSIZE_OFFS (BHIE_OFFSET + 0x0034)
#define BHIE_TXVECDB_OFFS (BHIE_OFFSET + 0x003C)
#define BHIE_TXVECDB_SEQNUM_BMSK (0x3FFFFFFF)
#define BHIE_TXVECDB_SEQNUM_SHFT (0)
#define BHIE_TXVECSTATUS_OFFS (BHIE_OFFSET + 0x0044)
#define BHIE_TXVECSTATUS_SEQNUM_BMSK (0x3FFFFFFF)
#define BHIE_TXVECSTATUS_SEQNUM_SHFT (0)
#define BHIE_TXVECSTATUS_STATUS_BMSK (0xC0000000)
#define BHIE_TXVECSTATUS_STATUS_SHFT (30)
#define BHIE_TXVECSTATUS_STATUS_RESET (0x00)
#define BHIE_TXVECSTATUS_STATUS_XFER_COMPL (0x02)
#define BHIE_TXVECSTATUS_STATUS_ERROR (0x03)
#define BHIE_RXVECADDR_LOW_OFFS (BHIE_OFFSET + 0x0060)
#define BHIE_RXVECADDR_HIGH_OFFS (BHIE_OFFSET + 0x0064)
#define BHIE_RXVECSIZE_OFFS (BHIE_OFFSET + 0x0068)
#define BHIE_RXVECDB_OFFS (BHIE_OFFSET + 0x0070)
#define BHIE_RXVECDB_SEQNUM_BMSK (0x3FFFFFFF)
#define BHIE_RXVECDB_SEQNUM_SHFT (0)
#define BHIE_RXVECSTATUS_OFFS (BHIE_OFFSET + 0x0078)
#define BHIE_RXVECSTATUS_SEQNUM_BMSK (0x3FFFFFFF)
#define BHIE_RXVECSTATUS_SEQNUM_SHFT (0)
#define BHIE_RXVECSTATUS_STATUS_BMSK (0xC0000000)
#define BHIE_RXVECSTATUS_STATUS_SHFT (30)
#define BHIE_RXVECSTATUS_STATUS_RESET (0x00)
#define BHIE_RXVECSTATUS_STATUS_XFER_COMPL (0x02)
#define BHIE_RXVECSTATUS_STATUS_ERROR (0x03)

#define BHI_MAJOR_VERSION 0x0
#define BHI_MINOR_VERSION 0x1

#define MSMHWID_NUMDWORDS 6    /* Number of dwords that make the MSMHWID */
#define OEMPKHASH_NUMDWORDS 24 /* Number of dwords that make the OEM PK HASH */

#define BHI_POLL_SLEEP_TIME_MS 100
#define FW_POLL_SLEEP_TIME_MS 500
#define BHI_POLL_TIMEOUT_MS 2000
#define BHIE_RDDM_DELAY_TIME_US (1000)

#define MHI_DEV_WAKE_DB 127


enum MHI_DEBUG_LEVEL {
	MHI_MSG_RAW = 0x1,
	MHI_MSG_VERBOSE = 0x2,
	MHI_MSG_INFO = 0x4,
	MHI_MSG_DBG = 0x8,
	MHI_MSG_WARNING = 0x10,
	MHI_MSG_ERROR = 0x20,
	MHI_MSG_CRITICAL = 0x40,
	MHI_MSG_reserved = 0x80000000
};

struct firmware_info {
	const char *fw_image;
	size_t max_sbl_len;
	size_t segment_size;
};

struct bhie_mem_info {
	void *pre_aligned;
	void *aligned;
	size_t alloc_size;
	size_t size;
	phys_addr_t phys_addr;
	dma_addr_t dma_handle;
};

struct bhie_vec_table {
	struct scatterlist *sg_list;
	struct bhie_mem_info *bhie_mem_info;
	struct bhi_vec_entry *bhi_vec_entry;
	unsigned segment_count;
	u32 sequence; /* sequence to indicate new xfer */
};

enum MHI_RING_CLASS {
	MHI_RING_INVALID = 0x0,
	MHI_HW_RING = 0x1,
	MHI_SW_RING = 0x2,
	MHI_RING_TYPE_reserved = 0x80000000
};

enum MHI_CHAN_STATE {
	MHI_CHAN_STATE_DISABLED = 0x0,
	MHI_CHAN_STATE_ENABLED = 0x1,
	MHI_CHAN_STATE_RUNNING = 0x2,
	MHI_CHAN_STATE_SUSPENDED = 0x3,
	MHI_CHAN_STATE_STOP = 0x4,
	MHI_CHAN_STATE_ERROR = 0x5,
	MHI_CHAN_STATE_LIMIT = 0x6,
	MHI_CHAN_STATE_reserved = 0x80000000
};

enum MHI_RING_TYPE {
	MHI_RING_TYPE_CMD_RING = 0x0,
	MHI_RING_TYPE_XFER_RING = 0x1,
	MHI_RING_TYPE_EVENT_RING = 0x2,
	MHI_RING_TYPE_MAX = 0x4,
	MHI_RING_reserved = 0x80000000
};

enum MHI_CHAIN {
	MHI_TRE_CHAIN_OFF = 0x0,
	MHI_TRE_CHAIN_ON = 0x1,
	MHI_TRE_CHAIN_LIMIT = 0x2,
	MHI_TRE_CHAIN_reserved = 0x80000000
};

enum MHI_STATE {
	MHI_STATE_RESET = 0x0,
	MHI_STATE_READY = 0x1,
	MHI_STATE_M0 = 0x2,
	MHI_STATE_M1 = 0x3,
	MHI_STATE_M2 = 0x4,
	MHI_STATE_M3 = 0x5,
	MHI_STATE_BHI  = 0x7,
	MHI_STATE_SYS_ERR  = 0xFF,
	MHI_STATE_INVALID,
	MHI_STATE_LIMIT,
};

enum MHI_BRSTMODE {
	/* BRST Mode Enable for HW Channels, SW Channel Disabled */
	MHI_BRSTMODE_DEFAULT = 0x0,
	MHI_BRSTMODE_RESERVED = 0x1,
	MHI_BRSTMODE_DISABLE = 0x2,
	MHI_BRSTMODE_ENABLE = 0x3
};

enum MHI_PM_STATE {
	MHI_PM_DISABLE = BIT(0), /* MHI is not enabled */
	MHI_PM_POR = BIT(1), /* Power On Reset State */
	MHI_PM_M0 = BIT(2),
	MHI_PM_M1 = BIT(3),
	MHI_PM_M1_M2_TRANSITION = BIT(4), /* Register access not allowed */
	MHI_PM_M2 = BIT(5),
	MHI_PM_M3_ENTER = BIT(6),
	MHI_PM_M3 = BIT(7),
	MHI_PM_M3_EXIT = BIT(8),
	MHI_PM_FW_DL_ERR = BIT(9), /* Firmware download failure state */
	MHI_PM_SYS_ERR_DETECT = BIT(10),
	MHI_PM_SYS_ERR_PROCESS = BIT(11),
	MHI_PM_SHUTDOWN_PROCESS = BIT(12),
	MHI_PM_LD_ERR_FATAL_DETECT = BIT(13), /* Link not accessible */
	MHI_PM_SSR_PENDING = BIT(14),
};

struct mhi_pm_transitions {
	enum MHI_PM_STATE from_state;
	u32 to_states;
};

enum MHI_XFER_TYPE {
	MHI_XFER_BUFFER,
	MHI_XFER_SKB,
	MHI_XFER_SCATTERLIST,
	MHI_XFER_IOMMU,
};

#define MHI_DB_ACCESS_VALID(pm_state) (pm_state & (MHI_PM_M0 | MHI_PM_M1))
#define MHI_WAKE_DB_ACCESS_VALID(pm_state) (pm_state & (MHI_PM_M0 | \
							MHI_PM_M1 | MHI_PM_M2))
#define MHI_REG_ACCESS_VALID(pm_state) ((pm_state & (MHI_PM_POR | MHI_PM_M0 | \
		MHI_PM_M1 | MHI_PM_M2 | MHI_PM_M3_ENTER | MHI_PM_M3_EXIT | \
		MHI_PM_SYS_ERR_DETECT | MHI_PM_SYS_ERR_PROCESS | \
		MHI_PM_SHUTDOWN_PROCESS | MHI_PM_FW_DL_ERR)))
#define MHI_EVENT_ACCESS_INVALID(pm_state) (pm_state == MHI_PM_DISABLE || \
					    pm_state >= MHI_PM_SYS_ERR_DETECT)
struct __packed mhi_event_ctxt {
	u32 reserved : 8;
	u32 intmodc : 8;
	u32 intmodt : 16;
	u32 ertype;
	u32 msivec;
	u64 rbase;
	u64 rlen;
	u64 rp;
	u64 wp;
};

struct __packed mhi_chan_ctxt {
	u32 chstate : 8;
	u32 brstmode : 2;
	u32 pollcfg : 6;
	u32 reserved : 16;
	u32 chtype;
	u32 erindex;
	u64 rbase;
	u64 rlen;
	u64 rp;
	u64 wp;
};

struct __packed mhi_cmd_ctxt {
	u32 reserved0;
	u32 reserved1;
	u32 reserved2;
	u64 rbase;
	u64 rlen;
	u64 rp;
	u64 wp;
};

struct __packed mhi_tre {
	u64 ptr;
	u32 dword[2];
};

/* NO OP Command */
#define MHI_TRE_CMD_NOOP_PTR (0)
#define MHI_TRE_CMD_NOOP_DWORD0 (0)
#define MHI_TRE_CMD_NOOP_DWORD1 (1 << 16)

/* Channel Reset Command */
#define MHI_TRE_CMD_RESET_PTR (0)
#define MHI_TRE_CMD_RESET_DWORD0 (0)
#define MHI_TRE_CMD_RESET_DWORD1(chid) ((chid << 24) | (16 << 16))

/* Channel Reset Command */
#define MHI_TRE_CMD_STOP_PTR (0)
#define MHI_TRE_CMD_STOP_DWORD0 (0)
#define MHI_TRE_CMD_STOP_DWORD1(chid) ((chid << 24) | (17 << 16))

/* Start Channel Command */
#define MHI_TRE_CMD_START_PTR (0)
#define MHI_TRE_CMD_START_DWORD0 (0)
#define MHI_TRE_CMD_START_DWORD1(chid) ((chid << 24) | (18 << 16))

#define MHI_TRE_GET_CMD_CHID(tre) (((tre)->dword[1] >> 24) & 0xFF)

/* Event Related macros */
#define MHI_TRE_EV_PTR(ptr) (ptr)
#define MHI_TRE_EV_DWORD0(code, len) ((code << 24) | len)
#define MHI_TRE_EV_DWORD1(chid, type) ((chid << 24) | (type << 16))
#define MHI_TRE_GET_EV_PTR(tre) ((tre)->ptr)
#define MHI_TRE_GET_EV_CODE(tre) (((tre)->dword[0] >> 24) & 0xFF)
#define MHI_TRE_GET_EV_LEN(tre) ((tre)->dword[0] & 0xFFFF)
#define MHI_TRE_GET_EV_CHID(tre) (((tre)->dword[1] >> 24) & 0xFF)
#define MHI_TRE_GET_EV_TYPE(tre) (((tre)->dword[1] >> 16) & 0xFF)
#define MHI_TRE_GET_EV_STATE(tre) (((tre)->dword[0] >> 24) & 0xFF)
#define MHI_TRE_GET_EV_EXECENV(tre) (((tre)->dword[0] >> 24) & 0xFF)


/* TRE macros */
#define MHI_TRE_DATA_PTR(ptr) (ptr)
#define MHI_TRE_DATA_DWORD0(len) (len)
#define MHI_TRE_DATA_DWORD1(bei, ieot, ieob, chain) ((2 << 16) | (bei << 10) \
	| (ieot << 9) | (ieob << 8) | chain )

enum MHI_COMMAND {
	MHI_COMMAND_NOOP = 0x0,
	MHI_COMMAND_RESET_CHAN = 0x1,
	MHI_COMMAND_STOP_CHAN = 0x2,
	MHI_COMMAND_START_CHAN = 0x3,
	MHI_COMMAND_RESUME_CHAN = 0x4,
	MHI_COMMAND_MAX_NR = 0x5,
	MHI_COMMAND_reserved = 0x80000000
};

enum MHI_PKT_TYPE {
	MHI_PKT_TYPE_RESERVED = 0x0,
	MHI_PKT_TYPE_NOOP_CMD = 0x1,
	MHI_PKT_TYPE_TRANSFER = 0x2,
	MHI_PKT_TYPE_RESET_CHAN_CMD = 0x10,
	MHI_PKT_TYPE_STOP_CHAN_CMD = 0x11,
	MHI_PKT_TYPE_START_CHAN_CMD = 0x12,
	MHI_PKT_TYPE_STATE_CHANGE_EVENT = 0x20,
	MHI_PKT_TYPE_CMD_COMPLETION_EVENT = 0x21,
	MHI_PKT_TYPE_TX_EVENT = 0x22,
	MHI_PKT_TYPE_EE_EVENT = 0x40,
	MHI_PKT_TYPE_STALE_EVENT, /* Internal event */
};


enum MHI_EVENT_CCS {
	MHI_EVENT_CC_INVALID = 0x0,
	MHI_EVENT_CC_SUCCESS = 0x1,
	MHI_EVENT_CC_EOT = 0x2,
	MHI_EVENT_CC_OVERFLOW = 0x3,
	MHI_EVENT_CC_EOB = 0x4,
	MHI_EVENT_CC_OOB = 0x5,
	MHI_EVENT_CC_DB_MODE = 0x6,
	MHI_EVENT_CC_UNDEFINED_ERR = 0x10,
	MHI_EVENT_CC_BAD_TRE = 0x11,
};

struct db_mode {
	/* if set do not reset DB_Mode during M0 resume */
	u32 preserve_db_state : 1;
	u32 db_mode : 1;
	u32 pollcfg : 16;
	enum MHI_BRSTMODE brstmode;
	dma_addr_t db;
	void (*process_db)(struct mhi_device *, struct db_mode *,
			   void __iomem *, dma_addr_t);
};

enum MHI_CMD_STATUS {
	MHI_CMD_NOT_PENDING = 0x0,
	MHI_CMD_PENDING = 0x1,
	MHI_CMD_RESET_PENDING = 0x2,
	MHI_CMD_RESERVED = 0x80000000
};

enum MHI_EVENT_RING_TYPE {
	MHI_EVENT_RING_TYPE_INVALID = 0x0,
	MHI_EVENT_RING_TYPE_VALID = 0x1,
};

enum MHI_INIT_ERROR_STAGE {
	MHI_INIT_ERROR_STAGE_UNWIND_ALL = 0x1,
	MHI_INIT_ERROR_STAGE_DEVICE_CTRL = 0x2,
	MHI_INIT_ERROR_STAGE_THREADS = 0x3,
	MHI_INIT_ERROR_STAGE_EVENTS = 0x4,
	MHI_INIT_ERROR_STAGE_MEM_ZONES = 0x5,
	MHI_INIT_ERROR_STAGE_SYNC = 0x6,
	MHI_INIT_ERROR_STAGE_THREAD_QUEUES = 0x7,
	MHI_INIT_ERROR_TIMERS = 0x8,
	MHI_INIT_ERROR_STAGE_RESERVED = 0x80000000
};

enum STATE_TRANSITION {
	STATE_TRANSITION_RESET = MHI_STATE_RESET,
	STATE_TRANSITION_READY = MHI_STATE_READY,
	STATE_TRANSITION_M0 = MHI_STATE_M0,
	STATE_TRANSITION_M1 = MHI_STATE_M1,
	STATE_TRANSITION_M2 = MHI_STATE_M2,
	STATE_TRANSITION_M3 = MHI_STATE_M3,
	STATE_TRANSITION_BHI,
	STATE_TRANSITION_SBL,
	STATE_TRANSITION_AMSS,
	STATE_TRANSITION_LINK_DOWN,
	STATE_TRANSITION_WAKE,
	STATE_TRANSITION_BHIE,
	STATE_TRANSITION_RDDM,
	STATE_TRANSITION_SYS_ERR = MHI_STATE_SYS_ERR,
	STATE_TRANSITION_MAX
};

enum MHI_EXEC_ENV {
	MHI_EXEC_ENV_PBL = 0x0,
	MHI_EXEC_ENV_SBL = 0x1,
	MHI_EXEC_ENV_AMSS = 0x2,
	MHI_EXEC_ENV_BHIE = 0x3,
	MHI_EXEC_ENV_RDDM = 0x4,
	MHI_EXEC_MAX_SUPPORTED = MHI_EXEC_ENV_RDDM,
	MHI_EXEC_ENV_DISABLE_TRANSITION, /* local EE, not related to mhi spec */
	MHI_EXEC_INVALID,
	MHI_EXEC_LIMIT
};

struct mhi_chan_info {
	u32 chan_nr;
	u32 max_desc;
	u32 ev_ring;
	u32 flags;
};

//Also put struct mhi_chan into it
struct mhi_client_data {
	int chan;
	struct mhi_device *mhi_dev;
	void (*mhi_client_cb)(struct mhi_cb_info *);
	void (*mhi_xfer_cb)(struct mhi_cb_info *);
	void *user_data;
	struct mhi_client_handle client_handle;
};

struct mhi_buf_info {
	dma_addr_t p_addr;
	void *v_addr;
	void *wp;
	size_t len;
	void *cb_buf;
	enum dma_data_direction dir;
};


#define MHI_MAX_CHANNELS (103)
#define MHI_SMMU_ATTACH BIT(0)
#define MHI_SMMU_S1_BYPASS BIT(1)
#define MHI_SMMU_FAST BIT(2)
#define MHI_SMMU_ATOMIC BIT(3)
#define MHI_SMMU_GEOMETRY BIT(4)
#define MHI_SMMU_FORCE_COHERENT BIT(5)

/* things copied from mhi_macros.h */
#define NR_OF_CMD_RINGS 1
#define PRIMARY_CMD_RING 0
#define MHI_EPID 4 //Move to rmnet
#define MHI_RPM_AUTOSUSPEND_TMR_VAL_MS 1000
#define CMD_EL_PER_RING 128
#define MHI_M2_DEBOUNCE_TMR_US 10000
#define MHI_THREAD_SLEEP_TIMEOUT_MS 100
#define MHI_MAX_STATE_TRANSITION_TIMEOUT 5000

#define PCI_INVALID_READ(val) (val == U32_MAX)

struct mhi_ring {
	dma_addr_t dma_handle;
	dma_addr_t phys_base;
	dma_addr_t *ctxt_wp; /* point to ctxt wp */
	void *pre_aligned;
	void *base;
	void *rp;
	void *wp;
	void *ack_rp; //FIXME: temporary.
	size_t el_size;
	size_t len;
	size_t elements;
	size_t alloc_size;
	void __iomem *db_addr;
};

struct mhi_event {
	struct mhi_ring ring;
	struct db_mode db_mode;
	spinlock_t lock;
	struct mutex mutex;
	struct tasklet_struct task;
	struct work_struct worker;
	struct mhi_device *mhi_dev;
	u32 index;
	u32 msi;
	u32 intmod;
	/*
	 * Priority of event handling:
	 * 0 = highest, handle events in isr (reserved for future)
	 * 1 = handles event using tasklet
	 * 2 = handles events using workerthread
	 */
	u32 priority;
	enum MHI_RING_CLASS class;
	bool client_manage;
	struct mhi_chan *chan; /* dedicated ev ring to this channel */
};
#define MHI_EV_PRIORITY_TASKLET (1)
#define MHI_CTRL_ER_INDEX (0) /* ctrl event ring */
#define MHI_EV_CFG_HW_EV BIT(0)
#define MHI_EV_CFG_CL_MANAGE BIT(1)

struct mhi_chan {
	/*
	 * important, when consuming update tre_ring first, when freeing update
	 * buf_ring first. If tre_ring has space, buf_ring
	 * guranteed to have space so we do not need to check both rings.
	 */
	struct mhi_ring buf_ring;
	struct mhi_ring tre_ring;
	u32 er_index;
	int chan;
	const char *name;
	enum dma_data_direction dir;
	enum MHI_CHAN_STATE ch_state;
	enum MHI_EXEC_ENV exec_env;
	struct db_mode db_mode;
	struct mutex mutex;
	rwlock_t lock;
	struct completion completion;
	struct __packed mhi_tre ev_tre;
	struct __packed mhi_tre cmd_tre;
	struct mhi_client_data *cldata;
	/* functions that generate the tre */
	int (*gen_tre)(struct mhi_device *, struct mhi_chan *, void *, void *,
		       size_t, enum MHI_FLAGS);
	int (*queue_xfer)(struct mhi_client_handle *, void *, size_t,
			  enum MHI_FLAGS);
	u32 tiocm;
	bool supported;
	size_t pkts;
	size_t bytes;
};

struct mhi_ctxt {
	struct mhi_event_ctxt *er_ctxt;
	struct mhi_chan_ctxt *chan_ctxt;
	struct mhi_cmd_ctxt *cmd_ctxt;
	dma_addr_t er_addr;
	dma_addr_t chan_addr;
	dma_addr_t cmd_addr;
};

struct arch_info;

struct mhi_device {
	struct list_head node;
	struct device *dev; /* dev used for all memory operations */
	struct platform_device *pdev;
	struct pci_dev *pci_dev;
	void __iomem *regs;
	void __iomem *bhi;
	void __iomem *wake_db;
	u32 dev_id;
	u32 domain;
	u32 bus;
	u32 slot;
	bool pci_master;
	u32 irq;

	/* firmware and rddm related info */
	bool dl_fw;
	const char *fw_image;
	size_t sbl_len;
	size_t seg_len;
	bool support_rddm;
	size_t rddm_len;
	struct bhie_vec_table fw_table;
	struct bhie_vec_table rddm_table;

	/* MHI Software and Hardware States */
	enum MHI_PM_STATE pm_state;
	enum MHI_STATE dev_state;
	enum MHI_EXEC_ENV dev_exec_env;
	bool wake;
	wait_queue_head_t state_event;
	struct completion completion;

	/* MHI Context */
	struct mhi_ctxt mhi_ctxt;
	dma_addr_t iova_start;
	dma_addr_t iova_end;
	struct mhi_chan mhi_chan[MHI_MAX_CHANNELS];
	struct mhi_ring mhi_cmd[NR_OF_CMD_RINGS];
	struct mhi_event *mhi_event;
	spinlock_t cmd_lock;
	u32 ev_rings;
	u32 hw_ev_rings;
	u32 sw_ev_rings;
	u32 hw_xfer_rings;
	u32 sw_xfer_rings;

	/* workers for state transitions */
	struct work_struct st_worker;
	struct work_struct m1_worker;
	struct work_struct sys_err_worker;
	struct work_struct fw_load_worker;
	struct mhi_ring work_ring;
	spinlock_t work_lock;

	bool configured;
	u32 smmu_cfg;
	u32 poll_timeout;
	u32 fw_timeout;

	/* architecture specific data structures */
	struct arch_info *arch_info;

	rwlock_t pm_lock;
	spinlock_t wake_lock;
	struct mutex mutex;

	atomic_t dev_wake;
	bool wake_set;
	atomic_t pending_acks;
	atomic_t alloc_size;

	/* Shadow functions pts since they may */
	int (*bus_master_rt_get)(struct pci_dev *);
	void (*bus_master_rt_put)(struct pci_dev *);
	void (*runtime_get)(struct mhi_device *);
	void (*runtime_put)(struct mhi_device *);
	void (*assert_wake)(struct mhi_device *, bool);
	void (*deassert_wake)(struct mhi_device *, bool);
	void (*status_cb)(enum MHI_CB_REASON, void *);
	long (*tiocmset)(struct mhi_device *, int, u32);
	void *priv_data; /* private data for bus master */


	struct dentry *dentry;
	void *log; /* arch specific logging */
};

struct mhi_device_driver {
	struct list_head head;
	struct mutex lock;
	struct dentry *dentry;
};

extern struct mhi_device_driver mhi_device_drv;

#ifndef CONFIG_ARCH_QCOM
static inline int mhi_arch_platform_init(struct mhi_device *mhi_dev) {
	return 0;
};
static inline int mhi_arch_pcie_init(struct mhi_device *mhi_dev) {
	return 0;
};
static inline int mhi_arch_post_init(struct mhi_device *mhi_dev) {
	return 0;
};
static inline int mhi_arch_link_off(struct mhi_device *mhi_dev, bool graceful) {
	return 0;
};
static inline int mhi_arch_link_on(struct mhi_device *mhi_dev) {
	return 0;
};

#define MHI_IOMMU_INIT(mhi_dev) mhi_default_iommu_init(mhi_dev)

#define mhi_log(mhi_dev, _msg_lvl, _msg, ...) do {	\
		if ((_msg_lvl) >= mhi_msg_lvl) \
			pr_alert("[%s] [0x%04x]" _msg, __func__, \
				 mhi_dev->dev_id, ##__VA_ARGS__); \
} while (0)

#else

#include <linux/ipc_logging.h>
extern enum MHI_DEBUG_LEVEL mhi_qcom_log_lvl;
#define mhi_log(mhi_dev, _msg_lvl, _msg, ...) do {	\
		if ((_msg_lvl) >= mhi_msg_lvl) \
			pr_alert("[%s] " _msg, __func__, ##__VA_ARGS__);\
		if (mhi_dev->log && \
		    ((_msg_lvl) >= mhi_qcom_log_lvl)) \
			ipc_log_string(mhi_dev->log,		      \
                              "[%s] " _msg, __func__, ##__VA_ARGS__); \
} while (0)

int mhi_arch_platform_init(struct mhi_device *);
int mhi_arch_pcie_init(struct mhi_device *);
int mhi_arch_post_init(struct mhi_device *);
int mhi_arch_link_off(struct mhi_device *, bool);
int mhi_arch_link_on(struct mhi_device *);
int mhi_arch_qcom_init_smmu(struct mhi_device *);

#define MHI_IOMMU_INIT(mhi_dev) mhi_arch_qcom_init_smmu(mhi_dev)

#endif



////////////////////////////////////////////////////
int mhi_dma_mask(struct mhi_device *mhi_dev);
void *mhi_alloc_coherent(struct mhi_device *, size_t, dma_addr_t *, gfp_t);
void mhi_free_coherent(struct mhi_device *, size_t, void *, dma_addr_t);
int mhi_init_chan_ctxt(struct mhi_device *, struct mhi_chan *);


void *mhi_to_virtual(struct mhi_ring *, dma_addr_t);

void mhi_ring_chan_db(struct mhi_device *, struct mhi_chan *);
enum MHI_EXEC_ENV mhi_get_exec_env(struct mhi_device *);
void mhi_queue_state_transition(struct mhi_device *, enum STATE_TRANSITION);
int mhi_runtime_suspend(struct device *);
int mhi_runtime_resume(struct device *);
int mhi_runtime_idle(struct device *dev);
int parse_xfer_event(struct mhi_device *, struct __packed mhi_tre *, struct mhi_chan *);
const char *state_transition_str(enum STATE_TRANSITION);
//FIXME: rename to system suspend/resume
int mhi_system_suspend(struct device *dev);
int mhi_system_resume(struct device *dev);
enum MHI_STATE mhi_get_m_state(struct mhi_device *);
enum MHI_PM_STATE __must_check mhi_tryset_pm_state(struct mhi_device*, enum MHI_PM_STATE);
void mhi_del_ring_element(struct mhi_device *, struct mhi_ring *);
int get_nr_avail_ring_elements(struct mhi_device *, struct mhi_ring *);
void mhi_add_ring_element(struct mhi_device *, struct mhi_ring *);
void mhi_ring_er_db(struct mhi_event *);
bool mhi_in_sys_err(struct mhi_device *);
void mhi_ev_task(unsigned long);
void process_event_ring(struct work_struct *);
void mhi_write_reg(struct mhi_device *, void __iomem *, u32, u32);
u32  __must_check mhi_read_reg(struct mhi_device *, void __iomem *, u32);
u32 __must_check mhi_read_reg_field(struct mhi_device *, void __iomem *, u32, u32, u32);
void mhi_write_reg_field(struct mhi_device *, void __iomem *,u32, u32, u32,
			 u32);
void mhi_ring_cmd_db(struct mhi_device *);
int mhi_test_for_device_reset(struct mhi_device *, bool);
int mhi_test_for_device_ready(struct mhi_device *);
int mhi_init_mmio(struct mhi_device *);
void mhi_notify_client(struct mhi_device *, struct mhi_chan *,
		       enum MHI_CB_REASON);
void mhi_set_m_state(struct mhi_device *, enum MHI_STATE);
void mhi_process_db_brstmode(struct mhi_device *, struct db_mode *,
		void __iomem *, dma_addr_t);
void mhi_process_db_brstmode_disable(struct mhi_device *, struct db_mode *,
		void __iomem *, dma_addr_t);
void mhi_assert_device_wake(struct mhi_device *, bool);
void mhi_deassert_device_wake(struct mhi_device *, bool);
void mhi_slave_mode_runtime_get(struct mhi_device *);
void mhi_slave_mode_runtime_put(struct mhi_device *);
void mhi_master_mode_runtime_put(struct mhi_device *);
void mhi_master_mode_runtime_get(struct mhi_device *);
void bhi_load_worker(struct work_struct *);
int process_reset_transition(struct mhi_device *mhi_dev);
int mhi_queue_buffer(struct mhi_client_handle *,  void *, size_t,
		     enum MHI_FLAGS);
int mhi_queue_buf_tre(struct mhi_device *, struct mhi_chan *, void *, void *,
		      size_t, enum MHI_FLAGS);
int mhi_queue_skb(struct mhi_client_handle *, void *, size_t, enum MHI_FLAGS);
int mhi_queue_scatterlist(struct mhi_client_handle *, void *,size_t,
			  enum MHI_FLAGS);

extern const char * const mhi_exec_env_str[MHI_EXEC_LIMIT];
#define TO_MHI_EXEC_STR(exec) (((exec) >= MHI_EXEC_INVALID) ? \
				 "INVALID_EXEC" : mhi_exec_env_str[exec])

int mhi_debugfs_mhi_states_show(struct seq_file *, void *);
int mhi_debugfs_mhi_event_show(struct seq_file *, void *);
int mhi_debugfs_mhi_chan_show(struct seq_file *, void *);

//FIXME: temp copy to fix compile errors
 int mhi_send_cmd(struct mhi_device *mhi_dev,
			enum MHI_COMMAND cmd,
		  u32 chan);

void mhi_reset_chan(struct mhi_device *, struct mhi_chan *);
int mhi_init_pm_sysfs(struct device *);
void process_m1_transition(struct work_struct *work);
void mhi_state_change_worker(struct work_struct *);
void mhi_sys_err_worker(struct work_struct *);
irqreturn_t mhi_msi_handlr(int irq_number, void *dev_id);
void mhi_init_debugfs(struct mhi_device *);
void mhi_deinit_chan_ctxt(struct mhi_device *, struct mhi_chan *);
void mhi_de_init_chan_ctxt(struct mhi_device *, int);
void mhi_assert_device_wake(struct mhi_device *mhi_dev, bool force_set);
int process_m0_transition(struct mhi_device *);
int process_m3_transition(struct mhi_device *);

#define MSI_TO_IRQ(_MHI_DEV, _MSI_NR) \
	((_MHI_DEV)->irq + (_MSI_NR))


extern enum MHI_DEBUG_LEVEL mhi_msg_lvl;

extern const char * const mhi_states_str[MHI_STATE_LIMIT];
#define TO_MHI_STATE_STR(state) (((state) >= MHI_STATE_LIMIT) ? \
				 "INVALID_STATE" : mhi_states_str[state])

void process_disable_transition(enum MHI_PM_STATE transition_state,
				struct mhi_device *mhi_dev);


#endif
