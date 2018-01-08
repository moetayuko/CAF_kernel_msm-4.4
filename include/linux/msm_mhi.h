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
#ifndef MSM_MHI_H
#define MSM_MHI_H
#include <linux/types.h>
#include <linux/device.h>
#include <linux/scatterlist.h>

#define MHI_MAX_MTU        0xFFFF

struct mhi_client_data;
struct mhi_device;

enum MHI_CB_REASON {
	MHI_CB_PENDING_DATA,
	MHI_CB_XFER,
	MHI_CB_MHI_DISABLED,
	MHI_CB_MHI_ENABLED,
	MHI_CB_MHI_SHUTDOWN,
	MHI_CB_SYS_ERROR,
	MHI_CB_RDDM,
	MHI_CB_MHI_PROBED,
};

enum MHI_FLAGS {
	MHI_EOB = 0x100,
	MHI_EOT = 0x200,
	MHI_CHAIN = 0x1,
};

struct mhi_result {
	void *buf_addr;
	size_t bytes_xferd;
	int transaction_status;
};

struct mhi_cb_info {
	struct mhi_result result;
	enum MHI_CB_REASON cb_reason;
	u32 chan;
	void *user_data;
};

/**
 * struct mhi_client_info_t - client registration information
 * @chan_name: MHI channel to register
 * @of_node: DT node pointing to MHI phandle
 * @node_name: MHI phandle name
 * @mhi_client_cb: Required, use for async notification and xfer cb
 * @mhi_xfer_cb: Optional, use for transfer callback
 * @user_data: client private data
 */
struct mhi_client_info_t {
	const char *chan_name;
	const struct device_node *of_node;
	const char *node_name;
	void (*mhi_client_cb)(struct mhi_cb_info *);
	void (*mhi_xfer_cb)(struct mhi_cb_info *);
	void *user_data;
};

struct mhi_client_handle {
	u32 dev_id;
	u32 domain;
	u32 bus;
	u32 slot;
	bool enabled;
	int chan_id;
	int (*xfer_func)(struct mhi_client_handle *, void *, size_t,
			 enum MHI_FLAGS);
	struct mhi_client_data *cldata;
};

struct __packed bhi_vec_entry {
	u64 phys_addr;
	u64 size;
};

struct __packed soc_id {
	u32 minor_version : 8;
	u32 major_version : 8;
	u32 device_number : 12;
	u32 family_number : 4;
};

/**
 * struct mhi_master - IO resources for MHI
 * @dev: device driver
 * @pdev: pci device node
 * @resource: bar memory space and IRQ resources
 * @support_rddm: this device support ramdump collection
 * @rddm_size: size of ramdump buffer in bytes to allocate
 * @fw_image: optional parameter, firmware image name
 * @of_node: parent dt node that points to mhi phandler
 * @version: device version
 * @pm_runtime_get: fp for bus masters rpm pm_runtime_get
 * @pm_runtime_noidle: fp for bus masters rpm pm_runtime_noidle
 * @status_cb: fp for MHI status change notifications
 * @mhi_dev_ctxt: private data for host
 */
struct mhi_master {
	struct device *dev;
	struct pci_dev *pci_dev;
	struct resource resources[2];
	bool support_rddm;
	size_t rddm_size;
	char *fw_image;
	const struct device_node *of_node;
	struct __packed soc_id version;
	int (*pm_runtime_get)(struct pci_dev *pci_dev);
	void (*pm_runtime_put_noidle)(struct pci_dev *pci_dev);
	void (*status_cb)(enum MHI_CB_REASON, void *priv);
	struct mhi_device *mhi_dev;
};

enum mhi_dev_ctrl {
	MHI_DEV_CTRL_INIT,
	MHI_DEV_CTRL_DE_INIT,
	MHI_DEV_CTRL_SUSPEND,
	MHI_DEV_CTRL_RESUME,
	MHI_DEV_CTRL_POWER_OFF,
	MHI_DEV_CTRL_POWER_ON,
	MHI_DEV_CTRL_TRIGGER_RDDM,
	MHI_DEV_CTRL_RDDM,
	MHI_DEV_CTRL_RDDM_KERNEL_PANIC,
	MHI_DEV_CTRL_NOTIFY_LINK_ERROR,
	MHI_DEV_CTRL_MAXCMD,
};

enum mhi_rddm_segment {
	MHI_RDDM_FW_SEGMENT,
	MHI_RDDM_RD_SEGMENT,
};

#if defined(CONFIG_MSM_MHI)
/**
 * mhi_is_device_ready - Check if MHI is ready to register clients
 *
 * @of_node: parent node that points to mhi phandle
 * @node_name: device tree node name that links MHI node
 *
 * @Return true if ready
 */
bool mhi_is_device_ready(const struct device_node *of_node,
			 const char *node_name);

/**
 * mhi_resgister_device - register hardware resources with MHI
 *
 * @mhi_master: resources to be used
 * @node_name: DT node name
 * @userdata: cb data for client
 * @Return 0 on success
 */
int mhi_register_device(struct mhi_master *mhi_master, const char *node_name,
			void *user_data);

/**
 * mhi_register_channel - Client must call this function to obtain a handle for
 *			  any MHI operations
 *
 *  @client_info:    Channel\device information provided by client to
 *                   which the handle maps to.
 *
 * @Return valid ptr
 */
struct mhi_client_handle *mhi_register_channel(
				struct mhi_client_info_t *client_info);

/**
 * mhi_pm_control_device - power management control api
 * @mhi_master: registered device structure
 * @ctrl: specific command
 * @param: optional parameter depend on command
 * @Return 0 on success
 */
int mhi_pm_control_device(struct mhi_master *mhi_master, enum mhi_dev_ctrl ctrl,
			  void *param);

/**
 * mhi_xfer_rddm - transfer rddm segment to bus master
 * @mhi_master: registered device structure
 * @seg: scatterlist pointing to segments
 * @Return: # of segments, 0 if no segment available
 */
int mhi_xfer_rddm(struct mhi_master *mhi_master, enum mhi_rddm_segment seg,
		  struct scatterlist **sg_list);

/**
 * mhi_deregister_channel - de-register callbacks from MHI
 *
 * @client_handle: Handle populated by MHI, opaque to client
 *
 * @Return errno
 */
int mhi_deregister_channel(struct mhi_client_handle *client_handle);

/**
 * mhi_open_channel - Client must call this function to open a channel
 *
 * @client_handle:  Handle populated by MHI, opaque to client
 *
 *  Not thread safe, caller must ensure concurrency protection.
 *
 * @Return errno
 */
int mhi_open_channel(struct mhi_client_handle *client_handle);

/**
 * mhi_queue_xfer - Client called function to add a buffer to MHI channel
 *
 *  @client_handle  Pointer to client handle previously obtained from
 *                  mhi_open_channel
 *  @buf            Pointer to client buffer
 *  @buf_len        Length of the client buffer
 *  @chain          Specify whether to set the chain bit on this buffer
 *  @eob            Specify whether this buffer should trigger EOB interrupt
 *
 *  NOTE:
 *  Not thread safe, caller must ensure concurrency protection.
 *  User buffer must be physically contiguous.
 *
 * @Return errno
 */
static inline int mhi_queue_xfer(struct mhi_client_handle *handle,
				 void *ptr,
				 size_t len,
				 enum MHI_FLAGS flags)
{
	return handle->xfer_func(handle, ptr, len, flags);
}


/**
 * mhi_close_channel - Client can request channel to be closed and handle freed
 *
 *  @client_handle  Pointer to client handle previously obtained from
 *                  mhi_open_channel
 *  Not thread safe, caller must ensure concurrency protection.
 *
 * @client_handle  Pointer to handle to be released
 */
void mhi_close_channel(struct mhi_client_handle *client_handle);

/**
 * mhi_get_free_desc - Get the number of free descriptors on channel.
 *  client_handle  Pointer to client handle previously obtained from
 *                      mhi_open_channel.
 *
 * This API returns a snapshot of available descriptors on the given
 * channel
 *
 * @Return  non negative on success
 */
int mhi_get_free_desc(struct mhi_client_handle *client_handle);

/**
 * mhi_get_max_desc - Get the maximum number of descriptors
 *			supported on the channel.
 * @client_handle  Pointer to client handle previously obtained from
 *                      mhi_open_channel.
 * @Return  non negative on success
 */
int mhi_get_max_desc(struct mhi_client_handle *client_handle);


long mhi_ioctl(struct mhi_client_handle *, unsigned int, unsigned long arg);


/* following APIs meant to be used by rmnet interface only */
int mhi_set_lpm(struct mhi_client_handle *client_handle, bool enable_lpm);
int mhi_get_epid(struct mhi_client_handle *mhi_handle);
int mhi_poll(struct mhi_client_handle *client_handle, u32 budget);

#else
static inline bool mhi_is_device_ready(const struct device_node *of_node,
				       const char *node_name)
{
	return false;
};

static inline int mhi_register_device(struct mhi_master *mhi_master,
				      const char *node_name, void *user_data)
{
	return -EINVAL;
};

static inline struct mhi_client_handle *mhi_register_channel(
					struct mhi_client_info_t *client_info)
{
	return ERR_PTR(-EINVAL);
};

static inline int mhi_pm_control_device(struct mhi_master *mhi_master,
					enum mhi_dev_ctrl ctrl, void *param)
{
	return -EINVAL;
};

static inline int mhi_xfer_rddm(struct mhi_master *mhi_master,
				enum mhi_rddm_segment seg,
				struct scatterlist **sg_list)
{
	return -EINVAL;
};

static inline int mhi_deregister_channel(struct mhi_client_handle
					 *client_handle)
{
	return -EINVAL;
};

static inline int mhi_open_channel(struct mhi_client_handle *client_handle)
{
	return -EINVAL;
};

static inline int mhi_queue_xfer(struct mhi_client_handle *client_handle,
				 void *buf, size_t buf_len,
				 enum MHI_FLAGS mhi_flags)
{
	return -EINVAL;
};

static inline void mhi_close_channel(struct mhi_client_handle *client_handle)
{
};

static inline int mhi_get_free_desc(struct mhi_client_handle *client_handle)
{
	return -EINVAL;
};

static inline int mhi_get_max_desc(struct mhi_client_handle *client_handle)
{
	return -EINVAL;
};

static inline int mhi_set_lpm(struct mhi_client_handle *client_handle,
			      bool enable_lpm)
{
	return -EINVAL;
};

static inline int mhi_get_epid(struct mhi_client_handle *mhi_handle)
{
	return -EINVAL;
};

static inline struct mhi_result *mhi_poll(struct mhi_client_handle
					  *client_handle, u32 budget)
{
	return NULL;
};


static inline long mhi_ioctl(struct mhi_client_handle *handle , unsigned int cmd, unsigned long arg)
{
	return NULL;
};

#endif
#endif
