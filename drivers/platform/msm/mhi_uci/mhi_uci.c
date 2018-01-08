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
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/wait.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/tty.h>
#include <linux/delay.h>
#include <linux/ipc_logging.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/of_device.h>

#define MHI_DEV_NODE_NAME_LEN 13
#define MHI_UCI_IPC_LOG_PAGES (25)

#define DEVICE_NAME "mhi"
#define MHI_UCI_DRIVER_NAME "mhi_uci"

enum UCI_DBG_LEVEL {
	DBG_VERBOSE = 0x0,
	DBG_INFO = 0x1,
	DBG_ERROR = 0x4,
	DBG_CRITICAL = 0x5,
};
enum UCI_DBG_LEVEL mhi_uci_msg_lvl = DBG_ERROR;

#ifdef CONFIG_MSM_MHI_DEBUG
enum UCI_DBG_LEVEL mhi_uci_ipc_log_lvl = DBG_VERBOSE;
#else
enum UCI_DBG_LEVEL mhi_uci_ipc_log_lvl = DBG_ERROR;
#endif

struct uci_chan {
	const char *chan_name;
	int chan_id;
	size_t max_packet_size;
	bool enabled;
	struct mhi_client_handle *mhi_handle;
	wait_queue_head_t wq;
	spinlock_t lock;
	struct list_head submitted; /* submitted to hardware */
	struct list_head pending; /* pending pkt client can read */
	u64 pkt_count;
	struct uci_buf *cur_buf; /* current buffer read processing */
	size_t rx_size;
};

struct uci_buf {
	void *data;
	u64 pkt_id;
	size_t len;
	struct list_head node;
};

struct uci_node {
	struct uci_chan in_chan;
	struct uci_chan out_chan;
	struct mutex mutex; /* sync open and close */
	int ref_count;
	struct mhi_uci_ctxt_t *uci_ctxt;
	struct cdev cdev;
	struct device *dev;
	struct mhi_uci *mhi_uci;
	void *ipc_log;
};

struct mhi_uci {
	struct list_head node;
	struct uci_node *nodes;
	int num_nodes;
	dev_t dev_t;
};

struct mhi_uci_drv {
	struct list_head head;
	struct mutex lock;
	struct class *class;
};

#define uci_log(uci_ipc_log, _msg_lvl, _msg, ...) do { \
	if (_msg_lvl >= mhi_uci_msg_lvl) { \
		pr_err("[%s] "_msg, __func__, ##__VA_ARGS__); \
	} \
	if (uci_ipc_log && (_msg_lvl >= mhi_uci_ipc_log_lvl)) { \
		ipc_log_string(uci_ipc_log, \
			"[%s] " _msg, __func__, ##__VA_ARGS__); \
	} \
} while (0)

module_param(mhi_uci_msg_lvl , uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(mhi_uci_msg_lvl, "uci dbg lvl");

module_param(mhi_uci_ipc_log_lvl, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(mhi_uci_ipc_log_lvl, "ipc dbg lvl");

static struct mhi_uci_drv mhi_uci_drv;

static long mhi_uci_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	struct uci_node *node = file->private_data;
	struct uci_chan *uci_chan = &node->out_chan;

	return mhi_ioctl(uci_chan->mhi_handle, cmd, arg);
}

static unsigned int mhi_uci_poll(struct file *file, poll_table *wait)
{
	struct uci_node *node = file->private_data;
	void *ipc_log = node->ipc_log;
	struct uci_chan *uci_chan;
	unsigned int mask = 0;

	poll_wait(file, &node->in_chan.wq, wait);
	poll_wait(file, &node->out_chan.wq, wait);

	uci_chan = &node->in_chan;
	spin_lock_bh(&uci_chan->lock);
	if (!uci_chan->enabled)
		mask = POLLERR;
	else if (!list_empty(&uci_chan->pending) || uci_chan->cur_buf) {
		uci_log(ipc_log, DBG_VERBOSE, "Client can read from node\n");
		mask |= POLLIN | POLLRDNORM;
	}
	spin_unlock_bh(&uci_chan->lock);

	uci_chan = &node->out_chan;
	spin_lock_bh(&uci_chan->lock);
	if (!uci_chan->enabled)
		mask |= POLLERR;
	else if (mhi_get_free_desc(uci_chan->mhi_handle) > 0) {
		uci_log(ipc_log, DBG_VERBOSE, "Client can write to node\n");
		mask |= POLLOUT | POLLWRNORM;
	}
	spin_unlock_bh(&uci_chan->lock);

	uci_log(ipc_log, DBG_VERBOSE,
		"Client attempted to poll, returning mask 0x%x\n", mask);
	return mask;
}

static ssize_t mhi_uci_read(struct file *file,
			    char __user *buf,
			    size_t count,
			    loff_t *ppos)
{
	struct uci_node *node = file->private_data;
	void *ipc_log = node->ipc_log;
	struct uci_chan *uci_chan = &node->in_chan;
	struct uci_buf *uci_buf;
	char *ptr;
	size_t to_copy;
	int ret = 0;

	if (!buf)
		return -EINVAL;

	uci_log(ipc_log, DBG_VERBOSE, "Client provided buf len:%lu\n", count);

	/* confirm channel is active */
	spin_lock_bh(&uci_chan->lock);
	if (!uci_chan->enabled) {
		spin_unlock_bh(&uci_chan->lock);
		return -ERESTARTSYS;
	}

	/* No data available to read, wait */
	if (!uci_chan->cur_buf && list_empty(&uci_chan->pending)) {
		uci_log(ipc_log, DBG_VERBOSE,
			"No data available to read waiting\n");
		spin_unlock_bh(&uci_chan->lock);
		ret = wait_event_interruptible(uci_chan->wq,
				(!uci_chan->enabled ||
				 !list_empty(&uci_chan->pending)));
		if (ret == -ERESTARTSYS) {
			uci_log(ipc_log, DBG_INFO,
				"Exit signal caught for node\n");
			return -ERESTARTSYS;
		}

		spin_lock_bh(&uci_chan->lock);
		if (!uci_chan->enabled || list_empty(&uci_chan->pending)) {
			uci_log(ipc_log, DBG_INFO, "node is disabled\n");
			ret = -ERESTARTSYS;
			goto read_error;
		}
	}

	/* new read, get the next descriptor from the list */
	if (!uci_chan->cur_buf) {
		uci_buf = list_first_entry_or_null(&uci_chan->pending,
						   struct uci_buf, node);
		if (unlikely(!uci_buf)) {
			ret = -EIO;
			goto read_error;
		}

		list_del(&uci_buf->node);
		uci_chan->cur_buf = uci_buf;
		uci_chan->rx_size = uci_buf->len;
		uci_log(ipc_log, DBG_VERBOSE,
			"Got pkt @ %llu size:%lu\n", uci_buf->pkt_id,
			uci_buf->len);
	}

	uci_buf = uci_chan->cur_buf;
	spin_unlock_bh(&uci_chan->lock);

	/* Copy the buffer to user space */
	to_copy = min_t(size_t, count, uci_chan->rx_size);
	ptr = uci_buf->data + (uci_buf->len - uci_chan->rx_size);
	ret = copy_to_user(buf, ptr, to_copy);
	if (ret)
		return ret;

	uci_log(ipc_log, DBG_VERBOSE, "Copied %lu of %lu bytes\n", to_copy,
		uci_chan->rx_size);
	uci_chan->rx_size -= to_copy;

	/* We finished with this buffer, map it back */
	if (!uci_chan->rx_size) {
		spin_lock_bh(&uci_chan->lock);
		uci_chan->cur_buf = NULL;
		uci_buf->pkt_id = uci_chan->pkt_count++;

		if (uci_chan->enabled)
			ret = mhi_queue_xfer(uci_chan->mhi_handle,
				uci_buf->data, uci_chan->max_packet_size,
				MHI_EOT);
		else
			ret = -ERESTARTSYS;

		if (ret) {
			uci_log(ipc_log, DBG_ERROR,
				"Failed to recycle element\n");
			kfree(uci_buf->data);
			goto read_error;
		}
		list_add_tail(&uci_buf->node, &uci_chan->submitted);
		spin_unlock_bh(&uci_chan->lock);
	}
	uci_log(ipc_log, DBG_VERBOSE, "Returning %lu bytes\n", to_copy);

	return to_copy;
read_error:
	spin_unlock_bh(&uci_chan->lock);
	return ret;
}

static ssize_t mhi_uci_write(struct file *file,
			     const char __user *buf,
			     size_t count,
			     loff_t *offp)
{
	struct uci_node *node = file->private_data;
	void *ipc_log = node->ipc_log;
	struct uci_chan *uci_chan = &node->out_chan;
	size_t bytes_xfered = 0;
	int ret;

	if (!buf || !count)
		return -EINVAL;

	/* confirm channel is active */
	spin_lock_bh(&uci_chan->lock);
	if (!uci_chan->enabled) {
		spin_unlock_bh(&uci_chan->lock);
		return -ERESTARTSYS;
	}

	uci_log(ipc_log, DBG_VERBOSE, "Enter: to xfer:%lu bytes\n", count);

	while (count) {
		size_t xfer_size;
		void *data_loc = NULL;
		struct uci_buf *uci_buf;
		enum MHI_FLAGS flags;

		spin_unlock_bh(&uci_chan->lock);
		ret = wait_event_interruptible(uci_chan->wq,
				(!uci_chan->enabled) ||
				mhi_get_free_desc(uci_chan->mhi_handle) > 0);

		if (ret == -ERESTARTSYS) {
			uci_log(ipc_log, DBG_INFO,
				"Exit signal caught for node\n");
			return -ERESTARTSYS;
		}

		xfer_size = min_t(size_t, count, uci_chan->max_packet_size);
		data_loc = kmalloc(xfer_size + sizeof(*uci_buf), GFP_ATOMIC);
		if (!data_loc) {
			uci_log(ipc_log, DBG_ERROR,
				"Failed to allocate memory %lu\n", xfer_size);
			return -ENOMEM;
		}

		uci_buf = data_loc + xfer_size;
		uci_buf->data = data_loc;
		uci_buf->len = xfer_size;
		uci_buf->pkt_id = uci_chan->pkt_count++;
		ret = copy_from_user(uci_buf->data, buf, xfer_size);
		if (unlikely(ret)) {
			kfree(uci_buf->data);
			return ret;
		}

		spin_lock_bh(&uci_chan->lock);
		flags = (count - xfer_size) ? MHI_EOB : MHI_EOT;
		if (uci_chan->enabled)
		    ret = mhi_queue_xfer(uci_chan->mhi_handle, uci_buf->data,
					 xfer_size, flags);
		else
			ret = -ERESTARTSYS;
		if (ret) {
			kfree(uci_buf->data);
			goto sys_interrupt;
		}

		bytes_xfered += xfer_size;
		count -= xfer_size;
		buf += xfer_size;
		list_add_tail(&uci_buf->node, &uci_chan->submitted);
	}

	spin_unlock_bh(&uci_chan->lock);
	uci_log(ipc_log, DBG_VERBOSE,
		"Exit: Number of bytes xferred:%lu\n", bytes_xfered);

	return bytes_xfered;
sys_interrupt:
	spin_unlock_bh(&uci_chan->lock);
	return ret;
}

static int mhi_uci_release(struct inode *inode, struct file *file)
{
	struct uci_node *node = file->private_data;
	void *ipc_log = node->ipc_log;

	mutex_lock(&node->mutex);
	node->ref_count--;
	if (!node->ref_count) {
		struct uci_buf *itr, *tmp;
		struct uci_chan *uci_chan;

		uci_log(ipc_log, DBG_INFO, "Last client left, closing node\n");

		/* close out outbound channel */
		uci_chan = &node->out_chan;
		if (uci_chan->enabled)
			mhi_close_channel(uci_chan->mhi_handle);
		list_for_each_entry_safe(itr, tmp, &uci_chan->submitted, node) {
			list_del(&itr->node);
			kfree(itr->data);
		}
		INIT_LIST_HEAD(&uci_chan->submitted);

		/* close out inbound channel */
		uci_chan = &node->in_chan;
		if (uci_chan->enabled)
			mhi_close_channel(uci_chan->mhi_handle);
		list_for_each_entry_safe(itr, tmp, &uci_chan->submitted, node) {
			list_del(&itr->node);
			kfree(itr->data);
		}
		list_for_each_entry_safe(itr, tmp, &uci_chan->pending, node) {
			list_del(&itr->node);
			kfree(itr->data);
		}
		if (uci_chan->cur_buf)
			kfree(uci_chan->cur_buf->data);

		uci_chan->cur_buf = NULL;
		INIT_LIST_HEAD(&uci_chan->submitted);
		INIT_LIST_HEAD(&uci_chan->pending);
	}
	mutex_unlock(&node->mutex);

	uci_log(ipc_log, DBG_INFO, "exit: ref_count:%d\n", node->ref_count);
	return 0;
}

static int mhi_queue_inbound(struct uci_node *node)
{
	void *ipc_log = node->ipc_log;
	struct uci_chan *uci_chan = &node->in_chan;
	int nr_trbs = mhi_get_free_desc(uci_chan->mhi_handle);
	size_t buf_len = uci_chan->max_packet_size;
	void *buf;
	struct uci_buf *uci_buf;
	int ret = -EIO, i;

	for (i = 0; i < nr_trbs; i++) {
		buf = kmalloc(buf_len + sizeof(*uci_buf), GFP_KERNEL);
		if (!buf)
			return -ENOMEM;

		uci_buf = buf + buf_len;
		uci_buf->data = buf;
		uci_buf->pkt_id = uci_chan->pkt_count++;

		uci_log(ipc_log, DBG_VERBOSE,
			"Allocated buffer %d of %d %llu size %ld\n",
			i, nr_trbs, uci_buf->pkt_id, buf_len);
		spin_lock_bh(&uci_chan->lock);
		ret = mhi_queue_xfer(uci_chan->mhi_handle, buf, buf_len,
				     MHI_EOT);
		if (ret) {
			spin_unlock_bh(&uci_chan->lock);
			kfree(buf);
			uci_log(ipc_log, DBG_ERROR,
				"Failed to queue buffer %d\n", i);
			return ret;
		}
		list_add_tail(&uci_buf->node, &uci_chan->submitted);
		spin_unlock_bh(&uci_chan->lock);
	}
	return ret;
}

static int mhi_uci_open(struct inode *inode, struct file *file)
{
	struct uci_node *node = NULL;
	struct mhi_uci *mhi_uci = NULL, *itr;
	const long timeout = msecs_to_jiffies(1000);
	struct uci_chan *tx_chan, *rx_chan;
	void *ipc_log;
	struct uci_buf *buf_itr, *tmp;
	int ret = 0;
	int minor = iminor(inode);
	int major = imajor(inode);

	/* Find the uci ctxt from major */
	mutex_lock(&mhi_uci_drv.lock);
	list_for_each_entry(itr, &mhi_uci_drv.head, node) {
		if (MAJOR(itr->dev_t) == major) {
			mhi_uci = itr;
			break;
		}
	}
	mutex_unlock(&mhi_uci_drv.lock);

	if (!mhi_uci)
		return -EINVAL;

	node = &mhi_uci->nodes[minor];
	ipc_log = node->ipc_log;
	tx_chan = &node->out_chan;
	ret = wait_event_interruptible_timeout(tx_chan->wq, tx_chan->enabled,
					       timeout);
	if (ret < 0)
		return -EAGAIN;

	rx_chan = &node->in_chan;
	ret = wait_event_interruptible_timeout(rx_chan->wq, rx_chan->enabled,
					       timeout);
	if (ret < 0)
		return -EAGAIN;

	mutex_lock(&node->mutex);
	if (!tx_chan->enabled || !rx_chan->enabled) {
		uci_log(ipc_log, DBG_INFO, "Node is still disabled\n");
		mutex_unlock(&node->mutex);
		return -EAGAIN;
	}

	node->ref_count++;
	uci_log(ipc_log, DBG_INFO, "Node open ref count %u\n", node->ref_count);

	if (node->ref_count == 1) {
		uci_log(ipc_log, DBG_INFO, "Starting tx channel %s\n",
			tx_chan->chan_name);

		ret = mhi_open_channel(tx_chan->mhi_handle);
		if (ret) {
			uci_log(ipc_log, DBG_ERROR, "Error opening tx chan\n");
			goto error_tx_chan;
		}

		uci_log(ipc_log, DBG_INFO, "Starting rx channel %s\n",
			rx_chan->chan_name);

		ret = mhi_open_channel(rx_chan->mhi_handle);
		if (ret) {
			uci_log(ipc_log, DBG_ERROR, "Error opening rx chan\n");
			goto error_rx_chan;
		}

		ret = mhi_queue_inbound(node);
		if (ret)
			goto error_rx_queue;

	}
	file->private_data = node;
	mutex_unlock(&node->mutex);
	uci_log(ipc_log, DBG_INFO, "Client successfully opened node\n");

	return 0;
error_rx_queue:
	list_for_each_entry_safe(buf_itr, tmp, &rx_chan->submitted, node) {
		list_del(&buf_itr->node);
		kfree(buf_itr->data);
	}
	list_for_each_entry_safe(buf_itr, tmp, &rx_chan->pending, node) {
		list_del(&buf_itr->node);
		kfree(buf_itr->data);
	}
	if (rx_chan->cur_buf)
		kfree(rx_chan->cur_buf->data);
	rx_chan->cur_buf = NULL;
	INIT_LIST_HEAD(&rx_chan->submitted);
	INIT_LIST_HEAD(&rx_chan->pending);
	mhi_close_channel(rx_chan->mhi_handle);
error_rx_chan:
	mhi_close_channel(tx_chan->mhi_handle);
error_tx_chan:
	node->ref_count--;
	mutex_unlock(&node->mutex);
	return ret;
}

static int mhi_uci_parse_dt(struct mhi_uci *mhi_uci,
			    struct device_node *of_node)
{
	struct {
		u32 chan_cfg[2];
	} *chan_cfg = NULL;
	int ret, num, i;
	struct uci_node *node;
	struct uci_chan *uci_chan;

	num = of_property_count_elems_of_size(of_node, "mhi,uci-chan",
					      sizeof(*chan_cfg));
	if (num <= 0)
		return -EINVAL;
	if (of_property_count_strings(of_node, "mhi,chan-names") != 2 * num)
		return -EINVAL;

	chan_cfg = kmalloc_array(num, sizeof(*chan_cfg), GFP_KERNEL);
	if (!chan_cfg)
		return -ENOMEM;

	mhi_uci->nodes = kcalloc(num, sizeof(*mhi_uci->nodes), GFP_KERNEL);
	if (!mhi_uci->nodes) {
		ret = -ENOMEM;
		goto error_no_mem;
	}

	ret = of_property_read_u32_array(of_node, "mhi,uci-chan",
					 (u32 *)chan_cfg,
					 num * sizeof(*chan_cfg) / sizeof(u32));
	if (ret)
		goto error_parse_dt;

	node = mhi_uci->nodes;
	for (i = 0; i < num; i++, node++) {
		uci_chan = &node->out_chan;
		ret = of_property_read_string_index(of_node, "mhi,chan-names",
						    i * 2, &uci_chan->chan_name);
		if (ret)
			goto error_parse_dt;
		uci_chan->max_packet_size = chan_cfg[i].chan_cfg[0];

		uci_chan = &node->in_chan;
		ret = of_property_read_string_index(of_node, "mhi,chan-names",
					      (i * 2) + 1, &uci_chan->chan_name);
		if (ret)
			goto error_parse_dt;
		uci_chan->max_packet_size = chan_cfg[i].chan_cfg[1];
	}
	mhi_uci->num_nodes = num;
	kfree(chan_cfg);
	return 0;
error_parse_dt:
	kfree(mhi_uci->nodes);
error_no_mem:
	kfree(chan_cfg);
	return ret;
}

static const struct file_operations mhi_uci_fops = {
	.read = mhi_uci_read,
	.write = mhi_uci_write,
	.open = mhi_uci_open,
	.release = mhi_uci_release,
	.poll = mhi_uci_poll,
	.unlocked_ioctl = mhi_uci_ioctl,
};

static int mhi_uci_create_devnode(struct mhi_uci *mhi_uci,
				  struct uci_node *node)
{
	char node_name[32];
	int index = node - mhi_uci->nodes;
	struct uci_chan *uci_chan = &node->out_chan;
	int ret;

	cdev_init(&node->cdev, &mhi_uci_fops);
	node->cdev.owner = THIS_MODULE;
	ret = cdev_add(&node->cdev, mhi_uci->dev_t + index, 1);
	if (ret)
		return ret;

	node->dev = device_create(mhi_uci_drv.class, NULL,
				  mhi_uci->dev_t + index, NULL,
				  DEVICE_NAME "_%04x_%02u.%02u.%02u%s%d",
				  uci_chan->mhi_handle->dev_id,
				  uci_chan->mhi_handle->domain,
				  uci_chan->mhi_handle->bus,
				  uci_chan->mhi_handle->slot,
				  "_pipe_",
				  uci_chan->chan_id);
	if (IS_ERR(node->dev)) {
		cdev_del(&node->cdev);
		return -EIO;
	}

	/* dev node created successfully, create logging buffer */
	snprintf(node_name, sizeof(node_name), "mhi_uci_%04x_%02u.%02u.%02u_%d",
		 uci_chan->mhi_handle->dev_id,
		 uci_chan->mhi_handle->domain,
		 uci_chan->mhi_handle->bus,
		 uci_chan->mhi_handle->slot,
		 uci_chan->chan_id);
	node->ipc_log = ipc_log_context_create(MHI_UCI_IPC_LOG_PAGES, node_name,
					       0);
	return 0;
}

static void uci_xfer_rx_cb(struct mhi_cb_info *cb_info)
{
	struct uci_node *node = cb_info->user_data;
	struct uci_chan *uci_chan = &node->in_chan;
	void *ipc_log = node->ipc_log;
	struct mhi_result *result = &cb_info->result;
	unsigned long flags;
	struct uci_buf *buf;

	spin_lock_irqsave(&uci_chan->lock, flags);
	buf = list_first_entry_or_null(&uci_chan->submitted, struct uci_buf,
				       node);
	BUG_ON(buf->data != result->buf_addr);
	list_del(&buf->node);
	buf->len = result->bytes_xferd;
	list_add_tail(&buf->node, &uci_chan->pending);
	spin_unlock_irqrestore(&uci_chan->lock, flags);
	uci_log(ipc_log, DBG_VERBOSE,"pkt_id: %llu len:%lu\n",
		buf->pkt_id, buf->len);
	wake_up(&uci_chan->wq);
}

static void uci_xfer_tx_cb(struct mhi_cb_info *cb_info)
{
	struct uci_node *node = cb_info->user_data;
	struct uci_chan *uci_chan = &node->out_chan;
	void *ipc_log = node->ipc_log;
	struct mhi_result *result = &cb_info->result;
	unsigned long flags;
	struct uci_buf *buf;

	spin_lock_irqsave(&uci_chan->lock, flags);
	buf = list_first_entry_or_null(&uci_chan->submitted, struct uci_buf,
				       node);
	BUG_ON(buf->data != result->buf_addr);
	BUG_ON(buf->len != result->bytes_xferd);
	list_del(&buf->node);
	spin_unlock_irqrestore(&uci_chan->lock, flags);
	uci_log(ipc_log, DBG_VERBOSE,"pkt_id: %llu len:%lu\n",
		buf->pkt_id, buf->len);
	kfree(buf->data);
	wake_up(&uci_chan->wq);
}

static void uci_status_cb(struct mhi_cb_info *cb_info)
{
	struct uci_node *node = cb_info->user_data;
	struct uci_chan *uci_chan;
	void *ipc_log = node->ipc_log;

	uci_log(ipc_log, DBG_INFO, "cb reason:0x%x\n", cb_info->cb_reason);

	switch (cb_info->cb_reason) {
	case MHI_CB_MHI_PROBED:
		/* If it's outbound channel create the node */
		mutex_lock(&node->mutex);
		if (!node->dev &&
		    cb_info->chan == node->out_chan.chan_id)
			mhi_uci_create_devnode(node->mhi_uci, node);
		mutex_unlock(&node->mutex);
		break;
	case MHI_CB_MHI_ENABLED:
		uci_chan = (node->out_chan.chan_id == cb_info->chan) ?
			&node->out_chan : &node->in_chan;

		/* changing state to enable does not require lock */
		uci_chan->enabled = true;
		wake_up(&uci_chan->wq);
		break;
	case MHI_CB_SYS_ERROR:
	case MHI_CB_MHI_SHUTDOWN:
	case MHI_CB_MHI_DISABLED:
		uci_chan = (node->out_chan.chan_id == cb_info->chan) ?
			&node->out_chan : &node->in_chan;

		mutex_lock(&node->mutex);
		spin_lock_irq(&uci_chan->lock);
		uci_chan->enabled = false;
		spin_unlock_irq(&uci_chan->lock);
		mutex_unlock(&node->mutex);
		wake_up(&uci_chan->wq);
		break;
	default:
		uci_log(ipc_log, DBG_ERROR, "Cannot handle cb reason 0x%x\n",
			cb_info->cb_reason);
	}
}

static int mhi_uci_probe(struct platform_device *pdev)
{
	struct mhi_uci *mhi_uci;
	struct uci_node *node;
	struct uci_chan *uci_chan;
	struct mhi_client_info_t client_info;
	int ret;
	int i;

	if (!pdev->dev.of_node)
		return -ENODEV;

	if (!mhi_is_device_ready(pdev->dev.of_node, "qcom,mhi"))
		return -EPROBE_DEFER;

	pdev->id = of_alias_get_id(pdev->dev.of_node, "mhi_uci");
	if (pdev->id < 0)
		return -ENODEV;

	mhi_uci = devm_kzalloc(&pdev->dev, sizeof(*mhi_uci), GFP_KERNEL);
	if (!mhi_uci)
		return -ENOMEM;

	ret = mhi_uci_parse_dt(mhi_uci, pdev->dev.of_node);
	if (ret)
		return ret;

	ret = alloc_chrdev_region(&mhi_uci->dev_t, 0, mhi_uci->num_nodes,
				  DEVICE_NAME);
	if (ret)
		goto error_chrdev_alloc;

	client_info.of_node = pdev->dev.of_node;
	client_info.node_name = "qcom,mhi";
	client_info.mhi_client_cb = uci_status_cb;
	node = mhi_uci->nodes;
	for (i = 0; i < mhi_uci->num_nodes; i++, node++) {
		mutex_init(&node->mutex);
		mutex_lock(&node->mutex);
		node->mhi_uci = mhi_uci;
		uci_chan = &node->in_chan;

		init_waitqueue_head(&uci_chan->wq);
		spin_lock_init(&uci_chan->lock);
		INIT_LIST_HEAD(&uci_chan->submitted);
		INIT_LIST_HEAD(&uci_chan->pending);

		client_info.user_data = node;
		client_info.mhi_xfer_cb = uci_xfer_rx_cb;
		client_info.chan_name = uci_chan->chan_name;
		uci_chan->mhi_handle = mhi_register_channel(&client_info);
		if (IS_ERR(uci_chan->mhi_handle)) {
			ret = PTR_ERR(uci_chan->mhi_handle);
			mutex_unlock(&node->mutex);
			goto error_register_chan;
		}
		uci_chan->chan_id = uci_chan->mhi_handle->chan_id;

		uci_chan = &node->out_chan;
		init_waitqueue_head(&uci_chan->wq);
		spin_lock_init(&uci_chan->lock);
		INIT_LIST_HEAD(&uci_chan->submitted);
		INIT_LIST_HEAD(&uci_chan->pending);

		client_info.user_data = node;
		client_info.mhi_xfer_cb = uci_xfer_tx_cb;
		client_info.chan_name = uci_chan->chan_name;
		uci_chan->mhi_handle = mhi_register_channel(&client_info);
		if (IS_ERR(uci_chan->mhi_handle)) {
			ret = PTR_ERR(uci_chan->mhi_handle);
			mutex_unlock(&node->mutex);
			//FIXME: Add deregister in chan
			goto error_register_chan;
		}
		uci_chan->chan_id = uci_chan->mhi_handle->chan_id;

		/* if we already have dev id create the node */
		if (uci_chan->mhi_handle->dev_id != PCI_ANY_ID) {
			ret = mhi_uci_create_devnode(mhi_uci, node);
			if (ret) {
				mutex_unlock(&node->mutex);
				goto error_register_chan;
			}
		}
		mutex_unlock(&node->mutex);
	}

	mutex_lock(&mhi_uci_drv.lock);
	list_add_tail(&mhi_uci->node, &mhi_uci_drv.head);
	mutex_unlock(&mhi_uci_drv.lock);

	return 0;

error_register_chan:
	node--;
	for (i = i - 1; i >= 0; i--, node--) {
		//mhi_uci_destroy_devnode(node);
		mhi_deregister_channel(node->in_chan.mhi_handle);
		mhi_deregister_channel(node->out_chan.mhi_handle);
	}

error_chrdev_alloc:
	kfree(mhi_uci->nodes);
	return ret;
};

static const struct of_device_id mhi_uci_match_table[] = {
	{.compatible = "qcom,mhi-uci"},
	{},
};

static struct platform_driver mhi_uci_driver = {
	.probe = mhi_uci_probe,
	.driver = {
		.name = MHI_UCI_DRIVER_NAME,
		.owner = THIS_MODULE,
		.of_match_table = mhi_uci_match_table,
	},
};

static int mhi_uci_init(void)
{
	int ret;
	mhi_uci_drv.class = class_create(THIS_MODULE, DEVICE_NAME);
	if (IS_ERR(mhi_uci_drv.class))
		return -ENODEV;

	mutex_init(&mhi_uci_drv.lock);
	INIT_LIST_HEAD(&mhi_uci_drv.head);

	ret = platform_driver_register(&mhi_uci_driver);
	if (ret)
		class_destroy(mhi_uci_drv.class);

	return ret;
}

module_init(mhi_uci_init);
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("MHI_UCI");
MODULE_DESCRIPTION("MHI UCI Driver");
