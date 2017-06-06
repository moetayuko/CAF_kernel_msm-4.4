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
/*
 * MHI Network interface
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/msm_rmnet.h>
#include <linux/if_arp.h>
#include <linux/dma-mapping.h>
#include <linux/msm_mhi.h>
#include <linux/debugfs.h>
#include <linux/ipc_logging.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/of_device.h>
#include <linux/rtnetlink.h>

#define MHI_NETDEV_DRIVER_NAME "mhi_netdev"
#define MHI_DEFAULT_MTU        SZ_16K
#define MHI_MAX_MRU            0xFFFF
#define MHI_NAPI_WEIGHT_VALUE  12
#define WATCHDOG_TIMEOUT       (30 * HZ)
#define IPC_LOG_PAGES (100)
#define LPM_MASKED_BIT (0)

enum DBG_LVL {
	MSG_VERBOSE,
	MSG_INFO,
	MSG_ERROR,
	MSG_MASK_ALL,
};

struct mhi_stats {
	u32 rx_int;
	u32 tx_full;
	u32 tx_pkts;
	u32 rx_budget_overflow;
	u32 rx_frag;
	u32 alloc_failed;
};

/* Important: do not exceed sk_buf->cb (48 bytes) */
struct mhi_skb_priv {
	void *buf;
	size_t size;
	struct mhi_netdev *mhi_netdev;
};

#define mhi_log(mhi_netdev, _msg_lvl, _msg, ...) do {	\
		if ((_msg_lvl) >= mhi_netdev->msg_lvl) \
			pr_alert("[%s] " _msg, __func__, ##__VA_ARGS__);\
		if (mhi_netdev->ipc_log && \
		    ((_msg_lvl) >= mhi_netdev->ipc_log_lvl)) \
			ipc_log_string(mhi_netdev->ipc_log, \
			       "[%s] " _msg, __func__, ##__VA_ARGS__);	\
} while (0)

struct mhi_netdev {
	struct list_head node;
	u32 dev_id;
	const char *interface_name;
	struct mhi_client_handle *tx_client;
	struct mhi_client_handle *rx_client;
	const char *tx_channel;
	const char *rx_channel;
	int tx_chan_id;
	int rx_chan_id;
	struct sk_buff_head tx_submitted;
	struct sk_buff_head rx_submitted;
	struct sk_buff_head rx_allocated;
	u32 mru;
	u32 max_mtu;
	u32 max_mru;
	struct napi_struct napi;
	bool tx_enabled;
	bool rx_enabled;
	struct platform_device *pdev;
	struct net_device *ndev;
	unsigned long flags;
	int wake_count;
	spinlock_t tx_lock;
	spinlock_t rx_lock;
	struct sk_buff *frag_skb;
	struct work_struct alloc_work;
	rwlock_t pm_lock; /* state change lock */
	struct mutex mutex;
	bool recycle_buf;
	int (*rx_queue)(struct mhi_netdev *, gfp_t);
	struct mhi_stats stats;
	struct dentry *dentry;
	enum DBG_LVL msg_lvl;
	enum DBG_LVL ipc_log_lvl;
	void *ipc_log;
};

struct mhi_netdev_priv
{
	struct mhi_netdev *mhi_netdev;
};

static LIST_HEAD(mhi_netdev_dev_list);
static struct platform_driver mhi_netdev_driver;

#if 0
static void rmnet_mhi_dequeue(struct mhi *rmnet_mhi,
			      struct sk_buff_head *queue)
{
	mhi_log(rmnet_mhi, MSG_INFO, "Entered\n");
	while (!skb_queue_empty(queue)) {
		struct sk_buff *skb = skb_dequeue(queue);
		if (skb)
			kfree_skb(skb);
	}
	mhi_log(rmnet_mhi, MSG_INFO, "Exited\n");
}
#endif

static __be16 mhi_netdev_ip_type_trans(struct sk_buff *skb)
{
	__be16 protocol = 0;

	/* Determine L3 protocol */
	switch (skb->data[0] & 0xf0) {
	case 0x40:
		protocol = htons(ETH_P_IP);
		break;
	case 0x60:
		protocol = htons(ETH_P_IPV6);
		break;
	default:
		/* Default is QMAP */
		protocol = htons(ETH_P_MAP);
		break;
	}
	return protocol;
}

static void mhi_netdev_skb_destructor(struct sk_buff *skb)
{
	struct mhi_skb_priv *skb_priv = (struct mhi_skb_priv *)(skb->cb);
	struct mhi_netdev *mhi_netdev = skb_priv->mhi_netdev;

	skb->data = skb->head;
	skb_reset_tail_pointer(skb);
	skb->len = 0;
	BUG_ON(skb->data != skb_priv->buf);
	skb_queue_tail(&mhi_netdev->rx_allocated, skb);
}

static int mhi_netdev_alloc_rx(struct mhi_netdev *mhi_netdev, gfp_t alloc_flags)
{
	u32 cur_mru = mhi_netdev->mru;
	struct mhi_skb_priv *skb_priv;
	int ret;
	struct sk_buff *skb;
	int no_tre = mhi_get_free_desc(mhi_netdev->rx_client);
	int i;

	for (i = 0; i < no_tre; i++) {
		skb = alloc_skb(cur_mru, alloc_flags);
		if (!skb)
			return -ENOMEM;

		read_lock_bh(&mhi_netdev->pm_lock);
		if (unlikely(!mhi_netdev->rx_enabled)) {
			read_unlock_bh(&mhi_netdev->pm_lock);
			dev_kfree_skb_any(skb);
			return -EIO;
		}

		skb_priv = (struct mhi_skb_priv *)skb->cb;
		skb_priv->buf = skb->data;
		skb_priv->size = cur_mru;
		skb_priv->mhi_netdev = mhi_netdev;
		skb->dev = mhi_netdev->ndev;

		/* These two steps must be locked */
		spin_lock_bh(&mhi_netdev->rx_lock);

		ret = mhi_queue_xfer(mhi_netdev->rx_client, skb, skb_priv->size,
				     MHI_EOT);
		if (unlikely(ret)) {
			spin_unlock_bh(&mhi_netdev->rx_lock);
			read_unlock_bh(&mhi_netdev->pm_lock);
			dev_kfree_skb_any(skb);
			return -EIO;
		}

		if (mhi_netdev->recycle_buf)
			skb->destructor = mhi_netdev_skb_destructor;

		skb_queue_tail(&mhi_netdev->rx_submitted, skb);
		spin_unlock_bh(&mhi_netdev->rx_lock);
		read_unlock_bh(&mhi_netdev->pm_lock);
	}
	return 0;
}

static void mhi_netdev_alloc_work(struct work_struct *work)
{
	struct mhi_netdev *mhi_netdev = container_of(work, struct mhi_netdev,
						   alloc_work);
	int ret;
	/* sleep about 1 sec and retry, that should be enough time
	 * for system to reclaim freed memory back.
	 */
	const int sleep_ms =  1000;
	int retry = 60;

	mhi_log(mhi_netdev, MSG_INFO, "Entered\n");
	do {
		ret = mhi_netdev_alloc_rx(mhi_netdev, GFP_KERNEL);
		/* sleep and try again */
		if (ret == -ENOMEM) {
			msleep(sleep_ms);
			retry--;
		}
	} while (ret == -ENOMEM && retry);

	mhi_log(mhi_netdev, MSG_INFO, "Exit with status:%d retry:%d\n",
		  ret, retry);
}

/* we will recycle buffers */
static int mhi_netdev_skb_recycle(struct mhi_netdev *mhi_netdev, gfp_t flag)
{
	int nr_el = mhi_get_free_desc(mhi_netdev->rx_client);
	int i, ret = 0;
	struct sk_buff *skb;
	struct mhi_skb_priv *skb_priv;

	read_lock_bh(&mhi_netdev->pm_lock);
	if (unlikely(!mhi_netdev->rx_enabled)) {
		read_unlock_bh(&mhi_netdev->pm_lock);
			return -EIO;
	}

	spin_lock_bh(&mhi_netdev->rx_lock);
	for (i = 0; i < nr_el; i++) {

		skb = skb_dequeue(&mhi_netdev->rx_allocated);
		/* no free buffers to recycle, reschedule work */
		if (unlikely(!skb)) {
			ret = -ENOMEM;
			goto error_queue;
		}

		skb_priv = (struct mhi_skb_priv *)(skb->cb);
		ret = mhi_queue_xfer(mhi_netdev->rx_client, skb, skb_priv->size,
				     MHI_EOT);

		/* failed to queue buffer */
		if (unlikely(ret)) {
			mhi_log(mhi_netdev, MSG_ERROR,
				  "failed to queue skb, ret:%d\n", ret);
			skb_queue_tail(&mhi_netdev->rx_allocated, skb);
			goto error_queue;
		}

		skb_queue_tail(&mhi_netdev->rx_submitted, skb);
	}

error_queue:
	spin_unlock_bh(&mhi_netdev->rx_lock);
	read_unlock_bh(&mhi_netdev->pm_lock);
	return ret;
}

static int mhi_netdev_poll(struct napi_struct *napi, int budget)
{
	struct net_device *dev = napi->dev;
	struct mhi_netdev_priv *mhi_netdev_priv = netdev_priv(dev);
	struct mhi_netdev *mhi_netdev = mhi_netdev_priv->mhi_netdev;
	int rx_work = 0;
	int ret;

	mhi_log(mhi_netdev, MSG_VERBOSE, "Entered\n");

	read_lock_bh(&mhi_netdev->pm_lock);
	mhi_set_lpm(mhi_netdev->rx_client, false);
	mhi_netdev->wake_count++;
	if (unlikely(!mhi_netdev->rx_enabled)) {
		mhi_log(mhi_netdev, MSG_INFO, "interface is disabled!\n");
		napi_complete(napi);
		goto exit_poll;
	}

	rx_work = mhi_poll(mhi_netdev->rx_client, budget);
	if (rx_work < 0) {
		mhi_log(mhi_netdev, MSG_ERROR,"Error polling ret:%d\n", rx_work);
		rx_work = 0;
		napi_complete(napi);
		goto exit_poll;
	}

	/* queue new buffers */
	ret = mhi_netdev->rx_queue(mhi_netdev, GFP_ATOMIC);
	if (ret == -ENOMEM) {
		mhi_log(mhi_netdev, MSG_INFO,
			  "out of tre, queuing bg worker\n");
		panic("no mem");
		mhi_netdev->stats.alloc_failed++;
		schedule_work(&mhi_netdev->alloc_work);

	}

	/* complete work if we processed budget */
	if (rx_work < budget)
		napi_complete(napi);
        else
		mhi_netdev->stats.rx_budget_overflow++;

exit_poll:
	mhi_set_lpm(mhi_netdev->rx_client, true);
	mhi_netdev->wake_count--;
	read_unlock_bh(&mhi_netdev->pm_lock);

	mhi_log(mhi_netdev, MSG_VERBOSE, "polled %d pkts\n", rx_work);
	return rx_work;
}

static int mhi_netdev_open(struct net_device *dev)
{
	struct mhi_netdev_priv *mhi_netdev_priv = netdev_priv(dev);
	struct mhi_netdev *mhi_netdev = mhi_netdev_priv->mhi_netdev;

	mhi_log(mhi_netdev, MSG_INFO,
		  "Opened net dev interface for MHI chans %s and %s\n",
		  mhi_netdev->tx_channel, mhi_netdev->rx_channel);

	/* tx queue may not necessarily be stopped already
	 * so stop the queue if tx path is not enabled
	 */
	if (!mhi_netdev->tx_client)
		netif_stop_queue(dev);
	else
		netif_start_queue(dev);

	return 0;

}

#if 0
static int mhi_netdev_disable(struct mhi_netdev *mhi_netdev)
{
	napi_disable(&(mhi_netdev->napi));
	mhi_netdev->rx_enabled = 0;
	mhi_netdev_internal_clean_unmap_buffers(mhi_netdev->dev,
					       &mhi_netdev->rx_buffers,
					       DMA_FROM_DEVICE);

	return 0;
}

#endif

static int mhi_netdev_change_mtu(struct net_device *dev, int new_mtu)
{
	struct mhi_netdev_priv *mhi_netdev_priv = netdev_priv(dev);
	struct mhi_netdev *mhi_netdev = mhi_netdev_priv->mhi_netdev;

	if (new_mtu < 0 || mhi_netdev->max_mtu < new_mtu)
		return -EINVAL;

	dev->mtu = new_mtu;
	return 0;
}

static int mhi_netdev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct mhi_netdev_priv *mhi_netdev_priv = netdev_priv(dev);
	struct mhi_netdev *mhi_netdev = mhi_netdev_priv->mhi_netdev;
	int res = 0;
	struct mhi_skb_priv *tx_priv;

	mhi_log(mhi_netdev, MSG_VERBOSE,
		  "Entered chan %s\n", mhi_netdev->tx_channel);

	tx_priv = (struct mhi_skb_priv *)(skb->cb);
	tx_priv->mhi_netdev = mhi_netdev;
	read_lock_bh(&mhi_netdev->pm_lock);
	if (unlikely(!mhi_netdev->tx_enabled)) {
		/* Only reason interface could be disabled and we get data
		 * is due to an SSR. We do not want to stop the queue and
		 * return error. instead we will flush all the uplink packets
		 * and return successful
		 */
		res = NETDEV_TX_OK;
		dev_kfree_skb_any(skb);
		goto mhi_xmit_exit;
	}

	spin_lock_bh(&mhi_netdev->tx_lock);
	res = mhi_queue_xfer(mhi_netdev->tx_client, skb, skb->len, MHI_EOT);
	if (res) {
		mhi_log(mhi_netdev, MSG_ERROR,
			  "Failed to queue with reason:%d\n", res);
		netif_stop_queue(dev);
		spin_unlock_bh(&mhi_netdev->tx_lock);
		mhi_netdev->stats.tx_full++;
		res = NETDEV_TX_BUSY;
		goto mhi_xmit_exit;
	}
	skb_queue_tail(&mhi_netdev->tx_submitted, skb);
	spin_unlock_bh(&mhi_netdev->tx_lock);

	mhi_netdev->stats.tx_pkts++;
mhi_xmit_exit:
	read_unlock_bh(&mhi_netdev->pm_lock);
	mhi_log(mhi_netdev, MSG_VERBOSE, "Exited\n");
	return res;
}

static int mhi_netdev_ioctl_extended(struct net_device *dev, struct ifreq *ifr)
{
	struct rmnet_ioctl_extended_s ext_cmd;
	int rc = 0;
	struct mhi_netdev_priv *mhi_netdev_priv = netdev_priv(dev);
	struct mhi_netdev *mhi_netdev = mhi_netdev_priv->mhi_netdev;

	rc = copy_from_user(&ext_cmd, ifr->ifr_ifru.ifru_data,
			    sizeof(struct rmnet_ioctl_extended_s));

	if (rc)
		return rc;

	switch (ext_cmd.extended_ioctl) {
	case RMNET_IOCTL_SET_MRU:
		if (!ext_cmd.u.data || ext_cmd.u.data > mhi_netdev->max_mru) {
			mhi_log(mhi_netdev, MSG_ERROR,
				  "Can't set MRU, value:%u is invalid max:%u\n",
				  ext_cmd.u.data, mhi_netdev->max_mru);
			return -EINVAL;
		}
		mhi_log(mhi_netdev, MSG_INFO, "MRU change request to 0x%x\n",
			  ext_cmd.u.data);
		mhi_netdev->mru = ext_cmd.u.data;
		break;
	case RMNET_IOCTL_GET_EPID:
		//FIXME: Get this from rmnet directly
		ext_cmd.u.data =
			mhi_get_epid(mhi_netdev->tx_client);
		break;
	case RMNET_IOCTL_GET_SUPPORTED_FEATURES:
		ext_cmd.u.data = 0;
		break;
	case RMNET_IOCTL_GET_DRIVER_NAME:
		strlcpy(ext_cmd.u.if_name, mhi_netdev->interface_name,
			sizeof(ext_cmd.u.if_name));
		break;
	case RMNET_IOCTL_SET_SLEEP_STATE:
		read_lock_bh(&mhi_netdev->pm_lock);
		if (mhi_netdev->tx_enabled && mhi_netdev->tx_client) {
			if (ext_cmd.u.data && !test_and_set_bit(LPM_MASKED_BIT,
						&mhi_netdev->flags)) {
				/* Request to enable LPM */
				mhi_log(mhi_netdev, MSG_INFO,
					  "Enable MHI LPM");
				mhi_netdev->wake_count--;
				mhi_set_lpm(mhi_netdev->tx_client, true);
			} else if (!ext_cmd.u.data &&
				   test_and_clear_bit(LPM_MASKED_BIT,
						      &mhi_netdev->flags)) {
				/* Request to disable LPM */
				mhi_log(mhi_netdev, MSG_INFO,
					  "Disable MHI LPM");
				mhi_netdev->wake_count++;
				mhi_set_lpm(mhi_netdev->tx_client, false);
			}
		} else {
			mhi_log(mhi_netdev, MSG_ERROR,
				  "Cannot set LPM value, MHI is not up.\n");
			read_unlock_bh(&mhi_netdev->pm_lock);
			return -ENODEV;
		}
		read_unlock_bh(&mhi_netdev->pm_lock);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	rc = copy_to_user(ifr->ifr_ifru.ifru_data, &ext_cmd,
			  sizeof(struct rmnet_ioctl_extended_s));
	return rc;
}

static int mhi_netdev_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	int rc = 0;
	struct rmnet_ioctl_data_s ioctl_data;

	switch (cmd) {
	case RMNET_IOCTL_SET_LLP_IP:        /* Set RAWIP protocol */
		break;
	case RMNET_IOCTL_GET_LLP:           /* Get link protocol state */
		ioctl_data.u.operation_mode = RMNET_MODE_LLP_IP;
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &ioctl_data,
		    sizeof(struct rmnet_ioctl_data_s)))
			rc = -EFAULT;
		break;
	case RMNET_IOCTL_GET_OPMODE:        /* Get operation mode      */
		ioctl_data.u.operation_mode = RMNET_MODE_LLP_IP;
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &ioctl_data,
		    sizeof(struct rmnet_ioctl_data_s)))
			rc = -EFAULT;
		break;
	case RMNET_IOCTL_SET_QOS_ENABLE:
		rc = -EINVAL;
		break;
	case RMNET_IOCTL_SET_QOS_DISABLE:
		rc = 0;
		break;
	case RMNET_IOCTL_OPEN:
	case RMNET_IOCTL_CLOSE:
		/* We just ignore them and return success */
		rc = 0;
		break;
	case RMNET_IOCTL_EXTENDED:
		rc = mhi_netdev_ioctl_extended(dev, ifr);
		break;
	default:
		/* Don't fail any IOCTL right now */
		rc = 0;
		break;
	}

	return rc;
}

static const struct net_device_ops mhi_netdev_ops_ip = {
	.ndo_open = mhi_netdev_open,
	.ndo_start_xmit = mhi_netdev_xmit,
	.ndo_do_ioctl = mhi_netdev_ioctl,
	.ndo_change_mtu = mhi_netdev_change_mtu,
	.ndo_set_mac_address = 0,
	.ndo_validate_addr = 0,
};

static void mhi_netdev_setup(struct net_device *dev)
{
	dev->netdev_ops = &mhi_netdev_ops_ip;
	ether_setup(dev);

	/* set this after calling ether_setup */
	dev->header_ops = 0;  /* No header */
	dev->type = ARPHRD_RAWIP;
	dev->hard_header_len = 0;
	dev->mtu = MHI_DEFAULT_MTU;
	dev->addr_len = 0;
	dev->flags &= ~(IFF_BROADCAST | IFF_MULTICAST);
	dev->watchdog_timeo = WATCHDOG_TIMEOUT;
}

/* enable mhi_netdev netdev, call only after grabbing mhi_netdev.mutex */
static int mhi_netdev_enable_iface(struct mhi_netdev *mhi_netdev)
{
	int ret = 0;
	char ifalias[IFALIASZ];
	char ifname[IFNAMSIZ];
	struct mhi_client_handle *client_handle = NULL;
	int no_tre;

	mhi_log(mhi_netdev, MSG_INFO, "Entered.\n");

	if (mhi_netdev->tx_client) {
		mhi_log(mhi_netdev, MSG_INFO, "Opening TX channel\n");
		ret = mhi_open_channel(mhi_netdev->tx_client);
		if (ret) {
			mhi_log(mhi_netdev, MSG_ERROR,
				  "Failed to start TX chan ret %d\n", ret);
			goto mhi_tx_chan_start_fail;
		}

		client_handle = mhi_netdev->tx_client;
	}
	if (mhi_netdev->rx_client) {
		mhi_log(mhi_netdev, MSG_INFO, "Opening RX channel\n");
		ret = mhi_open_channel(mhi_netdev->rx_client);
		if (ret) {
			mhi_log(mhi_netdev, MSG_ERROR,
				  "Failed to start RX chan ret %d\n", ret);
			goto mhi_rx_chan_start_fail;
		}

		/* Both tx & rx client handle contain same device info */
		client_handle = mhi_netdev->rx_client;
	}

	if (!client_handle) {
		ret = -EINVAL;
		goto net_dev_alloc_fail;
	}

	/* first time enabling the node */
	if (!mhi_netdev->ndev) {
		struct mhi_netdev_priv *mhi_netdev_priv;

		snprintf(ifalias, sizeof(ifalias), "%s_%04x_%02u.%02u.%02u_%u",
			 mhi_netdev->interface_name, client_handle->dev_id,
			 client_handle->domain, client_handle->bus,
			 client_handle->slot, mhi_netdev->dev_id);

		snprintf(ifname, sizeof(ifname), "%s%%d",
			 mhi_netdev->interface_name);

		rtnl_lock();
		mhi_netdev->ndev = alloc_netdev(sizeof(*mhi_netdev_priv),
					ifname, NET_NAME_PREDICTABLE,
					mhi_netdev_setup);

		if (!mhi_netdev->ndev) {
			mhi_log(mhi_netdev, MSG_ERROR,
				  "Network device allocation failed\n");
			ret = -ENOMEM;
			goto net_dev_alloc_fail;
		}

		SET_NETDEV_DEV(mhi_netdev->ndev, &mhi_netdev->pdev->dev);
		dev_set_alias(mhi_netdev->ndev, ifalias, strlen(ifalias));
		mhi_netdev_priv = netdev_priv(mhi_netdev->ndev);
		mhi_netdev_priv->mhi_netdev = mhi_netdev;
		rtnl_unlock();

		/* FIXME: get napi weight from DT */
		netif_napi_add(mhi_netdev->ndev, &mhi_netdev->napi,
			       mhi_netdev_poll, MHI_NAPI_WEIGHT_VALUE);
		ret = register_netdev(mhi_netdev->ndev);
		if (ret) {
			mhi_log(mhi_netdev, MSG_ERROR,
				  "Network device registration failed\n");
			goto net_dev_reg_fail;
		}

		skb_queue_head_init(&mhi_netdev->tx_submitted);
		skb_queue_head_init(&mhi_netdev->rx_submitted);
		skb_queue_head_init(&mhi_netdev->rx_allocated);
	}

	/* queue buffer for rx path */
	no_tre = mhi_get_free_desc(mhi_netdev->rx_client);
	ret = mhi_netdev_alloc_rx(mhi_netdev, GFP_KERNEL);
	if (ret)
		schedule_work(&mhi_netdev->alloc_work);

	/* if we recycle prepare one more set */
	if (mhi_netdev->recycle_buf)
		for (; no_tre >= 0; no_tre--) {
			struct sk_buff *skb = alloc_skb(mhi_netdev->mru,
						       GFP_KERNEL);
			struct mhi_skb_priv *skb_priv;

			if (!skb)
				break;

			skb_priv = (struct mhi_skb_priv *)skb->cb;
			skb_priv->buf = skb->data;
			skb_priv->size = mhi_netdev->mru;
			skb_priv->mhi_netdev = mhi_netdev;
			skb->dev = mhi_netdev->ndev;
			skb->destructor = mhi_netdev_skb_destructor;
			skb_queue_tail(&mhi_netdev->rx_allocated, skb);
		}

	napi_enable(&mhi_netdev->napi);

	mhi_log(mhi_netdev, MSG_INFO, "Exited.\n");

	return 0;

net_dev_reg_fail:
	netif_napi_del(&mhi_netdev->napi);
	free_netdev(mhi_netdev->ndev);
	mhi_netdev->ndev = NULL;
net_dev_alloc_fail:
	if (mhi_netdev->rx_client)
		mhi_close_channel(mhi_netdev->rx_client);
mhi_rx_chan_start_fail:
	if (mhi_netdev->tx_client)
		mhi_close_channel(mhi_netdev->tx_client);
mhi_tx_chan_start_fail:
	mhi_log(mhi_netdev, MSG_INFO, "Exited ret %d.\n", ret);
	return ret;
}

static void mhi_netdev_xfer_tx_cb(struct mhi_cb_info *cb_info)
{
	struct mhi_result *result = &cb_info->result;
	struct mhi_netdev *mhi_netdev = cb_info->user_data;
	struct sk_buff *skb = skb_dequeue(&mhi_netdev->tx_submitted);
	struct net_device *ndev = mhi_netdev->ndev;
	unsigned long flags;

	BUG_ON(skb != result->buf_addr);

	ndev->stats.tx_packets++;
	ndev->stats.tx_bytes += skb->len;
	dev_kfree_skb(skb);

	if (netif_queue_stopped(ndev)) {
		spin_lock_irqsave(&mhi_netdev->tx_lock, flags);
		netif_wake_queue(ndev);
		spin_unlock_irqrestore(&mhi_netdev->tx_lock, flags);
	}
}

//FIXME: Need to check if rmnet_data support frag buffers
static int mhi_netdev_process_fragment(struct mhi_netdev *mhi_netdev,
				      struct sk_buff *skb)
{
	struct sk_buff *temp_skb;

	if (mhi_netdev->frag_skb) {
		/* Merge the new skb into the old fragment */
		temp_skb = skb_copy_expand(mhi_netdev->frag_skb, 0, skb->len,
					   GFP_ATOMIC);
		if (!temp_skb) {
			dev_kfree_skb(mhi_netdev->frag_skb);
			mhi_netdev->frag_skb = NULL;
			return -ENOMEM;
		}
		dev_kfree_skb_any(mhi_netdev->frag_skb);
		mhi_netdev->frag_skb = temp_skb;
		memcpy(skb_put(mhi_netdev->frag_skb, skb->len), skb->data,
		       skb->len);
	} else {
		mhi_netdev->frag_skb = skb_copy(skb, GFP_ATOMIC);
		if (!mhi_netdev->frag_skb)
			return -ENOMEM;
	}

	/* recycle the skb */
	if (mhi_netdev->recycle_buf)
		mhi_netdev_skb_destructor(skb);
	else
		dev_kfree_skb(skb);

	mhi_netdev->stats.rx_frag++;
	return 0;
}

static void mhi_netdev_xfer_rx_cb(struct mhi_cb_info *cb_info)
{
	struct mhi_result *result = &cb_info->result;
	struct mhi_netdev *mhi_netdev = cb_info->user_data;
	struct sk_buff *skb = skb_dequeue(&mhi_netdev->rx_submitted);
	struct net_device *dev = mhi_netdev->ndev;
	int ret = 0;

	BUG_ON(skb != result->buf_addr);

	skb_put(skb, result->bytes_xferd);
	dev->stats.rx_packets++;
	dev->stats.rx_bytes += result->bytes_xferd;

	/* merge skb's together, it's a chain transfer */
	if (result->transaction_status == -EOVERFLOW ||
	    mhi_netdev->frag_skb) {
		ret = mhi_netdev_process_fragment(mhi_netdev, skb);
		if (ret)
			return;
	}

	/* more data will come, don't submit the buffer */
	if (result->transaction_status == -EOVERFLOW)
		return;

	if (mhi_netdev->frag_skb) {
		skb = mhi_netdev->frag_skb;
		skb->dev = dev;
		mhi_netdev->frag_skb = NULL;
	}

	skb->protocol = mhi_netdev_ip_type_trans(skb);
	netif_receive_skb(skb);
}

static void mhi_netdev_cb(struct mhi_cb_info *cb_info)
{
	struct mhi_netdev *mhi_netdev = cb_info->user_data;
	int ret = 0;

	switch (cb_info->cb_reason) {
	case MHI_CB_MHI_DISABLED:
	case MHI_CB_MHI_SHUTDOWN:
	case MHI_CB_SYS_ERROR:
		mhi_log(mhi_netdev, MSG_INFO,
			  "Got MHI_SYS_ERROR notification. Stopping stack\n");
#if 0
		/* Disable interface on first notification.  Long
		 * as we set mhi_enabled = 0, we gurantee rest of
		 * driver will not touch any critical data.
		*/
		write_lock_irq(&mhi_netdev->pm_lock);
		mhi_netdev_mh->mhi_enabled = 0;
		write_unlock_irq(&mhi_netdev->pm_lock);

		if (cb_info->chan == mhi_netdev->rx_channel) {
			mhi_log(mhi_netdev, MSG_INFO,
				  "Receive MHI_DISABLE notification for rx path\n");
			if (mhi_netdev->ndev)
				mhi_netdev_disable(mhi_netdev);
		} else {
			mhi_log(mhi_netdev, MSG_INFO,
				  "Receive MHI_DISABLE notification for tx path\n");
			mhi_netdev->tx_enabled = 0;
			if (mhi_netdev->dev)
				mhi_netdev_internal_clean_unmap_buffers(
						mhi_netdev->dev,
						&mhi_netdev->tx_buffers,
						DMA_TO_DEVICE);
		}

		/* Remove all votes disabling low power mode */
		if (!mhi_netdev->tx_enabled && !mhi_netdev->rx_enabled) {
			struct mhi_client_handle *handle =
				mhi_netdev->rx_client;

			if (!handle)
				handle = mhi_netdev->tx_client;
			while (mhi_netdev->wake_count) {
				mhi_set_lpm(handle, true);
				mhi_netdev->wake_count--;
			}
		}
#endif
		break;
	case MHI_CB_MHI_PROBED:
		mhi_log(mhi_netdev, MSG_INFO, "MHI Probed notification\n");
		if (!mhi_netdev->ipc_log) {
			char node_name[32];
			struct mhi_client_handle *handle;

			handle = (cb_info->chan == mhi_netdev->rx_chan_id) ?
				mhi_netdev->rx_client : mhi_netdev->tx_client;

			snprintf(node_name, sizeof(node_name),
				 "%s_%04x_%02u.%02u.%02u_%u",
				 mhi_netdev->interface_name, handle->dev_id,
				 handle->domain, handle->bus, handle->slot,
				 mhi_netdev->dev_id);
			mhi_netdev->ipc_log = ipc_log_context_create(
						IPC_LOG_PAGES, node_name, 0);

		}
		break;
	case MHI_CB_MHI_ENABLED:
		mhi_log(mhi_netdev, MSG_INFO, "Got MHI_ENABLED notification\n");
		write_lock_irq(&mhi_netdev->pm_lock);
		if (cb_info->chan == mhi_netdev->rx_chan_id)
			mhi_netdev->rx_enabled = 1;
		else
			mhi_netdev->tx_enabled = 1;
		write_unlock_irq(&mhi_netdev->pm_lock);

		if ((mhi_netdev->tx_enabled && mhi_netdev->rx_enabled) ||
		    (mhi_netdev->tx_enabled && !mhi_netdev->rx_client)
		    || (mhi_netdev->rx_enabled &&
			!mhi_netdev->tx_client)) {
			ret = mhi_netdev_enable_iface(mhi_netdev);
			if (ret)
				mhi_log(mhi_netdev, MSG_ERROR,
					  "Failed to enable iface ret:%d\n",
					  ret);
		}
		break;
	case MHI_CB_PENDING_DATA:
		/* only RX channel can receive this cb */
		if (napi_schedule_prep(&mhi_netdev->napi))
			__napi_schedule(&mhi_netdev->napi);

		mhi_netdev->stats.rx_int++;
		break;
	default:
		break;
	}
}

#ifdef CONFIG_DEBUG_FS
struct dentry *dentry;

static void mhi_netdev_create_debugfs(struct mhi_netdev *mhi_netdev)
{
	char node_name[32];
	int i;
	const umode_t mode = (S_IRUSR | S_IWUSR);
	struct dentry *file;
	struct mhi_client_handle *client_handle;

	const struct {
		char *name;
		u32 *ptr;
	} debugfs_table[] = {
		{
			"rx_int",
			&mhi_netdev->stats.rx_int
		},
		{
			"tx_full",
			&mhi_netdev->stats.tx_full
		},
		{
			"tx_pkts",
			&mhi_netdev->stats.tx_pkts
		},
		{
			"rx_budget_overflow",
			&mhi_netdev->stats.rx_budget_overflow
		},
		{
			"rx_fragmentation",
			&mhi_netdev->stats.rx_frag
		},
		{
			"alloc_failed",
			&mhi_netdev->stats.alloc_failed
		},
		{
			NULL, NULL
		},
	};

	/* Both tx & rx client handle contain same device info */
	client_handle = mhi_netdev->rx_client;
	if (!client_handle)
		client_handle = mhi_netdev->tx_client;

	snprintf(node_name, sizeof(node_name), "%s_%04x_%02u.%02u.%02u_%u",
		 mhi_netdev->interface_name, client_handle->dev_id,
		 client_handle->domain, client_handle->bus,
		 client_handle->slot, mhi_netdev->dev_id);

	if (IS_ERR_OR_NULL(dentry))
		return;

	mhi_netdev->dentry = debugfs_create_dir(node_name, dentry);
	if (IS_ERR_OR_NULL(mhi_netdev->dentry))
		return;

	file = debugfs_create_u32("msg_lvl", mode, mhi_netdev->dentry,
				  (u32 *)&mhi_netdev->msg_lvl);
	if (IS_ERR_OR_NULL(file))
		return;

	file = debugfs_create_u32("ipc_log_lvl", mode, mhi_netdev->dentry,
				  (u32 *)&mhi_netdev->ipc_log_lvl);
	if (IS_ERR_OR_NULL(file))
		return;

	file = debugfs_create_u32("mru", mode, mhi_netdev->dentry,
				  &mhi_netdev->mru);
	if (IS_ERR_OR_NULL(file))
		return;

	/* Add debug stats table */
	for (i = 0; debugfs_table[i].name; i++) {
		file = debugfs_create_u32(debugfs_table[i].name, mode,
					  mhi_netdev->dentry,
					  debugfs_table[i].ptr);
		if (IS_ERR_OR_NULL(file))
			return;
	}
}

static void mhi_netdev_create_debugfs_dir(void)
{
	dentry = debugfs_create_dir(MHI_NETDEV_DRIVER_NAME, 0);
}
#else
static void mhi_netdev_create_debugfs(struct mhi_netdev_private *mhi_netdev)
{
}

static void mhi_netdev_create_debugfs_dir(void)
{
}
#endif

static int mhi_netdev_probe(struct platform_device *pdev)
{
	int rc;
	const char *chan;
	struct mhi_netdev *mhi_netdev;
	struct mhi_client_handle *client_handle = NULL;
	char node_name[32];
	struct mhi_client_info_t client_info;
	struct device_node *of_node = pdev->dev.of_node;

	if (unlikely(!of_node))
		return -ENODEV;

	if (!mhi_is_device_ready(of_node, "qcom,mhi"))
		return -EPROBE_DEFER;

	pdev->id = of_alias_get_id(of_node, "mhi_netdev");
	if (unlikely(pdev->id < 0))
		return -ENODEV;

	mhi_netdev = kzalloc(sizeof(*mhi_netdev), GFP_KERNEL);
	if (unlikely(!mhi_netdev))
		return -ENOMEM;
	mhi_netdev->pdev = pdev;
	spin_lock_init(&mhi_netdev->tx_lock);
	rwlock_init(&mhi_netdev->pm_lock);

	rc = of_property_read_u32(of_node, "qcom,mhi-mru", &mhi_netdev->mru);
	if (unlikely(rc)) {
		mhi_log(mhi_netdev, MSG_ERROR, "failed to get valid mru\n");
			goto probe_fail;
	}

	rc = of_property_read_u32(of_node, "cell-index",
				  &mhi_netdev->dev_id);
	if (unlikely(rc)) {
		mhi_log(mhi_netdev, MSG_ERROR,
			  "failed to get valid 'cell-index'\n");
		goto probe_fail;
	}

	rc = of_property_read_u32(of_node, "qcom,mhi-max-mru",
				  &mhi_netdev->max_mru);
	if (likely(rc))
		mhi_netdev->max_mru = MHI_MAX_MRU;

	rc = of_property_read_u32(of_node, "qcom,mhi-max-mtu",
				  &mhi_netdev->max_mtu);
	if (likely(rc))
		mhi_netdev->max_mtu = MHI_MAX_MTU;

	rc = of_property_read_string(of_node, "qcom,interface-name",
				     &mhi_netdev->interface_name);
	if (likely(rc))
		mhi_netdev->interface_name = mhi_netdev_driver.driver.name;

	client_info.of_node = of_node;
	client_info.node_name = "qcom,mhi";
	client_info.mhi_client_cb = mhi_netdev_cb;
	client_info.user_data = mhi_netdev;

	rc = of_property_read_string(of_node, "qcom,mhi-tx-channel", &chan);
	if (!rc) {
		mhi_netdev->tx_channel = chan;
		client_info.chan_name = chan;
		client_info.mhi_xfer_cb = mhi_netdev_xfer_tx_cb;
		mhi_netdev->tx_client = mhi_register_channel(&client_info);
		if (IS_ERR(mhi_netdev->rx_client)) {
			rc = PTR_ERR(mhi_netdev->tx_client);
			mhi_log(mhi_netdev, MSG_ERROR,
				  "mhi_register_channel failed chan %s ret %d\n",
				  mhi_netdev->tx_channel, rc);
			goto probe_fail;
		}
		mhi_netdev->tx_chan_id = mhi_netdev->tx_client->chan_id;
		client_handle = mhi_netdev->tx_client;
	}

	rc = of_property_read_string(of_node, "qcom,mhi-rx-channel", &chan);
	if (!rc) {
		bool recycle_buf;

		mhi_netdev->rx_channel = chan;
		client_info.chan_name = chan;
		client_info.mhi_xfer_cb = mhi_netdev_xfer_rx_cb;
		INIT_WORK(&mhi_netdev->alloc_work, mhi_netdev_alloc_work);
		spin_lock_init(&mhi_netdev->rx_lock);
		mhi_netdev->rx_client = mhi_register_channel(&client_info);
		if (IS_ERR(mhi_netdev->rx_client)) {
			rc = PTR_ERR(mhi_netdev->rx_client);
			mhi_log(mhi_netdev, MSG_ERROR,
				  "mhi_register_channel failed chan %s ret %d\n",
				  mhi_netdev->rx_channel, rc);
			goto probe_fail;
		}
		mhi_netdev->rx_chan_id = mhi_netdev->rx_client->chan_id;
		/* overwriting tx_client is ok because dev_id and
		 * bdf are same for both channels
		 */
		client_handle = mhi_netdev->rx_client;

		recycle_buf = of_property_read_bool(of_node, "mhi,recycle-buf");
		mhi_netdev->recycle_buf = recycle_buf;
		mhi_netdev->rx_queue = recycle_buf ?
			mhi_netdev_skb_recycle : mhi_netdev_alloc_rx;
	}

	/* We must've have @ least one valid channel */
	if (!client_handle) {
		mhi_log(mhi_netdev, MSG_ERROR, "No registered channels\n");
		rc = -ENODEV;
		goto probe_fail;
	}

	/* by default MHI lpm is enable, set flag */
	set_bit(LPM_MASKED_BIT, &mhi_netdev->flags);

	/* create ipc logs if device id is known */
	if (client_handle->dev_id != PCI_ANY_ID) {
		snprintf(node_name, sizeof(node_name),
			 "%s_%04x_%02u.%02u.%02u_%u",
			 mhi_netdev->interface_name, client_handle->dev_id,
			 client_handle->domain, client_handle->bus,
			 client_handle->slot, mhi_netdev->dev_id);
		mhi_netdev->ipc_log = ipc_log_context_create(IPC_LOG_PAGES,
							     node_name, 0);
	}
	mhi_netdev->msg_lvl = MSG_MASK_ALL;

#ifdef CONFIG_MSM_MHI_DEBUG
	mhi_netdev->ipc_log_lvl = MSG_VERBOSE;
#else
	mhi_netdev->ipc_log_lvl = MSG_ERROR;
#endif

	mhi_netdev_create_debugfs(mhi_netdev);
	list_add_tail(&mhi_netdev->node, &mhi_netdev_dev_list);
	return 0;

probe_fail:
	kfree(mhi_netdev);
	return rc;
}

static const struct of_device_id msm_mhi_match_table[] = {
	{.compatible = "qcom,mhi-netdev"},
	{},
};

static struct platform_driver mhi_netdev_driver = {
	.probe = mhi_netdev_probe,
	.driver = {
		.name = MHI_NETDEV_DRIVER_NAME,
		.owner = THIS_MODULE,
		.of_match_table = msm_mhi_match_table,
	},
};

static int __init mhi_netdev_init(void)
{
	mhi_netdev_create_debugfs_dir();
	return platform_driver_register(&mhi_netdev_driver);
}

module_init(mhi_netdev_init);

MODULE_DESCRIPTION("MHI NETDEV Network Interface");
MODULE_LICENSE("GPL v2");
