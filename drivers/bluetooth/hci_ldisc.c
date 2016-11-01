/*
 *
 *  Bluetooth HCI UART driver
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2004-2005  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#define DEBUG
#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/poll.h>

#include <linux/slab.h>
#include <linux/serdev.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/signal.h>
#include <linux/ioctl.h>
#include <linux/skbuff.h>
#include <linux/firmware.h>

#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>

#include "btintel.h"
#include "btbcm.h"
#include "hci_uart.h"

#define VERSION "2.3"

static const struct hci_uart_proto *hup[HCI_UART_MAX_PROTO];

int hci_uart_register_proto(const struct hci_uart_proto *p)
{
	if (p->id >= HCI_UART_MAX_PROTO)
		return -EINVAL;

	if (hup[p->id])
		return -EEXIST;

	hup[p->id] = p;

	BT_INFO("HCI UART protocol %s registered", p->name);

	return 0;
}

int hci_uart_unregister_proto(const struct hci_uart_proto *p)
{
	if (p->id >= HCI_UART_MAX_PROTO)
		return -EINVAL;

	if (!hup[p->id])
		return -EINVAL;

	hup[p->id] = NULL;

	return 0;
}

static const struct hci_uart_proto *hci_uart_get_proto(unsigned int id)
{
	if (id >= HCI_UART_MAX_PROTO)
		return NULL;

	return hup[id];
}

static inline void hci_uart_tx_complete(struct hci_uart *hu, int pkt_type)
{
	struct hci_dev *hdev = hu->hdev;

	/* Update HCI stat counters */
	switch (pkt_type) {
	case HCI_COMMAND_PKT:
		hdev->stat.cmd_tx++;
		break;

	case HCI_ACLDATA_PKT:
		hdev->stat.acl_tx++;
		break;

	case HCI_SCODATA_PKT:
		hdev->stat.sco_tx++;
		break;
	}
}

static inline struct sk_buff *hci_uart_dequeue(struct hci_uart *hu)
{
	struct sk_buff *skb = hu->tx_skb;

	if (!skb)
		skb = hu->proto->dequeue(hu);
	else
		hu->tx_skb = NULL;

	return skb;
}

int hci_uart_tx_wakeup(struct hci_uart *hu)
{
	if (test_and_set_bit(HCI_UART_SENDING, &hu->tx_state)) {
		set_bit(HCI_UART_TX_WAKEUP, &hu->tx_state);
		return 0;
	}

	BT_DBG("");

	schedule_work(&hu->write_work);

	return 0;
}

static void hci_uart_write_work(struct work_struct *work)
{
	struct hci_uart *hu = container_of(work, struct hci_uart, write_work);
	struct serdev_device *serdev = hu->serdev;
	struct hci_dev *hdev = hu->hdev;
	struct sk_buff *skb;

	/* REVISIT: should we cope with bad skbs or ->write() returning
	 * and error value ?
	 */

restart:
	clear_bit(HCI_UART_TX_WAKEUP, &hu->tx_state);

	while ((skb = hci_uart_dequeue(hu))) {
		int len;

		len = serdev_device_write_buf(serdev, skb->data, skb->len);
		hdev->stat.byte_tx += len;

		skb_pull(skb, len);
		if (skb->len) {
			hu->tx_skb = skb;
			break;
		}

		hci_uart_tx_complete(hu, hci_skb_pkt_type(skb));
		kfree_skb(skb);
	}

	if (test_bit(HCI_UART_TX_WAKEUP, &hu->tx_state))
		goto restart;

	clear_bit(HCI_UART_SENDING, &hu->tx_state);
}

static void hci_uart_init_work(struct work_struct *work)
{
	struct hci_uart *hu = container_of(work, struct hci_uart, init_ready);
	int err;

	if (!test_and_clear_bit(HCI_UART_INIT_PENDING, &hu->hdev_flags))
		return;

	err = hci_register_dev(hu->hdev);
	if (err < 0) {
		BT_ERR("Can't register HCI device");
		hci_free_dev(hu->hdev);
		hu->hdev = NULL;
		hu->proto->close(hu);
	}

	set_bit(HCI_UART_REGISTERED, &hu->flags);
}

int hci_uart_init_ready(struct hci_uart *hu)
{
	if (!test_bit(HCI_UART_INIT_PENDING, &hu->hdev_flags))
		return -EALREADY;

	schedule_work(&hu->init_ready);

	return 0;
}

/* ------- Interface to HCI layer ------ */
/* Initialize device */
static int hci_uart_open(struct hci_dev *hdev)
{
	BT_DBG("%s %p", hdev->name, hdev);

	/* Nothing to do for UART driver */
	return 0;
}

/* Reset device */
static int hci_uart_flush(struct hci_dev *hdev)
{
	struct hci_uart *hu  = hci_get_drvdata(hdev);

	BT_DBG("hdev %p serdev %p", hdev, hu->serdev);

	if (hu->tx_skb) {
		kfree_skb(hu->tx_skb); hu->tx_skb = NULL;
	}

	/* Flush any pending characters in the driver and discipline. */
	serdev_device_write_flush(hu->serdev);

	if (test_bit(HCI_UART_PROTO_READY, &hu->flags))
		hu->proto->flush(hu);

	return 0;
}

/* Close device */
static int hci_uart_close(struct hci_dev *hdev)
{
	BT_DBG("hdev %p", hdev);

	hci_uart_flush(hdev);
	hdev->flush = NULL;
	return 0;
}

/* Send frames from HCI layer */
static int hci_uart_send_frame(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_uart *hu = hci_get_drvdata(hdev);

	BT_DBG("%s: type %d len %d", hdev->name, hci_skb_pkt_type(skb),
	       skb->len);

	hu->proto->enqueue(hu, skb);

	hci_uart_tx_wakeup(hu);

	return 0;
}

/* Flow control or un-flow control the device */
void hci_uart_set_flow_control(struct hci_uart *hu, bool enable)
{
	serdev_device_set_flow_control(hu->serdev, enable);
}

void hci_uart_set_speeds(struct hci_uart *hu, unsigned int init_speed,
			 unsigned int oper_speed)
{
	hu->init_speed = init_speed;
	hu->oper_speed = oper_speed;
}
#if 0
void hci_uart_init_tty(struct hci_uart *hu)
{
	struct tty_struct *tty = hu->tty;
	struct ktermios ktermios;

	/* Bring the UART into a known 8 bits no parity hw fc state */
	ktermios = tty->termios;
	ktermios.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP |
			      INLCR | IGNCR | ICRNL | IXON);
	ktermios.c_oflag &= ~OPOST;
	ktermios.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
	ktermios.c_cflag &= ~(CSIZE | PARENB);
	ktermios.c_cflag |= CS8;
	ktermios.c_cflag |= CRTSCTS;

	/* tty_set_termios() return not checked as it is always 0 */
	tty_set_termios(tty, &ktermios);
}
#endif
void hci_uart_set_baudrate(struct hci_uart *hu, unsigned int speed)
{
	int out_speed = serdev_device_set_baudrate(hu->serdev, speed);

	BT_DBG("%s: New tty speeds: %d/%d", hu->hdev->name,
	       speed, out_speed);
}

static int hci_uart_setup(struct hci_dev *hdev)
{
	struct hci_uart *hu = hci_get_drvdata(hdev);
	struct hci_rp_read_local_version *ver;
	struct sk_buff *skb;
	unsigned int speed;
	int err;

	/* Init speed if any */
	if (hu->init_speed)
		speed = hu->init_speed;
	else if (hu->proto->init_speed)
		speed = hu->proto->init_speed;
	else
		speed = 0;

	if (speed)
		hci_uart_set_baudrate(hu, speed);

	/* Operational speed if any */
	if (hu->oper_speed)
		speed = hu->oper_speed;
	else if (hu->proto->oper_speed)
		speed = hu->proto->oper_speed;
	else
		speed = 0;

	if (hu->proto->set_baudrate && speed) {
		err = hu->proto->set_baudrate(hu, speed);
		if (!err)
			hci_uart_set_baudrate(hu, speed);
	}

	if (hu->proto->setup)
		return hu->proto->setup(hu);

	if (!test_bit(HCI_UART_VND_DETECT, &hu->hdev_flags))
		return 0;

	skb = __hci_cmd_sync(hdev, HCI_OP_READ_LOCAL_VERSION, 0, NULL,
			     HCI_INIT_TIMEOUT);
	if (IS_ERR(skb)) {
		BT_ERR("%s: Reading local version information failed (%ld)",
		       hdev->name, PTR_ERR(skb));
		return 0;
	}

	if (skb->len != sizeof(*ver)) {
		BT_ERR("%s: Event length mismatch for version information",
		       hdev->name);
		goto done;
	}

	ver = (struct hci_rp_read_local_version *)skb->data;

	switch (le16_to_cpu(ver->manufacturer)) {
#ifdef CONFIG_BT_HCIUART_INTEL
	case 2:
		hdev->set_bdaddr = btintel_set_bdaddr;
		btintel_check_bdaddr(hdev);
		break;
#endif
#ifdef CONFIG_BT_HCIUART_BCM
	case 15:
		hdev->set_bdaddr = btbcm_set_bdaddr;
		btbcm_check_bdaddr(hdev);
		break;
#endif
	}

done:
	kfree_skb(skb);
	return 0;
}

/* hci_uart_tty_wakeup()
 *
 *    Callback for transmit wakeup. Called when low level
 *    device driver can accept more send data.
 *
 * Arguments:        tty    pointer to associated tty instance data
 * Return Value:    None
 */
static void hci_uart_write_wakeup(struct serdev_device *serdev)
{
	struct hci_uart *hu = serdev_device_get_drvdata(serdev);

	BT_DBG("");

	if (!hu)
		return;

	if (serdev != hu->serdev)
		return;

	if (test_bit(HCI_UART_PROTO_READY, &hu->flags))
		hci_uart_tx_wakeup(hu);
}

/* hci_uart_tty_receive()
 *
 *     Called by tty low level driver when receive data is
 *     available.
 *
 * Arguments:  tty          pointer to tty isntance data
 *             data         pointer to received data
 *             flags        pointer to flags for data
 *             count        count of received data in bytes
 *
 * Return Value:    None
 */
static int hci_uart_receive_buf(struct serdev_device *serdev, const u8 *data,
				   size_t count)
{
	struct hci_uart *hu = serdev_device_get_drvdata(serdev);

	if (!hu || serdev != hu->serdev)
		return 0;

	if (!test_bit(HCI_UART_PROTO_READY, &hu->flags))
		return 0;

	/* It does not need a lock here as it is already protected by a mutex in
	 * tty caller
	 */
	hu->proto->recv(hu, data, count);

	if (hu->hdev)
		hu->hdev->stat.byte_rx += count;

	return count;
}

struct serdev_device_ops hci_serdev_client_ops = {
	.receive_buf = hci_uart_receive_buf,
	.write_wakeup = hci_uart_write_wakeup,
};


static int hci_uart_register_dev(struct hci_uart *hu)
{
	struct hci_dev *hdev;

	BT_DBG("");

	/* Initialize and register HCI device */
	hdev = hci_alloc_dev();
	if (!hdev) {
		BT_ERR("Can't allocate HCI device");
		return -ENOMEM;
	}

	hu->hdev = hdev;

	hdev->bus = HCI_UART;
	hci_set_drvdata(hdev, hu);

	/* Only when vendor specific setup callback is provided, consider
	 * the manufacturer information valid. This avoids filling in the
	 * value for Ericsson when nothing is specified.
	 */
	if (hu->proto->setup)
		hdev->manufacturer = hu->proto->manufacturer;

	hdev->open  = hci_uart_open;
	hdev->close = hci_uart_close;
	hdev->flush = hci_uart_flush;
	hdev->send  = hci_uart_send_frame;
	hdev->setup = hci_uart_setup;
	SET_HCIDEV_DEV(hdev, &hu->serdev->dev);

	if (test_bit(HCI_UART_RAW_DEVICE, &hu->hdev_flags))
		set_bit(HCI_QUIRK_RAW_DEVICE, &hdev->quirks);

	if (test_bit(HCI_UART_EXT_CONFIG, &hu->hdev_flags))
		set_bit(HCI_QUIRK_EXTERNAL_CONFIG, &hdev->quirks);

	if (!test_bit(HCI_UART_RESET_ON_INIT, &hu->hdev_flags))
		set_bit(HCI_QUIRK_RESET_ON_CLOSE, &hdev->quirks);

	if (test_bit(HCI_UART_CREATE_AMP, &hu->hdev_flags))
		hdev->dev_type = HCI_AMP;
	else
		hdev->dev_type = HCI_PRIMARY;

	if (test_bit(HCI_UART_INIT_PENDING, &hu->hdev_flags))
		return 0;

	if (hci_register_dev(hdev) < 0) {
		BT_ERR("Can't register HCI device");
		hci_free_dev(hdev);
		return -ENODEV;
	}

	set_bit(HCI_UART_REGISTERED, &hu->flags);

	return 0;
}

static int hci_uart_set_proto(struct hci_uart *hu, int id)
{
	const struct hci_uart_proto *p;
	int err;

	p = hci_uart_get_proto(id);
	if (!p)
		return -EPROTONOSUPPORT;

	err = p->open(hu);
	if (err)
		return err;

	hu->proto = p;
	set_bit(HCI_UART_PROTO_READY, &hu->flags);

	err = hci_uart_register_dev(hu);
	if (err) {
		clear_bit(HCI_UART_PROTO_READY, &hu->flags);
		p->close(hu);
		return err;
	}

	return 0;
}
#if 0

static int hci_uart_set_flags(struct hci_uart *hu, unsigned long flags)
{
	unsigned long valid_flags = BIT(HCI_UART_RAW_DEVICE) |
				    BIT(HCI_UART_RESET_ON_INIT) |
				    BIT(HCI_UART_CREATE_AMP) |
				    BIT(HCI_UART_INIT_PENDING) |
				    BIT(HCI_UART_EXT_CONFIG) |
				    BIT(HCI_UART_VND_DETECT);

	if (flags & ~valid_flags)
		return -EINVAL;

	hu->hdev_flags = flags;

	return 0;
}

/* hci_uart_tty_ioctl()
 *
 *    Process IOCTL system call for the tty device.
 *
 * Arguments:
 *
 *    tty        pointer to tty instance data
 *    file       pointer to open file object for device
 *    cmd        IOCTL command code
 *    arg        argument for IOCTL call (cmd dependent)
 *
 * Return Value:    Command dependent
 */
static int hci_uart_tty_ioctl(struct tty_struct *tty, struct file *file,
			      unsigned int cmd, unsigned long arg)
{
	struct hci_uart *hu = tty->disc_data;
	int err = 0;

	BT_DBG("");

	/* Verify the status of the device */
	if (!hu)
		return -EBADF;

	switch (cmd) {
	case HCIUARTSETPROTO:
		if (!test_and_set_bit(HCI_UART_PROTO_SET, &hu->flags)) {
			err = hci_uart_set_proto(hu, arg);
			if (err)
				clear_bit(HCI_UART_PROTO_SET, &hu->flags);
		} else
			err = -EBUSY;
		break;

	case HCIUARTGETPROTO:
		if (test_bit(HCI_UART_PROTO_SET, &hu->flags))
			err = hu->proto->id;
		else
			err = -EUNATCH;
		break;

	case HCIUARTGETDEVICE:
		if (test_bit(HCI_UART_REGISTERED, &hu->flags))
			err = hu->hdev->id;
		else
			err = -EUNATCH;
		break;

	case HCIUARTSETFLAGS:
		if (test_bit(HCI_UART_PROTO_SET, &hu->flags))
			err = -EBUSY;
		else
			err = hci_uart_set_flags(hu, arg);
		break;

	case HCIUARTGETFLAGS:
		err = hu->hdev_flags;
		break;

	default:
		err = n_tty_ioctl_helper(tty, file, cmd, arg);
		break;
	}

	return err;
}
#endif

static int hci_uart_probe(struct serdev_device *serdev)
{
	int id, ret;
	struct hci_uart *hu;

	BT_INFO("HCI UART driver ver %s", VERSION);

	id = (int)of_device_get_match_data(&serdev->dev);

	hu = devm_kzalloc(&serdev->dev, sizeof(struct hci_uart), GFP_KERNEL);
	if (!hu)
		return -ENFILE;

	serdev_device_set_drvdata(serdev, hu);
	hu->serdev = serdev;

	INIT_WORK(&hu->init_ready, hci_uart_init_work);
	INIT_WORK(&hu->write_work, hci_uart_write_work);

	serdev_device_set_client_ops(serdev, &hci_serdev_client_ops);

	ret = serdev_device_open(serdev);
	if (ret)
		return ret;

	set_bit(HCI_UART_PROTO_SET, &hu->flags);
	ret = hci_uart_set_proto(hu, id);
	if (ret) {
		serdev_device_close(serdev);
		return ret;
	}

	/* Flush any pending characters in the driver */
//	tty_driver_flush_buffer(tty);


	return 0;
}

static void hci_uart_remove(struct serdev_device *serdev)
{
	struct hci_dev *hdev;
	struct hci_uart *hu = serdev_device_get_drvdata(serdev);

	hdev = hu->hdev;
	if (hdev)
		hci_uart_close(hdev);

	cancel_work_sync(&hu->write_work);

	if (test_and_clear_bit(HCI_UART_PROTO_READY, &hu->flags)) {
		if (hdev) {
			if (test_bit(HCI_UART_REGISTERED, &hu->flags))
				hci_unregister_dev(hdev);
			hci_free_dev(hdev);
		}
		hu->proto->close(hu);
	}
	clear_bit(HCI_UART_PROTO_SET, &hu->flags);

	pr_info("hci_uart disconnect!!!\n");
	serdev_device_close(serdev);
}


static const struct of_device_id hci_uart_of_match[] = {
	{ .compatible = "loopback-uart", .data = (void *)HCI_UART_BCM },
	{},
};
MODULE_DEVICE_TABLE(of, hci_uart_of_match);

static struct serdev_device_driver hci_uart_drv = {
	.driver		= {
		.name	= "hci-uart",
		.of_match_table = of_match_ptr(hci_uart_of_match),
	},
	.probe	= hci_uart_probe,
	.remove	= hci_uart_remove,
};

static int __init hci_uart_init(void)
{
#ifdef CONFIG_BT_HCIUART_H4
	h4_init();
#endif
#ifdef CONFIG_BT_HCIUART_BCSP
	bcsp_init();
#endif
#ifdef CONFIG_BT_HCIUART_LL
	ll_init();
#endif
#ifdef CONFIG_BT_HCIUART_ATH3K
	ath_init();
#endif
#ifdef CONFIG_BT_HCIUART_3WIRE
	h5_init();
#endif
#ifdef CONFIG_BT_HCIUART_INTEL
	intel_init();
#endif
#ifdef CONFIG_BT_HCIUART_BCM
	bcm_init();
#endif
#ifdef CONFIG_BT_HCIUART_QCA
	qca_init();
#endif
#ifdef CONFIG_BT_HCIUART_AG6XX
	ag6xx_init();
#endif
#ifdef CONFIG_BT_HCIUART_MRVL
	mrvl_init();
#endif

	return serdev_device_driver_register(&hci_uart_drv);
}

static void __exit hci_uart_exit(void)
{
#ifdef CONFIG_BT_HCIUART_H4
	h4_deinit();
#endif
#ifdef CONFIG_BT_HCIUART_BCSP
	bcsp_deinit();
#endif
#ifdef CONFIG_BT_HCIUART_LL
	ll_deinit();
#endif
#ifdef CONFIG_BT_HCIUART_ATH3K
	ath_deinit();
#endif
#ifdef CONFIG_BT_HCIUART_3WIRE
	h5_deinit();
#endif
#ifdef CONFIG_BT_HCIUART_INTEL
	intel_deinit();
#endif
#ifdef CONFIG_BT_HCIUART_BCM
	bcm_deinit();
#endif
#ifdef CONFIG_BT_HCIUART_QCA
	qca_deinit();
#endif
#ifdef CONFIG_BT_HCIUART_AG6XX
	ag6xx_deinit();
#endif
#ifdef CONFIG_BT_HCIUART_MRVL
	mrvl_deinit();
#endif
	serdev_device_driver_unregister(&hci_uart_drv);
}

module_init(hci_uart_init);
module_exit(hci_uart_exit);

MODULE_AUTHOR("Marcel Holtmann <marcel@holtmann.org>");
MODULE_DESCRIPTION("Bluetooth HCI UART driver ver " VERSION);
MODULE_VERSION(VERSION);
MODULE_LICENSE("GPL");
