/*
 * Copyright (C) 2016 Linaro Ltd., Rob Herring <robh@kernel.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/serdev.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/of.h>

MODULE_AUTHOR("Rob Herring <robh@kernel.org");
MODULE_DESCRIPTION("TTY port serial bus controller");
MODULE_LICENSE("GPL v2");

#define SERPORT_BUSY	1
#define SERPORT_ACTIVE	2
#define SERPORT_DEAD	3

struct serport {
	struct tty_port *port;
	struct tty_struct *tty;
	struct tty_driver *tty_drv;
	int tty_idx;
	struct mutex lock;
	unsigned long flags;
};

/*
 * Callback functions from the serdev code.
 */

static int ttyport_write_buf(struct serdev_controller *ctrl, const unsigned char *data, size_t len)
{
	struct serport *serport = serdev_controller_get_drvdata(ctrl);
	struct tty_struct *tty = serport->tty;

	set_bit(TTY_DO_WRITE_WAKEUP, &tty->flags);
	return serport->tty->ops->write(serport->tty, data, len);
}

static void ttyport_write_flush(struct serdev_controller *ctrl)
{
	struct serport *serport = serdev_controller_get_drvdata(ctrl);
	struct tty_struct *tty = serport->tty;

	tty_driver_flush_buffer(tty);
}

static int ttyport_open(struct serdev_controller *ctrl)
{
	struct serport *serport = serdev_controller_get_drvdata(ctrl);

	serport->tty = tty_init_dev(serport->tty_drv, serport->tty_idx);

	serport->tty->receive_room = 65536;

	if (serport->tty->ops->open)
		serport->tty->ops->open(serport->tty, NULL);
	else
		tty_port_open(serport->port, serport->tty, NULL);

	set_bit(TTY_DO_WRITE_WAKEUP, &serport->tty->flags);

	mutex_lock(&serport->lock);
	set_bit(SERPORT_ACTIVE, &serport->flags);
	mutex_unlock(&serport->lock);

	tty_unlock(serport->tty);
	return 0;
}

static void ttyport_close(struct serdev_controller *ctrl)
{
	struct serport *serport = serdev_controller_get_drvdata(ctrl);
	struct tty_struct *tty = serport->tty;

	mutex_lock(&serport->lock);

	if (tty->ops->close)
		tty->ops->close(tty, NULL);

	tty_release_struct(tty, serport->tty_idx);

	clear_bit(SERPORT_ACTIVE, &serport->flags);
	mutex_unlock(&serport->lock);
}

static unsigned int ttyport_set_baudrate(struct serdev_controller *ctrl, unsigned int speed)
{
	struct serport *serport = serdev_controller_get_drvdata(ctrl);
	struct tty_struct *tty = serport->tty;
	struct ktermios ktermios;

	ktermios = tty->termios;
	ktermios.c_cflag &= ~CBAUD;
	tty_termios_encode_baud_rate(&ktermios, speed, speed);

	/* tty_set_termios() return not checked as it is always 0 */
	tty_set_termios(tty, &ktermios);
	return speed;
}

static void ttyport_set_flow_control(struct serdev_controller *ctrl, bool enable)
{
	struct serport *serport = serdev_controller_get_drvdata(ctrl);
	struct tty_struct *tty = serport->tty;
	struct ktermios ktermios;
	int status;
	unsigned int set = 0;
	unsigned int clear = 0;

	if (enable) {
		/* Disable hardware flow control */
		ktermios = tty->termios;
		ktermios.c_cflag &= ~CRTSCTS;
		status = tty_set_termios(tty, &ktermios);
		dev_dbg(&ctrl->dev, "Disabling hardware flow control: %s",
			status ? "failed" : "success");

		/* Clear RTS to prevent the device from sending */
		/* Most UARTs need OUT2 to enable interrupts */
		status = tty->driver->ops->tiocmget(tty);
		dev_dbg(&ctrl->dev, "Current tiocm 0x%x", status);

		set &= ~(TIOCM_OUT2 | TIOCM_RTS);
		clear = ~set;
		set &= TIOCM_DTR | TIOCM_RTS | TIOCM_OUT1 |
		       TIOCM_OUT2 | TIOCM_LOOP;
		clear &= TIOCM_DTR | TIOCM_RTS | TIOCM_OUT1 |
			 TIOCM_OUT2 | TIOCM_LOOP;
		status = tty->driver->ops->tiocmset(tty, set, clear);
		dev_dbg(&ctrl->dev, "Clearing RTS: %s", status ? "failed" : "success");
	} else {
		/* Set RTS to allow the device to send again */
		status = tty->driver->ops->tiocmget(tty);
		dev_dbg(&ctrl->dev, "Current tiocm 0x%x", status);

		set |= (TIOCM_OUT2 | TIOCM_RTS);
		clear = ~set;
		set &= TIOCM_DTR | TIOCM_RTS | TIOCM_OUT1 |
		       TIOCM_OUT2 | TIOCM_LOOP;
		clear &= TIOCM_DTR | TIOCM_RTS | TIOCM_OUT1 |
			 TIOCM_OUT2 | TIOCM_LOOP;
		status = tty->driver->ops->tiocmset(tty, set, clear);
		dev_dbg(&ctrl->dev, "Setting RTS: %s", status ? "failed" : "success");

		/* Re-enable hardware flow control */
		ktermios = tty->termios;
		ktermios.c_cflag |= CRTSCTS;
		status = tty_set_termios(tty, &ktermios);
		dev_dbg(&ctrl->dev, "Enabling hardware flow control: %s",
			status ? "failed" : "success");
	}

}

struct serdev_controller_ops ctrl_ops = {
	.write_buf = ttyport_write_buf,
	.write_flush = ttyport_write_flush,
	.open = ttyport_open,
	.close = ttyport_close,
	.set_flow_control = ttyport_set_flow_control,
	.set_baudrate = ttyport_set_baudrate,
};

static int ttyport_receive_buf(struct tty_port *port, const unsigned char *cp,
				const unsigned char *fp, size_t count)
{
	struct serdev_controller *ctrl = port->client_data;
	struct serport *serport = serdev_controller_get_drvdata(ctrl);

	mutex_lock(&serport->lock);

	if (!test_bit(SERPORT_ACTIVE, &serport->flags))
		goto out;

	serdev_controller_receive_buf(ctrl, cp, count);

out:
	mutex_unlock(&serport->lock);
	return count;
}

static void ttyport_write_wakeup(struct tty_port *port)
{
	struct serdev_controller *ctrl = port->client_data;
	struct serport *serport = serdev_controller_get_drvdata(ctrl);

	clear_bit(TTY_DO_WRITE_WAKEUP, &port->tty->flags);

	if (test_bit(SERPORT_ACTIVE, &serport->flags))
		serdev_controller_write_wakeup(ctrl);
}

static const struct tty_port_client_operations client_ops = {
	.receive_buf = ttyport_receive_buf,
	.write_wakeup = ttyport_write_wakeup,
};

int serdev_tty_port_register(struct tty_port *port, struct device *parent,
			    struct tty_driver *drv, int idx)
{
	struct serdev_controller *ctrl;
	struct serport *serport;
	int ret;

	if (!port || !drv || !parent || !parent->of_node)
		return -ENODEV;

	ctrl = serdev_controller_alloc(parent, sizeof(struct serport));
	if (!ctrl)
		return -ENOMEM;
	serport = serdev_controller_get_drvdata(ctrl);

	mutex_init(&serport->lock);
	serport->port = port;
	serport->tty_idx = idx;
	serport->tty_drv = drv;

	port->client_ops = &client_ops;
	port->client_data = ctrl;

	ctrl->ops = &ctrl_ops;

	ret = serdev_controller_add(ctrl);
	if (ret)
		goto err;

	printk(KERN_INFO "serdev: Serial port %s\n", drv->name);
	return 0;

err:
	port->client_ops = NULL;
	port->client_data = NULL;
	serdev_controller_put(ctrl);
	return ret;
}

void serdev_tty_port_unregister(struct tty_port *port)
{
	struct serdev_controller *ctrl = port->client_data;
	struct serport *serport = serdev_controller_get_drvdata(ctrl);

	if (!serport)
		return;

	serdev_controller_remove(ctrl);
	port->client_ops = NULL;
	port->client_data = NULL;
	serdev_controller_put(ctrl);
}
