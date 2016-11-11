/*
 * Copyright (C) 2016 Linaro Ltd., Rob Herring <robh@kernel.org>
 *
 * Based on include/linux/spmi.h:
 * Copyright (c) 2012-2013, The Linux Foundation. All rights reserved.
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
#ifndef _LINUX_UART_DEVICE_H
#define _LINUX_UART_DEVICE_H

#include <linux/types.h>
#include <linux/device.h>
#include <linux/mod_devicetable.h>

struct serdev_device;

struct serdev_device_ops {
	int (*receive_buf)(struct serdev_device *serdev, const unsigned char *, size_t);
	void (*write_wakeup)(struct serdev_device *serdev);
};

/**
 * struct serdev_device - Basic representation of an serdev device
 * @dev:	Driver model representation of the device.
 * @nr:		Device number on serdev bus.
 * @ctrl:	serdev controller managing this device.
 * @ops:	Device operations.
 */
struct serdev_device {
	struct device dev;
	int nr;
	struct serdev_controller *ctrl;
	const struct serdev_device_ops *ops;
};

static inline struct serdev_device *to_serdev_device(struct device *d)
{
	return container_of(d, struct serdev_device, dev);
}

static inline void *serdev_device_get_drvdata(const struct serdev_device *serdev)
{
	return dev_get_drvdata(&serdev->dev);
}

static inline void serdev_device_set_drvdata(struct serdev_device *serdev, void *data)
{
	dev_set_drvdata(&serdev->dev, data);
}

/**
 * serdev_device_put() - decrement serdev device refcount
 * @serdev	serdev device.
 */
static inline void serdev_device_put(struct serdev_device *serdev)
{
	if (serdev)
		put_device(&serdev->dev);
}

struct serdev_device *serdev_device_alloc(struct serdev_controller *ctrl);
int serdev_device_add(struct serdev_device *serdev);
void serdev_device_remove(struct serdev_device *serdev);

static inline void serdev_device_set_client_ops(struct serdev_device *serdev,
					      const struct serdev_device_ops *ops)
{
	serdev->ops = ops;
}

struct serdev_controller_ops {
	int (*write_buf)(struct serdev_controller *, const unsigned char *, size_t);
	void (*write_flush)(struct serdev_controller *);
	int (*open)(struct serdev_controller *);
	void (*close)(struct serdev_controller *);
	void (*set_flow_control)(struct serdev_controller *, bool);
	unsigned int (*set_baudrate)(struct serdev_controller *, unsigned int);
};

/**
 * struct serdev_controller - interface to the serdev controller
 * @dev:	Driver model representation of the device.
 * @nr:		number identifier for this controller/bus.
 * @serdev:	Pointer to slave device for this controller.
 * @ops:	Controller operations.
 */
struct serdev_controller {
	struct device		dev;
	unsigned int		nr;
	struct serdev_device	*serdev;
	const struct serdev_controller_ops *ops;
};

static inline struct serdev_controller *to_serdev_controller(struct device *d)
{
	return container_of(d, struct serdev_controller, dev);
}

static inline
void *serdev_controller_get_drvdata(const struct serdev_controller *ctrl)
{
	return dev_get_drvdata(&ctrl->dev);
}

static inline void serdev_controller_set_drvdata(struct serdev_controller *ctrl,
					       void *data)
{
	dev_set_drvdata(&ctrl->dev, data);
}

/**
 * serdev_controller_put() - decrement controller refcount
 * @ctrl	serdev controller.
 */
static inline void serdev_controller_put(struct serdev_controller *ctrl)
{
	if (ctrl)
		put_device(&ctrl->dev);
}

struct serdev_controller *serdev_controller_alloc(struct device *parent,
						  size_t size);
int serdev_controller_add(struct serdev_controller *ctrl);
void serdev_controller_remove(struct serdev_controller *ctrl);

static inline void serdev_controller_write_wakeup(struct serdev_controller *ctrl)
{
	if (ctrl->serdev && ctrl->serdev->ops->write_wakeup)
		ctrl->serdev->ops->write_wakeup(ctrl->serdev);
}

static inline int serdev_controller_receive_buf(struct serdev_controller *ctrl,
					      const unsigned char *data,
					      size_t count)
{
	if (ctrl->serdev && ctrl->serdev->ops->receive_buf)
		return ctrl->serdev->ops->receive_buf(ctrl->serdev, data, count);

	return 0;
}

/**
 * struct serdev_device_driver - serdev slave device driver
 * @driver:	serdev device drivers should initialize name field of this
 *		structure.
 * @probe:	binds this driver to a serdev device.
 * @remove:	unbinds this driver from the serdev device.
 */
struct serdev_device_driver {
	struct device_driver driver;
	int	(*probe)(struct serdev_device *serdev);
	void	(*remove)(struct serdev_device *serdev);
};

static inline struct serdev_device_driver *to_serdev_device_driver(struct device_driver *d)
{
	return container_of(d, struct serdev_device_driver, driver);
}

#define serdev_device_driver_register(sdrv) \
	__serdev_device_driver_register(sdrv, THIS_MODULE)
int __serdev_device_driver_register(struct serdev_device_driver *sdrv, struct module *owner);

/**
 * serdev_device_driver_unregister() - unregister an serdev client driver
 * @sdrv:	the driver to unregister
 */
static inline void serdev_device_driver_unregister(struct serdev_device_driver *sdrv)
{
	if (sdrv)
		driver_unregister(&sdrv->driver);
}

#define module_serdev_device_driver(__serdev_device_driver) \
	module_driver(__serdev_device_driver, serdev_device_driver_register, \
			serdev_device_driver_unregister)

int serdev_device_open(struct serdev_device *serdev);
void serdev_device_close(struct serdev_device *serdev);
unsigned int serdev_device_set_baudrate(struct serdev_device *serdev, unsigned int speed);
void serdev_device_set_flow_control(struct serdev_device *serdev, bool enable);
int serdev_device_write_buf(struct serdev_device *serdev, u8 *buf, size_t count);
void serdev_device_write_flush(struct serdev_device *serdev);

#endif
