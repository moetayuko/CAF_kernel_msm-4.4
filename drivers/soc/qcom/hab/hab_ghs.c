/* Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include "hab.h"
#include "hab_ghs.h"

#if defined(__linux__)
const char *dt_gipc_path_name[] = {
	"testgipc1",
	"testgipc2",
	"testgipc3",
	"testgipc4",
	"testgipc5",
	"testgipc6",
	"testgipc7",
	"testgipc8",
	"testgipc9",
	"testgipc10",
	"testgipc11",
	"testgipc12",
	"testgipc13",
	"testgipc14",
	"testgipc15",
	"testgipc16",
	"testgipc17",
	"testgipc18",
	"testgipc19",
	"testgipc20",
};
#elif defined(__INTEGRITY)
static const fdt_header *SystemDtb;
static DevTree Dt;

#define GHS_IST_PRIO            253  /* higher number is higher priority */
#define GHS_IST_STACK_LENGTH (4*1024) /* must match the off-stack msg array */

/* the following has to match the dts settings */
const char *dt_gipc_path_name[] = {
	"/chosen/gipc/channelhab1/ep0",
	"/chosen/gipc/channelhab2/ep0",
	"/chosen/gipc/channelhab3/ep0",
	"/chosen/gipc/channelhab4/ep0",
	"/chosen/gipc/channelhab5/ep0",
	"/chosen/gipc/channelhab6/ep0",
	"/chosen/gipc/channelhab7/ep0",
	"/chosen/gipc/channelhab8/ep0",
	"/chosen/gipc/channelhab9/ep0",
	"/chosen/gipc/channelhab10/ep0",
	"/chosen/gipc/channelhab11/ep0",
	"/chosen/gipc/channelhab12/ep0",
	"/chosen/gipc/channelhab13/ep0",
	"/chosen/gipc/channelhab14/ep0",
	"/chosen/gipc/channelhab15/ep0",
	"/chosen/gipc/channelhab16/ep0",
	"/chosen/gipc/channelhab17/ep0",
	"/chosen/gipc/channelhab18/ep0",
	"/chosen/gipc/channelhab19/ep0",
	"/chosen/gipc/channelhab20/ep0",
};
#endif

static struct ghs_vmm_plugin_info_s {
	const char **dt_name;
	int curr;
	int probe_cnt;
} ghs_vmm_plugin_info = {
	dt_gipc_path_name,
	0,
	ARRAY_SIZE(dt_gipc_path_name)
};

#if defined(__linux__)
static void ghs_irq_handler(void *cookie)
{
	struct physical_channel *pchan = cookie;
	struct ghs_vdev *dev =
		(struct ghs_vdev *) (pchan ? pchan->hyp_data : NULL);

	if (dev)
		tasklet_schedule(&dev->task);
}
#endif /* __linux__ */

/* static struct physical_channel *habhyp_commdev_alloc(int id) */
int habhyp_commdev_alloc(void **commdev, int is_be, char *name, int vmid_remote,
		struct hab_device *mmid_device)
{
	struct ghs_vdev *dev = NULL;
	struct physical_channel *pchan = NULL;
	struct physical_channel **ppchan = (struct physical_channel **)commdev;
	int ret = 0;

#if defined(__INTEGRITY)
	DevTree_Node Node = NULL;
	int i;
#endif
	if (ghs_vmm_plugin_info.curr > ghs_vmm_plugin_info.probe_cnt) {
		pr_err("too many commdev alloc %d, supported is %d\n",
			ghs_vmm_plugin_info.curr,
			ghs_vmm_plugin_info.probe_cnt);
		ret = -ENOENT;
		goto err;
	}

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		ret = -ENOMEM;
		pr_err("allocate struct ghs_vdev failed %d bytes on pchan %s\n",
			sizeof(*dev), name);
		goto err;
	}

	memset(dev, 0, sizeof(*dev));
	spin_lock_init(&dev->io_lock);

	/*
	 * TODO: ExtractEndpoint is in ghs_comm.c because it blocks.
	 *	Extrace and Request should be in roughly the same spot
	 */
	if (is_be) {
		/* role is backend */
		dev->be = 1;
#if defined(__INTEGRITY)
		if (Dt == NULL) {
			CheckSuccess(DTB_RetrieveSystemDtb(&SystemDtb));
			if (DevTree_User_ParseTree(SystemDtb, &Dt) != Success) {
				HAB_LOG_ERR("DevTree_User_ParseTree failed!\n");
				ret = -ENOENT;
				goto err;
			}
		}

		Node = DevTree_FindNodeByPath(Dt,
			ghs_vmm_plugin_info.dt_name[ghs_vmm_plugin_info.curr]);
		if (!Node) {
			pr_err("DT FindNodeByPath failed %s id %d\n",
			ghs_vmm_plugin_info.dt_name[ghs_vmm_plugin_info.curr],
			ghs_vmm_plugin_info.curr);

			ret = -ENOENT;
			goto err;
		}
#define GHS_DT_QUERY_TIMEOUT 10000

		while (1) {
			result = DevTree_Node_ImportGipcEndpoint(Node,
			&dev->endpoint);
			if (result == Success) {
				HAB_LOG_INFO("EP IMP OK! ret %d, %p, loop %d\n",
					result, dev->endpoint, i);
				break;
			} else if (result == ResourceNotAvailable &&
						i < GHS_DT_QUERY_TIMEOUT) {
				/*dt is not available during bootup sometimes */
				i++;
				pr_warn("EP IMP timeout! %s ret %d cnt %d\n",
					name, dev->endpoint, i);
				usleep(1000);
				continue;
			} else {
				pr_err("EP IMP failed! ret %d, %p, cnt %d\n",
					result, dev->endpoint, i);
				ret = -ENOENT;
				goto err;
			}
		}
#endif
	} else {
		/* role is FE */
#ifdef __linux__
	struct device_node *gvh_dn;

	gvh_dn = of_find_node_by_path("/aliases");
	if (gvh_dn) {
		const char *ep_path = NULL;
		struct device_node *endpoint_dn;

		ret = of_property_read_string(gvh_dn,
			ghs_vmm_plugin_info.dt_name[ghs_vmm_plugin_info.curr],
			&ep_path);
		if (ret) {
			pr_err("failed to read endpoint string! ret %d on %p\n",
				ret, gvh_dn);
		}

		endpoint_dn = of_find_node_by_path(ep_path);
		if (endpoint_dn) {
			dev->endpoint = kgipc_endpoint_alloc(endpoint_dn);
			if (IS_ERR(dev->endpoint)) {
				ret = PTR_ERR(dev->endpoint);
				pr_err("KGIPC alloc failed id: %d, ret: %d\n",
					   ghs_vmm_plugin_info.curr, ret);
				goto err;
			} else {
				pr_info("gipc ep found for %d, created %p\n",
						ghs_vmm_plugin_info.curr,
						dev->endpoint);
			}
		} else {
			pr_err("of_parse_phandle failed id: %d\n",
				   ghs_vmm_plugin_info.curr);
			ret = -ENOENT;
			goto err;
		}
	} else {
		pr_err("of_find_compatible_node failed id: %d\n",
			   ghs_vmm_plugin_info.curr);
		ret = -ENOENT;
		goto err;
	}
#endif
	}

	pchan = hab_pchan_alloc(&hab_driver.devp[ghs_vmm_plugin_info.curr],
		dev->be);
	if (!pchan) {
		pr_err("hab_pchan_alloc failed\n");
		ret = -ENOMEM;
		goto err;
	}
	pchan->closed = 0;
	pchan->hyp_data = (void *)dev;
	pchan->is_be = is_be;
	strlcpy(dev->name, name, sizeof(dev->name));
	*ppchan = pchan;
	dev->read_data = kmalloc(GIPC_RECV_BUFF_SIZE_BYTES, GFP_KERNEL);
	if (!dev->read_data) {
		pr_err("allocate struct ghs_vdev failed for %d bytes\n",
			GIPC_RECV_BUFF_SIZE_BYTES);
		ret = -ENOMEM;
		goto err;
	} /* ToDo kfree */

#ifdef __INTEGRITY
	init_waitqueue_head(&hab_driver.devp[ghs_vmm_plugin_info.curr].openq);

	result = CommonCreateTaskWithArgument(GHS_IST_PRIO, ghs_hyp_rx_dispatch,
		(Address)pchan, GHS_IST_STACK_LENGTH, name, &dev->task);
	if (result != Success) {
		pr_err("failed to create msg thread %s ret %X\n", name, result);
		ret = -ENOMEM;
		goto err;
	} else {
		Address a1, a2;
		Value ts;

		result = RunTask(dev->task);
		if (result != Success) {
			pr_err("failed to run task %s, ret %X\n", name, result);
			ret = -ENOENT;
			goto err;
		}

		result = GetTaskStatus(dev->task, &ts, &a1, &a2);
		if (result != Success) {
			pr_err("failed to get %s task status, ret %X\n",
			name, result);
		} else {
			if (ts == StatHalted || ts == StatException ||
				ts == StatExited) {
				pr_err("task %s failed to run status %d!\n",
					name, ts);
				ret = -ENOMEM;
				goto err;
			} else {
				pr_err("task %s running!\n", name);
			}
		}
	}
#elif __linux__
	tasklet_init(&dev->task, physical_channel_rx_dispatch,
		(unsigned long) pchan);

	ret = kgipc_endpoint_start_with_irq_callback(dev->endpoint,
		ghs_irq_handler,
		pchan);
	if (ret) {
		pr_err("irq alloc failed id: %d %s, ret: %d\n",
				ghs_vmm_plugin_info.curr, name, ret);
		goto err;
	} else {
		pr_info("ep irq handler started for %d %s, pchan %p, ret %d\n",
				ghs_vmm_plugin_info.curr, name, pchan, ret);
	}
#endif
	ghs_vmm_plugin_info.curr++;
	return 0;
err:
	hab_pchan_put(pchan);
	if (dev)
		kfree(dev);
	return ret;
}

int habhyp_commdev_dealloc(void *commdev)
{
	struct physical_channel *pchan = (struct physical_channel *)commdev;
	struct ghs_vdev *dev = pchan->hyp_data;

	kfree(dev);
	hab_pchan_put(pchan);
	return 0;
}

void hab_hypervisor_unregister(void)
{
	int status, i;

	for (i = 0; i < hab_driver.ndevices; i++) {
		struct hab_device *dev = &hab_driver.devp[i];
		struct physical_channel *pchan;

		mutex_lock(&dev->pchan_lock);
		list_for_each_entry(pchan, &dev->pchannels, node) {
			status = habhyp_commdev_dealloc(pchan);
			if (status) {
				pr_err("free pchan failed %p dev(%d) ret %d\n",
					pchan, i, status);
			}
		}
		mutex_unlock(&dev->pchan_lock);
	}

	ghs_vmm_plugin_info.curr = 0;
}

int hab_hypervisor_register(void)
{
	int ret = 0;
#if defined(__linux__)
	hab_driver.b_server_dom = 0;
#else
	hab_driver.b_server_dom = 1;
#endif

	return ret;
}
