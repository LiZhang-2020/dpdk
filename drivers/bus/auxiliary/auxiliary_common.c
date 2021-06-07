/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Mellanox Technologies, Ltd
 */

#include <string.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/queue.h>
#include <rte_errno.h>
#include <rte_interrupts.h>
#include <rte_log.h>
#include <rte_bus.h>
#include <rte_per_lcore.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_eal_paging.h>
#include <rte_string_fns.h>
#include <rte_common.h>
#include <rte_devargs.h>

#include "private.h"
#include "rte_bus_auxiliary.h"


int auxiliary_bus_logtype;

static struct rte_devargs *
auxiliary_devargs_lookup(const char *name)
{
	struct rte_devargs *devargs;

	RTE_EAL_DEVARGS_FOREACH("auxiliary", devargs) {
		if (strcmp(devargs->name, name) == 0)
			return devargs;
	}
	return NULL;
}

/*
 * Test whether the auxiliary device exist
 */
__rte_weak bool
auxiliary_dev_exists(const char *name)
{
	RTE_SET_USED(name);
	return false;
}

/*
 * Scan the content of the auxiliary bus, and the devices in the devices
 * list
 */
__rte_weak int
auxiliary_scan(void)
{
	return 0;
}

void
auxiliary_on_scan(struct rte_auxiliary_device *aux_dev)
{
	aux_dev->device.devargs = auxiliary_devargs_lookup(aux_dev->name);
}

/*
 * Match the auxiliary Driver and Device using driver function.
 */
bool
auxiliary_match(const struct rte_auxiliary_driver *aux_drv,
		const struct rte_auxiliary_device *aux_dev)
{
	if (aux_drv->match == NULL)
		return false;
	return aux_drv->match(aux_dev->name);
}

/*
 * Call the probe() function of the driver.
 */
static int
rte_auxiliary_probe_one_driver(struct rte_auxiliary_driver *dr,
			       struct rte_auxiliary_device *dev)
{
	enum rte_iova_mode iova_mode;
	int ret;

	if ((dr == NULL) || (dev == NULL))
		return -EINVAL;

	/* The device is not blocked; Check if driver supports it */
	if (!auxiliary_match(dr, dev))
		/* Match of device and driver failed */
		return 1;

	AUXILIARY_LOG(DEBUG, "Auxiliary device %s on NUMA socket %i\n",
		      dev->name, dev->device.numa_node);

	/* no initialization when marked as blocked, return without error */
	if (dev->device.devargs != NULL &&
	    dev->device.devargs->policy == RTE_DEV_BLOCKED) {
		AUXILIARY_LOG(INFO, "  Device is blocked, not initializing\n");
		return -1;
	}

	if (dev->device.numa_node < 0) {
		AUXILIARY_LOG(INFO, "  Device is not NUMA-aware, defaulting socket to 0\n");
		dev->device.numa_node = 0;
	}

	AUXILIARY_LOG(DEBUG, "  Probe driver: %s\n", dr->driver.name);

	iova_mode = rte_eal_iova_mode();
	if ((dr->drv_flags & RTE_AUXILIARY_DRV_NEED_IOVA_AS_VA) &&
	    iova_mode != RTE_IOVA_VA) {
		AUXILIARY_LOG(ERR, "  Expecting VA IOVA mode but current mode is PA, not initializing\n");
		return -EINVAL;
	}

	dev->driver = dr;

	AUXILIARY_LOG(INFO, "Probe auxiliary driver: %s device: %s (socket %i)\n",
		      dr->driver.name, dev->name, dev->device.numa_node);
	ret = dr->probe(dr, dev);
	if (ret)
		dev->driver = NULL;
	else
		dev->device.driver = &dr->driver;

	return ret;
}

/*
 * Call the remove() function of the driver.
 */
static int
rte_auxiliary_driver_remove_dev(struct rte_auxiliary_device *dev)
{
	struct rte_auxiliary_driver *dr;
	int ret = 0;

	if (dev == NULL)
		return -EINVAL;

	dr = dev->driver;

	AUXILIARY_LOG(DEBUG, "Auxiliary device %s on NUMA socket %i\n",
		      dev->name, dev->device.numa_node);

	AUXILIARY_LOG(DEBUG, "  remove driver: %s %s\n",
		      dev->name, dr->driver.name);

	if (dr->remove) {
		ret = dr->remove(dev);
		if (ret < 0)
			return ret;
	}

	/* clear driver structure */
	dev->driver = NULL;
	dev->device.driver = NULL;

	return 0;
}

/*
 * Call the probe() function of all registered driver for the given device.
 * Return < 0 if initialization failed.
 * Return 1 if no driver is found for this device.
 */
static int
auxiliary_probe_all_drivers(struct rte_auxiliary_device *dev)
{
	struct rte_auxiliary_driver *dr;
	int rc;

	if (dev == NULL)
		return -EINVAL;

	FOREACH_DRIVER_ON_AUXILIARYBUS(dr) {
		if (!dr->match(dev->name))
			continue;

		rc = rte_auxiliary_probe_one_driver(dr, dev);
		if (rc < 0)
			/* negative value is an error */
			return rc;
		if (rc > 0)
			/* positive value means driver doesn't support it */
			continue;
		return 0;
	}
	return 1;
}

/*
 * Scan the content of the auxiliary bus, and call the probe() function for
 *
 * all registered drivers that have a matching entry in its id_table
 * for discovered devices.
 */
static int
auxiliary_probe(void)
{
	struct rte_auxiliary_device *dev = NULL;
	size_t probed = 0, failed = 0;
	int ret = 0;

	FOREACH_DEVICE_ON_AUXILIARYBUS(dev) {
		probed++;

		ret = auxiliary_probe_all_drivers(dev);
		if (ret < 0) {
			if (ret != -EEXIST) {
				AUXILIARY_LOG(ERR, "Requested device %s cannot be used\n",
					      dev->name);
				rte_errno = errno;
				failed++;
			}
			ret = 0;
		}
	}

	return (probed && probed == failed) ? -1 : 0;
}

static int
auxiliary_parse(const char *name, void *addr)
{
	struct rte_auxiliary_driver *dr = NULL;
	const char **out = addr;

	/* Allow dummy name to prevent bus scan. */
	if (strlen(name) == 0)
		return 0;

	FOREACH_DRIVER_ON_AUXILIARYBUS(dr) {
		if (dr->match(name))
			break;
	}
	if (dr != NULL && addr != NULL)
		*out = name;
	return dr != NULL ? 0 : -1;
}

/* register a driver */
void
rte_auxiliary_register(struct rte_auxiliary_driver *driver)
{
	TAILQ_INSERT_TAIL(&auxiliary_bus.driver_list, driver, next);
	driver->bus = &auxiliary_bus;
}

/* unregister a driver */
void
rte_auxiliary_unregister(struct rte_auxiliary_driver *driver)
{
	TAILQ_REMOVE(&auxiliary_bus.driver_list, driver, next);
	driver->bus = NULL;
}

/* Add a device to auxiliary bus */
void
auxiliary_add_device(struct rte_auxiliary_device *aux_dev)
{
	TAILQ_INSERT_TAIL(&auxiliary_bus.device_list, aux_dev, next);
}

/* Insert a device into a predefined position in auxiliary bus */
void
auxiliary_insert_device(struct rte_auxiliary_device *exist_aux_dev,
			struct rte_auxiliary_device *new_aux_dev)
{
	TAILQ_INSERT_BEFORE(exist_aux_dev, new_aux_dev, next);
}

/* Remove a device from auxiliary bus */
static void
rte_auxiliary_remove_device(struct rte_auxiliary_device *auxiliary_dev)
{
	TAILQ_REMOVE(&auxiliary_bus.device_list, auxiliary_dev, next);
}

static struct rte_device *
auxiliary_find_device(const struct rte_device *start, rte_dev_cmp_t cmp,
		      const void *data)
{
	const struct rte_auxiliary_device *pstart;
	struct rte_auxiliary_device *adev;

	if (start != NULL) {
		pstart = RTE_DEV_TO_AUXILIARY_CONST(start);
		adev = TAILQ_NEXT(pstart, next);
	} else {
		adev = TAILQ_FIRST(&auxiliary_bus.device_list);
	}
	while (adev != NULL) {
		if (cmp(&adev->device, data) == 0)
			return &adev->device;
		adev = TAILQ_NEXT(adev, next);
	}
	return NULL;
}

static int
auxiliary_plug(struct rte_device *dev)
{
	if (!auxiliary_dev_exists(dev->name))
		return -ENOENT;
	return auxiliary_probe_all_drivers(RTE_DEV_TO_AUXILIARY(dev));
}

static int
auxiliary_unplug(struct rte_device *dev)
{
	struct rte_auxiliary_device *adev;
	int ret;

	adev = RTE_DEV_TO_AUXILIARY(dev);
	ret = rte_auxiliary_driver_remove_dev(adev);
	if (ret == 0) {
		rte_auxiliary_remove_device(adev);
		rte_devargs_remove(dev->devargs);
		free(adev);
	}
	return ret;
}

static int
auxiliary_dma_map(struct rte_device *dev, void *addr, uint64_t iova, size_t len)
{
	struct rte_auxiliary_device *aux_dev = RTE_DEV_TO_AUXILIARY(dev);

	if (dev == NULL || !aux_dev->driver) {
		rte_errno = EINVAL;
		return -1;
	}
	if (aux_dev->driver->dma_map)
		return aux_dev->driver->dma_map(aux_dev, addr, iova, len);
	rte_errno = ENOTSUP;
	return -1;
}

static int
auxiliary_dma_unmap(struct rte_device *dev, void *addr, uint64_t iova,
		    size_t len)
{
	struct rte_auxiliary_device *aux_dev = RTE_DEV_TO_AUXILIARY(dev);

	if (dev == NULL || !aux_dev->driver) {
		rte_errno = EINVAL;
		return -1;
	}
	if (aux_dev->driver->dma_unmap)
		return aux_dev->driver->dma_unmap(aux_dev, addr, iova, len);
	rte_errno = ENOTSUP;
	return -1;
}

bool
auxiliary_ignore_device(const char *name)
{
	struct rte_devargs *devargs = auxiliary_devargs_lookup(name);

	switch (auxiliary_bus.bus.conf.scan_mode) {
	case RTE_BUS_SCAN_ALLOWLIST:
		if (devargs && devargs->policy == RTE_DEV_ALLOWED)
			return false;
		break;
	case RTE_BUS_SCAN_UNDEFINED:
	case RTE_BUS_SCAN_BLOCKLIST:
		if (devargs == NULL || devargs->policy != RTE_DEV_BLOCKED)
			return false;
		break;
	}
	return true;
}

static enum rte_iova_mode
auxiliary_get_iommu_class(void)
{
	const struct rte_auxiliary_driver *drv;

	FOREACH_DRIVER_ON_AUXILIARYBUS(drv) {
		if (drv->drv_flags & RTE_AUXILIARY_DRV_NEED_IOVA_AS_VA)
			return RTE_IOVA_VA;
	}

	return RTE_IOVA_DC;
}

struct rte_auxiliary_bus auxiliary_bus = {
	.bus = {
		.scan = auxiliary_scan,
		.probe = auxiliary_probe,
		.find_device = auxiliary_find_device,
		.plug = auxiliary_plug,
		.unplug = auxiliary_unplug,
		.parse = auxiliary_parse,
		.dma_map = auxiliary_dma_map,
		.dma_unmap = auxiliary_dma_unmap,
		.get_iommu_class = auxiliary_get_iommu_class,
		.dev_iterate = auxiliary_dev_iterate,
	},
	.device_list = TAILQ_HEAD_INITIALIZER(auxiliary_bus.device_list),
	.driver_list = TAILQ_HEAD_INITIALIZER(auxiliary_bus.driver_list),
};

RTE_REGISTER_BUS(auxiliary, auxiliary_bus.bus);
RTE_LOG_REGISTER(auxiliary_bus_logtype, bus.auxiliary, NOTICE);
