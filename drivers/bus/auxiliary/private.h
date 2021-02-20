/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Mellanox Technologies, Ltd
 */

#ifndef _AUXILIARY_PRIVATE_H_
#define _AUXILIARY_PRIVATE_H_

#include <stdbool.h>
#include <stdio.h>
#include "rte_bus_auxiliary.h"

extern struct rte_auxiliary_bus auxiliary_bus;
extern int auxiliary_bus_logtype;

#define AUXILIARY_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, auxiliary_bus_logtype, "%s(): " fmt "\n", \
		__func__, ##args)

/* Auxiliary bus iterators */
#define FOREACH_DEVICE_ON_AUXILIARYBUS(p)	\
		TAILQ_FOREACH(p, &(auxiliary_bus.device_list), next)

#define FOREACH_DRIVER_ON_AUXILIARYBUS(p)	\
		TAILQ_FOREACH(p, &(auxiliary_bus.driver_list), next)

/**
 * Test whether the auxiliary device exist
 *
 * @param name
 *  Auxiliary device name
 * @return
 *  true on exists, false otherwise
 */
bool auxiliary_dev_exists(const char *name);

/**
 * Scan the content of the auxiliary bus, and the devices in the devices
 * list
 *
 * @return
 *  0 on success, negative on error
 */
int auxiliary_scan(void);

/**
 * Setup or update device when being scanned.
 *
 * @param aux_dev
 *	AUXILIARY device.
 */
void auxiliary_on_scan(struct rte_auxiliary_device *aux_dev);

/**
 * Validate whether a device with given auxiliary device should be ignored
 * or not.
 *
 * @param name
 *	Auxiliary name of device to be validated
 * @return
 *	true: if device is to be ignored,
 *	false: if device is to be scanned,
 */
bool auxiliary_ignore_device(const char *name);

/**
 * Add an auxiliary device to the auxiliary bus (append to auxiliary Device
 * list). This function also updates the bus references of the auxiliary
 * Device (and the generic device object embedded within.
 *
 * @param aux_dev
 *	AUXILIARY device to add
 * @return void
 */
void auxiliary_add_device(struct rte_auxiliary_device *aux_dev);

/**
 * Insert an auxiliary device in the auxiliary bus at a particular location
 * in the device list. It also updates the auxiliary bus reference of the
 * new devices to be inserted.
 *
 * @param exist_aux_dev
 *	Existing auxiliary device in auxiliary bus
 * @param new_aux_dev
 *	AUXILIARY device to be added before exist_aux_dev
 * @return void
 */
void auxiliary_insert_device(struct rte_auxiliary_device *exist_aux_dev,
			     struct rte_auxiliary_device *new_aux_dev);

/**
 * Match the auxiliary Driver and Device by driver function
 *
 * @param aux_drv
 *      auxiliary driver
 * @param aux_dev
 *      auxiliary device to match against the driver
 * @return
 *      the driver can handle the device
 */
bool auxiliary_match(const struct rte_auxiliary_driver *aux_drv,
		     const struct rte_auxiliary_device *aux_dev);

/**
 * Iterate over internal devices, matching any device against the provided
 * string.
 *
 * @param start
 *   Iteration starting point.
 * @param str
 *   Device string to match against.
 * @param it
 *   (unused) iterator structure.
 * @return
 *   A pointer to the next matching device if any.
 *   NULL otherwise.
 */
void *auxiliary_dev_iterate(const void *start, const char *str,
			    const struct rte_dev_iterator *it);

#endif /* _AUXILIARY_PRIVATE_H_ */
