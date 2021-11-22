/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Mellanox Technologies, Ltd
 */

#include <string.h>

#include <rte_bus.h>
#include <rte_dev.h>
#include <rte_errno.h>
#include <rte_kvargs.h>

#include "private.h"
#include "rte_bus_auxiliary.h"

enum auxiliary_params {
	RTE_AUXILIARY_PARAM_NAME,
};

static const char * const auxiliary_params_keys[] = {
	[RTE_AUXILIARY_PARAM_NAME] = "name",
	NULL,
};

static int
auxiliary_dev_match(const struct rte_device *dev,
	      const void *_kvlist)
{
	const struct rte_kvargs *kvlist = _kvlist;
	int ret;

	ret = rte_kvargs_process(kvlist,
			auxiliary_params_keys[RTE_AUXILIARY_PARAM_NAME],
			rte_kvargs_strcmp, (void *)(uintptr_t)dev->name);

	return ret != 0 ? -1 : 0;
}

void *
auxiliary_dev_iterate(const void *start,
		    const char *str,
		    const struct rte_dev_iterator *it __rte_unused)
{
	rte_bus_find_device_t find_device;
	struct rte_kvargs *kvargs = NULL;
	struct rte_device *dev;

	if (str != NULL) {
		kvargs = rte_kvargs_parse(str, auxiliary_params_keys);
		if (kvargs == NULL) {
			RTE_LOG(ERR, EAL, "cannot parse argument list\n");
			rte_errno = EINVAL;
			return NULL;
		}
	}
	find_device = auxiliary_bus.bus.find_device;
	dev = find_device(start, auxiliary_dev_match, kvargs);
	rte_kvargs_free(kvargs);
	return dev;
}
