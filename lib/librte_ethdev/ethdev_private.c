/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Gaëtan Rivet
 */

#include "rte_ethdev.h"
#include "rte_ethdev_driver.h"
#include "ethdev_private.h"

uint16_t
eth_dev_to_id(const struct rte_eth_dev *dev)
{
	if (dev == NULL)
		return RTE_MAX_ETHPORTS;
	return dev - rte_eth_devices;
}

struct rte_eth_dev *
eth_find_device(const struct rte_eth_dev *start, rte_eth_cmp_t cmp,
		const void *data)
{
	struct rte_eth_dev *edev;
	ptrdiff_t idx;

	/* Avoid Undefined Behaviour */
	if (start != NULL &&
	    (start < &rte_eth_devices[0] ||
	     start > &rte_eth_devices[RTE_MAX_ETHPORTS]))
		return NULL;
	if (start != NULL)
		idx = eth_dev_to_id(start) + 1;
	else
		idx = 0;
	for (; idx < RTE_MAX_ETHPORTS; idx++) {
		edev = &rte_eth_devices[idx];
		if (cmp(edev, data) == 0)
			return edev;
	}
	return NULL;
}

static int
rte_eth_devargs_process_range(char *str, uint16_t *list, uint16_t *len_list,
	const uint16_t max_list)
{
	uint16_t lo, hi, val;
	int result;
	char *pos = str;

	result = sscanf(str, "%hu-%hu", &lo, &hi);
	if (result == 1) {
		if (*len_list >= max_list)
			return -ENOMEM;
		list[(*len_list)++] = lo;
	} else if (result == 2) {
		if (lo >= hi)
			return -EINVAL;
		for (val = lo; val <= hi; val++) {
			if (*len_list >= max_list)
				return -ENOMEM;
			list[(*len_list)++] = val;
		}
	} else
		return -EINVAL;
	while (*pos != 0 && ((*pos >= '0' && *pos <= '9') || *pos == '-'))
		pos++;
	return pos - str;
}

static int
rte_eth_devargs_process_list(char *str, uint16_t *list, uint16_t *len_list,
	const uint16_t max_list)
{
	char *pos = str;
	int ret;

	if (*pos == '[')
		pos++;
	while (1) {
		ret = rte_eth_devargs_process_range(pos, list, len_list,
						    max_list);
		if (ret < 0)
			return ret;
		pos += ret;
		if (*pos != ',') /* end of list */
			break;
		pos++;
	}
	if (*str == '[' && *pos != ']')
		return -EINVAL;
	if (*pos == ']')
		pos++;
	return pos - str;
}

/*
 * Parse representor ports, expand and update representor port ID.
 * Representor format:
 *   #: range or single number of VF representor - legacy
 *   c#: controller id or range
 *   [c#]pf#: PF port representor/s
 *   [[c#]pf#]vf#: VF port representor/s
 *   [[c#]pf#]sf#: SF port representor/s
 *
 * See RTE_ETH_REPR() for representor ID format.
 */
int
rte_eth_devargs_parse_representor_ports(char *str, void *data)
{
	struct rte_eth_devargs *eth_da = data;
	int ret;
	uint32_t c, p, f, i = 0;

	eth_da->type = RTE_ETH_REPRESENTOR_NONE;
	/* parse c# */
	if (str[0] == 'c') {
		str += 1;
		ret = rte_eth_devargs_process_list(str, eth_da->controllers,
				&eth_da->nb_controllers, RTE_MAX_ETHCTRLS);
		if (ret < 0)
			goto err;
		str += ret;
	}
	/* parse pf# */
	if (str[0] == 'p' && str[1] == 'f') {
		str += 2;
		eth_da->type = RTE_ETH_REPRESENTOR_PF;
		ret = rte_eth_devargs_process_list(str, eth_da->ports,
				&eth_da->nb_ports, RTE_MAX_ETHPORTS);
		if (ret < 0)
			goto err;
		str += ret;
	}
	/* parse vf# and sf#, default to VF */
	if (str[0] == 'v'  && str[1] == 'f') {
		eth_da->type = RTE_ETH_REPRESENTOR_VF;
		str += 2;
	} else if (str[0] == 's'  && str[1] == 'f') {
		eth_da->type = RTE_ETH_REPRESENTOR_SF;
		str += 2;
	} else {
		eth_da->type = RTE_ETH_REPRESENTOR_VF;
	}
	ret = rte_eth_devargs_process_list(str, eth_da->representor_ports,
		&eth_da->nb_representor_ports, RTE_MAX_ETHPORTS);
	if (ret < 0)
		goto err;

	/* Set default values, expand and update representor ID. */
	if (!eth_da->nb_controllers) {
		eth_da->nb_controllers = 1;
		eth_da->controllers[0] = 0;
	}
	if (!eth_da->nb_ports) {
		eth_da->nb_ports = 1;
		eth_da->ports[0] = 0;
	}
	if (!eth_da->nb_representor_ports) {
		eth_da->nb_representor_ports = 1;
		eth_da->representor_ports[0] = 0;
	}
	for (c = 0; c < eth_da->nb_controllers; ++c) {
		for (p = 0; p < eth_da->nb_ports; ++p) {
			for (f = 0; f < eth_da->nb_representor_ports; ++f) {
				i = c * eth_da->nb_ports *
					eth_da->nb_representor_ports +
				    p * eth_da->nb_representor_ports + f;
				if (i >= RTE_DIM(eth_da->representor_ports)) {
					RTE_LOG(ERR, EAL, "too many representor specified: %s",
						str);
					return -EINVAL;
				}
				eth_da->representor_ports[i] = RTE_ETH_REPR(
					eth_da->controllers[c],
					eth_da->ports[p],
					eth_da->type == RTE_ETH_REPRESENTOR_SF,
					eth_da->representor_ports[f]);
			}
		}
	}
	eth_da->nb_representor_ports = i + 1;
err:
	if (ret < 0)
		RTE_LOG(ERR, EAL, "wrong representor format: %s", str);
	return ret < 0 ? ret : 0;
}
