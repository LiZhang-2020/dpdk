/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Nvidia Inc. All rights reserved.
 *
 * This file contains the items related methods
 */

#ifndef FLOW_PERF_ITEMS_GEN
#define FLOW_PERF_ITEMS_GEN

#include <stdint.h>
#include <rte_flow.h>

#include "config.h"

void fill_items(struct rte_flow_item *items, uint64_t *flow_items,
	uint32_t outer_ip_src, uint8_t core_idx, bool cross_port, bool reply_dir,
	uint8_t  time_to_live, bool set_ipv4_addrs, bool no_frag,
	bool set_ports, uint16_t l3_type, bool set_ihl, uint64_t ports_per_ip);

#endif /* FLOW_PERF_ITEMS_GEN */
