/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Nvidia Inc. All rights reserved.
 *
 * This file contains the items, actions and attributes
 * definition. And the methods to prepare and fill items,
 * actions and attributes to generate rte_flow rule.
 */

#ifndef FLOW_PERF_FLOW_GEN
#define FLOW_PERF_FLOW_GEN

#include <stdint.h>
#include <rte_flow.h>

#include "config.h"

/* Actions */
#define HAIRPIN_QUEUE_ACTION FLOW_ACTION_MASK(0)
#define HAIRPIN_RSS_ACTION   FLOW_ACTION_MASK(1)
#define CT_ACTION            FLOW_ACTION_MASK(2)
#define CT_ROUTE_ID_ACTION   FLOW_ACTION_MASK(10)
#define AGING_SHARED_ACTION  FLOW_ACTION_MASK(11)

/* Attributes */
#define INGRESS              FLOW_ATTR_MASK(0)
#define EGRESS               FLOW_ATTR_MASK(1)
#define TRANSFER             FLOW_ATTR_MASK(2)

/* Items */
#define CT_TAG_ITEM          0

struct rte_flow *
generate_flow(uint16_t port_id,
	uint16_t group,
	uint32_t priority,
	uint64_t *flow_attrs,
	uint64_t *flow_items,
	uint64_t *flow_actions,
	uint16_t next_table,
	uint32_t outer_ip_src,
	uint16_t hairpinq,
	uint64_t encap_data,
	uint64_t decap_data,
	uint8_t core_idx,
	bool unique_data,
	uint32_t ct_route_id_count,
	bool cross_port,
	bool reply_dir,
	uint8_t time_to_live,
	bool set_ipv4_addrs,
	bool no_frag,
	bool set_ports,
	uint16_t l3_type,
	bool set_ihl,
	uint64_t ports_per_ip,
	struct rte_flow_error *error);

#endif /* FLOW_PERF_FLOW_GEN */
