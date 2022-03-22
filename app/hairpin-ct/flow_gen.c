/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Nvidia Inc. All rights reserved.
 *
 * The file contains the implementations of the method to
 * fill items, actions & attributes in their corresponding
 * arrays, and then generate rte_flow rule.
 *
 * After the generation. The rule goes to validation then
 * creation state and then return the results.
 */

#include <stdint.h>

#include "flow_gen.h"
#include "items_gen.h"
#include "actions_gen.h"
#include "config.h"

static void
fill_attributes(struct rte_flow_attr *attr,
	uint64_t *flow_attrs, uint16_t group, uint32_t priority)
{
	uint8_t i;
	for (i = 0; i < MAX_ATTRS_NUM; i++) {
		if (flow_attrs[i] == 0)
			break;
		if (flow_attrs[i] & INGRESS)
			attr->ingress = 1;
		else if (flow_attrs[i] & EGRESS)
			attr->egress = 1;
		else if (flow_attrs[i] & TRANSFER)
			attr->transfer = 1;
	}
	attr->group = group;
	attr->priority = priority;
}

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
	struct rte_flow_error *error)
{
	struct rte_flow_attr attr;
	struct rte_flow_item items[MAX_ITEMS_NUM];
	struct rte_flow_action actions[MAX_ACTIONS_NUM];
	struct rte_flow *flow = NULL;

	memset(items, 0, sizeof(items));
	memset(actions, 0, sizeof(actions));
	memset(&attr, 0, sizeof(struct rte_flow_attr));

	fill_attributes(&attr, flow_attrs, group, priority);

	fill_actions(actions, flow_actions,
		outer_ip_src, next_table, hairpinq,
		encap_data, decap_data, core_idx, unique_data,
		port_id, ct_route_id_count, cross_port, reply_dir);

	fill_items(items, flow_items, outer_ip_src, core_idx,
		cross_port, reply_dir, time_to_live, set_ipv4_addrs,
		no_frag, set_ports, l3_type, set_ihl, ports_per_ip);

	flow = rte_flow_create(port_id, &attr, items, actions, error);
	return flow;
}
