/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Nvidia Inc. All rights reserved.
 *
 * This file contains the functions definitions to
 * generate each supported action.
 */

#ifndef FLOW_PERF_ACTION_GEN
#define FLOW_PERF_ACTION_GEN

#include <rte_flow.h>

#include "config.h"

#define RTE_IP_TYPE_UDP	17
#define RTE_IP_TYPE_GRE	47
#define RTE_VXLAN_GPE_UDP_PORT 250
#define RTE_GENEVE_UDP_PORT 6081

int
query_ct_object(uint16_t core_id, uint32_t ctx_id, uint16_t port_id, struct rte_flow_error *err);

void
reset_ct_objects(uint16_t core_id, bool overwrite, bool reset_dir, uint16_t port_id);

void fill_actions(struct rte_flow_action *actions, uint64_t *flow_actions,
	uint32_t counter, uint16_t next_table, uint16_t hairpinq,
	uint64_t encap_data, uint64_t decap_data, uint8_t core_idx,
	bool unique_data, uint16_t port_id, uint32_t ct_route_id_count,
	bool cross_port, bool reply_dir);

#endif /* FLOW_PERF_ACTION_GEN */
