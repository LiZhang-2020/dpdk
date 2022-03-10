/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include <time.h>
#include "mlx5dr_test.h"

#define MAX_ITEMS 10
#define BIG_LOOP 10
#define MAX_ITEMS 10
#define QUEUE_SIZE 256
#define NUM_OF_RULES (QUEUE_SIZE * 3906) // Almost 1M
#define BURST_TH (32)

static int poll_for_comp(struct mlx5dr_context *ctx,
			 uint16_t queue_id,
			 uint32_t *pending_rules,
			 uint32_t expected_comp,
			 uint32_t *miss_count,
			 bool drain)
{
	bool queue_full = *pending_rules == QUEUE_SIZE;
	bool got_comp = *pending_rules >= expected_comp;
	struct rte_flow_op_result comp[BURST_TH];
	int ret;
	int j;

	/* Check if there are any completions at all */
	if (!got_comp && !drain)
		return 0;

	while (queue_full || ((got_comp || drain) && *pending_rules)) {
		ret = mlx5dr_send_queue_poll(ctx, queue_id, comp, expected_comp);
		if (ret < 0) {
			printf("Failed during poll queue\n");
			return -1;
		}

		if (ret) {
			(*pending_rules) -= ret;
			for (j = 0; j < ret; j++) {
				if (comp[j].status == RTE_FLOW_OP_ERROR)
					(*miss_count)++;
			}
			queue_full = false;
		}

		got_comp = !!ret;
	}

	return 0;
}

static void set_match_simple(struct rte_ipv4_hdr *ip_m,
			     struct rte_ipv4_hdr *ip_v,
			     struct rte_flow_item *items)
{
	memset(ip_m, 0, sizeof(*ip_m));
	memset(ip_v, 0, sizeof(*ip_v));

	ip_m->dst_addr = 0xffffffff;
	ip_m->version = 0xf;
	ip_v->version = 0x4;

	items[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
	items[0].mask = ip_m;
	items[0].spec = ip_v;

	items[1].type = RTE_FLOW_ITEM_TYPE_END;
}

static void set_match_mavneir(struct rte_flow_item_eth *eth_m,
			      struct rte_flow_item_eth *eth_v,
			      struct rte_ipv4_hdr *ip_m,
			      struct rte_ipv4_hdr *ip_v,
			      struct rte_flow_item_udp *udp_m,
			      struct rte_flow_item_udp *udp_v,
			      struct rte_flow_item_gtp *gtp_m,
			      struct rte_flow_item_gtp *gtp_v,
			      struct rte_ipv4_hdr *ip_m_in,
			      struct rte_ipv4_hdr *ip_v_in,
			      struct rte_flow_item_tcp *tcp_m_in,
			      struct rte_flow_item_tcp *tcp_v_in,
			      struct rte_flow_item *items)

{
	if (eth_m) {
		memset(eth_m, 0, sizeof(*eth_m));
		memset(eth_v, 0, sizeof(*eth_v));
		items->type = RTE_FLOW_ITEM_TYPE_ETH;
		items->mask = eth_m;
		items->spec = eth_v;
		items++;
	}

	if (ip_m) {
		memset(ip_m, 0, sizeof(*ip_m));
		memset(ip_v, 0, sizeof(*ip_v));
		ip_m->dst_addr = 0xffffffff;
		ip_m->src_addr = 0xffffffff;
		ip_v->dst_addr = 0x02020202;
		ip_v->src_addr = 0x01010101;
		ip_m->version = 0xf;
		ip_v->version = 0x4;
		items->type = RTE_FLOW_ITEM_TYPE_IPV4;
		items->mask = ip_m;
		items->spec = ip_v;
		items++;
	}

	if (udp_m) {
		memset(udp_m, 0, sizeof(*udp_m));
		memset(udp_v, 0, sizeof(*udp_v));
		items->type = RTE_FLOW_ITEM_TYPE_UDP;
		items->mask = udp_m;
		items->spec = udp_m;
		items++;
	}

	if (gtp_m) {
		memset(gtp_m, 0, sizeof(*gtp_m));
		memset(gtp_v, 0, sizeof(*gtp_v));
		gtp_m->teid = -1;
		gtp_v->teid = 0xabcd;
		items->type = RTE_FLOW_ITEM_TYPE_GTP;
		items->mask = gtp_m;
		items->spec = gtp_v;
		items++;
	}

	if (ip_m_in) {
		memset(ip_m_in, 0, sizeof(*ip_m_in));
		memset(ip_v_in, 0, sizeof(*ip_v_in));
		ip_m_in->dst_addr = 0xffffffff;
		ip_m_in->src_addr = 0xffffffff;
		ip_v_in->dst_addr = 0x04040404;
		ip_v_in->src_addr = 0x03030303;
		ip_v_in->version = 0xf;
		ip_v_in->version = 0x4;
		items->type = RTE_FLOW_ITEM_TYPE_IPV4;
		items->mask = ip_m_in;
		items->spec = ip_v_in;
		items++;
	}

	if (tcp_m_in) {
		memset(tcp_m_in, 0, sizeof(*tcp_m_in));
		memset(tcp_v_in, 0, sizeof(*tcp_v_in));
		tcp_m_in->hdr.dst_port = -1;
		tcp_m_in->hdr.src_port = -1;
		tcp_v_in->hdr.dst_port = 0xbbbb;
		tcp_v_in->hdr.src_port = 0xaaaa;
		items->type = RTE_FLOW_ITEM_TYPE_TCP;
		items->mask = tcp_m_in;
		items->spec = tcp_v_in;
		items++;
	}

	items->type = RTE_FLOW_ITEM_TYPE_END;
}


int run_test_rule_insert(struct ibv_context *ibv_ctx)
{
	struct mlx5dr_context *ctx;
	struct mlx5dr_table *root_tbl, *hws_tbl;
	struct mlx5dr_matcher *root_matcher, *hws_matcher1;
	struct mlx5dr_rule_action rule_actions[10];
	struct mlx5dr_action *to_hws_tbl;
	struct mlx5dr_action *decap;
	struct mlx5dr_action *drop;
	struct mlx5dr_rule *connect_rule;
	struct mlx5dr_rule *hws_rule;
	struct mlx5dr_context_attr dr_ctx_attr = {0};
	struct mlx5dr_table_attr dr_tbl_attr = {0};
	struct mlx5dr_matcher_attr matcher_attr = {0};
	struct mlx5dr_rule_attr rule_attr = {0};
	struct rte_flow_item items_conn[MAX_ITEMS] = {{0}};
	struct rte_ipv4_hdr ipv_mask_conn;
	struct rte_ipv4_hdr ipv_value_conn;
	struct rte_flow_item items[MAX_ITEMS] = {{0}};
	struct rte_flow_item_eth eth_mask;
	struct rte_flow_item_eth eth_value;
	struct rte_ipv4_hdr ipv_mask;
	struct rte_ipv4_hdr ipv_value;
	struct rte_flow_item_udp udp_mask;
	struct rte_flow_item_udp udp_value;
	struct mlx5dr_match_template *mt;
	struct mlx5dr_match_template *mt_root;
	uint32_t pending_rules = 0;
	uint32_t miss_count = 0;
	uint64_t start, end;
	int ret, i, j;

	dr_ctx_attr.initial_log_ste_memory = 0;
	dr_ctx_attr.pd = NULL;
	dr_ctx_attr.queues = 16;
	dr_ctx_attr.queue_size = QUEUE_SIZE;

	ctx = mlx5dr_context_open(ibv_ctx, &dr_ctx_attr);
	if (!ctx) {
		printf("Failed to create context\n");
		goto out_err;
	}

	/* Create root table */
	dr_tbl_attr.level = 0;
	dr_tbl_attr.type = MLX5DR_TABLE_TYPE_NIC_RX;
	root_tbl = mlx5dr_table_create(ctx, &dr_tbl_attr);
	if (!root_tbl) {
		printf("Failed to create root table\n");
		goto close_ctx;
	}

	/* Create HWS table */
	dr_tbl_attr.level = 1;
	dr_tbl_attr.type = MLX5DR_TABLE_TYPE_NIC_RX;
	hws_tbl = mlx5dr_table_create(ctx, &dr_tbl_attr);
	if (!hws_tbl) {
		printf("Failed to create HWS table\n");
		goto destroy_root_tbl;
	}

	set_match_simple(&ipv_mask_conn, &ipv_value_conn, items_conn);

	mt_root = mlx5dr_match_template_create(items_conn, 0);
	if (!mt_root) {
		printf("Failed root template\n");
		goto destroy_hws_tbl;
	}

	/* Create root matcher */
	matcher_attr.priority = 0;
	matcher_attr.mode = MLX5DR_MATCHER_RESOURCE_MODE_RULE;
	root_matcher = mlx5dr_matcher_create(root_tbl, &mt_root, 1, &matcher_attr);
	if (!root_matcher) {
		printf("Failed to create root matcher\n");
		goto destroy_root_template;
	}

	set_match_mavneir(&eth_mask, &eth_value,
			  &ipv_mask, &ipv_value,
			  &udp_mask, &udp_value,
			  NULL, NULL,
			  NULL, NULL,
			  NULL, NULL,
			  items);

	mt = mlx5dr_match_template_create(items, 0);
	if (!mt) {
		printf("Failed HWS template\n");
		goto destroy_root_matcher;
	}

	/* Create HWS matcher1 */
	matcher_attr.priority = 0;
	matcher_attr.mode = MLX5DR_MATCHER_RESOURCE_MODE_RULE;
	matcher_attr.rule.num_log = 22;
	hws_matcher1 = mlx5dr_matcher_create(hws_tbl, &mt, 1, &matcher_attr);
	if (!hws_matcher1) {
		printf("Failed to create HWS matcher 1\n");
		goto destroy_template;
	}

	/* Create goto table action */
	to_hws_tbl = mlx5dr_action_create_dest_table(ctx, hws_tbl, MLX5DR_ACTION_FLAG_ROOT_RX);
	if (!to_hws_tbl) {
		printf("Failed to create action jump to HWS table\n");
		goto destroy_hws_matcher1;
	}

	decap = mlx5dr_action_create_reformat(ctx, MLX5DR_ACTION_REFORMAT_TYPE_TNL_L2_TO_L2,
					      0, NULL, 0, MLX5DR_ACTION_FLAG_ROOT_RX);
	if (!decap) {
		printf("Failed to create decap action\n");
		goto destroy_action_to_hws_tbl;
	}

	/* Create drop action */
	drop = mlx5dr_action_create_dest_drop(ctx, MLX5DR_ACTION_FLAG_HWS_RX);
	if (!drop) {
		printf("Failed to create action drop\n");
		goto destroy_action_decap;
	}

	/* Allocate connecting rule to HWS */
	connect_rule = calloc(1, mlx5dr_rule_get_handle_size());
	if (!connect_rule) {
		printf("Failed to allocate memory for connect rule\n");
		goto destroy_action_drop;
	}

	/* Create connecting rule to HWS */
	ipv_value_conn.dst_addr = 0x01010102;
	rule_actions[0].action = to_hws_tbl;

	rule_attr.queue_id = 0;
	rule_attr.user_data = connect_rule;

	ret = mlx5dr_rule_create(root_matcher, 0, items_conn, rule_actions, 1, &rule_attr, connect_rule);
	if (ret) {
		printf("Failed to create connect rule\n");
		goto free_connect_rule;
	}
	pending_rules = 1;
	poll_for_comp(ctx, rule_attr.queue_id, &pending_rules, 1, &miss_count, true);

	/* Allocate HWS rules */
	hws_rule = calloc(NUM_OF_RULES, mlx5dr_rule_get_handle_size());
	if (!hws_rule) {
		printf("Failed to allocate memory for hws_rule\n");
		goto destroy_connect_rule;
	}

	for (j = 0; j < BIG_LOOP; j++) {
		miss_count = 0;
		start = rte_rdtsc();

		/* Create HWS rules */
		for (i = 0; i < NUM_OF_RULES; i++) {
			rule_attr.queue_id = 0;
			rule_attr.user_data = &hws_rule[i];

			/* Ring doorbell */
			rule_attr.burst = !((i + 1) % BURST_TH == 0);

			ipv_value.dst_addr = i;
			rule_actions[0].action = drop;

			ret = mlx5dr_rule_create(hws_matcher1, 0, items, rule_actions, 1, &rule_attr, &hws_rule[i]);
			if (ret) {
				printf("Failed to create hws rule\n");
				goto free_hws_rules;
			}

			pending_rules++;

			poll_for_comp(ctx, rule_attr.queue_id, &pending_rules, BURST_TH, &miss_count, false);
		}

		end = rte_rdtsc();
		/* Drain the queue */
		poll_for_comp(ctx, rule_attr.queue_id, &pending_rules, BURST_TH, &miss_count, true);
		printf("K-Rules/Sec: %lf Insertion. Total misses: %u (out of: %u)\n", (double) ((double) NUM_OF_RULES / 1000) / ((double) (end - start) / rte_get_tsc_hz()),
		       miss_count, NUM_OF_RULES);

		miss_count = 0;
		start = rte_rdtsc();

		/* Delete HWS rules */
		for (i = 0; i < NUM_OF_RULES; i++) {
			rule_attr.queue_id = 0;
			rule_attr.user_data = &hws_rule[i];

			/* Ring doorbell */
			rule_attr.burst = !((i + 1) % (BURST_TH) == 0);

			rule_actions[0].action = drop;
			ret = mlx5dr_rule_destroy(&hws_rule[i], &rule_attr);
			if (ret) {
				printf("Failed to destroy hws rule\n");
				goto free_hws_rules;
			}

			pending_rules++;

			poll_for_comp(ctx, rule_attr.queue_id, &pending_rules, BURST_TH, &miss_count, false);
		}

		end = rte_rdtsc();
		/* Drain the queue */
		poll_for_comp(ctx, rule_attr.queue_id, &pending_rules, BURST_TH, &miss_count, true);
		printf("K-Rules/Sec: %lf Deletion. Total misses: %u (out of: %u)\n", (double) ((double) NUM_OF_RULES / 1000) / ((double) (end - start) / rte_get_tsc_hz()),
		       miss_count, NUM_OF_RULES);
	}

	free(hws_rule);
	mlx5dr_rule_destroy(connect_rule, &rule_attr);
	free(connect_rule);
	mlx5dr_action_destroy(drop);
	mlx5dr_action_destroy(decap);
	mlx5dr_action_destroy(to_hws_tbl);
	mlx5dr_matcher_destroy(hws_matcher1);
	mlx5dr_match_template_destroy(mt);
	mlx5dr_matcher_destroy(root_matcher);
	mlx5dr_match_template_destroy(mt_root);
	mlx5dr_table_destroy(hws_tbl);
	mlx5dr_table_destroy(root_tbl);
	mlx5dr_context_close(ctx);

	return 0;

free_hws_rules:
	free(hws_rule);
destroy_connect_rule:
	mlx5dr_rule_destroy(connect_rule, &rule_attr);
free_connect_rule:
	free(connect_rule);
destroy_action_drop:
	mlx5dr_action_destroy(drop);
destroy_action_decap:
	mlx5dr_action_destroy(decap);
destroy_action_to_hws_tbl:
	mlx5dr_action_destroy(to_hws_tbl);
destroy_hws_matcher1:
	mlx5dr_matcher_destroy(hws_matcher1);
destroy_template:
	mlx5dr_match_template_destroy(mt);
destroy_root_matcher:
	mlx5dr_matcher_destroy(root_matcher);
destroy_root_template:
	mlx5dr_match_template_destroy(mt_root);
destroy_hws_tbl:
	mlx5dr_table_destroy(hws_tbl);
destroy_root_tbl:
	mlx5dr_table_destroy(root_tbl);
close_ctx:
	mlx5dr_context_close(ctx);
out_err:
	return -1;
}
