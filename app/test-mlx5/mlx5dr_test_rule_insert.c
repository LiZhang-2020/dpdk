/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_test.h"

static void set_mask_and_value(struct rte_ipv4_hdr *mask,
			       struct rte_ipv4_hdr *value,
			       struct rte_flow_item *items)
{
	memset(mask, 0, sizeof(*mask));
	memset(value, 0, sizeof(*value));

	mask->version = 0xf;
	value->version = 0x4;

	mask->dst_addr = 0xffffffff;
	value->dst_addr = 0x01010102;

	items[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
	items[0].mask = mask;
	items[0].spec = value;

	items[1].type = RTE_FLOW_ITEM_TYPE_END;
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
	struct rte_flow_item items[MAX_ITEMS] = {{0}};
	struct rte_ipv4_hdr ipv_mask;
	struct rte_ipv4_hdr ipv_value;
	int ret;

	dr_ctx_attr.initial_log_ste_memory = 0;
	dr_ctx_attr.pd = NULL;
	dr_ctx_attr.queues = 16;
	dr_ctx_attr.queue_size = 256;

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

	set_mask_and_value(&ipv_mask, &ipv_value, items);

	/* Create root matcher */
	matcher_attr.priority = 0;
	matcher_attr.insertion_mode = MLX5DR_MATCHER_INSERTION_MODE_ASSURED;
	root_matcher = mlx5dr_matcher_create(root_tbl, items, &matcher_attr);
	if (!root_matcher) {
		printf("Failed to create root matcher\n");
		goto destroy_hws_tbl;
	}

	/* Create HWS matcher1 */
	matcher_attr.priority = 0;
	matcher_attr.insertion_mode = MLX5DR_MATCHER_INSERTION_MODE_BEST_EFFORT;
	matcher_attr.size_hint_column_log = 1;
	matcher_attr.size_hint_rows_log = 1;
	hws_matcher1 = mlx5dr_matcher_create(hws_tbl, items, &matcher_attr);
	if (!hws_matcher1) {
		printf("Failed to create HWS matcher 1\n");
		goto destroy_root_matcher;
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
	drop = mlx5dr_action_create_drop(ctx, MLX5DR_ACTION_FLAG_HWS_RX);
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
	rule_actions[0].action = to_hws_tbl;
	ret = mlx5dr_rule_create(root_matcher, items, rule_actions, 1, &rule_attr, connect_rule);
	if (ret) {
		printf("Failed to create connect rule\n");
		goto free_connect_rule;
	}

	/* Allocate HWS rules */
	hws_rule = calloc(1, mlx5dr_rule_get_handle_size());
	if (!hws_rule) {
		printf("Failed to allocate memory for hws_rule\n");
		goto destroy_connect_rule;
	}

	/* Create HWS rules */
	rule_attr.queue_id = 0;
	rule_attr.burst = 0;
	rule_attr.requst_comp = 1;

	rule_actions[0].action = drop;
	ret = mlx5dr_rule_create(hws_matcher1, items, rule_actions, 1, &rule_attr, hws_rule);
	if (ret) {
		printf("Failed to create hws rule\n");
		goto free_hws_rules;
	}

	mlx5dr_rule_destroy(hws_rule, &rule_attr);
	free(hws_rule);
	mlx5dr_rule_destroy(connect_rule, &rule_attr);
	free(connect_rule);
	mlx5dr_action_destroy(drop);
	mlx5dr_action_destroy(decap);
	mlx5dr_action_destroy(to_hws_tbl);
	mlx5dr_matcher_destroy(hws_matcher1);
	mlx5dr_matcher_destroy(root_matcher);
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
destroy_root_matcher:
	mlx5dr_matcher_destroy(root_matcher);
destroy_hws_tbl:
	mlx5dr_table_destroy(hws_tbl);
destroy_root_tbl:
	mlx5dr_table_destroy(root_tbl);
close_ctx:
	mlx5dr_context_close(ctx);
out_err:
	return -1;
}
