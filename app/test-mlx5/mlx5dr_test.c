/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include <infiniband/verbs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <rte_flow.h>
#include "../../drivers/net/mlx5/steering/mlx5dr.h"
#include "/usr/include/infiniband/mlx5dv.h"

#include "../../drivers/net/mlx5/steering/mlx5dr_context.h"
#include "../../drivers/net/mlx5/steering/mlx5dr_send.h"
#include "../../drivers/net/mlx5/steering/mlx5dr_rule.h"

#define MAX_ITEMS 10
#define NUM_POSTS 5

char def_dev_name[] = "mlx5_0";

static int __mlx5dr_run_test_post(struct mlx5dr_context *ctx)
{
	struct mlx5dr_send_engine *queue = &ctx->send_queue[0];
	struct mlx5dr_send_engine_post_attr attr = {0};
	struct mlx5dr_rule *poll_rule[NUM_POSTS + 1] = {0};
	struct mlx5dr_send_engine_post_ctrl ctrl;
	struct mlx5dr_rule rule[NUM_POSTS] = {0};
	size_t len;
	char *buf;
	int ret = 0;
	int i;


	attr.user_comp = 1;
	for (i = 0; i < NUM_POSTS -1; i++) {
		ctrl = mlx5dr_send_engine_post_start(queue);
		mlx5dr_send_engine_post_req_wqe(&ctrl, &buf, &len);
		attr.rule = &rule[i];
		mlx5dr_send_engine_post_end(&ctrl, &attr);
	}

	attr.rule = &rule[i];
	attr.notify_hw = 1;
	ctrl = mlx5dr_send_engine_post_start(queue);
	mlx5dr_send_engine_post_req_wqe(&ctrl, &buf, &len);
	mlx5dr_send_engine_post_end(&ctrl, &attr);

	i = 0;
	ret = -1;
	while (ret && i < 2000) {
		ret = mlx5dr_send_engine_poll(ctrl.send_ring, poll_rule, NUM_POSTS);
		i++;
	}
	if (ret || i >= 2000)
		return -1;

	for (i = 0; i < NUM_POSTS && poll_rule[i]; i++) {
		if (poll_rule[i]->rule_status != MLX5DR_RULE_COMPLETED_SUCC)
			return -1;
	}

	return 0;
}

static int mlx5dr_run_test_post(struct mlx5dr_context *ctx)
{
	int ret;
	int i;

	for (i = 0; i < 5000; i++) {
		ret = __mlx5dr_run_test_post(ctx);
		if (ret)
			return ret;
	}

	return 0;
}
static int run_test_post_send(struct ibv_context *ibv_ctx)
{
	struct mlx5dr_context *ctx;
	struct mlx5dr_context_attr dr_ctx_attr = {0};
	int ret;

	dr_ctx_attr.initial_log_ste_memory = 0;
	dr_ctx_attr.pd = NULL;
	dr_ctx_attr.queues = 16;
	dr_ctx_attr.queue_size = 256;

	ctx = mlx5dr_context_open(ibv_ctx, &dr_ctx_attr);
	if (!ctx) {
		printf("%s - Failed to create context\n", __func__);
		goto out_err;
	}
	ret = mlx5dr_run_test_post(ctx);
	if (ret) {
		printf("%s Failed to run post test\n", __func__);
		goto close_ctx;
	}

	return ret;

close_ctx:
	mlx5dr_context_close(ctx);
out_err:
	return -1;
}

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

static int run_test_rule_insert(struct ibv_context *ibv_ctx)
{
	struct mlx5dr_context *ctx;
	struct mlx5dr_table *root_tbl, *hws_tbl;
	struct mlx5dr_matcher *root_matcher, *hws_matcher1, *hws_matcher2;
	struct mlx5dr_rule_action rule_actions[10];
	struct mlx5dr_action *to_hws_tbl;
	struct mlx5dr_rule *connect_rule;
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
	matcher_attr.size_hint_column_log = 4;
	matcher_attr.size_hint_rows_log = 4;
	hws_matcher1 = mlx5dr_matcher_create(hws_tbl, items, &matcher_attr);
	if (!hws_matcher1) {
		printf("Failed to create HWS matcher 1\n");
		goto destroy_root_matcher;
	}

	/* Create HWS matcher2 */
	matcher_attr.priority = 1;
	matcher_attr.insertion_mode = MLX5DR_MATCHER_INSERTION_MODE_BEST_EFFORT;
	matcher_attr.size_hint_column_log = 4;
	matcher_attr.size_hint_rows_log = 4;
	hws_matcher2 = mlx5dr_matcher_create(hws_tbl, items, &matcher_attr);
	if (!hws_matcher2) {
		printf("Failed to create HWS matcher 2\n");
		goto destroy_hws_matcher1;
	}

	/* Create goto table action */
	to_hws_tbl = mlx5dr_action_create_dest_table(ctx, MLX5DR_ACTION_FLAG_ROOT_ONLY, hws_tbl);
	if (!to_hws_tbl) {
		printf("Failed to create action jump to HWS table\n");
		goto destroy_hws_matcher2;
	}

	/* Create connecting rule to HWS */
	connect_rule = calloc(1, mlx5dr_rule_get_handle_size());
	if (!connect_rule) {
		printf("Failed to allocate memory for connect rule\n");
		goto destroy_action_to_hws_tbl;
	}

	rule_actions[0].action = to_hws_tbl;
	ret = mlx5dr_rule_create(root_matcher, items, rule_actions, 1, &rule_attr, connect_rule);
	if (ret) {
		printf("Failed to create connect rule\n");
		goto free_connect_rule;
	}

	mlx5dr_rule_destroy(connect_rule, &rule_attr);
	free(connect_rule);
	mlx5dr_action_destroy(to_hws_tbl);
	mlx5dr_matcher_destroy(hws_matcher2);
	mlx5dr_matcher_destroy(hws_matcher1);
	mlx5dr_matcher_destroy(root_matcher);
	mlx5dr_table_destroy(hws_tbl);
	mlx5dr_table_destroy(root_tbl);
	mlx5dr_context_close(ctx);

	return 0;

free_connect_rule:
	free(connect_rule);
destroy_action_to_hws_tbl:
	mlx5dr_action_destroy(to_hws_tbl);
destroy_hws_matcher2:
	mlx5dr_matcher_destroy(hws_matcher2);
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

int main(int argc, char **argv)
{
	struct mlx5dv_context_attr dv_ctx_attr = {};
	char *dev_name = def_dev_name;
	struct ibv_device **dev_list;
	struct ibv_context *ibv_ctx;
	struct ibv_device *dev;
	int i, ret;

	if (argc >= 3 && !memcmp("-d", argv[argc - 2], 2)) {
		dev_name = argv[argc - 1];
		argc -=2;
	}
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, ":: invalid EAL arguments\n");

	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		printf("Failed to get IB devices list\n");
		return 1;
	}

	for (i = 0; dev_list[i]; ++i)
		if(!strcmp(ibv_get_device_name(dev_list[i]), dev_name))
			break;

	dev = dev_list[i];
	if (!dev) {
		fprintf(stderr, "IB device %s not found\n", dev_name);
		goto free_dev_list;
	}
	fprintf(stderr, "IB device %s found\n", dev_name);

	dv_ctx_attr.flags = MLX5DV_CONTEXT_FLAGS_DEVX;
	ibv_ctx = mlx5dv_open_device(dev, &dv_ctx_attr);
	if (!ibv_ctx) {
	        fprintf(stderr,"Couldn't get context for %s\n", ibv_get_device_name(dev));
	        goto free_dev_list;
	}
	fprintf(stderr, "IB device %s Context found\n", dev_name);

	ret = run_test_post_send(ibv_ctx);
	if (ret) {
		fprintf(stderr,"Fail to run test rule insert\n");
		goto close_ib_dev;
	}
	fprintf(stderr, "Test done: post send\n");

	ret = run_test_rule_insert(ibv_ctx);
	if (ret) {
		fprintf(stderr,"Fail to run test rule insert\n");
		goto close_ib_dev;
	}
	fprintf(stderr, "Test done: rule insert\n");

	ibv_close_device(ibv_ctx);
	ibv_free_device_list(dev_list);

	return 0;

close_ib_dev:
	ibv_close_device(ibv_ctx);
free_dev_list:
	ibv_free_device_list(dev_list);
	return ret;
}
