/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_test.h"

#define NUM_POSTS 5
#define POLL_ONCE 3

static int __mlx5dr_run_test_post(struct mlx5dr_context *ctx)
{
	struct mlx5dr_send_engine *queue = &ctx->send_queue[0];
	struct mlx5dr_send_engine_post_attr attr = {0};
	struct rte_flow_op_result res[NUM_POSTS + 1] = {{0}};
	struct mlx5dr_send_engine_post_ctrl ctrl;
	struct mlx5dr_rule rule[NUM_POSTS] = {{0}};
	uint32_t tmp_rtc_id;
	size_t len;
	char *buf;
	int ret = 0;
	int i;

	for (i = 0; i < NUM_POSTS - 1; i++) {
		attr.user_data = (void *)&rule[i];
		attr.used_id = &tmp_rtc_id;
		ctrl = mlx5dr_send_engine_post_start(queue);
		mlx5dr_send_engine_post_req_wqe(&ctrl, &buf, &len);
		attr.rule = &rule[i];
		mlx5dr_send_engine_post_end(&ctrl, &attr);
	}

	attr.rule = &rule[i];
	attr.user_data = (void *)&rule[i];
	attr.notify_hw = 1;
	ctrl = mlx5dr_send_engine_post_start(queue);
	mlx5dr_send_engine_post_req_wqe(&ctrl, &buf, &len);
	mlx5dr_send_engine_post_end(&ctrl, &attr);

	i = 0;
	ret = -1;
	while (ret <= 0 && i < 2000) {
		ret = mlx5dr_send_queue_poll(ctx, 0, res, POLL_ONCE);
		i++;
	}
	if (ret <= 0 || i >= 2000) {
		return -1;
	}

	for (i = 0; i < NUM_POSTS && res[i].user_data; i++) {
		if (res[i].status != RTE_FLOW_OP_SUCCESS)
			return -1;
	}
	if (i != POLL_ONCE) {
		return -1;
	}

	memset(res, 0, sizeof(res));
	ret = mlx5dr_send_queue_poll(ctx, 0, res, POLL_ONCE);
	if (ret <= 0)
		return -1;
	for (i = 0; i < NUM_POSTS && res[i].user_data; i++) {
		if (res[i].status != RTE_FLOW_OP_SUCCESS)
			return -1;
	}
	if (i != NUM_POSTS - POLL_ONCE)
		return -1;

	return 0;
}

static int mlx5dr_run_test_post(struct mlx5dr_context *ctx)
{
	int ret;
	int i;

	for (i = 0; i < 50000; i++) {
		ret = __mlx5dr_run_test_post(ctx);
		if (ret)
			return ret;
	}

	return 0;
}

int run_test_post_send(struct ibv_context *ibv_ctx)
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

	mlx5dr_context_close(ctx);

	return ret;

close_ctx:
	mlx5dr_context_close(ctx);
out_err:
	return -1;
}
