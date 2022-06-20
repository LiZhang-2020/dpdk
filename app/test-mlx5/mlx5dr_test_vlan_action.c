/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 NVIDIA CORPORATION. All rights reserved.
 */

#include <time.h>
#include "mlx5dr_test.h"

static int mlx5d_run_test_pop_vlan_action(struct mlx5dr_context *ctx)
{
	struct mlx5dr_action *action1;
	uint32_t flags;

	flags = MLX5DR_ACTION_FLAG_HWS_RX;

	action1 = mlx5dr_action_create_pop_vlan(ctx, flags);
	if (!action1) {
		printf("failed to create action pop_vlan / RX, flags: 0x%x\n", flags);
		return -1;
	}

	mlx5dr_action_destroy(action1);

	flags = MLX5DR_ACTION_FLAG_HWS_TX;

	action1 = mlx5dr_action_create_pop_vlan(ctx, flags);
	if (!action1) {
		printf("failed to create action pop_vlan / TX , flags: 0x%x\n", flags);
		return -1;
	}

	mlx5dr_action_destroy(action1);

	return 0;
}

static int mlx5d_run_test_push_vlan_action(struct mlx5dr_context *ctx)
{
	struct mlx5dr_action *action1;
	uint32_t flags;

	flags = MLX5DR_ACTION_FLAG_HWS_RX;

	action1 = mlx5dr_action_create_push_vlan(ctx, flags);
	if (!action1) {
		printf("failed to create action push_vlan, flags: 0x%x\n", flags);
		return -1;
	}

	mlx5dr_action_destroy(action1);

	return 0;
}

int run_test_vlan_action(struct ibv_context *ibv_ctx)
{
	struct mlx5dr_context *ctx;
	struct mlx5dr_context_attr dr_ctx_attr = {0};
	int ret;

	dr_ctx_attr.initial_log_ste_memory = 0;
	dr_ctx_attr.pd = NULL;
	dr_ctx_attr.queues = 16;
	dr_ctx_attr.queue_size = 128;

	ctx = mlx5dr_context_open(ibv_ctx, &dr_ctx_attr);
	if (!ctx) {
		printf("Failed to create context\n");
		return -1;
	}

	ret = mlx5d_run_test_pop_vlan_action(ctx);
	if (ret) {
		printf("Failed to run pop_vlan_action test\n");
		return -1;
	}

	ret = mlx5d_run_test_push_vlan_action(ctx);
	if (ret) {
		printf("Failed to run push_vlan_action test\n");
		return -1;
	}

	mlx5dr_context_close(ctx);

	return ret;
}
