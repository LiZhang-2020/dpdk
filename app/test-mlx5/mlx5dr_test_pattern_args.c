/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include <time.h>
#include "mlx5dr_test.h"

static int mlx5d_run_test_modify_header_action(struct mlx5dr_context *ctx)
{
	struct mlx5dr_action *action1;
	struct mlx5dr_action *action2;
	size_t action_sz;
	__be64 modify_action_data[256];
	uint32_t bulk_size;
	uint32_t flags;
	uint8_t *action_ptr;

	action_ptr = (uint8_t *) modify_action_data;
	MLX5_SET(add_action_in, action_ptr, action_type, MLX5_MODIFICATION_TYPE_ADD);
	MLX5_SET(add_action_in, action_ptr, field, 0xa /*MLX5_ACTION_IN_FIELD_OUT_IP_TTL*/);
	MLX5_SET(add_action_in, action_ptr, data, 7);

	action_ptr += 8;

	MLX5_SET(set_action_in, action_ptr, action_type, MLX5_MODIFICATION_TYPE_SET);
	MLX5_SET(set_action_in, action_ptr, field, 91 /*MLX5_MODI_OUT_TCP_ACK_NUM*/);
	MLX5_SET(set_action_in, action_ptr, offset, 30);
	MLX5_SET(set_action_in, action_ptr, length, 1);
	MLX5_SET(set_action_in, action_ptr, data, 5);

	action_sz = 16;
	bulk_size = 10;
	flags = MLX5DR_ACTION_FLAG_HWS_RX;

	action1 = mlx5dr_action_create_modify_header(ctx, action_sz, modify_action_data, bulk_size, flags);
	if (!action1) {
		printf("failed to create action: action_sz: %zu bulk_size: %d, flags: 0x%x\n",
		       action_sz, bulk_size, flags);
		return -1;
	}

	/* create second action with the same params, should be cached */
	action2 = mlx5dr_action_create_modify_header(ctx, action_sz, modify_action_data, bulk_size, flags);
	if (!action2) {
		printf("failed to create action: action_sz: %zu bulk_size: %d, flags: 0x%x\n",
		       action_sz, bulk_size, flags);
		goto clean_action_1;
	}

	if (action1->modify_header.pattern_obj->id != action2->modify_header.pattern_obj->id) {
		printf("failed to use cache for action !!\n");
		goto clean_actions;
	}

	mlx5dr_action_destroy(action2);
	flags |=MLX5DR_ACTION_FLAG_INLINE;
	action2 = mlx5dr_action_create_modify_header(ctx, action_sz, modify_action_data, bulk_size, flags);
	if (!action2) {
		printf("failed to create action: action_sz: %zu bulk_size: %d, flags: 0x%x\n",
		       action_sz, bulk_size, flags);
		goto clean_action_1;
	}
	/* check that inline uses different pattern */
	mlx5dr_action_destroy(action1);
	return 0;

clean_actions:
	mlx5dr_action_destroy(action2);
clean_action_1:
	mlx5dr_action_destroy(action1);
	return -1;
}

int run_test_modify_header_action(struct ibv_context *ibv_ctx)
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
		printf("Failed to create context\n");
		return -1;
	}

	ret = mlx5d_run_test_modify_header_action(ctx);
	if (ret)
		printf("Failed to run modify_header_action test\n");

	mlx5dr_context_close(ctx);

	return ret;
}
