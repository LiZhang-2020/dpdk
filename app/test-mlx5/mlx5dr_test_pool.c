/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include <time.h>
#include "mlx5dr_test.h"

static int mlx5d_run_test_pool_operations(struct mlx5dr_context *ctx)
{
	struct mlx5dr_pool_attr pool_attr = {0};
	struct mlx5dr_pool *stc_pool;
	struct mlx5dr_pool *ste_pool;
	struct mlx5dr_pool_chunk stc_chunk = {0};
	struct mlx5dr_pool_chunk ste_chunk[100];
	int ret, i;

	/* Create an STC pool per FT type */
	pool_attr.single_resource = 1;
	pool_attr.pool_type = MLX5DR_POOL_TYPE_STC;
	pool_attr.alloc_log_sz = MLX5DR_POOL_STC_LOG_SZ;
	pool_attr.inital_log_sz = 0;

	pool_attr.table_type = 0;
	stc_pool = mlx5dr_pool_create(ctx, &pool_attr);
	if (!stc_pool) {
		printf("Failed to allocate STC pool");
		goto out_err;
	}

	/* alloc chunks from it */
	ret = mlx5dr_pool_chunk_alloc(stc_pool, &stc_chunk);
	if (ret) {
		printf("Failed to allocate single action STC");
		goto out_free_stc_pool;
	}

	mlx5dr_pool_chunk_free(stc_pool, &stc_chunk);


	/* Create an STE pool per FT type */
	pool_attr.single_resource = 0;
	pool_attr.pool_type = MLX5DR_POOL_TYPE_STE;
	pool_attr.alloc_log_sz = MLX5DR_POOL_STE_MIN_LOG_SZ;
	pool_attr.inital_log_sz = MLX5DR_POOL_STE_MIN_LOG_SZ;

	ste_pool = mlx5dr_pool_create(ctx, &pool_attr);
	if (!ste_pool) {
			printf("Failed to allocate STE pool");
			goto out_free_stc_pool;
	}

	/* alloc chunks from it */
	for (i = 0; i < 30; i ++) {
		ste_chunk[i].order = 20;
		ret = mlx5dr_pool_chunk_alloc(ste_pool, &ste_chunk[i]);
		if (ret) {
			printf("Failed to allocate single action STE, index: %d", i);
			goto out_free_ste_pool;
		}
	}

	for (i = 0; i < 30; i ++)
		mlx5dr_pool_chunk_free(ste_pool, &ste_chunk[i]);

	mlx5dr_pool_destroy(ste_pool);
	mlx5dr_pool_destroy(stc_pool);

	return 0;

out_free_ste_pool:
	mlx5dr_pool_destroy(ste_pool);
out_free_stc_pool:
	mlx5dr_pool_destroy(stc_pool);
out_err:
	return -1;
}

int run_test_pool(struct ibv_context *ibv_ctx)
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

	ret = mlx5d_run_test_pool_operations(ctx);
	if (ret)
		printf("Failed to run mlx5d_run_test_pool_operations test\n");

	mlx5dr_context_close(ctx);

	return ret;
}
