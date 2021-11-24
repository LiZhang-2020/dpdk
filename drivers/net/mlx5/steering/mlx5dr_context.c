/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_internal.h"

static int mlx5dr_context_pools_init(struct mlx5dr_context *ctx,
				     size_t log_ste_memory)
{
	struct mlx5dr_pool_attr pool_attr = {0};
	int i;

	if (mlx5dr_pat_init_pattern_cache(ctx->pattern_cache))
		return rte_errno;

	/* Create an STC pool per FT type */
	pool_attr.single_resource = 1;
	pool_attr.pool_type = MLX5DR_POOL_TYPE_STC;
	pool_attr.alloc_log_sz = MLX5DR_POOL_STC_LOG_SZ;
	pool_attr.inital_log_sz = 0;

	for (i = 0; i < MLX5DR_TABLE_TYPE_MAX; i++) {
		pool_attr.table_type = i;
		ctx->stc_pool[i] = mlx5dr_pool_create(ctx, &pool_attr);
		if (!ctx->stc_pool[i]) {
			DRV_LOG(ERR, "Failed to allocate STC pool [%d]" ,i);
			goto free_stc_pools;
		}
	}

	/* Create an STE pool per FT type */
	pool_attr.single_resource = 0;
	pool_attr.pool_type = MLX5DR_POOL_TYPE_STE;
	pool_attr.alloc_log_sz = MLX5DR_POOL_STE_LOG_SZ;
	pool_attr.inital_log_sz = log_ste_memory;

	for (i = 0; i < MLX5DR_TABLE_TYPE_MAX; i++) {
		pool_attr.table_type = i;
		ctx->ste_pool[i] = mlx5dr_pool_create(ctx, &pool_attr);
		if (!ctx->ste_pool[i]) {
			DRV_LOG(ERR, "Failed to allocate STE pool [%d]" ,i);
			goto free_ste_pools;
		}
	}

	return 0;

free_ste_pools:
	for (i = 0; i < MLX5DR_TABLE_TYPE_MAX; i++)
		if (ctx->ste_pool[i])
			mlx5dr_pool_destroy(ctx->ste_pool[i]);
free_stc_pools:
	for (i = 0; i < MLX5DR_TABLE_TYPE_MAX; i++)
		if (ctx->stc_pool[i])
			mlx5dr_pool_destroy(ctx->stc_pool[i]);

	mlx5dr_pat_uninit_pattern_cache(ctx->pattern_cache);

	return rte_errno;
}

static void mlx5dr_context_pools_uninit(struct mlx5dr_context *ctx)
{
	int i;

	for (i = 0; i < MLX5DR_TABLE_TYPE_MAX; i++) {
		if (ctx->ste_pool[i])
			mlx5dr_pool_destroy(ctx->ste_pool[i]);

		if (ctx->stc_pool[i])
			mlx5dr_pool_destroy(ctx->stc_pool[i]);
	}

	mlx5dr_pat_uninit_pattern_cache(ctx->pattern_cache);
}

static int mlx5dr_context_init_pd(struct mlx5dr_context *ctx,
				  struct ibv_pd *pd)
{
	struct mlx5dv_pd mlx5_pd = {0};
	struct mlx5dv_obj obj;
	int ret;

	if (pd) {
		ctx->pd = pd;
	} else {
		ctx->pd = mlx5_glue->alloc_pd(ctx->ibv_ctx);
		if (!ctx->pd) {
			DRV_LOG(ERR, "Failed to allocate PD");
			rte_errno = errno;
			return rte_errno;
		}
		ctx->flags |= MLX5DR_CONTEXT_FLAG_PRIVATE_PD;
	}

	obj.pd.in = ctx->pd;
	obj.pd.out = &mlx5_pd;

	ret = mlx5_glue->dv_init_obj(&obj, MLX5DV_OBJ_PD);
	if (ret)
		goto free_private_pd;

	ctx->pd_num = mlx5_pd.pdn;

	return 0;

free_private_pd:
	if (ctx->flags & MLX5DR_CONTEXT_FLAG_PRIVATE_PD)
		mlx5_glue->dealloc_pd(ctx->pd);

	return ret;
}

static int mlx5dr_context_uninit_pd(struct mlx5dr_context *ctx)
{
	if (ctx->flags & MLX5DR_CONTEXT_FLAG_PRIVATE_PD)
		return mlx5_glue->dealloc_pd(ctx->pd);

	return 0;
}

static int mlx5dr_context_hws_supp(struct mlx5dr_context *ctx)
{
	struct mlx5_hca_attr attr = {0};
	int ret;

	ret = mlx5_devx_cmd_query_hca_attr(ctx->ibv_ctx, &attr);
	if (ret) {
		DRV_LOG(ERR, "Failed to query hca attributes");
		return ret;
	}

	// TODO check supp general obj RTC
	// TODO check supp general obj STC
	// TODO check supp general obj STE-ID
	// TODO check wqe_based_flow_update

	ctx->flags |= MLX5DR_CONTEXT_FLAG_HWS_SUPPORT;

	return ret;
}

struct mlx5dr_context *mlx5dr_context_open(struct ibv_context *ibv_ctx,
					   struct mlx5dr_context_attr *attr)
{
	struct mlx5dr_context *ctx;
	int ret;

	ctx = simple_calloc(1, sizeof(*ctx));
	if (!ctx) {
		rte_errno = ENOMEM;
		return NULL;
	}

	ctx->ibv_ctx = ibv_ctx;
	pthread_spin_init(&ctx->ctrl_lock, PTHREAD_PROCESS_PRIVATE);

	ctx->caps = simple_calloc(1, sizeof(*ctx->caps));
	if (!ctx->caps)
		goto free_ctx;

	ret = mlx5dr_cmd_query_caps(ibv_ctx, ctx->caps);
	if (ret)
		goto free_caps;

	ret = mlx5dr_context_init_pd(ctx, attr->pd);
	if (ret)
		goto free_caps;

	/* Check HW steering is supported */
	ret = mlx5dr_context_hws_supp(ctx);
	if (ret)
		goto uninit_pd;

	/* Initialise memory pools */
	ret = mlx5dr_context_pools_init(ctx, attr->initial_log_ste_memory);
	if (ret)
		goto uninit_pd;

	ret = mlx5dr_send_queues_open(ctx, attr->queues, attr->queue_size);
	if (ret)
		goto pools_uninit;

	return ctx;

pools_uninit:
	mlx5dr_context_pools_uninit(ctx);
uninit_pd:
	mlx5dr_context_uninit_pd(ctx);
free_caps:
	simple_free(ctx->caps);
free_ctx:
	simple_free(ctx);
	return NULL;
}

int mlx5dr_context_close(struct mlx5dr_context *ctx)
{
	mlx5dr_send_queues_close(ctx);
	mlx5dr_context_pools_uninit(ctx);
	pthread_spin_destroy(&ctx->ctrl_lock);
	mlx5dr_context_uninit_pd(ctx);
	simple_free(ctx->caps);
	simple_free(ctx);
	return 0;
}
