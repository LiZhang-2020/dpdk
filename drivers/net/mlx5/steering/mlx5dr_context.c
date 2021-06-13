/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_internal.h"

static int mlx5dr_context_uninit_pd(struct mlx5dr_context *ctx)
{
	if (ctx->flags & MLX5DR_CONTEXT_FLAG_PRIVATE_PD)
		return mlx5_glue->dealloc_pd(ctx->pd);

	return 0;
}

static int mlx5dr_context_init_pd(struct mlx5dr_context *ctx,
				  struct ibv_pd *pd)
{
	struct mlx5dv_pd mlx5_pd = {};
	struct mlx5dv_obj obj;
	int ret;

	if (pd) {
		ctx->pd = pd;
	} else {
		ctx->pd = mlx5_glue->alloc_pd(ctx->ibv_ctx);
		if (!ctx->pd) {
			DRV_LOG(ERR, "Failed to allocate PD\n");
			return errno;
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

static int mlx5dr_context_hws_supp(struct mlx5dr_context *ctx)
{
	struct mlx5_hca_attr attr = {};
	int ret;

	ret = mlx5_devx_cmd_query_hca_attr(ctx->ibv_ctx, &attr);
	if (ret) {
		DRV_LOG(ERR, "Failed to query hca attributes\n");
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

	ctx = simple_malloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->ibv_ctx = ibv_ctx;

	ret = mlx5dr_context_init_pd(ctx, attr->pd);
	if (ret)
		goto free_ctx;

	// Check HW steering is supported
	ret = mlx5dr_context_hws_supp(ctx);
	if (ret)
		goto uninit_pd;

	// Init memory pools

	// Reserve STE memory

	// Allocate send rings

	return ctx;

uninit_pd:
	mlx5dr_context_uninit_pd(ctx);
free_ctx:
	simple_free(ctx);
	return NULL;
}

int mlx5dr_context_close(struct mlx5dr_context *ctx)
{
	// Deallocate send rings

	// Release STE memory

	mlx5dr_context_uninit_pd(ctx);
	simple_free(ctx);
	return 0;
}
