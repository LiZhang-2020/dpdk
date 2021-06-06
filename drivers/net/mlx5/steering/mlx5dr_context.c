/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_internal.h"

struct mlx5dr_context *mlx5dr_context_open(struct ibv_context *ibv_ctx,
					   struct mlx5dr_context_attr *attr)
{
	struct mlx5dr_context *ctx;

	ctx = simple_malloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	// Query caps

	if (attr->pd) {
		ctx->pd = attr->pd;
	} else {
		ctx->pd = mlx5_glue->alloc_pd(ibv_ctx);
		if (ctx->pd) {
			DRV_LOG(ERR, "Failed to allocate PD\n");
			goto free_ctx;
		}
	}

	// Check HW steering is supported

	// Reserve STE memory

	// Allocate send rings

	return ctx;

free_ctx:
	simple_free(ctx);
	return NULL;
}

int mlx5dr_context_close(struct mlx5dr_context *ctx)
{
	// Deallocate send rings

	// Release STE memory

	simple_free(ctx);
	return 0;
}
