/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_internal.h"

// TODO VALEX: this a BAD temporary implementation

int
mlx5dr_pool_chunk_alloc(struct mlx5dr_pool *pool,
			struct mlx5dr_pool_chunk *chunk)
{
	int ret = 0;

	pthread_spin_lock(&pool->lock);

	// STC, ACTION_STE -> fixed 1, quick, low memory overhead
	// STE_FOR_RTC -> by table size, slow
	// VALEX: Erez please do
	chunk.id = 5;

	pthread_spin_unlock(&pool->lock);

	return 0;
}

void mlx5dr_pool_chunk_free(struct mlx5dr_pool *pool,
			    struct mlx5dr_pool_chunk *chunk)
{
	pthread_spin_lock(&pool->lock);

	chunk->id = 0; // TODO just for compilation

	pthread_spin_unlock(&pool->lock);
}

static int mlx5dr_pool_resource_free(struct mlx5dr_pool_resource *resource)
{
	int ret;

	ret = mlx5dr_cmd_destroy_obj(resource->devx_obj);
	simple_free(resource);

	return ret;
}

static struct mlx5dr_pool_resource *
mlx5dr_pool_resource_alloc(struct mlx5dr_pool *pool, uint32_t log_range)
{
	struct mlx5dr_cmd_ste_create_attr ste_attr;
	struct mlx5dr_cmd_stc_create_attr stc_attr;
	struct mlx5dr_pool_resource *resource;
	struct mlx5dr_devx_obj *devx_obj;

	resource = simple_malloc(sizeof(*resource));
	if (!resource) {
		rte_errno = ENOMEM;
		return NULL;
	}

	switch (pool->type) {
	case MLX5DR_POOL_TYPE_STE:

		ste_attr.log_obj_range = log_range;
		ste_attr.table_type = pool->fw_ft_type;
		devx_obj = mlx5dr_cmd_ste_create(pool->ctx->ibv_ctx, &ste_attr);
		break;
	case MLX5DR_POOL_TYPE_STC:
		stc_attr.log_obj_range = log_range;
		stc_attr.table_type = pool->fw_ft_type;
		devx_obj = mlx5dr_cmd_stc_create(pool->ctx->ibv_ctx, &stc_attr);
		break;
	default:
		assert(0);
		break;
	}

	if (!devx_obj) {
		DRV_LOG(ERR, "Failed to allocate resource objects\n");
		goto free_resource;
	}

	resource->pool = pool;
	resource->devx_obj = devx_obj;
	resource->range = 1 << log_range;
	resource->base_id = devx_obj->id;

	return resource;

free_resource:
	simple_free(resource);
	return NULL;
}

struct mlx5dr_pool *
mlx5dr_pool_create(struct mlx5dr_context *ctx, struct mlx5dr_pool_attr *pool_attr)
{
	struct mlx5dr_pool *pool;

	pool = simple_calloc(sizeof(*pool));
	if (!pool)
		return NULL;

	pool->ctx = ctx;
	pool->type = pool_attr->pool_type;
	pool->alloc_log_sz = pool_attr->alloc_log_sz;
	pool->single_resource = pool_attr->single_resource;
	pthread_spin_init(&pool->lock, PTHREAD_PROCESS_PRIVATE);

	switch (pool_attr->table_type) {
	case MLX5DR_TABLE_TYPE_NIC_RX:
		pool->fw_ft_type = FS_FT_NIC_RX;
		break;
	case MLX5DR_TABLE_TYPE_NIC_TX:
		pool->fw_ft_type = FS_FT_NIC_TX;
		break;
	case MLX5DR_TABLE_TYPE_FDB:
		pool->fw_ft_type = FS_FT_FDB;
		break;
	default:
		DRV_LOG(ERR, "Unsupported memory pool type\n");
		errno = ENOTSUP;
		goto free_pool;
	}

	if (pool_attr->inital_log_sz) {
		pool->resource[0] = mlx5dr_pool_resource_alloc(pool, pool_attr->inital_log_sz);
		if (!pool->resource[0])
			goto free_pool;
	}

	return pool;

free_pool:
	pthread_spin_destroy(&pool->lock);
	simple_free(pool);
	return NULL;
}

int mlx5dr_pool_destroy(struct mlx5dr_pool *pool)
{
	int i;

	for (i = 0; i <= MLX5DR_POOL_RESOURCE_ARR_SZ; i++)
		if (pool->resource[i])
			mlx5dr_pool_resource_free(pool->resource[i]);

	pthread_spin_destroy(&pool->lock);
	simple_free(pool);
	return 0;
}
