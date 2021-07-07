/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include <rte_bitmap.h>
#include <rte_malloc.h>
#include "mlx5dr_internal.h"

static int mlx5dr_onesize_db_get_chunk(struct mlx5dr_pool *pool,
				       struct mlx5dr_pool_chunk *chunk)
{
	uint64_t slab = 0;
	uint32_t iidx = 0;

	if (!rte_bitmap_scan(pool->db.bitmap, &iidx, &slab))
		return -1;

	iidx += __builtin_ctzll(slab);

	rte_bitmap_clear(pool->db.bitmap, iidx);

	// Assume only one array:
	chunk->resource_idx = 0;//TBD, support more than one array
	chunk->offset = iidx; //pool->resource[0][iidx].devx_obj->id;
	//chunk->mem_arr_idx = 0;

	return 0;
}

static void mlx5dr_onesize_db_put_chunk(struct mlx5dr_pool *pool,
					struct mlx5dr_pool_chunk *chunk)
{
	rte_bitmap_clear(pool->db.bitmap, chunk->resource_idx);
}

static int mlx5dr_one_size_db_init(struct mlx5dr_pool *pool, uint32_t log_range)
{
	uint32_t bmp_size;
	void *mem;
	int ret = 0;

	bmp_size = rte_bitmap_get_memory_footprint(1 << log_range);
	mem = rte_zmalloc("create_stc_bmap", bmp_size, RTE_CACHE_LINE_SIZE);
	if (!mem) {
		printf("no mem for bitmap\n");
		return -1 /*rte_errno*/; //TBD
	}

	pool->db.bitmap = rte_bitmap_init_with_all_set(1 << log_range,
						       mem, bmp_size);
	if (!pool->db.bitmap) {
		printf("Failed to initialize stc bitmap.");
		ret = -rte_errno;
		goto err_mem_alloc;
	}
	pool->p_get_chunk = mlx5dr_onesize_db_get_chunk;
	pool->p_put_chunk = mlx5dr_onesize_db_put_chunk;

	return 0;

err_mem_alloc:
	rte_free(mem);
	return ret;
}

static int mlx5dr_pool_db_init(struct mlx5dr_pool *pool, uint32_t log_range,
			       enum mlx5dr_db_type db_type)
{
	int ret;

	if (db_type == MLX5DR_DB_TYPE_ONE_SIZE) {
		ret = mlx5dr_one_size_db_init(pool, log_range);
		if (ret) {
			printf("%s failed to init db (ret: %d)\n", __func__, ret);
			return ret;
		}
	}
	return 0;
}

static void mlx5dr_pool_db_unint(struct mlx5dr_pool *pool)
{
	if (pool->db.type == MLX5DR_DB_TYPE_ONE_SIZE)
		rte_free(pool->db.bitmap);
}

int
mlx5dr_pool_chunk_alloc(struct mlx5dr_pool *pool,
			struct mlx5dr_pool_chunk *chunk)
{
	int ret;

	pthread_spin_lock(&pool->lock);

	// STC, ACTION_STE -> fixed 1, quick, low memory overhead
	// STE_FOR_RTC -> by table size, slow
	// VALEX: Erez please do
	ret = pool->p_get_chunk(pool, chunk);
	pthread_spin_unlock(&pool->lock);

	return ret;
}

void mlx5dr_pool_chunk_free(struct mlx5dr_pool *pool,
			    struct mlx5dr_pool_chunk *chunk)
{
	pthread_spin_lock(&pool->lock);
	pool->p_put_chunk(pool, chunk);
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
	enum mlx5dr_db_type res_db_type = MLX5DR_DB_TYPE_ONE_SIZE; //now support db one size
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

	res_db_type = MLX5DR_DB_TYPE_ONE_SIZE;

	/* the first resource that allocated use this tracking db */
	if (mlx5dr_pool_db_init(pool, pool_attr->alloc_log_sz, res_db_type))
		goto free_pool;

	if (pool_attr->alloc_log_sz/*inital_log_sz*/) {
		pool->resource[0] = mlx5dr_pool_resource_alloc(pool, pool_attr->alloc_log_sz);
		if (!pool->resource[0])
			goto free_db;
	}

	return pool;

free_db:
	mlx5dr_pool_db_unint(pool);
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

	mlx5dr_pool_db_unint(pool);

	pthread_spin_destroy(&pool->lock);
	simple_free(pool);
	return 0;
}
