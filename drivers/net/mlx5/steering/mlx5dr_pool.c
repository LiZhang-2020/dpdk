/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include <rte_bitmap.h>
#include <rte_malloc.h>
#include "mlx5dr_buddy.h"
#include "mlx5dr_internal.h"

static int mlx5dr_onesize_db_get_chunk(struct mlx5dr_pool *pool,
				       struct mlx5dr_pool_chunk *chunk)
{
	uint64_t slab = 0;
	uint32_t iidx = 0;

	__rte_bitmap_scan_init(pool->db.bitmap);

	if (!rte_bitmap_scan(pool->db.bitmap, &iidx, &slab)) {
		DRV_LOG(ERR, "no more objects in db\n");
		return rte_errno;
	}

	iidx += __builtin_ctzll(slab);

	rte_bitmap_clear(pool->db.bitmap, iidx);

	/* Assume only one array */
	chunk->resource_idx = 0;
	chunk->offset = iidx;

	return 0;
}

static void mlx5dr_onesize_db_put_chunk(struct mlx5dr_pool *pool,
					struct mlx5dr_pool_chunk *chunk)
{
	rte_bitmap_set(pool->db.bitmap, chunk->offset);
}

static void mlx5dr_one_size_db_uninit(struct mlx5dr_pool *pool)
{
	rte_free(pool->db.bitmap);
}

static int mlx5dr_one_size_db_init(struct mlx5dr_pool *pool, uint32_t log_range)
{
	uint32_t bmp_size;
	void *mem;
	int ret = 0;

	bmp_size = rte_bitmap_get_memory_footprint(1 << log_range);
	mem = rte_zmalloc("create_stc_bmap", bmp_size, RTE_CACHE_LINE_SIZE);
	if (!mem) {
		DRV_LOG(ERR, "no mem for bitmap\n");
		return rte_errno;
	}

	pool->db.bitmap = rte_bitmap_init_with_all_set(1 << log_range,
						       mem, bmp_size);
	if (!pool->db.bitmap) {
		DRV_LOG(ERR, "Failed to initialize stc bitmap.");
		ret = rte_errno;
		goto err_mem_alloc;
	}

	pool->p_db_uninit = mlx5dr_one_size_db_uninit;
	pool->p_get_chunk = mlx5dr_onesize_db_get_chunk;
	pool->p_put_chunk = mlx5dr_onesize_db_put_chunk;

	return 0;

err_mem_alloc:
	rte_free(mem);
	return ret;
}

static void mlx5dr_buddy_db_put_chunk(struct mlx5dr_pool *pool,
				      struct mlx5dr_pool_chunk *chunk)
{
	struct mlx5dr_buddy_mem *buddy;

	buddy = pool->db.buddy_manager->buddies[chunk->resource_idx];
	if (!buddy ||
	    chunk->resource_idx > pool->db.buddy_manager->num_of_buddies) {
		assert(false);
		DRV_LOG(ERR, "no shuch buddy (%d)\n", chunk->resource_idx);
		return;
	}

	mlx5dr_buddy_free_mem(buddy, chunk->offset, chunk->order);
}

static int mlx5dr_pool_buddy_get_mem_chunk(struct mlx5dr_pool *pool,
					   int order,
					   uint32_t *buddy_idx,
					   int *seg)
{
	struct mlx5dr_buddy_mem *buddy;
	bool new_mem = false;
	int err = 0;
	int i;

	*seg = -1;

	/* find the next free place from the buddy array */
	while (*seg == -1) {
		for (i = 0; i < MLX5DR_POOL_RESOURCE_ARR_SZ; i++) {
			buddy = pool->db.buddy_manager->buddies[i];
			if (!buddy) {
				 buddy = mlx5dr_buddy_create(pool->alloc_log_sz);
				if (!buddy)
					goto out;
				pool->db.buddy_manager->buddies[i] = buddy;
				pool->db.buddy_manager->num_of_buddies++;
				new_mem = true;
			}
			*seg = mlx5dr_buddy_alloc_mem(buddy, order);
			if (*seg != -1)
				goto found;

			if (new_mem) {
				/* We have new memory pool, should be place for us */
				assert(false);
				DRV_LOG(ERR, "No memory for order: %d with buddy no: %d\n",
					order, i);
				rte_errno = ENOMEM;
				err = ENOMEM;
				goto out;
			}
		}
	}

found:
	*buddy_idx = i;
out:
	return err;
}

static int mlx5dr_buddy_db_get_chunk(struct mlx5dr_pool *pool,
				     struct mlx5dr_pool_chunk *chunk)
{
	int ret = 0;

	/* go over the buddies and find next free slot */
	ret = mlx5dr_pool_buddy_get_mem_chunk(pool, chunk->order,
					      &chunk->resource_idx,
					      &chunk->offset);
	if (ret)
		DRV_LOG(ERR, "failed to get free slot for chunk with order: %d\n",
			chunk->order);

	return ret;
}

static void mlx5dr_buddy_db_uninit(struct mlx5dr_pool *pool)
{
	struct mlx5dr_buddy_mem *buddy;
	int i;

	for (i = 0; i < pool->db.buddy_manager->num_of_buddies; i++) {
		buddy = pool->db.buddy_manager->buddies[i];
		assert(buddy);
		mlx5dr_buddy_cleanup(buddy);
		simple_free(buddy);
	}

	simple_free(pool->db.buddy_manager);
}

static int mlx5dr_buddy_db_init(struct mlx5dr_pool *pool, uint32_t log_range)
{
	pool->db.buddy_manager = simple_calloc(1, sizeof(*pool->db.buddy_manager));
	if (!pool->db.buddy_manager) {
		DRV_LOG(ERR, "no mem for buddy_manager with log_range: %d\n",
			log_range);
		return rte_errno;
	}

	/* init the first buddy object */
	pool->db.buddy_manager->buddies[0] = mlx5dr_buddy_create(log_range);
	if (!pool->db.buddy_manager->buddies[0]) {
		DRV_LOG(ERR, "failed create first buddy log_range: %d\n",
			log_range);
		goto free_buddy_manager;
	}
	pool->db.buddy_manager->num_of_buddies = 1;

	pool->p_db_uninit = mlx5dr_buddy_db_uninit;
	pool->p_get_chunk = mlx5dr_buddy_db_get_chunk;
	pool->p_put_chunk = mlx5dr_buddy_db_put_chunk;

	return 0;

free_buddy_manager:
	simple_free(pool->db.buddy_manager);
	return rte_errno;
}

static int mlx5dr_pool_db_init(struct mlx5dr_pool *pool,
			       enum mlx5dr_db_type db_type)
{
	int ret;
	if (db_type == MLX5DR_DB_TYPE_ONE_SIZE) {
		ret = mlx5dr_one_size_db_init(pool, pool->alloc_log_sz);
		if (ret) {
			DRV_LOG(ERR, "failed to init db (ret: %d)\n", ret);
			return ret;
		}
	} else {
		ret = mlx5dr_buddy_db_init(pool, pool->alloc_log_sz);
		if (ret) {
			DRV_LOG(ERR, "failed to init buddy db (ret: %d)\n", ret);
			return ret;
		}
	}

	return 0;
}

static void mlx5dr_pool_db_unint(struct mlx5dr_pool *pool)
{
	pool->p_db_uninit(pool);
}

int
mlx5dr_pool_chunk_alloc(struct mlx5dr_pool *pool,
			struct mlx5dr_pool_chunk *chunk)
{
	int ret;

	pthread_spin_lock(&pool->lock);
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
	int ret = 0;

	if (resource->devx_obj)
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
	case MLX5DR_POOL_TYPE_NONE:
		return resource;
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
	enum mlx5dr_db_type res_db_type;
	struct mlx5dr_pool *pool;

	pool = simple_calloc(1, sizeof(*pool));
	if (!pool)
		return NULL;

	pool->ctx = ctx;
	pool->type = pool_attr->pool_type; // STC / STE
	pool->alloc_log_sz = pool_attr->alloc_log_sz;

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
	case MLX5DR_TABLE_TYPE_MAX:
		printf("%s create pool for Test only !!\n", __func__);
		pool->fw_ft_type = MLX5DR_POOL_TYPE_NONE;
		break;
	default:
		DRV_LOG(ERR, "Unsupported memory pool type\n");
		rte_errno = ENOTSUP;
		goto free_pool;
	}

	if (pool_attr->single_resource)
		res_db_type = MLX5DR_DB_TYPE_ONE_SIZE;
	else
		res_db_type = MLX5DR_DB_TYPE_BUDDY;

	pool->alloc_log_sz = pool_attr->alloc_log_sz;

	/* the first resource that allocated use this tracking db */
	if (mlx5dr_pool_db_init(pool, res_db_type))
		goto free_pool;

	if (pool_attr->alloc_log_sz) {
		pool->resource[0] =
			mlx5dr_pool_resource_alloc(pool, pool_attr->alloc_log_sz);
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
