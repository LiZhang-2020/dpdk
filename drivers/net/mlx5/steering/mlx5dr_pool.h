/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_POOL_H_
#define MLX5DR_POOL_H_

enum mlx5dr_pool_type {
	MLX5DR_POOL_TYPE_STE,
	MLX5DR_POOL_TYPE_STC,
};

#define MLX5DR_POOL_STC_LOG_SZ 14
#define MLX5DR_POOL_STE_LOG_SZ 25

#define MLX5DR_POOL_RESOURCE_ARR_SZ 100

struct mlx5dr_pool_chunk {
	uint32_t resource_idx;
	/* Internal offset, relative to base index */
	int      offset;
	int      order;
};

struct mlx5dr_pool_resource {
	struct mlx5dr_pool *pool;
	struct mlx5dr_devx_obj *devx_obj;
	uint32_t base_id;
	uint32_t range;
};

struct mlx5dr_pool_attr {
	enum mlx5dr_pool_type pool_type;
	enum mlx5dr_table_type table_type;
	/* Initial resource allocation */
	size_t inital_log_sz;
	/* Allocation size once memory is depleted */
	size_t alloc_log_sz;
	/* Only a single resource allocation is allowed */
	bool single_resource;
};

enum mlx5dr_db_type {
	MLX5DR_DB_TYPE_ONE_SIZE,
	MLX5DR_DB_TYPE_BUDDY,
};

struct mlx5dr_buddy_manager {
	uint16_t num_of_buddies;
	struct mlx5dr_buddy_mem *buddies[MLX5DR_POOL_RESOURCE_ARR_SZ];
};

struct mlx5dr_pool_db {
	enum mlx5dr_db_type type;
	union {
		struct rte_bitmap	*bitmap; /*for one size elements db*/
		struct mlx5dr_buddy_manager *buddy_manager;
	};
};

typedef int (*mlx5dr_pool_db_get_chunk)(struct mlx5dr_pool *pool,
					struct mlx5dr_pool_chunk *chunk);
typedef void (*mlx5dr_pool_db_put_chunk)(struct mlx5dr_pool *pool,
					 struct mlx5dr_pool_chunk *chunk);
typedef void (*mlx5dr_pool_unint_db)(struct mlx5dr_pool *pool);

struct mlx5dr_pool {
	struct mlx5dr_context *ctx;
	enum mlx5dr_pool_type type;
	pthread_spinlock_t lock;
	size_t alloc_log_sz;
	uint32_t fw_ft_type;
	struct mlx5dr_pool_resource *resource[MLX5DR_POOL_RESOURCE_ARR_SZ];
	/* db */
	struct mlx5dr_pool_db db;
	/* functions */
	mlx5dr_pool_unint_db p_db_uninit;
	mlx5dr_pool_db_get_chunk p_get_chunk;
	mlx5dr_pool_db_put_chunk p_put_chunk;
};

struct mlx5dr_pool *
mlx5dr_pool_create(struct mlx5dr_context *ctx,
		   struct mlx5dr_pool_attr *pool_attr);

int mlx5dr_pool_destroy(struct mlx5dr_pool *pool);

int mlx5dr_pool_chunk_alloc(struct mlx5dr_pool *pool,
			    struct mlx5dr_pool_chunk *chunk);

void mlx5dr_pool_chunk_free(struct mlx5dr_pool *pool,
			    struct mlx5dr_pool_chunk *chunk);

static inline struct mlx5dr_devx_obj *
mlx5dr_pool_chunk_get_base_devx_obj(struct mlx5dr_pool *pool,
				    struct mlx5dr_pool_chunk *chunk)
{
	return pool->resource[chunk->resource_idx]->devx_obj;
}
#endif
