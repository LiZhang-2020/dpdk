/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_TABLE_H_
#define MLX5DR_TABLE_H_

#define MLX5DR_ROOT_LEVEL 0
#define MLX5DR_DEFAULT_LEVEL 0xdc

struct mlx5dr_table_nic {
	struct mlx5dr_pool_chunk stc;
};

struct mlx5dr_table {
	struct mlx5dr_context *ctx;
	struct mlx5dr_devx_obj *ft;
	enum mlx5dr_table_type type;
	uint32_t fw_ft_type;
	uint32_t level;
	struct mlx5dr_table_nic rx;
	struct mlx5dr_table_nic tx;
	LIST_HEAD(matcher_head, mlx5dr_matcher) head;
};

static inline bool mlx5dr_table_is_root(struct mlx5dr_table *tbl)
{
	return (tbl->level == MLX5DR_ROOT_LEVEL);
}

#endif
