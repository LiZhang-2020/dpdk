/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_TABLE_H_
#define MLX5DR_TABLE_H_

#define MLX5DR_ROOT_LEVEL 0

struct mlx5dr_table {
	struct mlx5dr_context *ctx;
	struct mlx5dr_devx_obj *ft;
	enum mlx5dr_table_type type;
	uint32_t fw_ft_type;
	uint32_t level;
	LIST_HEAD(matcher_head, mlx5dr_matcher) head;
	LIST_ENTRY(mlx5dr_table) next;
};

static inline
uint32_t mlx5dr_table_get_res_fw_ft_type(struct mlx5dr_table *tbl,
					 uint8_t id)
{
	if (tbl->type == MLX5DR_TABLE_TYPE_NIC_RX ||
	    tbl->type == MLX5DR_TABLE_TYPE_NIC_TX)
		return tbl->fw_ft_type;

	if (tbl->type == MLX5DR_TABLE_TYPE_FDB)
		return id ? FS_FT_FDB_TX : FS_FT_FDB_RX;

	assert(0);
	return 0;
}

static inline bool mlx5dr_table_is_root(struct mlx5dr_table *tbl)
{
	return (tbl->level == MLX5DR_ROOT_LEVEL);
}

#endif
