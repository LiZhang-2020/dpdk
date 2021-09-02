/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_MATCHER_H_
#define MLX5DR_MATCHER_H_

/* Max supported match template */
#define MLX5DR_MATCHER_MAX_MT 2
#define MLX5DR_MATCHER_MAX_MT_ROOT 1

struct mlx5dr_match_template {
	struct rte_flow_item *items;
	struct mlx5dr_definer *definer;
	struct mlx5dr_definer_fc *fc;
	uint32_t fc_sz;
	uint32_t refcount;
};

struct mlx5dr_matcher_nic {
	struct mlx5dr_devx_obj *rtc;
	struct mlx5dr_pool_chunk ste;
};

struct mlx5dr_matcher {
	struct mlx5dr_table *tbl;
	struct mlx5dr_matcher_attr attr;
	struct mlx5dv_flow_matcher *dv_matcher;
	struct mlx5dr_match_template *mt[MLX5DR_MATCHER_MAX_MT];
	uint8_t num_of_mt;
	struct mlx5dr_devx_obj *end_ft;
	struct mlx5dr_matcher_nic rx;
	struct mlx5dr_matcher_nic tx;
	LIST_ENTRY(mlx5dr_matcher) next;
};

int mlx5dr_matcher_conv_items_to_prm(uint64_t *match_buf,
				     struct rte_flow_item *items,
				     uint8_t *match_criteria,
				     bool is_value);

#endif
