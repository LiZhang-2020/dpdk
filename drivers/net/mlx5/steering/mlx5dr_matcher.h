/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_MATCHER_H_
#define MLX5DR_MATCHER_H_

/* Max supported match template */
#define MLX5DR_MATCHER_MAX_MT 2
#define MLX5DR_MATCHER_MAX_MT_ROOT 1

/* We calculated that concatenating a collision table to the main table with
 * 3% of the main table rows will be enough resources for high insertion
 * success probability.
 *
 * The calculation: log2( 2^x * 3 / 100) = log(2^x) + log(3/100) = x - 5.05 ~ 5
 */
#define MLX5DR_MATCHER_ASSURED_ROW_RATIO 5
/* Thrashold to determine if amount of rules require a collision table */
#define MLX5DR_MATCHER_ASSURED_RULES_TH 10
/* Required depth of an assured collision table */
#define MLX5DR_MATCHER_ASSURED_COL_TBL_DEPTH 4
/* Required depth of the main large table */
#define MLX5DR_MATCHER_ASSURED_MAIN_TBL_DEPTH 2

struct mlx5dr_match_template {
	struct rte_flow_item *items;
	struct mlx5dr_definer *definer;
	struct mlx5dr_definer_fc *fc;
	uint32_t fc_sz;
	enum mlx5dr_match_template_flags flags;
	uint32_t refcount;
};

struct mlx5dr_matcher {
	struct mlx5dr_table *tbl;
	struct mlx5dr_matcher_attr attr;
	struct mlx5dv_flow_matcher *dv_matcher;
	struct mlx5dr_match_template *mt[MLX5DR_MATCHER_MAX_MT];
	uint8_t num_of_mt;
	struct mlx5dr_devx_obj *end_ft;
	struct mlx5dr_devx_obj *rtc_0;
	struct mlx5dr_devx_obj *rtc_1;
	struct mlx5dr_pool_chunk ste;
	struct mlx5dr_matcher *col_matcher;
	LIST_ENTRY(mlx5dr_matcher) next;
};

int mlx5dr_matcher_conv_items_to_prm(uint64_t *match_buf,
				     struct rte_flow_item *items,
				     uint8_t *match_criteria,
				     bool is_value);

#endif
