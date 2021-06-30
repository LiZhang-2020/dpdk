/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_MATCHER_H_
#define MLX5DR_MATCHER_H_

struct mlx5dr_matcher_nic {
	struct mlx5dr_devx_obj *rtc;
	struct mlx5dr_pool_chunk ste;
};

struct mlx5dr_matcher {
	struct mlx5dr_table *tbl;
	struct mlx5dr_matcher_attr attr;
	struct mlx5dv_flow_matcher *dv_matcher;
	struct mlx5dr_devx_obj *definer;
	struct mlx5dr_devx_obj *end_ft;
	struct mlx5dr_matcher_nic rx;
	struct mlx5dr_matcher_nic tx;
	LIST_ENTRY(mlx5dr_matcher) next;
};

#endif
