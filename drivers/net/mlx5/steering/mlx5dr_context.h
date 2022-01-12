/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_CONTEXT_H_
#define MLX5DR_CONTEXT_H_

enum mlx5dr_context_flags {
	MLX5DR_CONTEXT_FLAG_HWS_SUPPORT = 1 << 0,
	MLX5DR_CONTEXT_FLAG_PRIVATE_PD = 1 << 1,
};

struct mlx5dr_context_common_res {
	struct mlx5dr_action_default_stc *default_stc;
	struct mlx5dr_action_shared_stc *shared_stc;
};

struct mlx5dr_context {
	struct ibv_context *ibv_ctx;
	struct mlx5dr_cmd_query_caps *caps;
	struct ibv_pd *pd;
	uint32_t pd_num;
	struct mlx5dr_pool *stc_pool[MLX5DR_TABLE_TYPE_MAX];
	struct mlx5dr_pool *ste_pool[MLX5DR_TABLE_TYPE_MAX];
	struct mlx5dr_context_common_res common_res[MLX5DR_TABLE_TYPE_MAX];
	struct mlx5dr_pattern_cache *pattern_cache;
	pthread_spinlock_t ctrl_lock;
	enum mlx5dr_context_flags flags;
	struct mlx5dr_send_engine *send_queue;
	size_t queues;
	LIST_HEAD(table_head, mlx5dr_table) head;
};

#endif