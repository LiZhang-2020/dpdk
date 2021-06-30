/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_H_
#define MLX5DR_H_

struct mlx5dr_context;
struct mlx5dr_table;
struct mlx5dr_matcher;

enum mlx5dr_table_type {
	MLX5DR_TABLE_TYPE_NIC_RX,
	MLX5DR_TABLE_TYPE_NIC_TX,
	MLX5DR_TABLE_TYPE_FDB,
	MLX5DR_TABLE_TYPE_MAX,
};

enum mlx5dr_matcher_insertion_mode {
	MLX5DR_MATCHER_INSERTION_MODE_ASSURED,
	MLX5DR_MATCHER_INSERTION_MODE_BEST_EFFORT,
};

struct mlx5dr_context_attr {
	uint16_t queues;
	uint16_t queues_size;
	size_t initial_log_ste_memory;
	struct ibv_pd *pd;
};

struct mlx5dr_table_attr {
	enum mlx5dr_table_type type;
	uint32_t level;
};

struct mlx5dr_matcher_attr {
	uint32_t priority;
	enum mlx5dr_matcher_insertion_mode insertion_mode;
	uint32_t size_hint_rows_log;
	uint32_t size_hint_column_log;
};

struct mlx5dr_context *
mlx5dr_context_open(struct ibv_context *ibv_ctx,
		    struct mlx5dr_context_attr *attr);

int mlx5dr_context_close(struct mlx5dr_context *ctx);

struct mlx5dr_table *
mlx5dr_table_create(struct mlx5dr_context *ctx,
		    struct mlx5dr_table_attr *attr);

int mlx5dr_table_destroy(struct mlx5dr_table *tbl);

struct mlx5dr_matcher *
mlx5dr_matcher_create(struct mlx5dr_table *table,
		      struct rte_flow_item items[],
		      struct mlx5dr_matcher_attr *attr);

int mlx5dr_matcher_destroy(struct mlx5dr_matcher *matcher);

#endif
