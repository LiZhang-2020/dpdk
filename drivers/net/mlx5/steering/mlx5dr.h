/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_H_
#define MLX5DR_H_

struct mlx5dr_context;
struct mlx5dr_table;

enum mlx5dr_table_type {
	MLX5DR_TABLE_TYPE_NIC_RX,
	MLX5DR_TABLE_TYPE_NIC_TX,
	MLX5DR_TABLE_TYPE_FDB,
};

struct mlx5dr_context_attr {
	uint16_t queues;
	uint16_t queues_size;
	size_t initial_ste_memory;
	struct ibv_pd *pd;
};

struct mlx5dr_table_attr {
	enum mlx5dr_table_type type;
	uint32_t level;
};

struct mlx5dr_context *
mlx5dr_context_open(struct ibv_context *ibv_ctx,
		    struct mlx5dr_context_attr *attr);

int mlx5dr_context_close(struct mlx5dr_context *ctx);

struct mlx5dr_table *
mlx5dr_table_create(struct mlx5dr_context *ctx,
		    struct mlx5dr_table_attr *attr);

int mlx5dr_table_destroy(struct mlx5dr_table *tbl);

#endif
