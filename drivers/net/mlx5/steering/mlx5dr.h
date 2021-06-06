/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_H_
#define MLX5DR_H_

struct mlx5dr_context;

struct mlx5dr_context_attr {
	uint16_t queues;
	uint16_t queues_size;
	size_t initial_ste_memory;
	struct ibv_pd *pd;
};

struct mlx5dr_context *mlx5dr_context_open(struct ibv_context *ibv_ctx,
					   struct mlx5dr_context_attr *attr);

int mlx5dr_context_close(struct mlx5dr_context *ctx);

#endif
