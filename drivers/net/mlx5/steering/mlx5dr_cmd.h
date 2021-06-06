/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_CMD_H_
#define MLX5DR_CMD_H_

struct mlx5dr_cmd_flow_table_attr {
	uint8_t	type;
	uint8_t	level;
};

struct mlx5dv_devx_obj *
mlx5dr_cmd_flow_table_create(struct ibv_context *ctx,
			     struct mlx5dr_cmd_flow_table_attr *ft_attr);

#endif
