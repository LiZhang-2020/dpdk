/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5_prm.h"
#include "mlx5dr_internal.h"

struct mlx5dv_devx_obj *
mlx5dr_cmd_flow_table_create(struct ibv_context *ctx,
			     struct mlx5dr_cmd_flow_table_attr *ft_attr)
{
	uint32_t out[MLX5_ST_SZ_DW(create_flow_table_out)] = {};
	uint32_t in[MLX5_ST_SZ_DW(create_flow_table_in)] = {};
	void *ft_ctx;

	MLX5_SET(create_flow_table_in, in, opcode, MLX5_CMD_OP_CREATE_FLOW_TABLE);
	MLX5_SET(create_flow_table_in, in, table_type, ft_attr->type);

	ft_ctx = MLX5_ADDR_OF(create_flow_table_in, in, flow_table_context);
	MLX5_SET(flow_table_context, ft_ctx, level, ft_attr->level);

	return mlx5_glue->devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
}
