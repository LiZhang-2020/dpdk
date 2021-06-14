/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_CMD_H_
#define MLX5DR_CMD_H_

struct mlx5dr_cmd_flow_table_attr {
	uint8_t type;
	uint8_t level;
	uint32_t rtc_id;
	uint32_t rx_rtc_id;
	uint32_t tx_rtc_id;
	bool wqe_based_flow_update;
};

struct mlx5dv_devx_obj *
mlx5dr_cmd_flow_table_create(struct ibv_context *ctx,
			     struct mlx5dr_cmd_flow_table_attr *ft_attr);

#endif
