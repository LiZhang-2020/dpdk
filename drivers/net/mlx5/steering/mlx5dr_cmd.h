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

struct mlx5dr_cmd_rtc_create_attr {
	uint32_t pd;
	uint32_t stc_id;
	uint32_t ste_base;
	uint32_t ste_offset;
	uint32_t miss_ft_id;
	uint8_t update_index_mode;
	uint8_t log_depth;
	uint8_t log_size;
	uint8_t table_type;
	uint8_t definer_id;
};

struct mlx5dv_devx_obj *
mlx5dr_cmd_flow_table_create(struct ibv_context *ctx,
			     struct mlx5dr_cmd_flow_table_attr *ft_attr);

struct mlx5dv_devx_obj *
mlx5dr_cmd_rtc_create(struct ibv_context *ctx,
		      struct mlx5dr_cmd_rtc_create_attr *rtc_attr);

#endif
