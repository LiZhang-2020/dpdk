/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_CMD_H_
#define MLX5DR_CMD_H_

struct mlx5dr_devx_obj {
	struct mlx5dv_devx_obj *obj;
	uint32_t id;
};

struct mlx5dr_cmd_ft_create_attr {
	uint8_t type;
	uint8_t level;
	uint32_t rtc_id;
	bool wqe_based_flow_update;
};

struct mlx5dr_cmd_ft_modify_attr {
	uint8_t type;
	uint32_t rtc_id;
	uint64_t modify_fs;
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

struct mlx5dr_cmd_stc_create_attr {
	uint8_t log_obj_range;
	uint8_t table_type;
};

struct mlx5dr_cmd_stc_modify_attr {
	uint64_t modify_bits;
};

int mlx5dr_cmd_destroy_obj(struct mlx5dr_devx_obj *devx_obj);

struct mlx5dr_devx_obj *
mlx5dr_cmd_flow_table_create(struct ibv_context *ctx,
			     struct mlx5dr_cmd_ft_create_attr *ft_attr);

int
mlx5dr_cmd_flow_table_modify(struct mlx5dr_devx_obj *devx_obj,
			     struct mlx5dr_cmd_ft_modify_attr *ft_attr);

struct mlx5dr_devx_obj *
mlx5dr_cmd_rtc_create(struct ibv_context *ctx,
		      struct mlx5dr_cmd_rtc_create_attr *rtc_attr);

#endif
