/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_CMD_H_
#define MLX5DR_CMD_H_

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
	bool wqe_based_flow_update;
};

struct mlx5dr_cmd_rtc_create_attr {
	uint32_t pd;
	uint32_t stc_base;
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
	uint32_t stc_offset;
	uint8_t action_offset;
	enum mlx5_ifc_stc_action_type action_type;
	union {
		uint32_t id; /* TIRN, TAG, FT ID, STE ID */
		uint32_t dest_table_id;
		uint32_t dest_tir_num;
	};
};

struct mlx5dr_cmd_ste_create_attr {
	uint8_t log_obj_range;
	uint8_t table_type;
};

struct mlx5dr_cmd_definer_create_attr {
	uint16_t format_id;
	uint8_t *match_mask;
};

struct mlx5dr_cmd_sq_create_attr {
	uint32_t cqn;
	uint32_t pdn;
	uint32_t page_id;
	uint32_t dbr_id;
	uint32_t wq_id;
	uint32_t log_wq_sz;
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

struct mlx5dr_devx_obj *
mlx5dr_cmd_stc_create(struct ibv_context *ctx,
		      struct mlx5dr_cmd_stc_create_attr *stc_attr);

int
mlx5dr_cmd_stc_modify(struct mlx5dr_devx_obj *devx_obj,
		      struct mlx5dr_cmd_stc_modify_attr *stc_attr);

struct mlx5dr_devx_obj *
mlx5dr_cmd_ste_create(struct ibv_context *ctx,
		      struct mlx5dr_cmd_ste_create_attr *ste_attr);

struct mlx5dr_devx_obj *
mlx5dr_cmd_definer_create(struct ibv_context *ctx,
			  struct mlx5dr_cmd_definer_create_attr *def_attr);

struct mlx5dr_devx_obj *
mlx5dr_cmd_sq_create(struct ibv_context *ctx,
		     struct mlx5dr_cmd_sq_create_attr *attr);

int mlx5dr_cmd_sq_modify_rdy(struct mlx5dr_devx_obj *devx_obj);

#endif
