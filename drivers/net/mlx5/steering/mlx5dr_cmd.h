/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_CMD_H_
#define MLX5DR_CMD_H_

struct mlx5dr_cmd_ft_create_attr {
	uint8_t type;
	uint8_t level;
	bool rtc_valid;
};

struct mlx5dr_cmd_ft_modify_attr {
	uint8_t type;
	uint32_t rtc_id_0;
	uint32_t rtc_id_1;
	uint32_t table_miss_id;
	uint8_t table_miss_action;
	uint64_t modify_fs;
};

struct mlx5dr_cmd_fg_attr {
	uint32_t	table_id;
	uint32_t	table_type;
};

struct mlx5dr_cmd_forward_tbl {
	struct mlx5dr_devx_obj	*ft;
	struct mlx5dr_devx_obj	*fg;
	struct mlx5dr_devx_obj	*fte;
	uint32_t refcount;
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
		struct {
			uint8_t decap;
			uint16_t start_anchor;
			uint16_t end_anchor;
		} remove_header;
		struct {
			uint32_t arg_id;
			uint32_t pattern_id;
		} modify_header;
		struct {
			uint16_t src_field;
			uint8_t src_offset;
			uint8_t length;
			uint16_t dst_field;
			uint8_t dst_offset;
		} modify_action;
		struct {
			uint32_t arg_id;
			uint32_t header_size;
			uint8_t is_inline;
			uint8_t encap;
			uint16_t insert_anchor;
		} reformat;
		struct {
			uint32_t devx_obj_id;
			uint8_t return_reg_id;
		} aso;

		uint32_t dest_table_id;
		uint32_t dest_tir_num;
	};
};

struct mlx5dr_cmd_ste_create_attr {
	uint8_t log_obj_range;
	uint8_t table_type;
};

struct mlx5dr_cmd_definer_create_attr {
	uint8_t *dw_selector;
	uint8_t *byte_selector;
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

struct mlx5dr_cmd_query_ft_caps {
	uint8_t max_level;
	uint8_t reparse;
};

struct mlx5dr_cmd_query_caps {
	uint32_t flex_protocols;
	uint8_t wqe_based_update;
	uint8_t rtc_reparse_mode;
	uint16_t ste_format;
	uint8_t rtc_index_mode;
	uint8_t ste_alloc_log_max;
	uint8_t ste_alloc_log_gran;
	uint8_t stc_alloc_log_max;
	uint8_t stc_alloc_log_gran;
	uint8_t rtc_log_depth_max;
	uint8_t flex_parser_id_gtpu_dw_0;
	uint8_t flex_parser_id_gtpu_teid;
	uint8_t flex_parser_id_gtpu_dw_2;
	uint8_t flex_parser_id_gtpu_first_ext_dw_0;
	struct mlx5dr_cmd_query_ft_caps nic_ft;
	struct mlx5dr_cmd_query_ft_caps fdb_ft;
	uint8_t log_header_modify_argument_granularity;
	uint8_t log_header_modify_argument_max_alloc;
	uint64_t definer_format_sup;
	char fw_ver[64];
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

struct mlx5dr_devx_obj *
mlx5dr_cmd_arg_create(struct ibv_context *ctx,
		      uint16_t log_obj_range,
		      uint32_t pd);

struct mlx5dr_devx_obj *
mlx5dr_cmd_header_modify_pattern_create(struct ibv_context *ctx,
					uint32_t pattern_length,
					uint8_t *actions);

int mlx5dr_cmd_sq_modify_rdy(struct mlx5dr_devx_obj *devx_obj);

int mlx5dr_cmd_query_caps(struct ibv_context *ctx,
			  struct mlx5dr_cmd_query_caps *caps);

void mlx5dr_cmd_miss_ft_destroy(struct mlx5dr_cmd_forward_tbl *tbl);
struct mlx5dr_cmd_forward_tbl *
mlx5dr_cmd_miss_ft_create(struct ibv_context *ctx,
			  struct mlx5dr_cmd_ft_create_attr *ft_attr,
			  uint32_t vport);
#endif

