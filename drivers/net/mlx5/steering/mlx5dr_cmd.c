/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5_prm.h"
#include "mlx5dr_internal.h"

struct mlx5dv_devx_obj *
mlx5dr_cmd_flow_table_create(struct ibv_context *ctx,
			     struct mlx5dr_cmd_ft_create_attr *ft_attr)
{
	uint32_t out[MLX5_ST_SZ_DW(create_flow_table_out)] = {};
	uint32_t in[MLX5_ST_SZ_DW(create_flow_table_in)] = {};
	void *ft_ctx;

	MLX5_SET(create_flow_table_in, in, opcode, MLX5_CMD_OP_CREATE_FLOW_TABLE);
	MLX5_SET(create_flow_table_in, in, table_type, ft_attr->type);

	ft_ctx = MLX5_ADDR_OF(create_flow_table_in, in, flow_table_context);
	MLX5_SET(flow_table_context, ft_ctx, level, ft_attr->level);
	MLX5_SET(flow_table_context, ft_ctx, wqe_based_flow_update,
		 ft_attr->wqe_based_flow_update);

	return mlx5_glue->devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
}

int
mlx5dr_cmd_flow_table_modify(struct mlx5dv_devx_obj *devx_obj,
			     struct mlx5dr_cmd_ft_modify_attr *ft_attr)
{
	uint32_t out[MLX5_ST_SZ_DW(modify_flow_table_out)] = {};
	uint32_t in[MLX5_ST_SZ_DW(modify_flow_table_in)] = {};
	void *ft_ctx;

	MLX5_SET(modify_flow_table_in, in, opcode, MLX5_CMD_OP_MODIFY_FLOW_TABLE);
	MLX5_SET(modify_flow_table_in, in, table_type, ft_attr->type);
	MLX5_SET(modify_flow_table_in, in, modify_field_select, ft_attr->modify_fs);
	MLX5_SET(modify_flow_table_in, in, table_id,
		 mlx5dv_devx_obj_get_id(devx_obj));

	ft_ctx = MLX5_ADDR_OF(modify_flow_table_in, in, flow_table_context);
	MLX5_SET(flow_table_context, ft_ctx, rtc_id, ft_attr->rtc_id);

	return mlx5_glue->devx_obj_modify(devx_obj, in, sizeof(in), out, sizeof(out));
}

struct mlx5dv_devx_obj *
mlx5dr_cmd_rtc_create(struct ibv_context *ctx,
		      struct mlx5dr_cmd_rtc_create_attr *rtc_attr)
{
	uint32_t out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)] = {};
	uint32_t in[MLX5_ST_SZ_DW(create_rtc_in)] = {};
	void *attr;

	attr = MLX5_ADDR_OF(create_rtc_in, in, hdr);
	MLX5_SET(general_obj_in_cmd_hdr,
		 attr, opcode, MLX5_CMD_OP_CREATE_GENERAL_OBJECT);
	MLX5_SET(general_obj_in_cmd_hdr,
		 attr, obj_type, MLX5_GENERAL_OBJ_TYPE_RTC);

	attr = MLX5_ADDR_OF(create_rtc_in, in, rtc);
	MLX5_SET(rtc, attr, ste_format, MLX5_IFC_RTC_STE_FORMAT_8DW);
	MLX5_SET(rtc, attr, pd, rtc_attr->pd);
	MLX5_SET(rtc, attr, update_index_mode, rtc_attr->update_index_mode);
	MLX5_SET(rtc, attr, log_depth, rtc_attr->log_depth);
	MLX5_SET(rtc, attr, log_hash_size, rtc_attr->log_size);
	MLX5_SET(rtc, attr, table_type, rtc_attr->table_type);
	MLX5_SET(rtc, attr, match_definer_id, rtc_attr->definer_id);
	MLX5_SET(rtc, attr, stc_id, rtc_attr->stc_id);
	MLX5_SET(rtc, attr, ste_table_base_id, rtc_attr->ste_base);
	MLX5_SET(rtc, attr, ste_table_offset, rtc_attr->ste_offset);
	MLX5_SET(rtc, attr, miss_flow_table_id, rtc_attr->miss_ft_id);

	return mlx5_glue->devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
}
