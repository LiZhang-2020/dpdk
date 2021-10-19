/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_internal.h"

int mlx5dr_cmd_destroy_obj(struct mlx5dr_devx_obj *devx_obj)
{
	int ret;

	ret = mlx5_glue->devx_obj_destroy(devx_obj->obj);
	simple_free(devx_obj);

	return ret;
}

struct mlx5dr_devx_obj *
mlx5dr_cmd_flow_table_create(struct ibv_context *ctx,
			     struct mlx5dr_cmd_ft_create_attr *ft_attr)
{
	uint32_t out[MLX5_ST_SZ_DW(create_flow_table_out)] = {0};
	uint32_t in[MLX5_ST_SZ_DW(create_flow_table_in)] = {0};
	struct mlx5dr_devx_obj *devx_obj;
	void *ft_ctx;

	devx_obj = simple_malloc(sizeof(*devx_obj));
	if (!devx_obj) {
		DR_LOG(ERR, "Failed to allocate memory for flow table object");
                rte_errno = ENOMEM;
                return NULL;
	}

	MLX5_SET(create_flow_table_in, in, opcode, MLX5_CMD_OP_CREATE_FLOW_TABLE);
	MLX5_SET(create_flow_table_in, in, table_type, ft_attr->type);

	ft_ctx = MLX5_ADDR_OF(create_flow_table_in, in, flow_table_context);
	MLX5_SET(flow_table_context, ft_ctx, level, ft_attr->level);
	MLX5_SET(flow_table_context, ft_ctx, wqe_based_flow_update,
		 ft_attr->wqe_based_flow_update);

	devx_obj->obj = mlx5_glue->devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
	if (!devx_obj->obj) {
		DR_LOG(ERR, "Failed to create FT");
		simple_free(devx_obj);
		rte_errno = errno;
		return NULL;
	}

	devx_obj->id = MLX5_GET(create_flow_table_out, out, table_id);

	return devx_obj;
}

int
mlx5dr_cmd_flow_table_modify(struct mlx5dr_devx_obj *devx_obj,
			     struct mlx5dr_cmd_ft_modify_attr *ft_attr)
{
	uint32_t out[MLX5_ST_SZ_DW(modify_flow_table_out)] = {0};
	uint32_t in[MLX5_ST_SZ_DW(modify_flow_table_in)] = {0};
	void *ft_ctx;
	int ret;

	MLX5_SET(modify_flow_table_in, in, opcode, MLX5_CMD_OP_MODIFY_FLOW_TABLE);
	MLX5_SET(modify_flow_table_in, in, table_type, ft_attr->type);
	MLX5_SET(modify_flow_table_in, in, modify_field_select, ft_attr->modify_fs);
	MLX5_SET(modify_flow_table_in, in, table_id, devx_obj->id);

	ft_ctx = MLX5_ADDR_OF(modify_flow_table_in, in, flow_table_context);
	MLX5_SET(flow_table_context, ft_ctx, rtc_id, ft_attr->rtc_id);

	ret = mlx5_glue->devx_obj_modify(devx_obj->obj, in, sizeof(in), out, sizeof(out));
	if (ret) {
		DR_LOG(ERR, "Failed to modify FT");
		rte_errno = errno;
	}

	return ret;
}

struct mlx5dr_devx_obj *
mlx5dr_cmd_rtc_create(struct ibv_context *ctx,
		      struct mlx5dr_cmd_rtc_create_attr *rtc_attr)
{
	uint32_t out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)] = {0};
	uint32_t in[MLX5_ST_SZ_DW(create_rtc_in)] = {0};
	struct mlx5dr_devx_obj *devx_obj;
	void *attr;

	devx_obj = simple_malloc(sizeof(*devx_obj));
	if (!devx_obj) {
		DR_LOG(ERR, "Failed to allocate memory for RTC object");
		rte_errno = ENOMEM;
		return NULL;
	}

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
	MLX5_SET(rtc, attr, stc_id, rtc_attr->stc_base);
	MLX5_SET(rtc, attr, ste_table_base_id, rtc_attr->ste_base);
	MLX5_SET(rtc, attr, ste_table_offset, rtc_attr->ste_offset);
	MLX5_SET(rtc, attr, miss_flow_table_id, rtc_attr->miss_ft_id);
	/* TODO Reparse is an RTC attribute and cannot be controlled per rule */
	// MLX5_SET(rtc, attr, reparse_mode, MLX5_IFC_RTC_REPARSE_ALWAYS);

	devx_obj->obj = mlx5_glue->devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
	if (!devx_obj->obj) {
		DR_LOG(ERR, "Failed to create RTC");
		simple_free(devx_obj);
		rte_errno = errno;
		return NULL;
	}

	devx_obj->id = MLX5_GET(general_obj_out_cmd_hdr, out, obj_id);

	return devx_obj;
}

struct mlx5dr_devx_obj *
mlx5dr_cmd_stc_create(struct ibv_context *ctx,
		      struct mlx5dr_cmd_stc_create_attr *stc_attr)
{
	uint32_t out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)] = {0};
	uint32_t in[MLX5_ST_SZ_DW(create_stc_in)] = {0};
	struct mlx5dr_devx_obj *devx_obj;
	void *attr;

	devx_obj = simple_malloc(sizeof(*devx_obj));
	if (!devx_obj) {
		DR_LOG(ERR, "Failed to allocate memory for STC object");
		rte_errno = ENOMEM;
		return NULL;
	}

	attr = MLX5_ADDR_OF(create_stc_in, in, hdr);
	MLX5_SET(general_obj_in_cmd_hdr,
		 attr, opcode, MLX5_CMD_OP_CREATE_GENERAL_OBJECT);
	MLX5_SET(general_obj_in_cmd_hdr,
		 attr, obj_type, MLX5_GENERAL_OBJ_TYPE_STC);
	MLX5_SET(general_obj_in_cmd_hdr,
		 attr, log_obj_range, stc_attr->log_obj_range);

	attr = MLX5_ADDR_OF(create_stc_in, in, stc);
	MLX5_SET(stc, attr, table_type, stc_attr->table_type);

	devx_obj->obj = mlx5_glue->devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
	if (!devx_obj->obj) {
		DR_LOG(ERR, "Failed to create STC");
		simple_free(devx_obj);
		rte_errno = errno;
		return NULL;
	}

	devx_obj->id = MLX5_GET(general_obj_out_cmd_hdr, out, obj_id);

	return devx_obj;
}

static int
mlx5dr_cmd_stc_modify_set_stc_param(struct mlx5dr_cmd_stc_modify_attr *stc_attr,
				    void *stc_parm)
{
	switch (stc_attr->action_type) {
	case MLX5_IFC_STC_ACTION_TYPE_COUNTER:
		MLX5_SET(stc_ste_param_flow_counter, stc_parm, flow_counter_id, stc_attr->id);
		break;
	case MLX5_IFC_STC_ACTION_TYPE_JUMP_TO_TIR:
		MLX5_SET(stc_ste_param_tir, stc_parm, tirn, stc_attr->dest_tir_num);
		break;
	case MLX5_IFC_STC_ACTION_TYPE_JUMP_TO_FT:
		MLX5_SET(stc_ste_param_table, stc_parm, table_id, stc_attr->dest_table_id);
		break;
	case MLX5_IFC_STC_ACTION_TYPE_ACC_MODIFY_LIST:
		MLX5_SET(stc_ste_param_header_modify_list, stc_parm,
			 header_modify_pattern_id, stc_attr->modify_header.pattern_id);
		MLX5_SET(stc_ste_param_header_modify_list, stc_parm,
			 header_modify_argument_id, stc_attr->modify_header.arg_id);
		break;
	case MLX5_IFC_STC_ACTION_TYPE_HEADER_REMOVE:
		MLX5_SET(stc_ste_param_remove, stc_parm, action_type,
			 MLX5_MODIFICATION_TYPE_REMOVE);
		MLX5_SET(stc_ste_param_remove, stc_parm, decap,
			 stc_attr->remove_header.decap);
		MLX5_SET(stc_ste_param_remove, stc_parm, remove_start_anchor,
			 stc_attr->remove_header.start_anchor);
		MLX5_SET(stc_ste_param_remove, stc_parm, remove_end_anchor,
			 stc_attr->remove_header.end_anchor);
		break;
	case MLX5_IFC_STC_ACTION_TYPE_HEADER_INSERT:
		MLX5_SET(stc_ste_param_insert, stc_parm, action_type,
			 MLX5_MODIFICATION_TYPE_INSERT);
		MLX5_SET(stc_ste_param_insert, stc_parm, encap,
			 stc_attr->reformat.encap);
		MLX5_SET(stc_ste_param_insert, stc_parm, inline_data,
			 stc_attr->reformat.is_inline);
		MLX5_SET(stc_ste_param_insert, stc_parm, insert_anchor,
			 stc_attr->reformat.insert_anchor);
		/* HW gets that size in words */
		MLX5_SET(stc_ste_param_insert, stc_parm, insert_size,
			 stc_attr->reformat.header_size / 2);
		MLX5_SET(stc_ste_param_insert, stc_parm, insert_argument,
			 stc_attr->reformat.arg_id);
		break;
	case MLX5_IFC_STC_ACTION_TYPE_DROP:
	case MLX5_IFC_STC_ACTION_TYPE_NOP:
	case MLX5_IFC_STC_ACTION_TYPE_TAG:
	case MLX5_IFC_STC_ACTION_TYPE_ALLOW:
		break;
	default:
		DR_LOG(ERR, "not supported type %d", stc_attr->action_type);
		rte_errno = EINVAL;
		return rte_errno;
		break;
	}
	return 0;
}

int
mlx5dr_cmd_stc_modify(struct mlx5dr_devx_obj *devx_obj,
		      struct mlx5dr_cmd_stc_modify_attr *stc_attr)
{
	uint32_t out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)] = {0};
	uint32_t in[MLX5_ST_SZ_DW(create_stc_in)] = {0};
	void *stc_parm;
	void *attr;
	int ret;

	/* TODO Current support is DROP, NOP, TIR, Allow others will be NOP */
	if (stc_attr->action_type != MLX5_IFC_STC_ACTION_TYPE_DROP &&
	    stc_attr->action_type != MLX5_IFC_STC_ACTION_TYPE_ACC_MODIFY_LIST &&
	    stc_attr->action_type != MLX5_IFC_STC_ACTION_TYPE_NOP &&
	    stc_attr->action_type != MLX5_IFC_STC_ACTION_TYPE_ALLOW &&
	    stc_attr->action_type != MLX5_IFC_STC_ACTION_TYPE_JUMP_TO_TIR &&
	    stc_attr->action_type != MLX5_IFC_STC_ACTION_TYPE_HEADER_REMOVE &&
	    stc_attr->action_type != MLX5_IFC_STC_ACTION_TYPE_HEADER_INSERT) {
		DR_LOG(ERR, "TODO FYI - ignoring action STC!");
		stc_attr->action_type = MLX5_IFC_STC_ACTION_TYPE_NOP;
		stc_attr->action_offset = 0;
		stc_attr->id = 0;
	}

	attr = MLX5_ADDR_OF(create_stc_in, in, hdr);
	MLX5_SET(general_obj_in_cmd_hdr,
		 attr, opcode, MLX5_CMD_OP_MODIFY_GENERAL_OBJECT);
	MLX5_SET(general_obj_in_cmd_hdr,
		 attr, obj_type, MLX5_GENERAL_OBJ_TYPE_STC);
	MLX5_SET(general_obj_in_cmd_hdr, in, obj_id, devx_obj->id);
	MLX5_SET(general_obj_in_cmd_hdr, in, obj_offset, stc_attr->stc_offset);

	attr = MLX5_ADDR_OF(create_stc_in, in, stc);
	MLX5_SET(stc, attr, ste_action_offset, stc_attr->action_offset);
	MLX5_SET(stc, attr, action_type, stc_attr->action_type);
	MLX5_SET64(stc, attr, modify_field_select,
		   MLX5_IFC_MODIFY_STC_FIELD_SELECT_NEW_STC);

	/* Set destination TIRN, TAG, FT ID, STE ID */
	stc_parm = MLX5_ADDR_OF(stc, attr, stc_param);
	ret = mlx5dr_cmd_stc_modify_set_stc_param(stc_attr, stc_parm);
	if (ret)
		return ret;

	ret = mlx5_glue->devx_obj_modify(devx_obj->obj, in, sizeof(in), out, sizeof(out));
	if (ret) {
		DR_LOG(ERR, "Failed to modify STC");
		rte_errno = errno;
	}

	return ret;
}

struct mlx5dr_devx_obj *
mlx5dr_cmd_arg_create(struct ibv_context *ctx,
		      uint16_t log_obj_range,
		      uint32_t pd)
{
	uint32_t out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)] = {0};
	uint32_t in[MLX5_ST_SZ_DW(create_arg_in)] = {0};
	struct mlx5dr_devx_obj *devx_obj;
	void *attr;

	devx_obj = simple_malloc(sizeof(*devx_obj));
	if (!devx_obj) {
		DR_LOG(ERR, "Failed to allocate memory for ARG object");
		rte_errno = ENOMEM;
		return NULL;
	}

	attr = MLX5_ADDR_OF(create_arg_in, in, hdr);
	MLX5_SET(general_obj_in_cmd_hdr,
		 attr, opcode, MLX5_CMD_OP_CREATE_GENERAL_OBJECT);
	MLX5_SET(general_obj_in_cmd_hdr,
		 attr, obj_type, MLX5_GENERAL_OBJ_TYPE_ARG);
	MLX5_SET(general_obj_in_cmd_hdr,
		 attr, log_obj_range, log_obj_range);

	attr = MLX5_ADDR_OF(create_arg_in, in, arg);
	MLX5_SET(arg, attr, access_pd, pd);

	devx_obj->obj = mlx5_glue->devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
	if (!devx_obj->obj) {
		DR_LOG(ERR, "Failed to create ARG");
		simple_free(devx_obj);
		rte_errno = errno;
		return NULL;
	}

	devx_obj->id = MLX5_GET(general_obj_out_cmd_hdr, out, obj_id);

	return devx_obj;
}

struct mlx5dr_devx_obj *
mlx5dr_cmd_header_modify_pattern_create(struct ibv_context *ctx,
					uint32_t pattern_length,
					uint8_t *actions)
{
	uint32_t in[MLX5_ST_SZ_DW(create_header_modify_pattern_in)] = {0};
	uint32_t out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)] = {0};
	struct mlx5dr_devx_obj *devx_obj;
	void *pattern_data;
	void *pattern;
	void *attr;

	if (pattern_length > MAX_ACTIONS_DATA_IN_HEADER_MODIFY) {
		DR_LOG(ERR, "too much patterns (%d), more than %d",
			pattern_length, MAX_ACTIONS_DATA_IN_HEADER_MODIFY);
		rte_errno = EINVAL;
		return NULL;
	}

	devx_obj = simple_malloc(sizeof(*devx_obj));
	if (!devx_obj) {
		DR_LOG(ERR, "Failed to allocate memory for header_modify_pattern object");
		rte_errno = ENOMEM;
		return NULL;
	}

	attr = MLX5_ADDR_OF(create_header_modify_pattern_in, in, hdr);
	MLX5_SET(general_obj_in_cmd_hdr,
		 attr, opcode, MLX5_CMD_OP_CREATE_GENERAL_OBJECT);
	MLX5_SET(general_obj_in_cmd_hdr,
		 attr, obj_type, MLX5_GENERAL_OBJ_TYPE_MODIFY_HEADER_PATTERN);

	pattern = MLX5_ADDR_OF(create_header_modify_pattern_in, in, pattern);
	/* pattern_length is in dwords */
	MLX5_SET(header_modify_pattern_in, pattern, pattern_length, pattern_length / DW_SIZE);

	pattern_data = MLX5_ADDR_OF(header_modify_pattern_in, pattern, pattern_data);
	memcpy(pattern_data, actions, pattern_length);

	devx_obj->obj = mlx5_glue->devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
	if (!devx_obj->obj) {
		DR_LOG(ERR, "Failed to create header_modify_pattern");
		rte_errno = errno;
		goto free_obj;
	}

	devx_obj->id = MLX5_GET(general_obj_out_cmd_hdr, out, obj_id);

	return devx_obj;

free_obj:
	simple_free(devx_obj);
	return NULL;
}

struct mlx5dr_devx_obj *
mlx5dr_cmd_ste_create(struct ibv_context *ctx,
		      struct mlx5dr_cmd_ste_create_attr *ste_attr)
{
	uint32_t out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)] = {0};
	uint32_t in[MLX5_ST_SZ_DW(create_ste_in)] = {0};
	struct mlx5dr_devx_obj *devx_obj;
	void *attr;

	devx_obj = simple_malloc(sizeof(*devx_obj));
	if (!devx_obj) {
		DR_LOG(ERR, "Failed to allocate memory for STE object");
		rte_errno = ENOMEM;
		return NULL;
	}

	attr = MLX5_ADDR_OF(create_ste_in, in, hdr);
	MLX5_SET(general_obj_in_cmd_hdr,
		 attr, opcode, MLX5_CMD_OP_CREATE_GENERAL_OBJECT);
	MLX5_SET(general_obj_in_cmd_hdr,
		 attr, obj_type, MLX5_GENERAL_OBJ_TYPE_STE);
	MLX5_SET(general_obj_in_cmd_hdr,
		 attr, log_obj_range, ste_attr->log_obj_range);

	attr = MLX5_ADDR_OF(create_ste_in, in, ste);
	MLX5_SET(ste, attr, table_type, ste_attr->table_type);

	devx_obj->obj = mlx5_glue->devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
	if (!devx_obj->obj) {
		DR_LOG(ERR, "Failed to create STE");
		simple_free(devx_obj);
		rte_errno = errno;
		return NULL;
	}

	devx_obj->id = MLX5_GET(general_obj_out_cmd_hdr, out, obj_id);

	return devx_obj;
}

struct mlx5dr_devx_obj *
mlx5dr_cmd_definer_create(struct ibv_context *ctx,
			  struct mlx5dr_cmd_definer_create_attr *def_attr)
{
	uint32_t out[MLX5_ST_SZ_DW(general_obj_out_cmd_hdr)] = {0};
	uint32_t in[MLX5_ST_SZ_DW(create_definer_in)] = {0};
	struct mlx5dr_devx_obj *devx_obj;
	void *ptr;

	devx_obj = simple_malloc(sizeof(*devx_obj));
	if (!devx_obj) {
		DR_LOG(ERR, "Failed to allocate memory for STE object");
		rte_errno = ENOMEM;
		return NULL;
	}

	MLX5_SET(general_obj_in_cmd_hdr,
		 in, opcode, MLX5_CMD_OP_CREATE_GENERAL_OBJECT);
	MLX5_SET(general_obj_in_cmd_hdr,
		 in, obj_type, MLX5_GENERAL_OBJ_TYPE_DEFINER);

	ptr = MLX5_ADDR_OF(create_definer_in, in, definer);
	MLX5_SET(definer, ptr, format_id, def_attr->format_id);

	/* Current support match and not jumbo */
	ptr = MLX5_ADDR_OF(definer, ptr, match_mask_dw_7_0);
	memcpy(ptr, def_attr->match_mask, MLX5_FLD_SZ_BYTES(definer, match_mask_dw_7_0));

	devx_obj->obj = mlx5_glue->devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
	if (!devx_obj->obj) {
		DR_LOG(ERR, "Failed to create Definer");
		simple_free(devx_obj);
		rte_errno = errno;
		return NULL;
	}

	devx_obj->id = MLX5_GET(general_obj_out_cmd_hdr, out, obj_id);

	return devx_obj;
}

struct mlx5dr_devx_obj *
mlx5dr_cmd_sq_create(struct ibv_context *ctx,
		     struct mlx5dr_cmd_sq_create_attr *attr)
{
	uint32_t out[DEVX_ST_SZ_DW(create_sq_out)] = {0};
	uint32_t in[DEVX_ST_SZ_DW(create_sq_in)] = {0};
	void *sqc = DEVX_ADDR_OF(create_sq_in, in, ctx);
	void *wqc = DEVX_ADDR_OF(sqc, sqc, wq);
	struct mlx5dr_devx_obj *devx_obj;

	devx_obj = simple_malloc(sizeof(*devx_obj));
	if (!devx_obj) {
		DR_LOG(ERR, "Failed to create SQ");
		rte_errno = ENOMEM;
		return NULL;
	}

	MLX5_SET(create_sq_in, in, opcode, MLX5_CMD_OP_CREATE_SQ);
	MLX5_SET(sqc, sqc, cqn, attr->cqn);
	MLX5_SET(sqc, sqc, flush_in_error_en, 1);
	MLX5_SET(sqc, sqc, non_wire, 1);
	MLX5_SET(wq, wqc, wq_type, MLX5_WQ_TYPE_CYCLIC);
	MLX5_SET(wq, wqc, pd, attr->pdn);
	MLX5_SET(wq, wqc, uar_page, attr->page_id);
	MLX5_SET(wq, wqc, log_wq_stride, log2above(MLX5_SEND_WQE_BB));
	MLX5_SET(wq, wqc, log_wq_sz, attr->log_wq_sz);
	MLX5_SET(wq, wqc, dbr_umem_id, attr->dbr_id);
	MLX5_SET(wq, wqc, wq_umem_id, attr->wq_id);

	devx_obj->obj = mlx5_glue->devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
	if (!devx_obj->obj) {
		simple_free(devx_obj);
		rte_errno = errno;
		return NULL;
	}

	devx_obj->id = MLX5_GET(create_sq_out, out, sqn);

	return devx_obj;
}

int mlx5dr_cmd_sq_modify_rdy(struct mlx5dr_devx_obj *devx_obj)
{
	uint32_t out[DEVX_ST_SZ_DW(modify_sq_out)] = {0};
	uint32_t in[DEVX_ST_SZ_DW(modify_sq_in)] = {0};
	void *sqc = DEVX_ADDR_OF(modify_sq_in, in, ctx);
	int ret;

	MLX5_SET(modify_sq_in, in, opcode, MLX5_CMD_OP_MODIFY_SQ);
	MLX5_SET(modify_sq_in, in, sqn, devx_obj->id);
	MLX5_SET(modify_sq_in, in, sq_state, MLX5_SQC_STATE_RST);
	MLX5_SET(sqc, sqc, state, MLX5_SQC_STATE_RDY);

	ret = mlx5_glue->devx_obj_modify(devx_obj->obj, in, sizeof(in), out, sizeof(out));
	if (ret) {
		DR_LOG(ERR, "Failed to modify SQ");
		rte_errno = errno;
	}

	return ret;
}

int mlx5dr_cmd_query_caps(struct ibv_context *ctx,
			  struct mlx5dr_cmd_query_caps *caps)
{
	uint32_t out[DEVX_ST_SZ_DW(query_hca_cap_out)] = {0};
	uint32_t in[DEVX_ST_SZ_DW(query_hca_cap_in)] = {0};
	int ret;

	MLX5_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	MLX5_SET(query_hca_cap_in, in, op_mod,
		 MLX5_GET_HCA_CAP_OP_MOD_GENERAL_DEVICE |
		 MLX5_HCA_CAP_OPMOD_GET_CUR);

	ret = mlx5_glue->devx_general_cmd(ctx, in, sizeof(in), out, sizeof(out));
	if (ret) {
		DR_LOG(ERR, "Failed to query device caps");
		rte_errno = errno;
		return rte_errno;
	}

	caps->wqe_based_update =
		MLX5_GET(query_hca_cap_out, out,
			 capability.cmd_hca_cap.wqe_based_flow_table_update_cap);

	caps->flex_protocols = MLX5_GET(query_hca_cap_out, out,
					capability.cmd_hca_cap.flex_parser_protocols);

	if (caps->flex_protocols & MLX5_HCA_FLEX_GTPU_DW_0_ENABLED)
		caps->flex_parser_id_gtpu_dw_0 =
			MLX5_GET(query_hca_cap_out,
				 out,
				 capability.cmd_hca_cap.flex_parser_id_gtpu_dw_0);

	if (caps->flex_protocols & MLX5_HCA_FLEX_GTPU_TEID_ENABLED)
		caps->flex_parser_id_gtpu_teid =
			MLX5_GET(query_hca_cap_out,
				 out,
				 capability.cmd_hca_cap.flex_parser_id_gtpu_teid);

	if (caps->flex_protocols & MLX5_HCA_FLEX_GTPU_DW_2_ENABLED)
		caps->flex_parser_id_gtpu_dw_2 =
			MLX5_GET(query_hca_cap_out,
				 out,
				 capability.cmd_hca_cap.flex_parser_id_gtpu_dw_2);

	if (caps->flex_protocols & MLX5_HCA_FLEX_GTPU_FIRST_EXT_DW_0_ENABLED)
		caps->flex_parser_id_gtpu_first_ext_dw_0 =
			MLX5_GET(query_hca_cap_out,
				 out,
				 capability.cmd_hca_cap.flex_parser_id_gtpu_first_ext_dw_0);

	MLX5_SET(query_hca_cap_in, in, op_mod,
		 MLX5_GET_HCA_CAP_OP_MOD_NIC_FLOW_TABLE |
		 MLX5_HCA_CAP_OPMOD_GET_CUR);

	ret = mlx5_glue->devx_general_cmd(ctx, in, sizeof(in), out, sizeof(out));
	if (ret) {
		DR_LOG(ERR, "Failed to query flow table caps");
		rte_errno = errno;
		return rte_errno;
	}

	caps->nic_ft.max_level = MLX5_GET(query_hca_cap_out, out,
					  capability.flow_table_nic_cap.
					  flow_table_properties_nic_receive.max_ft_level);

	caps->nic_ft.reparse = MLX5_GET(query_hca_cap_out, out,
					capability.flow_table_nic_cap.
					flow_table_properties_nic_receive.reparse);

	if (caps->wqe_based_update) {
		MLX5_SET(query_hca_cap_in, in, op_mod,
			 MLX5_GET_HCA_CAP_OP_MOD_WQE_BASED_FLOW_TABLE |
			 MLX5_HCA_CAP_OPMOD_GET_CUR);

		ret = mlx5_glue->devx_general_cmd(ctx, in, sizeof(in), out, sizeof(out));
		if (ret) {
			DR_LOG(ERR, "Failed to query WQE based FT caps");
			rte_errno = errno;
			return rte_errno;
		}

		caps->rtc_reparse_mode = MLX5_GET(query_hca_cap_out, out,
						  capability.wqe_based_flow_table_cap.
						  rtc_reparse_mode);

		caps->ste_format = MLX5_GET(query_hca_cap_out, out,
					    capability.wqe_based_flow_table_cap.
					    ste_format);

		caps->rtc_index_mode = MLX5_GET(query_hca_cap_out, out,
						capability.wqe_based_flow_table_cap.
						rtc_index_mode);

		caps->rtc_log_depth_max = MLX5_GET(query_hca_cap_out, out,
						   capability.wqe_based_flow_table_cap.
						   rtc_log_depth_max);

		caps->ste_alloc_log_max = MLX5_GET(query_hca_cap_out, out,
						   capability.wqe_based_flow_table_cap.
						   ste_alloc_log_max);

		caps->ste_alloc_log_gran = MLX5_GET(query_hca_cap_out, out,
						    capability.wqe_based_flow_table_cap.
						    ste_alloc_log_granularity);

		caps->stc_alloc_log_max = MLX5_GET(query_hca_cap_out, out,
						   capability.wqe_based_flow_table_cap.
						   stc_alloc_log_max);

		caps->stc_alloc_log_gran = MLX5_GET(query_hca_cap_out, out,
						    capability.wqe_based_flow_table_cap.
						    stc_alloc_log_granularity);
	}

	// TODO Current FW don't set this bit (yet)
	caps->nic_ft.reparse = 1;

	return ret;
}
