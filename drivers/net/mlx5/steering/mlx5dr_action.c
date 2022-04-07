/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_internal.h"

#define MLX5DR_ACTION_ASO_METER_INIT_COLOR_OFFSET 1

int mlx5dr_action_root_build_attr(struct mlx5dr_rule_action rule_actions[],
				  uint32_t num_actions,
				  struct mlx5dv_flow_action_attr *attr)
{
	struct mlx5dr_action *action;
	uint32_t i;

	for (i = 0; i < num_actions; i++) {
		action = rule_actions[i].action;

		switch (action->type) {
		case MLX5DR_ACTION_TYP_FT:
		case MLX5DR_ACTION_TYP_TIR:
			attr[i].type = MLX5DV_FLOW_ACTION_DEST_DEVX;
			attr[i].obj = action->devx_obj;
			break;
		case MLX5DR_ACTION_TYP_QP:
			attr[i].type = MLX5DV_FLOW_ACTION_DEST_IBV_QP;
			attr[i].qp = action->qp;
			break;
		case MLX5DR_ACTION_TYP_TAG:
			attr[i].type = MLX5DV_FLOW_ACTION_TAG;
			attr[i].tag_value = rule_actions[i].tag.value;
			break;
#ifdef HAVE_MLX5_DR_CREATE_ACTION_DEFAULT_MISS
		case MLX5DR_ACTION_TYP_MISS:
			attr[i].type = MLX5DV_FLOW_ACTION_DEFAULT_MISS;
			break;
#endif
		case MLX5DR_ACTION_TYP_DROP:
			attr[i].type = MLX5DV_FLOW_ACTION_DROP;
			break;
		case MLX5DR_ACTION_TYP_TNL_L2_TO_L2:
		case MLX5DR_ACTION_TYP_L2_TO_TNL_L2:
		case MLX5DR_ACTION_TYP_TNL_L3_TO_L2:
		case MLX5DR_ACTION_TYP_L2_TO_TNL_L3:
		case MLX5DR_ACTION_TYP_MODIFY_HDR:
			attr[i].type = MLX5DV_FLOW_ACTION_IBV_FLOW_ACTION;
			attr[i].action = action->flow_action;
			break;
#ifndef HAVE_IBV_FLOW_DEVX_COUNTERS
		case MLX5DR_ACTION_TYP_CTR:
			attr[i].type = MLX5DV_FLOW_ACTION_COUNTERS_DEVX;
			attr[i].obj = action->devx_obj;

			if (rule_actions[i].counter.offset) {
				attr_aux[i].type = MLX5_FLOW_ACTION_COUNTER_OFFSET;
				attr_aux[i].offset = rule_actions[i].counter.offset;
			}
			break;
#endif
		default:
			DR_LOG(ERR, "Found unsupported action type: %d", action->type);
			rte_errno = ENOTSUP;
			return rte_errno;
		}
	}

	return 0;
}

static bool mlx5dr_action_fixup_stc_attr(struct mlx5dr_cmd_stc_modify_attr *stc_attr,
					 struct mlx5dr_cmd_stc_modify_attr *fixup_stc_attr,
					 uint32_t table_type,
					 bool is_mirror)
{
	uint32_t fw_tbl_type;

	if (table_type != MLX5DR_TABLE_TYPE_FDB)
		return false;

	fw_tbl_type = mlx5dr_table_get_res_fw_ft_type(table_type, is_mirror);

	if (stc_attr->action_type == MLX5_IFC_STC_ACTION_TYPE_JUMP_TO_VPORT &&
	    stc_attr->vport.vport_num == WIRE_PORT) {
		if (fw_tbl_type == FS_FT_FDB_RX) {
			/*The FW doesn't allow to go back to wire in the RX side, so change it to DROP*/
			fixup_stc_attr->action_type = MLX5_IFC_STC_ACTION_TYPE_DROP;
			fixup_stc_attr->action_offset = MLX5DR_ACTION_OFFSET_HIT;
			fixup_stc_attr->stc_offset = stc_attr->stc_offset;
		} else if (fw_tbl_type == FS_FT_FDB_TX) {
			/*The FW doesn't allow to go to wire in the TX by JUMP_TO_VPORT*/
			fixup_stc_attr->action_type = MLX5_IFC_STC_ACTION_TYPE_JUMP_TO_UPLINK;
			fixup_stc_attr->action_offset = stc_attr->action_offset;
			fixup_stc_attr->stc_offset = stc_attr->stc_offset;
			fixup_stc_attr->vport.vport_num = 0;
			fixup_stc_attr->vport.esw_owner_vhca_id = stc_attr->vport.esw_owner_vhca_id;
		}
		return true;
	}

	return false;
}

static int
mlx5dr_action_alloc_single_stc(struct mlx5dr_context *ctx,
			       struct mlx5dr_cmd_stc_modify_attr *stc_attr,
			       uint32_t table_type,
			       struct mlx5dr_pool_chunk *stc)
{
	struct mlx5dr_cmd_stc_modify_attr cleanup_stc_attr = {0};
	struct mlx5dr_pool *stc_pool = ctx->stc_pool[table_type];
	struct mlx5dr_cmd_stc_modify_attr fixup_stc_attr = {0};
	struct mlx5dr_devx_obj *devx_obj_0;
	bool use_fixup;
	int ret;

	ret = mlx5dr_pool_chunk_alloc(stc_pool, stc);
	if (ret) {
		DR_LOG(ERR, "Failed to allocate single action STC");
		return ret;
	}

	stc_attr->stc_offset = stc->offset;
	devx_obj_0 = mlx5dr_pool_chunk_get_base_devx_obj(stc_pool, stc);

	/* according to table/action limitation change the stc_attr */
	use_fixup = mlx5dr_action_fixup_stc_attr(stc_attr, &fixup_stc_attr, table_type, false);
	ret = mlx5dr_cmd_stc_modify(devx_obj_0, use_fixup ? &fixup_stc_attr : stc_attr);
	if (ret) {
		DR_LOG(ERR, "Failed to modify STC action_type %d tbl_type %d",
		       stc_attr->action_type, table_type);
		goto free_chunk;
	}

	/* Modify the FDB peer */
	if (table_type == MLX5DR_TABLE_TYPE_FDB) {
		struct mlx5dr_devx_obj *devx_obj_1;

		devx_obj_1 = mlx5dr_pool_chunk_get_base_devx_obj_mirror(stc_pool, stc);

		use_fixup = mlx5dr_action_fixup_stc_attr(stc_attr, &fixup_stc_attr,
							 table_type, true);
		ret = mlx5dr_cmd_stc_modify(devx_obj_1, use_fixup ? &fixup_stc_attr : stc_attr);
		if (ret) {
			DR_LOG(ERR, "Failed to modify peer STC action_type %d tbl_type %d",
			       stc_attr->action_type, table_type);
			goto clean_devx_obj_0;
		}
	}

	return 0;

clean_devx_obj_0:
	cleanup_stc_attr.action_type = MLX5_IFC_STC_ACTION_TYPE_DROP;
	cleanup_stc_attr.action_offset = MLX5DR_ACTION_OFFSET_HIT;
	cleanup_stc_attr.stc_offset = stc->offset;
	mlx5dr_cmd_stc_modify(devx_obj_0, &cleanup_stc_attr);
free_chunk:
       mlx5dr_pool_chunk_free(stc_pool, stc);
       return rte_errno;
}

static void
mlx5dr_action_free_single_stc(struct mlx5dr_context *ctx,
			       uint32_t table_type,
			       struct mlx5dr_pool_chunk *stc)
{
	struct mlx5dr_pool *stc_pool = ctx->stc_pool[table_type];
	struct mlx5dr_cmd_stc_modify_attr stc_attr = {0};
	struct mlx5dr_devx_obj *devx_obj;

	/* Modify the STC not to point to an object */
	stc_attr.action_type = MLX5_IFC_STC_ACTION_TYPE_DROP;
	stc_attr.action_offset = MLX5DR_ACTION_OFFSET_HIT;
	stc_attr.stc_offset = stc->offset;
	devx_obj = mlx5dr_pool_chunk_get_base_devx_obj(stc_pool, stc);
	mlx5dr_cmd_stc_modify(devx_obj, &stc_attr);

	if (table_type == MLX5DR_TABLE_TYPE_FDB) {
		devx_obj = mlx5dr_pool_chunk_get_base_devx_obj_mirror(stc_pool, stc);
		mlx5dr_cmd_stc_modify(devx_obj, &stc_attr);
	}

	mlx5dr_pool_chunk_free(stc_pool, stc);
}

static void mlx5dr_action_fill_stc_attr(struct mlx5dr_action *action,
					struct mlx5dr_devx_obj *obj,
					struct mlx5dr_cmd_stc_modify_attr *attr)
{
	switch (action->type) {
	case MLX5DR_ACTION_TYP_TAG:
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_TAG;
		attr->action_offset = MLX5DR_ACTION_OFFSET_DW5;
		break;
	case MLX5DR_ACTION_TYP_DROP:
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_DROP;
		attr->action_offset = MLX5DR_ACTION_OFFSET_HIT;
		break;
	case MLX5DR_ACTION_TYP_MISS:
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_ALLOW;
		attr->action_offset = MLX5DR_ACTION_OFFSET_HIT;
		/* TODO Need to support default miss for FDB */
		break;
	case MLX5DR_ACTION_TYP_CTR:
		attr->id = obj->id;
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_COUNTER;
		attr->action_offset = MLX5DR_ACTION_OFFSET_DW0;
		break;
	case MLX5DR_ACTION_TYP_TIR:
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_JUMP_TO_TIR;
		attr->action_offset = MLX5DR_ACTION_OFFSET_HIT;
		attr->dest_tir_num = obj->id;
		break;
	case MLX5DR_ACTION_TYP_TNL_L3_TO_L2:
	case MLX5DR_ACTION_TYP_MODIFY_HDR:
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_ACC_MODIFY_LIST;
		attr->action_offset = MLX5DR_ACTION_OFFSET_DW6;
		attr->modify_header.arg_id = action->modify_header.arg_obj->id;
		attr->modify_header.pattern_id = action->modify_header.pattern_obj->id;
		break;
	case MLX5DR_ACTION_TYP_FT:
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_JUMP_TO_FT;
		attr->action_offset = MLX5DR_ACTION_OFFSET_HIT;
		attr->dest_table_id = obj->id;
		break;
	case MLX5DR_ACTION_TYP_TNL_L2_TO_L2:
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_HEADER_REMOVE;
		attr->action_offset = MLX5DR_ACTION_OFFSET_DW5;
		attr->remove_header.decap = 1;
		attr->remove_header.start_anchor = MLX5_HEADER_ANCHOR_PACKET_START;
		attr->remove_header.end_anchor = MLX5_HEADER_ANCHOR_INNER_MAC;
		break;
	case MLX5DR_ACTION_TYP_L2_TO_TNL_L2:
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_HEADER_INSERT;
		attr->action_offset = MLX5DR_ACTION_OFFSET_DW6;
		attr->reformat.encap = 1;
		attr->reformat.insert_anchor = MLX5_HEADER_ANCHOR_PACKET_START;
		attr->reformat.arg_id = action->reformat.arg_obj->id;
		attr->reformat.header_size = action->reformat.header_size;
		break;
	case MLX5DR_ACTION_TYP_L2_TO_TNL_L3:
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_HEADER_INSERT;
		attr->action_offset = MLX5DR_ACTION_OFFSET_DW6;
		attr->reformat.encap = 1;
		attr->reformat.insert_anchor = MLX5_HEADER_ANCHOR_PACKET_START;
		attr->reformat.arg_id = action->reformat.arg_obj->id;
		attr->reformat.header_size = action->reformat.header_size;
		break;
	case MLX5DR_ACTION_TYP_MH_SET:
		attr->action_offset = MLX5DR_ACTION_OFFSET_DW6;
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_SET;
		attr->modify_action.src_field =
			action->modify_action.src_field;
		attr->modify_action.src_offset =
			action->modify_action.src_offset;
		attr->modify_action.length =
			action->modify_action.length;
		break;
	case MLX5DR_ACTION_TYP_MH_ADD:
		attr->action_offset = MLX5DR_ACTION_OFFSET_DW6;
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_ADD;
		attr->modify_action.src_field =
			action->modify_action.src_field;
		break;
	case MLX5DR_ACTION_TYP_MH_COPY:
		attr->action_offset = MLX5DR_ACTION_OFFSET_DW6;
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_COPY;
		attr->modify_action.src_field =
			action->modify_action.src_field;
		attr->modify_action.src_offset =
			action->modify_action.src_offset;
		attr->modify_action.length =
			action->modify_action.length;
		attr->modify_action.dst_field =
			action->modify_action.dst_field;
		attr->modify_action.dst_offset =
			action->modify_action.dst_offset;
		break;
	case MLX5DR_ACTION_TYP_ASO_METER:
		attr->action_offset = MLX5DR_ACTION_OFFSET_DW6;
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_ASO;
		attr->aso.devx_obj_id = obj->id;
		attr->aso.return_reg_id = action->aso.return_reg_id;
		break;
	case MLX5DR_ACTION_TYP_VPORT:
		attr->action_offset = MLX5DR_ACTION_OFFSET_HIT;
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_JUMP_TO_VPORT;
		attr->vport.vport_num = action->vport.vport_num;
		attr->vport.esw_owner_vhca_id =	action->vport.esw_owner_vhca_id;
		break;
	default:
		DR_LOG(ERR, "Invalid action type %d", action->type);
		assert(false);
	}
}

static int
mlx5dr_action_create_stcs(struct mlx5dr_action *action,
			  struct mlx5dr_devx_obj *obj)
{
	struct mlx5dr_cmd_stc_modify_attr stc_attr = {0};
	struct mlx5dr_context *ctx = action->ctx;
	int ret;

	mlx5dr_action_fill_stc_attr(action, obj, &stc_attr);

	/* Block unsupported parallel devx obj modify over the same base */
	pthread_spin_lock(&ctx->ctrl_lock);

	/* Allocate STC for RX */
	if (action->flags & MLX5DR_ACTION_FLAG_HWS_RX) {
		ret = mlx5dr_action_alloc_single_stc(ctx, &stc_attr,
						     MLX5DR_TABLE_TYPE_NIC_RX,
						     &action->stc[MLX5DR_TABLE_TYPE_NIC_RX]);
		if (ret)
			goto out_err;
	}

	/* Allocate STC for TX */
	if (action->flags & MLX5DR_ACTION_FLAG_HWS_TX) {
		ret = mlx5dr_action_alloc_single_stc(ctx, &stc_attr,
						     MLX5DR_TABLE_TYPE_NIC_TX,
						     &action->stc[MLX5DR_TABLE_TYPE_NIC_TX]);
		if (ret)
			goto free_nic_rx_stc;
	}

	/* Allocate STC for FDB */
	if (action->flags & MLX5DR_ACTION_FLAG_HWS_FDB) {
		ret = mlx5dr_action_alloc_single_stc(ctx, &stc_attr,
						     MLX5DR_TABLE_TYPE_FDB,
						     &action->stc[MLX5DR_TABLE_TYPE_FDB]);
		if (ret)
			goto free_nic_tx_stc;
	}

	pthread_spin_unlock(&ctx->ctrl_lock);

	return 0;

free_nic_tx_stc:
	if (action->flags & MLX5DR_ACTION_FLAG_HWS_TX)
		mlx5dr_action_free_single_stc(ctx,
					      MLX5DR_TABLE_TYPE_NIC_TX,
					      &action->stc[MLX5DR_TABLE_TYPE_NIC_TX]);
free_nic_rx_stc:
	if (action->flags & MLX5DR_ACTION_FLAG_HWS_RX)
		mlx5dr_action_free_single_stc(ctx,
					      MLX5DR_TABLE_TYPE_NIC_RX,
					      &action->stc[MLX5DR_TABLE_TYPE_NIC_RX]);
out_err:
	pthread_spin_unlock(&ctx->ctrl_lock);
	return rte_errno;
}

static void
mlx5dr_action_destroy_stcs(struct mlx5dr_action *action)
{
	struct mlx5dr_context *ctx = action->ctx;

	/* Block unsupported parallel devx obj modify over the same base */
	pthread_spin_lock(&ctx->ctrl_lock);

	if (action->flags & MLX5DR_ACTION_FLAG_HWS_RX)
		mlx5dr_action_free_single_stc(ctx, MLX5DR_TABLE_TYPE_NIC_RX,
					      &action->stc[MLX5DR_TABLE_TYPE_NIC_RX]);

	if (action->flags & MLX5DR_ACTION_FLAG_HWS_TX)
		mlx5dr_action_free_single_stc(ctx, MLX5DR_TABLE_TYPE_NIC_TX,
					      &action->stc[MLX5DR_TABLE_TYPE_NIC_TX]);

	if (action->flags & MLX5DR_ACTION_FLAG_HWS_FDB)
		mlx5dr_action_free_single_stc(ctx, MLX5DR_TABLE_TYPE_FDB,
					      &action->stc[MLX5DR_TABLE_TYPE_FDB]);

	pthread_spin_unlock(&ctx->ctrl_lock);
}

static bool
mlx5dr_action_is_root_flags(uint32_t flags)
{
	return flags & (MLX5DR_ACTION_FLAG_ROOT_RX |
		     	MLX5DR_ACTION_FLAG_ROOT_TX |
		     	MLX5DR_ACTION_FLAG_ROOT_FDB);
}

static bool
mlx5dr_action_is_hws_flags(uint32_t flags)
{
	return flags & (MLX5DR_ACTION_FLAG_HWS_RX |
			MLX5DR_ACTION_FLAG_HWS_TX |
			MLX5DR_ACTION_FLAG_HWS_FDB);
}

static struct mlx5dr_action *
mlx5dr_action_create_generic(struct mlx5dr_context *ctx,
			     uint32_t flags,
			     enum mlx5dr_action_type action_type)
{
	struct mlx5dr_action *action;

	if (!mlx5dr_action_is_root_flags(flags) &&
	    !mlx5dr_action_is_hws_flags(flags)) {
		DR_LOG(ERR, "Action flags must specify root or non root (HWS)");
		rte_errno = ENOTSUP;
		return NULL;
	}

	action = simple_calloc(1, sizeof(*action));
	if (!action) {
		DR_LOG(ERR, "Failed to allocate memory for action [%d]", action_type);
		rte_errno = ENOMEM;
		return NULL;
	}

	action->ctx = ctx;
	action->flags = flags;
	action->type = action_type;

	return action;
}

struct mlx5dr_action *
mlx5dr_action_create_dest_table(struct mlx5dr_context *ctx,
				struct mlx5dr_table *tbl,
				uint32_t flags)
{
	struct mlx5dr_action *action;
	int ret;

	if (mlx5dr_table_is_root(tbl)) {
		DR_LOG(ERR, "Root table cannot be set as destination");
		rte_errno = ENOTSUP;
		return NULL;
	}

	if (mlx5dr_action_is_hws_flags(flags) &&
	    mlx5dr_action_is_root_flags(flags)) {
		DR_LOG(ERR, "Same action cannot be used for root and non root");
		rte_errno = ENOTSUP;
		return NULL;
	}

	action = mlx5dr_action_create_generic(ctx, flags, MLX5DR_ACTION_TYP_FT);
	if (!action)
		return NULL;

	if (mlx5dr_action_is_root_flags(flags)) {
		action->devx_obj = tbl->ft->obj;
	} else {
		ret = mlx5dr_action_create_stcs(action, tbl->ft);
		if (ret)
			goto free_action;
	}

	return action;

free_action:
	simple_free(action);
	return NULL;
}

struct mlx5dr_action *
mlx5dr_action_create_dest_tir(struct mlx5dr_context *ctx,
			      struct mlx5dr_devx_obj *obj,
			      uint32_t flags)
{
	struct mlx5dr_action *action;
	int ret;

	if (mlx5dr_action_is_hws_flags(flags) &&
	    mlx5dr_action_is_root_flags(flags)) {
		DR_LOG(ERR, "Same action cannot be used for root and non root");
		rte_errno = ENOTSUP;
		return NULL;
	}

	action = mlx5dr_action_create_generic(ctx, flags, MLX5DR_ACTION_TYP_TIR);
	if (!action)
		return NULL;

	if (mlx5dr_action_is_root_flags(flags)) {
		action->devx_obj = obj->obj;
	} else {
		ret = mlx5dr_action_create_stcs(action, obj);
		if (ret)
			goto free_action;
	}

	return action;

free_action:
	simple_free(action);
	return NULL;
}

struct mlx5dr_action *
mlx5dr_action_create_dest_drop(struct mlx5dr_context *ctx,
			       uint32_t flags)
{
	struct mlx5dr_action *action;
	int ret;

	action = mlx5dr_action_create_generic(ctx, flags, MLX5DR_ACTION_TYP_DROP);
	if (!action)
		return NULL;

	if (mlx5dr_action_is_hws_flags(flags)) {
		ret = mlx5dr_action_create_stcs(action, NULL);
		if (ret)
			goto free_action;
	}

	return action;

free_action:
	simple_free(action);
	return NULL;
}

struct mlx5dr_action *
mlx5dr_action_create_default_miss(struct mlx5dr_context *ctx,
				  uint32_t flags)
{
	struct mlx5dr_action *action;
	int ret;

	action = mlx5dr_action_create_generic(ctx, flags, MLX5DR_ACTION_TYP_MISS);
	if (!action)
		return NULL;

	if (mlx5dr_action_is_hws_flags(flags)) {
		ret = mlx5dr_action_create_stcs(action, NULL);
		if (ret)
			goto free_action;
	}

	return action;

free_action:
	simple_free(action);
	return NULL;
}

struct mlx5dr_action *
mlx5dr_action_create_tag(struct mlx5dr_context *ctx,
			 uint32_t flags)
{
	struct mlx5dr_action *action;
	int ret;

	action = mlx5dr_action_create_generic(ctx, flags, MLX5DR_ACTION_TYP_TAG);
	if (!action)
		return NULL;

	if (mlx5dr_action_is_hws_flags(flags)) {
		ret = mlx5dr_action_create_stcs(action, NULL);
		if (ret)
			goto free_action;
	}

	return action;

free_action:
	simple_free(action);
	return NULL;
}
struct mlx5dr_action *
mlx5dr_action_create_aso_meter(struct mlx5dr_context *ctx,
			       struct mlx5dr_devx_obj *devx_obj,
			       uint8_t return_reg_id,
			       uint32_t flags)
{
	struct mlx5dr_action *action;
	int ret;

	if (mlx5dr_action_is_root_flags(flags)) {
		DR_LOG(ERR, "ASO flow meter action cannot be used for root");
		rte_errno = ENOTSUP;
		return NULL;
	}

	action = mlx5dr_action_create_generic(ctx, flags, MLX5DR_ACTION_TYP_ASO_METER);
	if (!action)
		return NULL;

	action->aso.devx_obj = devx_obj;
	action->aso.return_reg_id = return_reg_id;

	ret = mlx5dr_action_create_stcs(action, devx_obj);
	if (ret)
		goto free_action;

	return action;

free_action:
	simple_free(action);
	return NULL;
}

struct mlx5dr_action *
mlx5dr_action_create_counter(struct mlx5dr_context *ctx,
			     struct mlx5dr_devx_obj *obj,
			     uint32_t flags)
{
	struct mlx5dr_action *action;
	int ret;

	if (mlx5dr_action_is_hws_flags(flags) &&
	    mlx5dr_action_is_root_flags(flags)) {
		DR_LOG(ERR, "Same action cannot be used for root and non root");
		rte_errno = ENOTSUP;
		return NULL;
	}

	action = mlx5dr_action_create_generic(ctx, flags, MLX5DR_ACTION_TYP_CTR);
	if (!action)
		return NULL;

	if (mlx5dr_action_is_root_flags(flags)) {
		action->devx_obj = obj->obj;
	} else {
		ret = mlx5dr_action_create_stcs(action, obj);
		if (ret)
			goto free_action;
	}

	return action;

free_action:
	simple_free(action);
	return NULL;
}

static int mlx5dr_action_create_dest_vport_hws(struct mlx5dr_context *ctx,
					       struct mlx5dr_action *action,
					       uint32_t ib_port_num)
{
	struct mlx5dr_cmd_query_vport_caps vport_caps = {0};
	int ret;

	ret = mlx5dr_cmd_query_ib_port(ctx->ibv_ctx, &vport_caps, ib_port_num);
	if (ret) {
		DR_LOG(ERR, "Failed quering port %d\n", ib_port_num);
		return ret;
	}
	action->vport.vport_num = vport_caps.vport_num;
	action->vport.esw_owner_vhca_id = vport_caps.esw_owner_vhca_id;

	ret = mlx5dr_action_create_stcs(action, NULL);
		if (ret){
		DR_LOG(ERR, "Failed creating stc for port %d\n", ib_port_num);
		return ret;
	}

	return 0;
}

struct mlx5dr_action *
mlx5dr_action_create_dest_vport(struct mlx5dr_context *ctx,
				uint32_t ib_port_num,
				uint32_t flags)
{
	struct mlx5dr_action *action;
	int ret;

	if (!(flags & MLX5DR_ACTION_FLAG_HWS_FDB)) {
		DR_LOG(ERR, "Vport action is supported for FDB only\n");
		rte_errno = EINVAL;
		return NULL;
	}

	action = mlx5dr_action_create_generic(ctx, flags, MLX5DR_ACTION_TYP_VPORT);
	if (!action)
		return NULL;

	ret = mlx5dr_action_create_dest_vport_hws(ctx, action, ib_port_num);
	if (ret) {
		DR_LOG(ERR, "Failed to create vport action HWS\n");
		goto free_action;
	}

	return action;

free_action:
	simple_free(action);
	return NULL;
}

static int
mlx5dr_action_conv_reformat_type_to_action(uint32_t reformat_type,
					   uint32_t *action_type)
{
	switch (reformat_type) {
	case MLX5DR_ACTION_REFORMAT_TYPE_TNL_L2_TO_L2:
		*action_type = MLX5DR_ACTION_TYP_TNL_L2_TO_L2;
		break;
	case MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L2:
		*action_type = MLX5DR_ACTION_TYP_L2_TO_TNL_L2;
		break;
	case MLX5DR_ACTION_REFORMAT_TYPE_TNL_L3_TO_L2:
		*action_type = MLX5DR_ACTION_TYP_TNL_L3_TO_L2;
		break;
	case MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L3:
		*action_type = MLX5DR_ACTION_TYP_L2_TO_TNL_L3;
		break;
	default:
		DR_LOG(ERR, "Invalid reformat type requested");
		rte_errno = ENOTSUP;
		return rte_errno;
	}
	return 0;
}

static void
mlx5dr_action_conv_reformat_to_verbs(uint32_t action_type,
				     uint32_t *verb_reformat_type)
{
	switch (action_type) {
	case MLX5DR_ACTION_TYP_TNL_L2_TO_L2:
		*verb_reformat_type =
			MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TUNNEL_TO_L2;
		break;
	case MLX5DR_ACTION_TYP_L2_TO_TNL_L2:
		*verb_reformat_type =
			MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L2_TUNNEL;
		break;
	case MLX5DR_ACTION_TYP_TNL_L3_TO_L2:
		*verb_reformat_type =
			MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L3_TUNNEL_TO_L2;
		break;
	case MLX5DR_ACTION_TYP_L2_TO_TNL_L3:
		*verb_reformat_type =
			MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L3_TUNNEL;
		break;
	}
}

static void
mlx5dr_action_conv_flags_to_ft_type(uint32_t flags, uint32_t *ft_type)
{
	if (flags & MLX5DR_ACTION_FLAG_ROOT_RX) {
		*ft_type = MLX5_IB_UAPI_FLOW_TABLE_TYPE_NIC_RX;
	} else if (flags & MLX5DR_ACTION_FLAG_ROOT_TX) {
		*ft_type = MLX5_IB_UAPI_FLOW_TABLE_TYPE_NIC_TX;
	} else if (flags & MLX5DR_ACTION_FLAG_ROOT_FDB) {
		*ft_type = MLX5_IB_UAPI_FLOW_TABLE_TYPE_FDB;
	}
}

static int
mlx5dr_action_create_reformat_root(struct mlx5dr_action *action,
				   size_t data_sz,
				   void *data)
{
	enum mlx5dv_flow_table_type ft_type = 0; /*fix compilation warn*/
	uint32_t verb_reformat_type = 0;

	/* Convert action to FT type and verbs reformat type */
	mlx5dr_action_conv_flags_to_ft_type(action->flags, &ft_type);
	mlx5dr_action_conv_reformat_to_verbs(action->type, &verb_reformat_type);

	/* Create the reformat type for root table */
	action->flow_action =
		mlx5_glue->dv_create_flow_action_packet_reformat_root(action->ctx->ibv_ctx,
								      data_sz,
								      data,
								      verb_reformat_type,
								      ft_type);
	if (!action->flow_action) {
		rte_errno = errno;
		return rte_errno;
	}

	return 0;
}

static int mlx5dr_action_handle_reformat_args(struct mlx5dr_context *ctx,
					      size_t data_sz,
					      void *data,
					      uint32_t bulk_size,
					      struct mlx5dr_action *action)
{
	uint32_t args_log_size;
	int ret;

	if (data_sz % 2 != 0) {
		DR_LOG(ERR, "Data size should be multiply of 2");
		rte_errno = EINVAL;
		return rte_errno;
	}
	action->reformat.header_size = data_sz;

	args_log_size = mlx5dr_arg_data_size_to_arg_log_size(data_sz);
	if (args_log_size >= MLX5DR_ARG_CHUNK_SIZE_MAX) {
		DR_LOG(ERR, "Data size is bigger than supported");
		rte_errno = EINVAL;
		return rte_errno;
	}
	args_log_size += bulk_size;

	if (!mlx5dr_arg_is_valid_arg_request_size(ctx, args_log_size)) {
		DR_LOG(ERR, "Arg size %d does not fit FW requests",
		       args_log_size);
		rte_errno = EINVAL;
		return rte_errno;
	}

	action->reformat.arg_obj = mlx5dr_cmd_arg_create(ctx->ibv_ctx,
							 args_log_size,
							 ctx->pd_num);
	if (!action->reformat.arg_obj) {
		DR_LOG(ERR, "Failed to create arg for reformat");
		return rte_errno;
	}

	/* when INLINE need to write the arg data */
	if (action->flags & MLX5DR_ACTION_FLAG_SHARED) {
		ret = mlx5dr_arg_write_inline_arg_data(ctx,
						       action->reformat.arg_obj->id,
						       data,
						       data_sz);
		if (ret) {
			DR_LOG(ERR, "Failed to write inline arg for reformat");
			goto free_arg;
		}
	}

	return 0;

free_arg:
	mlx5dr_cmd_destroy_obj(action->reformat.arg_obj);
	return ret;
}

static int mlx5dr_action_handle_l2_to_tunnel_l2(struct mlx5dr_context *ctx,
						size_t data_sz,
						void *data,
						uint32_t bulk_size,
						struct mlx5dr_action *action)
{
	int ret;

	ret = mlx5dr_action_handle_reformat_args(ctx, data_sz, data, bulk_size,
						 action);
	if (ret) {
		DR_LOG(ERR, "Failed to create args for reformat");
		return ret;
	}

	ret = mlx5dr_action_create_stcs(action, NULL);
	if (ret) {
		DR_LOG(ERR, "Failed to create stc for reformat");
		goto free_arg;
	}

	return 0;

free_arg:
	mlx5dr_cmd_destroy_obj(action->reformat.arg_obj);
	return ret;
}

static int mlx5dr_action_get_shared_stc_offset(struct mlx5dr_context_common_res *common_res)
{
	return common_res->shared_stc->remove_header.offset;
}

static int mlx5dr_action_get_shared_stc_nic(struct mlx5dr_context *ctx,
				       uint8_t tbl_type)
{
	struct mlx5dr_cmd_stc_modify_attr stc_attr = {0};
	struct mlx5dr_action_shared_stc *shared_stc;
	int ret;

	pthread_spin_lock(&ctx->ctrl_lock);
	if (ctx->common_res[tbl_type].shared_stc) {
		rte_atomic32_add(&ctx->common_res[tbl_type].shared_stc->refcount, 1);
		pthread_spin_unlock(&ctx->ctrl_lock);
		return 0;
	}

	shared_stc = simple_calloc(1, sizeof(*shared_stc));
	if (!shared_stc) {
		DR_LOG(ERR, "Failed to allocate memory for shared STCs");
		rte_errno = ENOMEM;
		goto unlock_and_out;
	}

	stc_attr.action_type = MLX5_IFC_STC_ACTION_TYPE_HEADER_REMOVE;
	stc_attr.action_offset = MLX5DR_ACTION_OFFSET_DW5;
	stc_attr.remove_header.decap = 0;
	stc_attr.remove_header.start_anchor = MLX5_HEADER_ANCHOR_PACKET_START;
	stc_attr.remove_header.end_anchor = MLX5_HEADER_ANCHOR_IPV6_IPV4;

	ret = mlx5dr_action_alloc_single_stc(ctx, &stc_attr, tbl_type,
					     &shared_stc->remove_header);
	if (ret) {
		DR_LOG(ERR, "Failed to allocate shared decap l2 STC");
		goto free_shared_stc;
	}

	ctx->common_res[tbl_type].shared_stc = shared_stc;

	rte_atomic32_init(&ctx->common_res[tbl_type].shared_stc->refcount);
	rte_atomic32_set(&ctx->common_res[tbl_type].shared_stc->refcount, 1);

	pthread_spin_unlock(&ctx->ctrl_lock);

	return 0;

free_shared_stc:
	simple_free(shared_stc);
unlock_and_out:
	pthread_spin_unlock(&ctx->ctrl_lock);
	return rte_errno;
}

static void mlx5dr_action_put_shared_stc_nic(struct mlx5dr_context *ctx,
					  uint8_t tbl_type)
{
	struct mlx5dr_action_shared_stc *shared_stc;

	pthread_spin_lock(&ctx->ctrl_lock);
	if (!rte_atomic32_dec_and_test(&ctx->common_res[tbl_type].shared_stc->refcount)) {
		pthread_spin_unlock(&ctx->ctrl_lock);
		return;
	}

	shared_stc = ctx->common_res[tbl_type].shared_stc;

	mlx5dr_action_free_single_stc(ctx, tbl_type, &shared_stc->remove_header);
	simple_free(shared_stc);
	ctx->common_res[tbl_type].shared_stc = NULL;
	pthread_spin_unlock(&ctx->ctrl_lock);
}

static int mlx5dr_action_get_shared_stc(struct mlx5dr_action *action)
{
	struct mlx5dr_context *ctx = action->ctx;
	int ret;

	if (action->flags & MLX5DR_ACTION_FLAG_HWS_RX) {
		ret = mlx5dr_action_get_shared_stc_nic(ctx, MLX5DR_TABLE_TYPE_NIC_RX);
		if (ret) {
			DR_LOG(ERR, "Failed to allocate memory for RX shared STCs");
			return ret;
		}
	}

	if (action->flags & MLX5DR_ACTION_FLAG_HWS_TX) {
		ret = mlx5dr_action_get_shared_stc_nic(ctx, MLX5DR_TABLE_TYPE_NIC_TX);
		if (ret) {
			DR_LOG(ERR, "Failed to allocate memory for TX shared STCs");
			goto clean_nic_rx_stc;
		}
	}

	if (action->flags & MLX5DR_ACTION_FLAG_HWS_FDB) {
		ret = mlx5dr_action_get_shared_stc_nic(ctx, MLX5DR_TABLE_TYPE_FDB);
		if (ret) {
			DR_LOG(ERR, "Failed to allocate memory for FDB shared STCs");
			goto clean_nic_tx_stc;
		}
	}

	return 0;

clean_nic_tx_stc:
	if (action->flags & MLX5DR_ACTION_FLAG_HWS_TX)
		mlx5dr_action_put_shared_stc_nic(ctx, MLX5DR_TABLE_TYPE_NIC_TX);
clean_nic_rx_stc:
	if (action->flags & MLX5DR_ACTION_FLAG_HWS_RX)
		mlx5dr_action_put_shared_stc_nic(ctx, MLX5DR_TABLE_TYPE_NIC_RX);

	return ret;
}

static void mlx5dr_action_put_shared_stc(struct mlx5dr_action *action)
{
	struct mlx5dr_context *ctx = action->ctx;

	if (action->flags & MLX5DR_ACTION_FLAG_HWS_RX)
		mlx5dr_action_put_shared_stc_nic(ctx, MLX5DR_TABLE_TYPE_NIC_RX);

	if (action->flags & MLX5DR_ACTION_FLAG_HWS_TX)
		mlx5dr_action_put_shared_stc_nic(ctx, MLX5DR_TABLE_TYPE_NIC_TX);

	if (action->flags & MLX5DR_ACTION_FLAG_HWS_FDB)
		mlx5dr_action_put_shared_stc_nic(ctx, MLX5DR_TABLE_TYPE_FDB);
}

static int mlx5dr_action_handle_l2_to_tunnel_l3(struct mlx5dr_context *ctx,
						size_t data_sz,
						void *data,
						uint32_t bulk_size,
						struct mlx5dr_action *action)
{
	int ret;

	ret = mlx5dr_action_handle_reformat_args(ctx, data_sz, data, bulk_size,
						 action);
	if (ret) {
		DR_LOG(ERR, "Failed to create args for reformat");
		return ret;
	}

	/* the action is remove-l2-header + insert-l3-header */
	ret = mlx5dr_action_get_shared_stc(action);
	if (ret) {
		DR_LOG(ERR, "Failed to create remove stc for reformat");
		goto free_arg;
	}

	ret = mlx5dr_action_create_stcs(action, NULL);
	if (ret) {
		DR_LOG(ERR, "Failed to create insert stc for reformat");
		goto down_shared;
	}

	return 0;

down_shared:
	mlx5dr_action_put_shared_stc(action);
free_arg:
	mlx5dr_cmd_destroy_obj(action->reformat.arg_obj);
	return ret;
}

static void mlx5dr_action_prepare_decap_l3_actions(size_t data_sz,
						   uint8_t *mh_data,
						   int *num_of_actions)
{
	int actions;
	uint32_t i;

	/* Remove L2L3 outer headers */
	MLX5_SET(stc_ste_param_remove, mh_data, action_type,
		 MLX5_MODIFICATION_TYPE_REMOVE);
	MLX5_SET(stc_ste_param_remove, mh_data, decap, 0x1);
	MLX5_SET(stc_ste_param_remove, mh_data, remove_start_anchor,
		 MLX5_HEADER_ANCHOR_PACKET_START);
	MLX5_SET(stc_ste_param_remove, mh_data, remove_end_anchor,
		 MLX5_HEADER_ANCHOR_INNER_IPV6_IPV4);
	mh_data += MLX5DR_ACTION_DOUBLE_SIZE; /* assume every action is 2 dw */
	actions = 1;

	/* Add the new header using inline action 4Byte at a time, the header
	 * is added in reversed order to the beginning of the packet to avoid
	 * incorrect parsing by the HW. Since header is 14B or 18B an extra
	 * two bytes are padded and later removed.
	 */
	for (i = 0; i < data_sz / MLX5DR_ACTION_INLINE_DATA_SIZE + 1; i++) {
		MLX5_SET(stc_ste_param_insert, mh_data, action_type,
			 MLX5_MODIFICATION_TYPE_INSERT);
		MLX5_SET(stc_ste_param_insert, mh_data, inline_data, 0x1);
		MLX5_SET(stc_ste_param_insert, mh_data, insert_anchor,
			 MLX5_HEADER_ANCHOR_PACKET_START);
		MLX5_SET(stc_ste_param_insert, mh_data, insert_size, 2);
		mh_data += MLX5DR_ACTION_DOUBLE_SIZE;
		actions++;
	}

	/* Remove first 2 extra bytes */
	MLX5_SET(stc_ste_param_remove_words, mh_data, action_type,
		 MLX5_MODIFICATION_TYPE_REMOVE_WORDS);
	MLX5_SET(stc_ste_param_remove_words, mh_data, remove_start_anchor,
		 MLX5_HEADER_ANCHOR_PACKET_START);
	/* The hardware expects here size in words (2 bytes) */
	MLX5_SET(stc_ste_param_remove_words, mh_data, remove_size, 1);
	actions++;

	*num_of_actions = actions;
}

static int
mlx5dr_action_handle_tunnel_l3_to_l2(struct mlx5dr_context *ctx,
				     size_t data_sz,
				     uint32_t bulk_size,
				     struct mlx5dr_action *action)
{
	uint8_t mh_data[MLX5DR_ACTION_REFORMAT_DATA_SIZE] = {0};
	int num_of_actions;
	int mh_data_size;
	int ret;

	if (data_sz != MLX5DR_ACTION_HDR_LEN_L2 &&
	    data_sz != MLX5DR_ACTION_HDR_LEN_L2_W_VLAN) {
		DR_LOG(ERR, "data size is not supported for decap-l3\n");
		rte_errno = EINVAL;
		return rte_errno;
	}

	mlx5dr_action_prepare_decap_l3_actions(data_sz, mh_data, &num_of_actions);

	mh_data_size = num_of_actions * MLX5DR_MODIFY_ACTION_SIZE;

	ret = mlx5dr_pat_arg_create_modify_header(ctx, action, mh_data_size,
						  (__be64 *) mh_data, bulk_size);
	if (ret) {
		DR_LOG(ERR, "Failed allocating modify-header for decap-l3\n");
		return ret;
	}

	ret = mlx5dr_action_create_stcs(action, NULL);
	if (ret)
		goto free_mh_obj;

	return 0;

free_mh_obj:
	mlx5dr_pat_arg_destroy_modify_header(ctx, action);
	return ret;
}

static int
mlx5dr_action_create_reformat_hws(struct mlx5dr_context *ctx,
				  size_t data_sz,
				  void *data,
				  uint32_t bulk_size,
				  struct mlx5dr_action *action)
{
	int ret = ENOTSUP;

	switch (action->type) {
	case MLX5DR_ACTION_TYP_TNL_L2_TO_L2:
		ret = mlx5dr_action_create_stcs(action, NULL);
		break;
	case MLX5DR_ACTION_TYP_L2_TO_TNL_L2:
		ret = mlx5dr_action_handle_l2_to_tunnel_l2(ctx, data_sz, data, bulk_size, action);
		break;
	case MLX5DR_ACTION_TYP_L2_TO_TNL_L3:
		ret = mlx5dr_action_handle_l2_to_tunnel_l3(ctx, data_sz, data, bulk_size, action);
		break;
	case MLX5DR_ACTION_TYP_TNL_L3_TO_L2:
		ret = mlx5dr_action_handle_tunnel_l3_to_l2(ctx, data_sz, bulk_size, action);
		break;

	default:
		assert(false);
		rte_errno = ENOTSUP;
		return rte_errno;
	}

	return ret;
}

struct mlx5dr_action *
mlx5dr_action_create_reformat(struct mlx5dr_context *ctx,
			      enum mlx5dr_action_reformat_type reformat_type,
			      size_t data_sz,
			      void *inline_data,
			      uint32_t log_bulk_size,
			      uint32_t flags)
{
	struct mlx5dr_action *action;
	uint32_t action_type;
	int ret;

	ret = mlx5dr_action_conv_reformat_type_to_action(reformat_type, &action_type);
	if (ret)
		return NULL;

	action = mlx5dr_action_create_generic(ctx, flags, action_type);
	if (!action)
		return NULL;

	if (mlx5dr_action_is_root_flags(flags)) {
		if (log_bulk_size) {
			DR_LOG(ERR, "Bulk reformat not supported over root");
			rte_errno = ENOTSUP;
			goto free_action;
		}

		ret = mlx5dr_action_create_reformat_root(action, data_sz, inline_data);
		if (ret)
			goto free_action;

		return action;
	}

	if (!mlx5dr_action_is_hws_flags(flags) ||
	    ((flags & MLX5DR_ACTION_FLAG_SHARED) && log_bulk_size)) {
		DR_LOG(ERR, "Reformat flags don't fit HWS (flags: %x0x)\n",
			flags);
		rte_errno = EINVAL;
		goto free_action;
	}

	ret = mlx5dr_action_create_reformat_hws(ctx, data_sz, inline_data, log_bulk_size, action);
	if (ret) {
		DR_LOG(ERR, "Failed to create reformat.\n");
		rte_errno = EINVAL;
		goto free_action;
	}

	return action;

free_action:
	simple_free(action);
	return NULL;
}


static int
mlx5dr_action_create_modify_header_root(struct mlx5dr_action *action,
					size_t actions_sz,
					__be64 *actions)
{
	enum mlx5dv_flow_table_type ft_type = 0;

	mlx5dr_action_conv_flags_to_ft_type(action->flags, &ft_type);

	action->flow_action =
		mlx5_glue->dv_create_flow_action_modify_header_root(action->ctx->ibv_ctx,
								    actions_sz,
								    (uint64_t *)actions,
								    ft_type);
	if (!action->flow_action) {
		rte_errno = errno;
		return rte_errno;
	}

	return 0;
}

static enum mlx5dr_action_type mlx5dr_action_get_mh_action_type(__be64 pattern)
{
	u8 action_type;

	 action_type = MLX5_GET(set_action_in, &pattern, action_type);
	switch (action_type) {
	case MLX5_MODIFICATION_TYPE_SET:
		return MLX5DR_ACTION_TYP_MH_SET;
	case MLX5_MODIFICATION_TYPE_ADD:
		return MLX5DR_ACTION_TYP_MH_ADD;
	case MLX5_MODIFICATION_TYPE_COPY:
		return MLX5DR_ACTION_TYP_MH_COPY;
	default:
		assert(false);
		DR_LOG(ERR, "Unsupported action type: 0x%x\n", action_type);
		rte_errno = ENOTSUP;
		return MLX5DR_ACTION_TYP_MAX;
	}
}

static int mlx5dr_action_fill_modify_action(struct mlx5dr_action *action,
					     __be64 pattern)
{
	enum mlx5dr_action_type action_type;

	action_type = mlx5dr_action_get_mh_action_type(pattern);
	if (action_type == MLX5DR_ACTION_TYP_MAX)
		return ENOTSUP;

	action->type = action_type;
	switch (action_type) {
	case MLX5DR_ACTION_TYP_MH_SET:
		action->modify_action.src_field =
			MLX5_GET(set_action_in, &pattern, field);
		action->modify_action.src_offset =
			MLX5_GET(set_action_in, &pattern, offset);
		action->modify_action.length =
			MLX5_GET(set_action_in, &pattern, length);
		break;
	case MLX5DR_ACTION_TYP_MH_ADD:
		action->modify_action.src_field =
			MLX5_GET(set_action_in, &pattern, field);
		break;
	case MLX5DR_ACTION_TYP_MH_COPY:
		action->modify_action.src_field =
			MLX5_GET(copy_action_in, &pattern, src_field);
		action->modify_action.src_offset =
			MLX5_GET(copy_action_in, &pattern, src_offset);
		action->modify_action.length =
			MLX5_GET(copy_action_in, &pattern, length);
		action->modify_action.dst_field =
			MLX5_GET(copy_action_in, &pattern, dst_field);
		action->modify_action.dst_offset =
			MLX5_GET(copy_action_in, &pattern, dst_offset);
		break;
	default:
		rte_errno = ENOTSUP;
		assert(false);
		return ENOTSUP;
	}
	/* in shared(inline) action the data kept inline the struct */
	if (action->flags & MLX5DR_ACTION_FLAG_SHARED &&
	    action_type != MLX5DR_ACTION_TYP_MH_COPY)
		action->modify_action.data =
		htobe32(MLX5_GET(set_action_in, &pattern, data));

	return 0;
}

struct mlx5dr_action *
mlx5dr_action_create_modify_header(struct mlx5dr_context *ctx,
				   size_t pattern_sz,
				   __be64 pattern[],
				   uint32_t log_bulk_size,
				   uint32_t flags)
{
	struct mlx5dr_action *action;
	int ret;

	action = mlx5dr_action_create_generic(ctx, flags, MLX5DR_ACTION_TYP_MODIFY_HDR);
	if (!action)
		return NULL;

	if (mlx5dr_action_is_root_flags(flags)) {
		if (log_bulk_size) {
			DR_LOG(ERR, "Bulk modify-header not supported over root");
			rte_errno = ENOTSUP;
			goto free_action;
		}
		ret = mlx5dr_action_create_modify_header_root(action, pattern_sz, pattern);
		if (ret)
			goto free_action;

		return action;
	}

	if (!mlx5dr_action_is_hws_flags(flags) ||
	    ((flags & MLX5DR_ACTION_FLAG_SHARED) && log_bulk_size)) {
		DR_LOG(ERR, "flags don't fit hws (flags: %x0x, log_bulk_size: %d)\n",
			flags, log_bulk_size);
		rte_errno = EINVAL;
		goto free_action;
	}

	if (pattern_sz / MLX5DR_MODIFY_ACTION_SIZE == 1) {
		if (mlx5dr_action_fill_modify_action(action, pattern[0])) {
			DR_LOG(ERR, "Failed allocating modify-header one action\n");
			goto free_action;
		}
	} else {
		ret = mlx5dr_pat_arg_create_modify_header(ctx, action, pattern_sz,
							  pattern, log_bulk_size);
		if (ret) {
			DR_LOG(ERR, "Failed allocating modify-header\n");
			goto free_action;
		}
	}

	ret = mlx5dr_action_create_stcs(action, NULL);
	if (ret)
		goto free_mh_obj;

	return action;

free_mh_obj:
	mlx5dr_pat_arg_destroy_modify_header(ctx, action);
free_action:
	simple_free(action);
	return NULL;
}

static void mlx5dr_action_destroy_hws(struct mlx5dr_action *action)
{
	switch (action->type) {
	case MLX5DR_ACTION_TYP_TIR:
	case MLX5DR_ACTION_TYP_MISS:
	case MLX5DR_ACTION_TYP_TAG:
	case MLX5DR_ACTION_TYP_DROP:
	case MLX5DR_ACTION_TYP_CTR:
	case MLX5DR_ACTION_TYP_FT:
	case MLX5DR_ACTION_TYP_TNL_L2_TO_L2:
	case MLX5DR_ACTION_TYP_MH_SET:
	case MLX5DR_ACTION_TYP_MH_ADD:
	case MLX5DR_ACTION_TYP_MH_COPY:
	case MLX5DR_ACTION_TYP_ASO_METER:
		mlx5dr_action_destroy_stcs(action);
		break;
	case MLX5DR_ACTION_TYP_TNL_L3_TO_L2:
	case MLX5DR_ACTION_TYP_MODIFY_HDR:
		mlx5dr_action_destroy_stcs(action);
		mlx5dr_pat_arg_destroy_modify_header(action->ctx, action);
		break;
	case MLX5DR_ACTION_TYP_L2_TO_TNL_L3:
		mlx5dr_action_destroy_stcs(action);
		mlx5dr_action_put_shared_stc(action);
		mlx5dr_cmd_destroy_obj(action->reformat.arg_obj);
		break;
	case MLX5DR_ACTION_TYP_L2_TO_TNL_L2:
		mlx5dr_action_destroy_stcs(action);
		mlx5dr_cmd_destroy_obj(action->reformat.arg_obj);
		break;
	}
}

static void mlx5dr_action_destroy_root(struct mlx5dr_action *action)
{
	switch (action->type) {
	case MLX5DR_ACTION_TYP_TNL_L2_TO_L2:
	case MLX5DR_ACTION_TYP_L2_TO_TNL_L2:
	case MLX5DR_ACTION_TYP_TNL_L3_TO_L2:
	case MLX5DR_ACTION_TYP_L2_TO_TNL_L3:
	case MLX5DR_ACTION_TYP_MODIFY_HDR:
		ibv_destroy_flow_action(action->flow_action);
		break;
	}
}

int mlx5dr_action_destroy(struct mlx5dr_action *action)
{
	if (mlx5dr_action_is_root_flags(action->flags))
		mlx5dr_action_destroy_root(action);
	else
		mlx5dr_action_destroy_hws(action);

	simple_free(action);
	return 0;
}

/* called under pthread_spin_lock(&ctx->ctrl_lock) */
int mlx5dr_action_get_default_stc(struct mlx5dr_context *ctx,
				  uint8_t tbl_type)
{
	struct mlx5dr_cmd_stc_modify_attr stc_attr = {0};
	struct mlx5dr_action_default_stc *default_stc;
	int ret;

	if (ctx->common_res[tbl_type].default_stc) {
		ctx->common_res[tbl_type].default_stc->refcount++;
		return 0;
	}

	default_stc = simple_calloc(1, sizeof(*default_stc));
	if (!default_stc) {
		DR_LOG(ERR, "Failed to allocate memory for default STCs");
		rte_errno = ENOMEM;
		return rte_errno;
	}

	stc_attr.action_type = MLX5_IFC_STC_ACTION_TYPE_NOP;
	stc_attr.action_offset = MLX5DR_ACTION_OFFSET_DW0;
	ret = mlx5dr_action_alloc_single_stc(ctx, &stc_attr, tbl_type,
					     &default_stc->nop_ctr);
	if (ret) {
		DR_LOG(ERR, "Failed to allocate default counter STC");
		goto free_default_stc;
	}

	stc_attr.action_offset = MLX5DR_ACTION_OFFSET_DW5;
	ret = mlx5dr_action_alloc_single_stc(ctx, &stc_attr, tbl_type,
					     &default_stc->nop_dw5);
	if (ret) {
		DR_LOG(ERR, "Failed to allocate default NOP DW5 STC");
		goto free_nop_ctr;
	}

	stc_attr.action_offset = MLX5DR_ACTION_OFFSET_DW6;
	ret = mlx5dr_action_alloc_single_stc(ctx, &stc_attr, tbl_type,
					     &default_stc->nop_dw6);
	if (ret) {
		DR_LOG(ERR, "Failed to allocate default NOP DW6 STC");
		goto free_nop_dw5;
	}

	stc_attr.action_offset = MLX5DR_ACTION_OFFSET_DW7;
	ret = mlx5dr_action_alloc_single_stc(ctx, &stc_attr, tbl_type,
					     &default_stc->nop_dw7);
	if (ret) {
		DR_LOG(ERR, "Failed to allocate default NOP DW7 STC");
		goto free_nop_dw6;
	}

	stc_attr.action_type = MLX5_IFC_STC_ACTION_TYPE_ALLOW;
	stc_attr.action_offset = MLX5DR_ACTION_OFFSET_HIT;
	ret = mlx5dr_action_alloc_single_stc(ctx, &stc_attr, tbl_type,
					     &default_stc->default_hit);
	if (ret) {
		DR_LOG(ERR, "Failed to allocate default allow STC");
		goto free_nop_dw7;
	}

	ctx->common_res[tbl_type].default_stc = default_stc;
	ctx->common_res[tbl_type].default_stc->refcount++;

	return 0;

free_nop_dw7:
	mlx5dr_action_free_single_stc(ctx, tbl_type, &default_stc->nop_dw7);
free_nop_dw6:
	mlx5dr_action_free_single_stc(ctx, tbl_type, &default_stc->nop_dw6);
free_nop_dw5:
	mlx5dr_action_free_single_stc(ctx, tbl_type, &default_stc->nop_dw5);
free_nop_ctr:
	mlx5dr_action_free_single_stc(ctx, tbl_type, &default_stc->nop_ctr);
free_default_stc:
	simple_free(default_stc);
	return rte_errno;
}

void mlx5dr_action_put_default_stc(struct mlx5dr_context *ctx,
				   uint8_t tbl_type)
{
	struct mlx5dr_action_default_stc *default_stc;

	default_stc = ctx->common_res[tbl_type].default_stc;

	default_stc = ctx->common_res[tbl_type].default_stc;
	if (--default_stc->refcount)
		return;

	mlx5dr_action_free_single_stc(ctx, tbl_type, &default_stc->default_hit);
	mlx5dr_action_free_single_stc(ctx, tbl_type, &default_stc->nop_dw7);
	mlx5dr_action_free_single_stc(ctx, tbl_type, &default_stc->nop_dw6);
	mlx5dr_action_free_single_stc(ctx, tbl_type, &default_stc->nop_dw5);
	mlx5dr_action_free_single_stc(ctx, tbl_type, &default_stc->nop_ctr);
	simple_free(default_stc);
	ctx->common_res[tbl_type].default_stc = NULL;
}

static void mlx5dr_action_modify_write(struct mlx5dr_send_engine *queue,
				       uint32_t arg_idx,
				       uint8_t *arg_data,
				       uint16_t num_of_actions)
{
	mlx5dr_arg_write(queue, NULL, arg_idx, arg_data,
			 num_of_actions * MLX5DR_MODIFY_ACTION_SIZE);
}

void
mlx5dr_action_prepare_decap_l3_data(uint8_t *src, uint8_t *dst,
				    uint16_t num_of_actions)
{
	uint8_t *e_src;
	int i;

	/* num_of_actions = remove l3l2 + 4/5 inserts + remove extra 2 bytes
	 * copy from end of src to the start of dst.
	 * move to the end, 2 is the leftover from 14B or 18B
	 */
	if (num_of_actions == DECAP_L3_NUM_ACTIONS_W_NO_VLAN)
		e_src = src + MLX5DR_ACTION_HDR_LEN_L2;
	else
		e_src = src + MLX5DR_ACTION_HDR_LEN_L2_W_VLAN;

	/* move dst over the first remove action + zero data */
	dst += MLX5DR_ACTION_DOUBLE_SIZE;
	/* move dst over the first insert ctrl action */
	dst += MLX5DR_ACTION_DOUBLE_SIZE / 2;
	/* actions:
	 * no vlan: r_h-insert_4b-insert_4b-insert_4b-insert_4b-remove_2b.
	 * with vlan: r_h-insert_4b-insert_4b-insert_4b-insert_4b-insert_4b-remove_2b.
	 * the loop is without the last insertion.
	 */
	for (i = 0; i < num_of_actions - 3; i++) {
		e_src -= MLX5DR_ACTION_INLINE_DATA_SIZE;
		memcpy(dst, e_src, MLX5DR_ACTION_INLINE_DATA_SIZE); /* data */
		dst += MLX5DR_ACTION_DOUBLE_SIZE;
	}
	/* copy the last 2 bytes after a gap of 2 bytes which will be removed */
	e_src -= MLX5DR_ACTION_INLINE_DATA_SIZE / 2;
	dst += MLX5DR_ACTION_INLINE_DATA_SIZE / 2;
	memcpy(dst, e_src, 2);
}

int mlx5dr_actions_quick_apply(struct mlx5dr_send_engine *queue,
			       struct mlx5dr_context_common_res *common_res,
			       struct mlx5dr_wqe_gta_ctrl_seg *wqe_ctrl,
			       struct mlx5dr_wqe_gta_data_seg_ste *wqe_data,
			       struct mlx5dr_rule_action rule_actions[],
			       uint8_t num_actions,
			       enum mlx5dr_table_type tbl_type,
			       bool is_jumbo)
{
	struct mlx5dr_action_default_stc *default_stc = common_res->default_stc;
	uint32_t stc_arr[MLX5DR_ACTION_STC_IDX_MAX] = {0};
	uint32_t *raw_wqe = (uint32_t *)wqe_data;
	struct mlx5dr_action *action;
	bool require_double = false;
	int stc_idx;
	int i;

	/* Set the default STC, current HW checks require all action fields to
	 * be covered. This is needed to prevent invalid action creation using
	 * multiple writes to the same STE.
	 */

	wqe_ctrl->op_dirix = htobe32(MLX5DR_WQE_GTA_OP_ACTIVATE << 28);
	stc_arr[MLX5DR_ACTION_STC_IDX_CTRL] = default_stc->nop_ctr.offset;
	stc_arr[MLX5DR_ACTION_STC_IDX_DW5] = default_stc->nop_dw5.offset;
	stc_arr[MLX5DR_ACTION_STC_IDX_DW6] = default_stc->nop_dw6.offset;
	stc_arr[MLX5DR_ACTION_STC_IDX_DW7] = default_stc->nop_dw7.offset;
	stc_arr[MLX5DR_ACTION_STC_IDX_HIT] = default_stc->default_hit.offset;

	/* Perform lazy/quick action apply:
	 * - Without action pattern (always assume dependent write)
	 * - Support 0 additional action STEs
	 * - Location are hardcoded, double, single, hit
	 */
	for (i = 0; i < num_actions; i++) {
		uint32_t exe_aso_ctrl;
		uint32_t arg_idx;
		uint8_t arg_sz;

		action = rule_actions[i].action;
		stc_idx = action->stc[tbl_type].offset;

		switch (action->type) {
		case MLX5DR_ACTION_TYP_TAG:
			raw_wqe[MLX5DR_ACTION_OFFSET_DW5] = htobe32(rule_actions[i].tag.value);
			stc_arr[MLX5DR_ACTION_STC_IDX_DW5] = stc_idx;
			break;
		case MLX5DR_ACTION_TYP_CTR:
			raw_wqe[MLX5DR_ACTION_OFFSET_DW0] = htobe32(rule_actions[i].counter.offset);
			stc_arr[MLX5DR_ACTION_STC_IDX_CTRL] = stc_idx;
			break;
		case MLX5DR_ACTION_TYP_TNL_L2_TO_L2:
			stc_arr[MLX5DR_ACTION_STC_IDX_DW5] = stc_idx;
			break;
		case MLX5DR_ACTION_TYP_L2_TO_TNL_L2:
			arg_sz =
				1 << mlx5dr_arg_data_size_to_arg_log_size(action->reformat.header_size);
			/* Argument offset multiple on number of actions */
			arg_idx = rule_actions[i].reformat.offset * arg_sz;
			raw_wqe[MLX5DR_ACTION_OFFSET_DW7] = htobe32(arg_idx);
			stc_arr[MLX5DR_ACTION_STC_IDX_DW6] = stc_idx;
			require_double = true;

			if (!(action->flags & MLX5DR_ACTION_FLAG_SHARED))
				mlx5dr_arg_write(queue, NULL,
						 action->reformat.arg_obj->id + arg_idx,
						 rule_actions[i].reformat.data,
						 action->reformat.header_size);
			break;
		case MLX5DR_ACTION_TYP_TNL_L3_TO_L2:
			arg_sz = 1 << mlx5dr_arg_get_arg_log_size(action->modify_header.num_of_actions);
			arg_idx = rule_actions[i].reformat.offset * arg_sz;
			raw_wqe[MLX5DR_ACTION_OFFSET_DW7] = htobe32(arg_idx);
			stc_arr[MLX5DR_ACTION_STC_IDX_DW6] = stc_idx;
			require_double = true;

			if (!(action->flags & MLX5DR_ACTION_FLAG_SHARED))
				mlx5dr_arg_decapl3_write(queue,
							 action->modify_header.arg_obj->id + arg_idx,
							 rule_actions[i].reformat.data,
							 action->modify_header.num_of_actions);
			break;
		case MLX5DR_ACTION_TYP_L2_TO_TNL_L3:
			/* Remove L2 header, shared stc - single */
			stc_arr[MLX5DR_ACTION_STC_IDX_DW5] =
				mlx5dr_action_get_shared_stc_offset(common_res);

			/* Insert with pointer (arg-id) - double */
			arg_sz =
				1 << mlx5dr_arg_data_size_to_arg_log_size(action->reformat.header_size);
			arg_idx = rule_actions[i].reformat.offset * arg_sz;
			raw_wqe[MLX5DR_ACTION_OFFSET_DW7] = htobe32(arg_idx);
			stc_arr[MLX5DR_ACTION_STC_IDX_DW6] = stc_idx;
			require_double = true;

			if (!(action->flags & MLX5DR_ACTION_FLAG_SHARED))
				mlx5dr_arg_write(queue, NULL,
						 action->reformat.arg_obj->id + arg_idx,
						 rule_actions[i].reformat.data,
						 action->reformat.header_size);
			break;
		case MLX5DR_ACTION_TYP_MODIFY_HDR:
			arg_sz = 1 << mlx5dr_arg_get_arg_log_size(action->modify_header.num_of_actions);
			/* Argument offset multiple with number of args per these actions */
			arg_idx = rule_actions[i].modify_header.offset * arg_sz;
			raw_wqe[MLX5DR_ACTION_OFFSET_DW7] = htobe32(arg_idx);
			stc_arr[MLX5DR_ACTION_STC_IDX_DW6] = stc_idx;
			require_double = true;

			if (!(action->flags & MLX5DR_ACTION_FLAG_SHARED))
				mlx5dr_action_modify_write(queue,
							   action->modify_header.arg_obj->id + arg_idx,
							   rule_actions[i].modify_header.data,
							   action->modify_header.num_of_actions);
			break;
		case MLX5DR_ACTION_TYP_MH_ADD:
		case MLX5DR_ACTION_TYP_MH_SET:
			stc_arr[MLX5DR_ACTION_STC_IDX_DW6] = stc_idx;
			require_double = true;

			if (!(action->flags & MLX5DR_ACTION_FLAG_SHARED))
				/* modify_header.data: | 4 bytes pattern | 4 bytes data| */
				raw_wqe[MLX5DR_ACTION_OFFSET_DW7] =
				*(uint32_t *)&rule_actions[i].modify_header.data[4];
			else
				raw_wqe[MLX5DR_ACTION_OFFSET_DW7] = action->modify_action.data;
			break;
		case MLX5DR_ACTION_TYP_MH_COPY:
			stc_arr[MLX5DR_ACTION_STC_IDX_DW6] = stc_idx;
			require_double = true;
			break;
		case MLX5DR_ACTION_TYP_ASO_METER:
			/* exe_aso_ctrl format:
			 * [STC only and reserved bits 29b][init_color 2b][meter_id 1b]
			 */
			exe_aso_ctrl = rule_actions[i].aso_meter.offset % MLX5_ASO_METER_NUM_PER_OBJ;
			exe_aso_ctrl |= rule_actions[i].aso_meter.init_color <<
				MLX5DR_ACTION_ASO_METER_INIT_COLOR_OFFSET;
			/* aso_object_offset format: [24B] */
			raw_wqe[MLX5DR_ACTION_OFFSET_DW6] = htobe32(rule_actions[i].aso_meter.offset /
				MLX5_ASO_METER_NUM_PER_OBJ);
			raw_wqe[MLX5DR_ACTION_OFFSET_DW7] = htobe32(exe_aso_ctrl);
			stc_arr[MLX5DR_ACTION_STC_IDX_DW6] = stc_idx;
			require_double = true;
			break;
		case MLX5DR_ACTION_TYP_DROP:
		case MLX5DR_ACTION_TYP_FT:
		case MLX5DR_ACTION_TYP_TIR:
		case MLX5DR_ACTION_TYP_MISS:
		case MLX5DR_ACTION_TYP_VPORT:
			stc_arr[MLX5DR_ACTION_STC_IDX_HIT] = stc_idx;
			break;
		default:
			DR_LOG(ERR, "Found unsupported action type: %d", action->type);
			rte_errno = ENOTSUP;
			return rte_errno;
		}
	}

	/* Set shared STC for combo1 and combo2 */
	wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_CTRL] = htobe32(stc_arr[MLX5DR_ACTION_STC_IDX_CTRL]);
	wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_HIT] = htobe32(stc_arr[MLX5DR_ACTION_STC_IDX_HIT]);

	if (is_jumbo) {
		/* With jumbo we temporarily support counter and HIT action */
		wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_DW5] = htobe32(default_stc->nop_dw5.offset);
		wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_DW6] = htobe32(default_stc->nop_dw6.offset);
		wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_DW7] = htobe32(default_stc->nop_dw7.offset);
		wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_CTRL] |= htobe32(MLX5DR_ACTION_STC_IDX_LAST_COMBO2 << 29);
		return 0;
	}

	if (require_double) {
		/* Combo1: Set 1 single (DW5) and 1 double (DW6-7) actions */
		wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_DW5] = htobe32(stc_arr[MLX5DR_ACTION_STC_IDX_DW5]);
		wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_DW6] = htobe32(stc_arr[MLX5DR_ACTION_STC_IDX_DW6]);
		wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_CTRL] |= htobe32(MLX5DR_ACTION_STC_IDX_LAST_COMBO1 << 29);
	} else {
		/* Combo2: Set 3 single (DW5-7) actions */
		wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_DW5] = htobe32(stc_arr[MLX5DR_ACTION_STC_IDX_DW5]);
		wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_DW6] = htobe32(stc_arr[MLX5DR_ACTION_STC_IDX_DW6]);
		wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_DW7] = htobe32(stc_arr[MLX5DR_ACTION_STC_IDX_DW7]);
		wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_CTRL] |= htobe32(MLX5DR_ACTION_STC_IDX_LAST_COMBO2 << 29);
	}

	return 0;
}
