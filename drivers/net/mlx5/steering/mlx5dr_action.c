/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_internal.h"

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
#ifndef HAVE_MLX5_DR_CREATE_ACTION_DEFAULT_MISS
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

static int
mlx5dr_action_alloc_single_stc(struct mlx5dr_context *ctx,
			       struct mlx5dr_cmd_stc_modify_attr *stc_attr,
			       uint32_t table_type,
			       struct mlx5dr_pool_chunk *stc)
{
	struct mlx5dr_pool *stc_pool = ctx->stc_pool[table_type];
	struct mlx5dr_devx_obj *devx_obj;
	int ret;

	ret = mlx5dr_pool_chunk_alloc(stc_pool, stc);
	if (ret) {
		DR_LOG(ERR, "Failed to allocate single action STC");
		return ret;
	}

	stc_attr->stc_offset = stc->offset;

	devx_obj = mlx5dr_pool_chunk_get_base_devx_obj(stc_pool, stc);

	ret = mlx5dr_cmd_stc_modify(devx_obj, stc_attr);
	if (ret) {
		DR_LOG(ERR, "Failed to modify STC to type %d", stc_attr->action_type);
		goto free_chunk;
	}

	return 0;

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

	mlx5dr_pool_chunk_free(stc_pool, stc);
}

static void mlx5dr_action_fill_stc_attr(struct mlx5dr_action *action,
					struct mlx5dr_devx_obj *obj,
					struct mlx5dr_cmd_stc_modify_attr *attr)
{
	switch (action->type) {
	case MLX5DR_ACTION_TYP_TAG:
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_TAG;
		attr->action_offset = MLX5DR_ACTION_OFFSET_DW7;
		break;
	case MLX5DR_ACTION_TYP_DROP:
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_DROP;
		attr->action_offset = MLX5DR_ACTION_OFFSET_HIT;
		break;
	case MLX5DR_ACTION_TYP_MISS:
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_ALLOW;
		attr->action_offset = MLX5DR_ACTION_OFFSET_HIT;
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
	case MLX5DR_ACTION_TYP_MODIFY_HDR:
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_ACC_MODIFY_LIST;
		attr->action_offset = MLX5DR_ACTION_OFFSET_DW5;
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
		attr->remove_header.start_anchor = MLX5_HEADER_START_OF_PACKET;
		attr->remove_header.end_anchor = MLX5_HEADER_ANCHOR_INNER_MAC;
		break;
	case MLX5DR_ACTION_TYP_L2_TO_TNL_L2:
		attr->action_type = MLX5_IFC_STC_ACTION_TYPE_HEADER_INSERT;
		attr->action_offset = MLX5DR_ACTION_OFFSET_DW5;
		attr->reformat.encap = 1;
		attr->reformat.insert_anchor = MLX5_HEADER_START_OF_PACKET;
		attr->reformat.arg_id = action->reformat.arg_obj->id;
		attr->reformat.header_size = action->reformat.header_size;
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

	/* Allocate STC for RX */
	if (action->flags & MLX5DR_ACTION_FLAG_HWS_RX) {
		ret = mlx5dr_action_alloc_single_stc(ctx, &stc_attr,
						     MLX5DR_TABLE_TYPE_NIC_RX,
						     &action->stc_rx);
		if (ret)
			goto out_err;
	}

	/* Allocate STC for TX */
	if (action->flags & MLX5DR_ACTION_FLAG_HWS_TX) {
		ret = mlx5dr_action_alloc_single_stc(ctx, &stc_attr,
						     MLX5DR_TABLE_TYPE_NIC_TX,
						     &action->stc_tx);
		if (ret)
		       goto free_stc_rx;
	}

	/* TODO FDB */

	return 0;

free_stc_rx:
	if (action->flags & MLX5DR_ACTION_FLAG_HWS_RX)
		mlx5dr_action_free_single_stc(ctx, MLX5DR_TABLE_TYPE_NIC_RX, &action->stc_rx);
out_err:
	return rte_errno;
}

static void
mlx5dr_action_destroy_stcs(struct mlx5dr_action *action)
{
	struct mlx5dr_context *ctx = action->ctx;

	if (action->flags & MLX5DR_ACTION_FLAG_HWS_TX)
		mlx5dr_action_free_single_stc(ctx, MLX5DR_TABLE_TYPE_NIC_TX, &action->stc_tx);

	if (action->flags & MLX5DR_ACTION_FLAG_HWS_RX)
		mlx5dr_action_free_single_stc(ctx, MLX5DR_TABLE_TYPE_NIC_RX, &action->stc_rx);
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
			     enum mlx5dr_action_flags flags,
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
				enum mlx5dr_action_flags flags)
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
			      enum mlx5dr_action_flags flags)
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
			       enum mlx5dr_action_flags flags)
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
				  enum mlx5dr_action_flags flags)
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
			 enum mlx5dr_action_flags flags)
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
mlx5dr_action_create_counter(struct mlx5dr_context *ctx,
			     struct mlx5dr_devx_obj *obj,
			     enum mlx5dr_action_flags flags)
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
	case MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L2:
		*verb_reformat_type =
			MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L2_TUNNEL;
		break;
	case MLX5DR_ACTION_REFORMAT_TYPE_TNL_L3_TO_L2:
		*verb_reformat_type =
			MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L3_TUNNEL_TO_L2;
		break;
	case MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L3:
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
	uint32_t verb_reformat_type;

	/* Convert action to FT type and verbs reformat type */
	mlx5dr_action_conv_flags_to_ft_type(action->flags, &ft_type);
	mlx5dr_action_conv_reformat_to_verbs(action->type, &verb_reformat_type);

	/* Create the reformat type for root table */
	action->flow_action =
		mlx5dv_create_flow_action_packet_reformat(action->ctx->ibv_ctx,
							  data_sz, data,
							  verb_reformat_type,
							  ft_type);
	if (!action->flow_action) {
		rte_errno = errno;
		return rte_errno;
	}

	return 0;
}

static int mlx5dr_action_handle_l2_to_tunnel_l2(struct mlx5dr_context *ctx,
						size_t data_sz,
						void *data,
						uint32_t bulk_size,
						struct mlx5dr_action *action)
{
	uint32_t args_log_size;
	int ret;

	if (data_sz % 2 != 0) {
		DR_LOG(ERR, "data size should be multiply of 2");
		rte_errno = EINVAL;
		return rte_errno;
	}
	action->reformat.header_size = data_sz;

	args_log_size = mlx5dr_arg_data_size_to_arg_log_size(data_sz);
	if (args_log_size >= MLX5DR_ARG_CHUNK_SIZE_MAX) {
		DR_LOG(ERR, "data size is bigger than supported");
		rte_errno = EINVAL;
		return rte_errno;
	}
	args_log_size += bulk_size;
	action->reformat.arg_obj = mlx5dr_cmd_arg_create(ctx->ibv_ctx,
							 args_log_size,
							 ctx->pd_num);
	if (!action->reformat.arg_obj) {
		DR_LOG(ERR, "failed to create arg for reformat");
		return rte_errno;
	}

	/* when INLINE need to write the arg data */
	if (action->flags & MLX5DR_ACTION_FLAG_INLINE)
		ret = mlx5dr_arg_write_inline_arg_data(action, data);
	if (ret) {
		DR_LOG(ERR, "failed to write inline arg for reformat");
		goto free_arg;
	}

	ret = mlx5dr_action_create_stcs(action, NULL);
	if (ret) {
		DR_LOG(ERR, "failed to create stc for reformat");
		goto free_arg;
	}

	return 0;

free_arg:
	mlx5dr_cmd_destroy_obj(action->reformat.arg_obj);
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
			      void *data,
			      uint32_t bulk_size,
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
		if (bulk_size) {
			DR_LOG(ERR, "Bulk reformat not supported over root");
			rte_errno = ENOTSUP;
			goto free_action;
		}

		ret = mlx5dr_action_create_reformat_root(action, data_sz, data);
		if (ret)
			goto free_action;

		return action;
	}

	if (!mlx5dr_action_is_hws_flags(flags)||
	    ((flags & MLX5DR_ACTION_FLAG_INLINE) && bulk_size)) {
		DR_LOG(ERR, "reformat flags don't fit hws (flags: %x0x)\n",
			flags);
		rte_errno = EINVAL;
		goto free_action;
	}

	ret = mlx5dr_action_create_reformat_hws(ctx, data_sz, data, bulk_size, action);
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
	enum mlx5dv_flow_table_type ft_type;

	mlx5dr_action_conv_flags_to_ft_type(action->flags, &ft_type);

	action->flow_action =
		mlx5dv_create_flow_action_modify_header(action->ctx->ibv_ctx,
							actions_sz,
							(uint64_t *)actions,
							ft_type);
	if (!action->flow_action) {
		rte_errno = errno;
		return rte_errno;
	}

	return 0;
}

struct mlx5dr_action *
mlx5dr_action_create_modify_header(struct mlx5dr_context *ctx,
				   size_t pattern_sz,
				   __be64 pattern[],
				   uint32_t bulk_size,
				   uint32_t flags)
{
	struct mlx5dr_action *action;
	int ret;

	action = mlx5dr_action_create_generic(ctx, flags, MLX5DR_ACTION_TYP_MODIFY_HDR);
	if (!action)
		return NULL;

	if (mlx5dr_action_is_root_flags(flags)) {
		if (bulk_size) {
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
	    ((flags & MLX5DR_ACTION_FLAG_INLINE) && bulk_size)) {
		DR_LOG(ERR, "flags don't fit hws (flags: %x0x, bulk_size: %d)\n",
			flags, bulk_size);
		rte_errno = EINVAL;
		goto free_action;
	}

	ret = mlx5dr_pat_arg_create_modify_header(ctx, action, pattern_sz,
						  pattern, bulk_size);
	if (ret) {
		DR_LOG(ERR, "Failed allocating modify-header\n");
		goto free_action;
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
	case MLX5DR_ACTION_TYP_MISS:
	case MLX5DR_ACTION_TYP_TAG:
	case MLX5DR_ACTION_TYP_DROP:
	case MLX5DR_ACTION_TYP_QP:
	case MLX5DR_ACTION_TYP_TNL_L2_TO_L2:
		mlx5dr_action_destroy_stcs(action);
		break;
	case MLX5DR_ACTION_TYP_MODIFY_HDR:
		mlx5dr_pat_arg_destroy_modify_header(action->ctx, action);
		mlx5dr_action_destroy_stcs(action);
		break;
	case MLX5DR_ACTION_TYP_L2_TO_TNL_L2:
		mlx5dr_cmd_destroy_obj(action->reformat.arg_obj);
		mlx5dr_action_destroy_stcs(action);
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

int mlx5dr_action_get_default_stc(struct mlx5dr_context *ctx,
				  uint8_t tbl_type)
{
	struct mlx5dr_cmd_stc_modify_attr stc_attr = {0};
	struct mlx5dr_action_default_stc *default_stc;
	int ret;

	pthread_spin_lock(&ctx->ctrl_lock);

	if (ctx->default_stc[tbl_type]) {
		ctx->default_stc[tbl_type]->refcount++;
		pthread_spin_unlock(&ctx->ctrl_lock);
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
					     &default_stc->nop_double);
	if (ret) {
		DR_LOG(ERR, "Failed to allocate default double STC");
		goto free_nop_ctr;
	}

	stc_attr.action_offset = MLX5DR_ACTION_OFFSET_DW7;
	ret = mlx5dr_action_alloc_single_stc(ctx, &stc_attr, tbl_type,
					     &default_stc->nop_single);
	if (ret) {
		DR_LOG(ERR, "Failed to allocate default single STC");
		goto free_nop_double;
	}

	stc_attr.action_offset = MLX5DR_ACTION_OFFSET_HIT;
	ret = mlx5dr_action_alloc_single_stc(ctx, &stc_attr, tbl_type,
					     &default_stc->default_hit);
	if (ret) {
		DR_LOG(ERR, "Failed to allocate default allow STC");
		goto free_nop_single;
	}

	ctx->default_stc[tbl_type] = default_stc;
	ctx->default_stc[tbl_type]->refcount++;

	pthread_spin_unlock(&ctx->ctrl_lock);

	return 0;

free_nop_single:
	mlx5dr_action_free_single_stc(ctx, tbl_type, &default_stc->nop_single);
free_nop_double:
	mlx5dr_action_free_single_stc(ctx, tbl_type, &default_stc->nop_double);
free_nop_ctr:
	mlx5dr_action_free_single_stc(ctx, tbl_type, &default_stc->nop_ctr);
free_default_stc:
	simple_free(default_stc);
	pthread_spin_unlock(&ctx->ctrl_lock);
	return rte_errno;
}

void mlx5dr_action_put_default_stc(struct mlx5dr_context *ctx,
				   uint8_t tbl_type)
{
	struct mlx5dr_action_default_stc *default_stc;

	default_stc = ctx->default_stc[tbl_type];

	pthread_spin_lock(&ctx->ctrl_lock);

	default_stc = ctx->default_stc[tbl_type];
	if (--default_stc->refcount) {
		pthread_spin_unlock(&ctx->ctrl_lock);
		return;
	}

	mlx5dr_action_free_single_stc(ctx, tbl_type, &default_stc->default_hit);
	mlx5dr_action_free_single_stc(ctx, tbl_type, &default_stc->nop_single);
	mlx5dr_action_free_single_stc(ctx, tbl_type, &default_stc->nop_double);
	mlx5dr_action_free_single_stc(ctx, tbl_type, &default_stc->nop_ctr);
	simple_free(default_stc);
	ctx->default_stc[tbl_type] = NULL;

	pthread_spin_unlock(&ctx->ctrl_lock);
}

static void mlx5dr_action_arg_write(struct mlx5dr_send_engine *queue,
				    struct mlx5dr_rule *rule,
				    uint32_t arg_idx,
				    uint8_t *arg_data,
				    uint16_t num_of_actions)
{
	mlx5dr_arg_write(queue, rule, arg_idx, arg_data,
			 num_of_actions * MLX5DR_MODIFY_ACTION_SIZE);
}

int mlx5dr_actions_quick_apply(struct mlx5dr_send_engine *queue,
			       struct mlx5dr_rule *rule,
			       struct mlx5dr_action_default_stc *default_stc,
			       struct mlx5dr_wqe_gta_ctrl_seg *wqe_ctrl,
			       struct mlx5dr_wqe_gta_data_seg_ste *wqe_data,
			       struct mlx5dr_rule_action rule_actions[],
			       uint8_t num_actions,
			       bool is_rx)
{
	uint32_t *raw_wqe = (uint32_t *)wqe_data;
	struct mlx5dr_action *action;
	int stc_idx;
	int i;

	/* Set the default STC, current HW checks require all action fields to
	 * be covered. This is needed to prevent invalid action creation using
	 * multiple writes to the same STE.
	 *
	 * Current combination allows CTR(0) + Double/Single(5) + Single(7)
	 */
	wqe_ctrl->op_dirix = htobe32(MLX5DR_WQE_GTA_OP_ACTIVATE << 28);
	wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_CTR] = htobe32(default_stc->nop_ctr.offset);
	wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_DOUBLE] = htobe32(default_stc->nop_double.offset);
	wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_SINGLE] = htobe32(default_stc->nop_single.offset);
	wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_HIT] = htobe32(default_stc->default_hit.offset);

	/* Perform lazy/quick action apply:
	 * - Without action pattern (always assume dependent write)
	 * - Support 0 additional action STEs
	 * - Location are hardcoded, double, single, hit
	 * - One single action, one double action and jump
	 */
	for (i = 0; i < num_actions; i++) {
		uint32_t arg_idx;
		uint8_t arg_sz;

		action = rule_actions[i].action;
		stc_idx = is_rx ? action->stc_rx.offset : action->stc_tx.offset;

		switch (action->type) {
		case MLX5DR_ACTION_TYP_TAG:
			raw_wqe[MLX5DR_ACTION_OFFSET_DW5] = htobe32(rule_actions[i].tag.value);
			wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_SINGLE] = htobe32(stc_idx);
			break;
		case MLX5DR_ACTION_TYP_CTR:
			raw_wqe[MLX5DR_ACTION_OFFSET_DW0] = htobe32(rule_actions[i].counter.offset);
			wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_CTR] = htobe32(stc_idx);
			break;
		case MLX5DR_ACTION_TYP_TNL_L2_TO_L2:
			wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_SINGLE] = htobe32(stc_idx);
			break;
		case MLX5DR_ACTION_TYP_L2_TO_TNL_L2:
			arg_sz =
				1 << mlx5dr_arg_data_size_to_arg_log_size(action->reformat.header_size);
			/* Argument base + offset based on number of actions */
			arg_idx = action->reformat.arg_obj->id;
			arg_idx += rule_actions[i].reformat.offset * arg_sz;
			raw_wqe[MLX5DR_ACTION_OFFSET_DW6] = htobe32(arg_idx);
			wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_DOUBLE] = htobe32(stc_idx);

			if (!(action->flags & MLX5DR_ACTION_FLAG_INLINE))
				mlx5dr_arg_write(queue, rule, arg_idx,
						 rule_actions[i].reformat.data,
						 action->reformat.header_size);
			break;
		case MLX5DR_ACTION_TYP_TNL_L3_TO_L2:
			/* Modify header: remove L2L3 + insert inline */
			raw_wqe[MLX5DR_ACTION_OFFSET_DW6] = htobe32(rule_actions[i].reformat.offset);
			wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_DOUBLE] = htobe32(stc_idx);
			// TODO if not inline mlx5dr_send_arg()
			assert(0);
			break;
		case MLX5DR_ACTION_TYP_L2_TO_TNL_L3:
			/* Remove L2 header - single
			 * Insert with pointer - double
			 */
			assert(0);
			break;
		case MLX5DR_ACTION_TYP_MODIFY_HDR:
			arg_sz = 1 << mlx5dr_arg_get_arg_log_size(action->modify_header.num_of_actions);
			/* Argument base + offset based on number of actions */
			arg_idx = action->modify_header.arg_obj->id;
			arg_idx += rule_actions[i].modify_header.offset * arg_sz;
			raw_wqe[MLX5DR_ACTION_OFFSET_DW6] = htobe32(arg_idx);
			wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_DOUBLE] = htobe32(stc_idx);

			if (!(action->flags & MLX5DR_ACTION_FLAG_INLINE))
				mlx5dr_action_arg_write(queue, rule, arg_idx,
							rule_actions[i].modify_header.data,
							action->modify_header.num_of_actions);
			break;
		case MLX5DR_ACTION_TYP_DROP:
		case MLX5DR_ACTION_TYP_FT:
		case MLX5DR_ACTION_TYP_TIR:
		case MLX5DR_ACTION_TYP_MISS:
			wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_HIT] = htobe32(stc_idx);
			break;
		default:
			DR_LOG(ERR, "Found unsupported action type: %d", action->type);
			rte_errno = ENOTSUP;
			return rte_errno;
		}
	}

	/* Set Fixed number of actions */
	wqe_ctrl->stc_ix[MLX5DR_ACTION_STC_IDX_CTR] |= htobe32(MLX5DR_ACTION_STC_IDX_MAX << 29);

	return 0;
}
