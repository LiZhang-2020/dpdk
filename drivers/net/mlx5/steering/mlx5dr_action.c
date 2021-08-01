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
		case DR_ACTION_TYP_CTR:
			attr[i].type = MLX5DV_FLOW_ACTION_COUNTERS_DEVX;
			attr[i].obj = action->devx_obj;

			if (rule_actions[i].counter.offset) {
				attr_aux[i].type = MLX5_FLOW_ACTION_COUNTER_OFFSET;
				attr_aux[i].offset = rule_actions[i].counter.offset;
			}
			break;
#endif
		default:
			DRV_LOG(ERR, "Found unsupported action type: %d", action->type);
			rte_errno = ENOTSUP;
			return rte_errno;
		}
	}

	return 0;
}

static int
mlx5dr_action_alloc_single_stc(struct mlx5dr_context *ctx,
			       uint32_t obj_id,
			       uint32_t table_type,
			       uint32_t action_type,
			       struct mlx5dr_pool_chunk *stc)
{
	struct mlx5dr_pool *stc_pool = ctx->stc_pool[table_type];
	struct mlx5dr_cmd_stc_modify_attr stc_attr = {0};
	struct mlx5dr_devx_obj *devx_obj;
	int ret;

	/* Check if valid action */
	if (!action_type) {
		DRV_LOG(ERR, "Unsupported action");
		rte_errno = ENOTSUP;
		return rte_errno;
	}

	ret = mlx5dr_pool_chunk_alloc(stc_pool, stc);
	if (ret) {
		DRV_LOG(ERR, "Failed to allocate single action STC");
		return ret;
	}

	stc_attr.stc_offset = stc->offset;
	stc_attr.action_type = action_type;
	stc_attr.id = obj_id;
	devx_obj = mlx5dr_pool_chunk_get_base_devx_obj(stc_pool, stc);

	ret = mlx5dr_cmd_stc_modify(devx_obj, &stc_attr);
	if (ret) {
		DRV_LOG(ERR, "Failed to modify STC to type %d", action_type);
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

static int
mlx5dr_action_create_stcs(struct mlx5dr_action *action,
			  struct mlx5dr_devx_obj *obj)
{
	struct mlx5dr_context *ctx = action->ctx;
	uint32_t stc_type_rx, stc_type_tx;
	uint32_t obj_id;
	int ret;

	switch (action->type) {
	case MLX5DR_ACTION_TYP_CTR:
		stc_type_rx = MLX5_IFC_STC_ACTION_TYPE_COUNTER;
		stc_type_tx = MLX5_IFC_STC_ACTION_TYPE_COUNTER;
		break;
	case MLX5DR_ACTION_TYP_DROP:
		stc_type_rx = MLX5_IFC_STC_ACTION_TYPE_DROP;
		stc_type_tx = MLX5_IFC_STC_ACTION_TYPE_DROP;
		break;
	case MLX5DR_ACTION_TYP_FT:
		stc_type_rx = MLX5_IFC_STC_ACTION_TYPE_JUMP_TO_FT;
		stc_type_tx = MLX5_IFC_STC_ACTION_TYPE_JUMP_TO_FT;
		break;
	case MLX5DR_ACTION_TYP_MISS:
		stc_type_rx = MLX5_IFC_STC_ACTION_TYPE_DROP;
		stc_type_tx = MLX5_IFC_STC_ACTION_TYPE_WIRE;
		break;
	case MLX5DR_ACTION_TYP_TAG:
		stc_type_rx = MLX5_IFC_STC_ACTION_TYPE_TAG;
		stc_type_tx = MLX5_IFC_STC_ACTION_TYPE_NONE;
		break;
	case MLX5DR_ACTION_TYP_TIR:
		stc_type_rx = MLX5_IFC_STC_ACTION_TYPE_JUMP_TO_TIR;
		stc_type_tx = MLX5_IFC_STC_ACTION_TYPE_NONE;
		break;
	default:
		DRV_LOG(ERR, "Invalid action type %d", action->type);
		rte_errno = ENOTSUP;
		assert(0);
		return rte_errno;
	}

	obj_id = obj ? obj->id : 0;

	/* Allocate STC for RX */
	if (action->flags & MLX5DR_ACTION_FLAG_HWS_RX) {
		ret = mlx5dr_action_alloc_single_stc(ctx, obj_id,
						     MLX5DR_TABLE_TYPE_NIC_RX,
						     stc_type_rx,
						     &action->stc_rx);
		if (ret)
		      goto out_err;
	}

	/* Allocate STC for TX */
	if (action->flags & MLX5DR_ACTION_FLAG_HWS_TX) {
		ret = mlx5dr_action_alloc_single_stc(ctx, obj_id,
						     MLX5DR_TABLE_TYPE_NIC_TX,
						     stc_type_tx,
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
		DRV_LOG(ERR, "Action flags must specify root or non root (HWS)");
		rte_errno = ENOTSUP;
		return NULL;
	}

	action = simple_calloc(1, sizeof(*action));
	if (!action) {
		DRV_LOG(ERR, "Failed to allocate memory for action [%d]", action_type);
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

	if (mlx5dr_table_is_root(tbl)) {
		DRV_LOG(ERR, "Root table cannot be set as destination");
		rte_errno = ENOTSUP;
		return NULL;
	}

	if (mlx5dr_action_is_hws_flags(flags) &&
	    mlx5dr_action_is_root_flags(flags)) {
		DRV_LOG(ERR, "Same action cannot be used for root and non root");
		rte_errno = ENOTSUP;
		return NULL;
	}

	action = mlx5dr_action_create_generic(ctx, flags, MLX5DR_ACTION_TYP_FT);
	if (!action)
		return NULL;

	if (mlx5dr_action_is_root_flags(flags)) {
		action->devx_obj = tbl->ft->obj;
	} else {
		if (flags & MLX5DR_ACTION_FLAG_HWS_RX)
			action->stc_rx = tbl->rx.stc;

		if (flags & MLX5DR_ACTION_FLAG_HWS_TX)
			action->stc_tx = tbl->tx.stc;

		/* TODO Add support for FDB */
	}

	return action;
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
		DRV_LOG(ERR, "Same action cannot be used for root and non root");
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
mlx5dr_action_create_drop(struct mlx5dr_context *ctx,
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
		DRV_LOG(ERR, "Invalid reformat type requested");
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
	enum mlx5dv_flow_table_type ft_type;
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

	if (mlx5dr_action_is_hws_flags(flags)) {
		// TODO support reformat on HWS
		DRV_LOG(ERR, "reformat not supported on HWS yet");
		rte_errno = ENOTSUP;
		return NULL;
	}

	if (mlx5dr_action_is_root_flags(flags)) {
		if (bulk_size) {
			DRV_LOG(ERR, "Bulk reformat not supported over root");
			rte_errno = ENOTSUP;
			goto free_action;
		}

		ret = mlx5dr_action_create_reformat_root(action, data_sz, data);
		if (ret)
			goto free_action;
	}

	return action;

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
