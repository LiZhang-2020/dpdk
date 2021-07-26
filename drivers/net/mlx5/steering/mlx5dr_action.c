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
			attr[i].type = MLX5DV_FLOW_ACTION_DEST_DEVX;
			attr[i].obj = action->devx_obj;
			break;
#ifndef HAVE_MLX5_DR_CREATE_ACTION_DEFAULT_MISS
		case MLX5DR_ACTION_TYP_MISS:
			attr[i].type = MLX5DV_FLOW_ACTION_DEFAULT_MISS;
			break;
#endif
		case MLX5DR_ACTION_TYP_DROP:
			attr[i].type = MLX5DV_FLOW_ACTION_DROP;
			break;
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
		DRV_LOG(ERR, "Unsupported action\n");
		rte_errno = ENOTSUP;
		return rte_errno;
	}

	ret = mlx5dr_pool_chunk_alloc(stc_pool, stc);
	if (ret) {
		DRV_LOG(ERR, "Failed to allocate single action STC\n");
		return ret;
	}

	stc_attr.stc_offset = stc->offset;
	stc_attr.action_type = action_type;
	stc_attr.id = obj_id;
	devx_obj = mlx5dr_pool_chunk_get_base_devx_obj(stc_pool, stc);

	ret = mlx5dr_cmd_stc_modify(devx_obj, &stc_attr);
	if (ret) {
		DRV_LOG(ERR, "Failed to modify STC to type %d\n", action_type);
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
	case MLX5DR_ACTION_TYP_QP:
		stc_type_rx = MLX5_IFC_STC_ACTION_TYPE_JUMP_TO_TIR;
		stc_type_tx = MLX5_IFC_STC_ACTION_TYPE_NONE;
		break;
	default:
		DRV_LOG(ERR, "Invalid action type %d\n", action->type);
		rte_errno = ENOTSUP;
		assert(0);
		return rte_errno;
	}

	obj_id = obj ? obj->id : 0;

	/* Allocate STC for RX */
	if (action->flags & MLX5DR_ACTION_FLAG_HWS_NIC_RX) {
		ret = mlx5dr_action_alloc_single_stc(ctx, obj_id,
						     MLX5DR_TABLE_TYPE_NIC_RX,
						     stc_type_rx,
						     &action->stc_rx);
		if (ret)
		      goto out_err;
	}

	/* Allocate STC for TX */
	if (action->flags & MLX5DR_ACTION_FLAG_HWS_NIC_TX) {
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
	if (action->flags & MLX5DR_ACTION_FLAG_HWS_NIC_RX)
		mlx5dr_action_free_single_stc(ctx, MLX5DR_TABLE_TYPE_NIC_RX, &action->stc_rx);
out_err:
	return rte_errno;
}

static void
mlx5dr_action_destroy_stcs(struct mlx5dr_action *action)
{
	struct mlx5dr_context *ctx = action->ctx;

	if (action->flags & MLX5DR_ACTION_FLAG_HWS_NIC_TX)
		mlx5dr_action_free_single_stc(ctx, MLX5DR_TABLE_TYPE_NIC_TX, &action->stc_tx);

	if (action->flags & MLX5DR_ACTION_FLAG_HWS_NIC_RX)
		mlx5dr_action_free_single_stc(ctx, MLX5DR_TABLE_TYPE_NIC_RX, &action->stc_rx);
}

static struct mlx5dr_action *
mlx5dr_action_create_generic(struct mlx5dr_context *ctx,
			     enum mlx5dr_action_flags flags,
			     enum mlx5dr_action_type action_type)
{
	struct mlx5dr_action *action;

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
				enum mlx5dr_action_flags flags,
				struct mlx5dr_table *tbl)
{
	struct mlx5dr_action *action;

	if (mlx5dr_table_is_root(tbl)) {
		DRV_LOG(ERR, "Root table cannot be set as destination");
		rte_errno = ENOTSUP;
		return NULL;
	}

	action = mlx5dr_action_create_generic(ctx, flags, MLX5DR_ACTION_TYP_FT);
	if (!action)
		return NULL;


	if (flags & MLX5DR_ACTION_FLAG_ROOT_ONLY) {
		action->devx_obj = tbl->ft->obj;
	} else {
		if (flags & MLX5DR_ACTION_FLAG_HWS_NIC_RX)
			action->stc_rx = tbl->rx.stc;

		if (flags & MLX5DR_ACTION_FLAG_HWS_NIC_TX)
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

	action = mlx5dr_action_create_generic(ctx, flags, MLX5DR_ACTION_TYP_QP);
	if (!action)
		return NULL;

	if (flags & MLX5DR_ACTION_FLAG_ROOT_ONLY) {
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

	if (!(flags & MLX5DR_ACTION_FLAG_ROOT_ONLY)) {
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

	if (!(flags & MLX5DR_ACTION_FLAG_ROOT_ONLY)) {
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

	if (!(flags & MLX5DR_ACTION_FLAG_ROOT_ONLY)) {
		ret = mlx5dr_action_create_stcs(action, NULL);
		if (ret)
			goto free_action;
	}

	return action;

free_action:
	simple_free(action);
	return NULL;
}

int mlx5dr_action_destroy(struct mlx5dr_action *action)
{
	if (action->flags & MLX5DR_ACTION_FLAG_ROOT_ONLY)
		goto free_action;

	switch (action->type) {
	case MLX5DR_ACTION_TYP_MISS:
	case MLX5DR_ACTION_TYP_TAG:
	case MLX5DR_ACTION_TYP_DROP:
	case MLX5DR_ACTION_TYP_QP:
		mlx5dr_action_destroy_stcs(action);
		break;
	default:
		rte_errno = ENOTSUP;
		assert(0);
		return rte_errno;
	}

free_action:
	simple_free(action);
	return 0;
}
