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
			attr[i].obj = action->tbl->ft->obj;
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

static struct mlx5dr_action *
mlx5dr_action_create_generic(enum mlx5dr_action_type action_type)
{
	struct mlx5dr_action *action;

	action = simple_calloc(1, sizeof(*action));
	if (!action) {
		DRV_LOG(ERR, "Failed to allocate memory for action [%d]", action_type);
		rte_errno = ENOMEM;
		return NULL;
	}

	action->type = action_type;

	return action;
}

struct mlx5dr_action *
mlx5dr_action_create_table_dest(struct mlx5dr_table *tbl,
				enum mlx5dr_action_flags flags)
{
	struct mlx5dr_action *action;

	if (flags) {
		rte_errno = ENOTSUP;
		return NULL;
	}

	if (mlx5dr_table_is_root(tbl)) {
		DRV_LOG(ERR, "Root table cannot be set as destination");
		rte_errno = ENOTSUP;
		return NULL;
	}

	action = mlx5dr_action_create_generic(MLX5DR_ACTION_TYP_FT);
	if (!action)
		return NULL;

	action->tbl = tbl;

	return action;
}

struct mlx5dr_action *
mlx5dr_action_create_drop(struct mlx5dr_context *ctx,
			  enum mlx5dr_action_flags flags)
{
	struct mlx5dr_action *action;

	if (flags) {
		rte_errno = ENOTSUP;
		return NULL;
	}

	DRV_LOG(ERR, "This is TEMP for the warn %p\n", (void *)ctx);

	action = mlx5dr_action_create_generic(MLX5DR_ACTION_TYP_DROP);
	if (!action)
		return NULL;

	// TODO create STC?

	return action;
}

struct mlx5dr_action *
mlx5dr_action_create_default_miss(struct mlx5dr_context *ctx,
				  enum mlx5dr_action_flags flags)
{
	struct mlx5dr_action *action;

	if (flags) {
		rte_errno = ENOTSUP;
		return NULL;
	}

	DRV_LOG(ERR, "This is TEMP for the warn %p\n", (void *)ctx);

	action = mlx5dr_action_create_generic(MLX5DR_ACTION_TYP_MISS);
	if (!action)
		return NULL;

	// TODO create STC?

	return action;
}

void mlx5dr_action_destroy(struct mlx5dr_action *action)
{
	simple_free(action);
}
