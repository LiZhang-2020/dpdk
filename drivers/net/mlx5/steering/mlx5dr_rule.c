/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_internal.h"

static int mlx5dr_rule_create_root(struct mlx5dr_rule *rule,
				   struct rte_flow_item items[],
				   struct mlx5dr_rule_action rule_actions[],
				   uint8_t num_actions)
{
	struct mlx5dv_flow_matcher *dv_matcher = rule->matcher->dv_matcher;
	struct mlx5dv_flow_match_parameters *value;
	struct mlx5dv_flow_action_attr *attr;
	uint8_t match_criteria;
	int ret;

	attr = simple_calloc(num_actions, sizeof(*attr));
	if (!attr) {
		rte_errno = ENOMEM;
		return rte_errno;
	}

	value = simple_calloc(1, MLX5_ST_SZ_BYTES(fte_match_param) +
		      	      offsetof(struct mlx5dv_flow_match_parameters, match_buf));
	if (!value) {
		rte_errno = ENOMEM;
		goto free_attr;
	}

	ret = mlx5dr_matcher_conv_items_to_prm(value->match_buf,
					       items,
					       &match_criteria,
					       true);
	if (ret) {
		DRV_LOG(ERR, "Failed to convert items to PRM");
		goto free_value;
	}

	/* Convert actions to verb action attr */
	ret = mlx5dr_action_root_build_attr(rule_actions, num_actions, attr);
	if (ret)
		goto free_value;

	/* Create verb action */
	value->match_sz = MLX5_ST_SZ_BYTES(fte_match_param);
	rule->flow = mlx5dv_create_flow(dv_matcher, value, num_actions, attr);
	if (!rule->flow)
		goto free_value;

	simple_free(value);
	simple_free(attr);

	return 0;

free_value:
	simple_free(value);
free_attr:
	simple_free(attr);
	return rte_errno;
}

static int mlx5dr_rule_destroy_root(struct mlx5dr_rule *rule)
{
	return ibv_destroy_flow(rule->flow);
}

size_t mlx5dr_rule_get_handle_size(void)
{
	return sizeof(struct mlx5dr_rule);
}

int mlx5dr_rule_create(struct mlx5dr_matcher *matcher,
		       struct rte_flow_item items[],
		       struct mlx5dr_rule_action rule_actions[],
		       uint8_t num_of_actions,
		       struct mlx5dr_rule_attr *attr,
		       struct mlx5dr_rule *rule_handle)
{
	rule_handle->matcher = matcher;

	DRV_LOG(ERR, "This is TEMP for the warn %p\n", (void *)attr);

	if (mlx5dr_table_is_root(matcher->tbl))
		return mlx5dr_rule_create_root(rule_handle,
					       items,
					       rule_actions,
					       num_of_actions);

	rte_errno = ENOTSUP;
	return rte_errno;
}

int mlx5dr_rule_destroy(struct mlx5dr_rule *rule,
			struct mlx5dr_rule_attr *attr)
{
	DRV_LOG(ERR, "This is TEMP for the warn %p\n", (void *)attr);

	if (mlx5dr_table_is_root(rule->matcher->tbl))
		return mlx5dr_rule_destroy_root(rule);

	rte_errno = ENOTSUP;
	return rte_errno;
}
