/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_internal.h"

static int mlx5dr_rule_create_hws(struct mlx5dr_rule *rule,
				   struct rte_flow_item items[],
				   struct mlx5dr_rule_attr *attr,
				   struct mlx5dr_rule_action rule_actions[],
				   uint8_t num_actions)
{
	struct mlx5dr_send_engine_post_attr send_attr = {0};
	struct mlx5dr_matcher *matcher = rule->matcher;
	struct mlx5dr_context *ctx = matcher->tbl->ctx;
	struct mlx5dr_wqe_gta_data_seg_ste *wqe_data;
	struct mlx5dr_wqe_gta_ctrl_seg *wqe_ctrl;
	struct mlx5dr_send_engine_post_ctrl ctrl;
	size_t wqe_len;

	if (unlikely(mlx5dr_send_engine_full(&ctx->send_queue[attr->queue_id]))) {
		rte_errno = -EBUSY;
		return rte_errno;
	}

	mlx5dr_send_engine_inc_rule(&ctx->send_queue[attr->queue_id]);

	/* Check if there are pending work completions */

	/* Check if there is room in queue */

	rule->status = MLX5DR_RULE_STATUS_CREATING;

	/* Allocate WQE */
	ctrl = mlx5dr_send_engine_post_start(&ctx->send_queue[attr->queue_id]);
	mlx5dr_send_engine_post_req_wqe(&ctrl, (void *)&wqe_ctrl, &wqe_len);
	mlx5dr_send_engine_post_req_wqe(&ctrl, (void *)&wqe_data, &wqe_len);

	/* Prepare rule insert WQE */
	wqe_ctrl->op_dirix = htobe32(MLX5DR_WQR_GTA_OP_ACTIVATE << 28);
	wqe_ctrl->stc_ix[0] = htobe32(num_actions << 29 |
				      rule_actions->action->stc_rx.offset);

	/* Create tag directly on WQE and backup it on the rule for deletion */
	mlx5dr_definer_create_tag(items,
				  matcher->fc,
				  matcher->fc_sz,
				  (uint8_t *)wqe_data->tag);

	memcpy(rule->match_tag, wqe_data->tag, MLX5DR_MATCH_TAG_SZ);

	send_attr.rule = rule;
	send_attr.opcode = 0x2c;
	send_attr.len = 48 + 64;
	send_attr.notify_hw = attr->burst;
	send_attr.user_data = attr->user_data;
	send_attr.id = rule->matcher->rx.rtc->id;
	mlx5dr_send_engine_post_end(&ctrl, &send_attr);

	return 0;
}

static int mlx5dr_rule_destroy_hws(struct mlx5dr_rule *rule,
				    struct mlx5dr_rule_attr *attr)
{
	struct mlx5dr_context *ctx = rule->matcher->tbl->ctx;
	struct mlx5dr_send_engine_post_attr send_attr = {0};
	struct mlx5dr_wqe_gta_data_seg_ste *wqe_data;
	struct mlx5dr_wqe_gta_ctrl_seg *wqe_ctrl;
	struct mlx5dr_send_engine_post_ctrl ctrl;
	size_t wqe_len;


	/* In case the rule is not completed */
	if (rule->status != MLX5DR_RULE_STATUS_CREATED) {
		if (rule->status == MLX5DR_RULE_STATUS_CREATING) {
			rte_errno = EBUSY;
			return rte_errno;
		}

		/* In case the rule is not completed */
		if (rule->status == MLX5DR_RULE_STATUS_FAILED) {
			// TODO generate comp / free resources
			return 0;
		}
	}

	if (unlikely(mlx5dr_send_engine_full(&ctx->send_queue[attr->queue_id]))) {
		rte_errno = EBUSY;
		return rte_errno;
	}

	mlx5dr_send_engine_inc_rule(&ctx->send_queue[attr->queue_id]);

	/* Check if there are pending work completions */

	rule->status = MLX5DR_RULE_STATUS_DELETING;

	/* Check if there is room in queue */

	/* Allocate WQE */
	ctrl = mlx5dr_send_engine_post_start(&ctx->send_queue[attr->queue_id]);
	mlx5dr_send_engine_post_req_wqe(&ctrl, (void *)&wqe_ctrl, &wqe_len);
	mlx5dr_send_engine_post_req_wqe(&ctrl, (void *)&wqe_data, &wqe_len);

	wqe_ctrl->op_dirix = htobe32(MLX5DR_WQR_GTA_OP_DEACTIVATE << 28);

	memcpy(wqe_data->tag, rule->match_tag, MLX5DR_MATCH_TAG_SZ);

	send_attr.rule = rule;
	send_attr.opcode = 0x2c;
	send_attr.len = 48 + 64;
	send_attr.notify_hw = attr->burst;
	send_attr.user_data = attr->user_data;

	mlx5dr_send_engine_post_end(&ctrl, &send_attr);

	return 0;
}

static int mlx5dr_rule_create_root(struct mlx5dr_rule *rule,
				   struct rte_flow_item items[],
				   struct mlx5dr_rule_action rule_actions[],
				   uint8_t num_actions)
{
	struct mlx5dv_flow_matcher *dv_matcher = rule->matcher->dv_matcher;
	struct mlx5dv_flow_match_parameters *value;
	struct mlx5_flow_attr flow_attr = {0};
	struct mlx5dv_flow_action_attr *attr;
	struct rte_flow_error rte_error;
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

	flow_attr.tbl_type = rule->matcher->tbl->type;

	ret = flow_dv_translate_items_hws(items, &flow_attr, value->match_buf,
					  MLX5_SET_MATCHER_HS_V, NULL,
					  &match_criteria,
					  &rte_error);
	if (ret) {
		DRV_LOG(ERR, "Failed to convert items to PRM [%s]", rte_error.message);
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

int mlx5dr_rule_create(struct mlx5dr_matcher *matcher,
		       struct rte_flow_item items[],
		       struct mlx5dr_rule_action rule_actions[],
		       uint8_t num_of_actions,
		       struct mlx5dr_rule_attr *attr,
		       struct mlx5dr_rule *rule_handle)
{
	rule_handle->matcher = matcher;

	if (unlikely(!attr->user_data)) {
		rte_errno = EINVAL;
		return rte_errno;
	}

	if (mlx5dr_table_is_root(matcher->tbl))
		return mlx5dr_rule_create_root(rule_handle,
					       items,
					       rule_actions,
					       num_of_actions);

	return mlx5dr_rule_create_hws(rule_handle,
				      items,
				      attr,
				      rule_actions,
				      num_of_actions);
}

int mlx5dr_rule_destroy(struct mlx5dr_rule *rule,
			struct mlx5dr_rule_attr *attr)
{
	if (unlikely(!attr->user_data)) {
		rte_errno = EINVAL;
		return rte_errno;
	}

	if (mlx5dr_table_is_root(rule->matcher->tbl))
		return mlx5dr_rule_destroy_root(rule);

	return mlx5dr_rule_destroy_hws(rule, attr);
}

size_t mlx5dr_rule_get_handle_size(void)
{
	return sizeof(struct mlx5dr_rule);
}