/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_internal.h"

static void mlx5dr_rule_skip(struct mlx5dr_match_template *mt,
			     const struct rte_flow_item *items,
			     bool *skip_rx, bool *skip_tx)
{
	const struct rte_flow_item_ethdev *v;
	const struct flow_hw_port_info *vport;

	/* By default FDB rules are added to both RX and TX */
	*skip_rx = false;
	*skip_tx = false;

	if (mt->item_flags & MLX5_FLOW_ITEM_REPRESENTED_PORT) {
		v = items[mt->vport_item_id].spec;
		vport = flow_hw_conv_port_id(v->port_id);
		if (unlikely(!vport)) {
			DR_LOG(ERR, "Fail to map port ID %d, ignoring", v->port_id);
			return;
		}

		if (!vport->is_wire)
			/* Match vport ID is not WIRE -> Skip RX */
			*skip_rx = true;
		else
			/* Match vport ID is WIRE -> Skip TX */
			*skip_tx = true;
	}
}

static void mlx5dr_rule_init_dep_wqe(struct mlx5dr_send_ring_dep_wqe *dep_wqe,
				     struct mlx5dr_rule *rule,
				     const struct rte_flow_item *items,
				     void *user_data)
{
	struct mlx5dr_matcher *matcher = rule->matcher;
	struct mlx5dr_table *tbl = matcher->tbl;
	bool skip_rx, skip_tx;

	dep_wqe->rule = rule;
	dep_wqe->user_data = user_data;

	switch (tbl->type) {
	case MLX5DR_TABLE_TYPE_NIC_RX:
	case MLX5DR_TABLE_TYPE_NIC_TX:
		dep_wqe->rtc_0 = matcher->match_ste.rtc_0->id;
		dep_wqe->retry_rtc_0 = matcher->col_matcher ?
				       matcher->col_matcher->match_ste.rtc_0->id : 0;
		dep_wqe->rtc_1 = 0;
		dep_wqe->retry_rtc_1 = 0;
		break;

	case MLX5DR_TABLE_TYPE_FDB:
		mlx5dr_rule_skip(matcher->mt[0], items, &skip_rx, &skip_tx);

		if (!skip_rx) {
			dep_wqe->rtc_0 = matcher->match_ste.rtc_0->id;
			dep_wqe->retry_rtc_0 = matcher->col_matcher ?
					       matcher->col_matcher->match_ste.rtc_0->id : 0;
		}

		if (!skip_tx) {
			dep_wqe->rtc_1 = matcher->match_ste.rtc_1->id;
			dep_wqe->retry_rtc_1 = matcher->col_matcher ?
					       matcher->col_matcher->match_ste.rtc_1->id : 0;
		}

		break;

	default:
		assert(false);
		break;
	}
}

static void mlx5dr_rule_gen_comp(struct mlx5dr_send_engine *queue,
				 struct mlx5dr_rule *rule,
				 bool err,
				 void *user_data,
				 enum mlx5dr_rule_status rule_status_on_succ)
{
	enum rte_flow_op_status comp_status;

	if (!err){
		comp_status = RTE_FLOW_OP_SUCCESS;
		rule->status = rule_status_on_succ;
	} else {
		comp_status = RTE_FLOW_OP_ERROR;
		rule->status = MLX5DR_RULE_STATUS_FAILED;
	}

	mlx5dr_send_engine_inc_rule(queue);
	mlx5dr_send_engine_gen_comp(queue, user_data, comp_status);
}

static int mlx5dr_rule_create_hws(struct mlx5dr_rule *rule,
				  uint8_t mt_idx,
				  const struct rte_flow_item items[],
				  struct mlx5dr_rule_attr *attr,
				  struct mlx5dr_rule_action rule_actions[],
				  uint8_t num_actions)
{
	struct mlx5dr_matcher *matcher = rule->matcher;
	struct mlx5dr_send_ring_dep_wqe *dep_wqe;
	struct mlx5dr_table *tbl = matcher->tbl;
	struct mlx5dr_context *ctx = tbl->ctx;
	struct mlx5dr_send_engine *queue;
	bool is_jumbo;

	queue = &ctx->send_queue[attr->queue_id];
	if (unlikely(mlx5dr_send_engine_err(queue))) {
		rte_errno = EIO;
		return rte_errno;
	}

	mlx5dr_send_engine_inc_rule(queue);

	/* Initialise rule */
	rule->rtc_0 = 0;
	rule->rtc_1 = 0;
	rule->pending_wqes = 0;
	rule->status = MLX5DR_RULE_STATUS_CREATING;

	/* Today we assume all rules have a dependent WQE.
	 * This is inefficient and should be optimised.
	 */
	dep_wqe = mlx5dr_send_add_new_dep_wqe(queue);
	mlx5dr_rule_init_dep_wqe(dep_wqe, rule, items, attr->user_data);
	is_jumbo = mlx5dr_definer_is_jumbo(matcher->mt[mt_idx]->definer);

	/* Apply action on */
	mlx5dr_actions_quick_apply(queue,
				   &ctx->common_res[tbl->type],
				   &dep_wqe->wqe_ctrl,
				   &dep_wqe->wqe_data,
				   rule_actions, num_actions,
				   tbl->type,
				   is_jumbo);

	/* Create tag directly on WQE and backup it on the rule for deletion */
	mlx5dr_definer_create_tag(items,
				  matcher->mt[mt_idx]->fc,
				  matcher->mt[mt_idx]->fc_sz,
				  (uint8_t *)dep_wqe->wqe_data.action);

	if (is_jumbo)
		memcpy(rule->tag.jumbo, dep_wqe->wqe_data.action, MLX5DR_JUMBO_TAG_SZ);
	else
		memcpy(rule->tag.match, dep_wqe->wqe_data.tag, MLX5DR_MATCH_TAG_SZ);

	/* Send dependent WQE */
	if (!attr->burst)
		mlx5dr_send_all_dep_wqe(queue);

	return 0;
}

static void mlx5dr_rule_destroy_failed_hws(struct mlx5dr_rule *rule,
					   struct mlx5dr_rule_attr *attr)
{
	struct mlx5dr_context *ctx = rule->matcher->tbl->ctx;
	struct mlx5dr_send_engine *queue;

	queue = &ctx->send_queue[attr->queue_id];

	mlx5dr_rule_gen_comp(queue, rule, false,
			     attr->user_data, MLX5DR_RULE_STATUS_DELETED);

	/* If a rule that was indicated as burst (need to trigger HW) has failed
	 * insertion we won't ring the HW as nothing is being written to the WQ.
	 * In such case update the last WQE and ring the HW with that work
	 */
	if (attr->burst)
		return;

	mlx5dr_send_engine_flush_queue(queue);
}

static int mlx5dr_rule_destroy_hws(struct mlx5dr_rule *rule,
				   struct mlx5dr_rule_attr *attr)
{
	struct mlx5dr_context *ctx = rule->matcher->tbl->ctx;
	struct mlx5dr_matcher *matcher = rule->matcher;
	struct mlx5dr_wqe_gta_ctrl_seg wqe_ctrl = {0};
	struct mlx5dr_send_rule_attr send_attr = {0};
	struct mlx5dr_send_engine *queue;

	queue = &ctx->send_queue[attr->queue_id];

	/* Rule is not completed yet */
	if (rule->status == MLX5DR_RULE_STATUS_CREATING) {
		rte_errno = EBUSY;
		return rte_errno;
	}

	/* Rule failed and doesn't require cleanup */
	if (rule->status == MLX5DR_RULE_STATUS_FAILED) {
		mlx5dr_rule_destroy_failed_hws(rule, attr);
		return 0;
	}

	if (unlikely(mlx5dr_send_engine_err(queue))) {
		mlx5dr_rule_destroy_failed_hws(rule, attr);
		return 0;
	}

	mlx5dr_send_engine_inc_rule(queue);

	/* Send dependent WQE */
	if (!attr->burst)
		mlx5dr_send_all_dep_wqe(queue);

	rule->status = MLX5DR_RULE_STATUS_DELETING;

	wqe_ctrl.op_dirix = htobe32(MLX5DR_WQE_GTA_OP_DEACTIVATE << 28);

	send_attr.queue = queue;
	send_attr.notify_hw = !attr->burst;
	send_attr.user_data = attr->user_data;
	send_attr.rtc_0 = rule->rtc_0;
	send_attr.rtc_1 = rule->rtc_1;
	send_attr.wqe_ctrl = &wqe_ctrl;
	send_attr.wqe_tag = &rule->tag;
	send_attr.is_jumbo = mlx5dr_definer_is_jumbo(matcher->mt[0]->definer);

	mlx5dr_send_rule(rule, &send_attr);

	return 0;
}

static int mlx5dr_rule_create_root(struct mlx5dr_rule *rule,
				   struct mlx5dr_rule_attr *rule_attr,
				   const struct rte_flow_item items[],
				   struct mlx5dr_rule_action rule_actions[],
				   uint8_t num_actions)
{
	struct mlx5dv_flow_matcher *dv_matcher = rule->matcher->dv_matcher;
	struct mlx5dr_context *ctx = rule->matcher->tbl->ctx;
	struct mlx5dv_flow_match_parameters *value;
	struct mlx5_flow_attr flow_attr = {0};
	struct mlx5dv_flow_action_attr *attr;
	struct rte_flow_error error;
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
					  &error);
	if (ret) {
		DR_LOG(ERR, "Failed to convert items to PRM [%s]", error.message);
		goto free_value;
	}

	/* Convert actions to verb action attr */
	ret = mlx5dr_action_root_build_attr(rule_actions, num_actions, attr);
	if (ret)
		goto free_value;

	/* Create verb flow */
	value->match_sz = MLX5_ST_SZ_BYTES(fte_match_param);
	rule->flow = mlx5_glue->dv_create_flow_root(dv_matcher,
						    value,
						    num_actions,
						    attr);

	mlx5dr_rule_gen_comp(&ctx->send_queue[rule_attr->queue_id], rule, !rule->flow,
			     rule_attr->user_data, MLX5DR_RULE_STATUS_CREATED);

	simple_free(value);
	simple_free(attr);

	return 0;

free_value:
	simple_free(value);
free_attr:
	simple_free(attr);

	return -rte_errno;
}

static int mlx5dr_rule_destroy_root(struct mlx5dr_rule *rule,
				    struct mlx5dr_rule_attr *attr)
{
	struct mlx5dr_context *ctx = rule->matcher->tbl->ctx;
	int err = 0;

	if (rule->flow)
		err = ibv_destroy_flow(rule->flow);

	mlx5dr_rule_gen_comp(&ctx->send_queue[attr->queue_id], rule, err,
			     attr->user_data, MLX5DR_RULE_STATUS_DELETED);

	return 0;
}

int mlx5dr_rule_create(struct mlx5dr_matcher *matcher,
		       uint8_t mt_idx,
		       const struct rte_flow_item items[],
		       struct mlx5dr_rule_action rule_actions[],
		       uint8_t num_of_actions,
		       struct mlx5dr_rule_attr *attr,
		       struct mlx5dr_rule *rule_handle)
{
	struct mlx5dr_context *ctx;
	int ret;

	rule_handle->matcher = matcher;
	ctx = matcher->tbl->ctx;

	if (unlikely(!attr->user_data)) {
		rte_errno = EINVAL;
		return -rte_errno;
	}

	/* Check if there is room in queue */
	if (unlikely(mlx5dr_send_engine_full(&ctx->send_queue[attr->queue_id]))) {
		rte_errno = EBUSY;
		return -rte_errno;
	}

	assert(matcher->num_of_mt >= mt_idx);

	if (unlikely(mlx5dr_table_is_root(matcher->tbl)))
		ret = mlx5dr_rule_create_root(rule_handle,
					      attr,
					      items,
					      rule_actions,
					      num_of_actions);
	else
		ret = mlx5dr_rule_create_hws(rule_handle,
					     mt_idx,
					     items,
					     attr,
					     rule_actions,
					     num_of_actions);
	return -ret;
}

int mlx5dr_rule_destroy(struct mlx5dr_rule *rule,
			struct mlx5dr_rule_attr *attr)
{
	struct mlx5dr_context *ctx = rule->matcher->tbl->ctx;
	int ret;

	if (unlikely(!attr->user_data)) {
		rte_errno = EINVAL;
		return -rte_errno;
	}

	/* Check if there is room in queue */
	if (unlikely(mlx5dr_send_engine_full(&ctx->send_queue[attr->queue_id]))) {
		rte_errno = EBUSY;
		return -rte_errno;
	}

	if (unlikely(mlx5dr_table_is_root(rule->matcher->tbl)))
		ret = mlx5dr_rule_destroy_root(rule, attr);
	else
		ret = mlx5dr_rule_destroy_hws(rule, attr);

	return -ret;
}

size_t mlx5dr_rule_get_handle_size(void)
{
	return sizeof(struct mlx5dr_rule);
}
