/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_internal.h"

static int mlx5dr_rule_build_tag(uint8_t *tag, struct rte_flow_item *items)
{
	for (; items->type != RTE_FLOW_ITEM_TYPE_END; items++) {
		switch (items->type) {
		case RTE_FLOW_ITEM_TYPE_IPV4:
		{
			const struct rte_ipv4_hdr *v =  items->spec;

			MLX5_SET(ste_def22, tag, outer_ip_src_addr, v->src_addr);
			MLX5_SET(ste_def22, tag, outer_ip_dst_addr, v->dst_addr);

			break;
		}
		default:
			rte_errno = ENOTSUP;
			return rte_errno;
		}
	}

	return 0;
}

static int mlx5dr_rule_create_hws(struct mlx5dr_rule *rule,
				  struct rte_flow_item items[],
				  struct mlx5dr_rule_attr *attr,
				  struct mlx5dr_rule_action rule_actions[],
				  uint8_t num_actions)
{
	struct mlx5dr_context *ctx = rule->matcher->tbl->ctx;
	struct mlx5dr_send_engine_post_attr send_attr = {0};
	struct mlx5dr_wqe_gta_data_seg_ste *wqe_data;
	struct mlx5dr_wqe_gta_ctrl_seg *wqe_ctrl;
	struct mlx5dr_send_engine_post_ctrl ctrl;
	size_t wqe_len;

	/* Build tag + actions attr */
	ctrl = mlx5dr_send_engine_post_start(&ctx->send_queue[attr->queue_id]);
	mlx5dr_send_engine_post_req_wqe(&ctrl, (void *)&wqe_ctrl, &wqe_len);
	mlx5dr_send_engine_post_req_wqe(&ctrl, (void *)&wqe_data, &wqe_len);

	wqe_ctrl->op_dirix = 0;
	wqe_ctrl->stc_ix[0] = htobe32(num_actions << 29);
	wqe_ctrl->stc_ix[0] |= htobe32(rule_actions->action->stc_rx.offset);

	/* Create tag directly on WQE and backup it on the rule for deletion */
	mlx5dr_rule_build_tag((uint8_t *)wqe_data->tag, items);
	memcpy(rule->match_tag, wqe_data->tag, MLX5DR_MATCH_TAG_SZ);

	send_attr.rule = rule;
	send_attr.opcode = 0x2c;
	send_attr.len = 48 + 64;
	send_attr.notify_hw = 1;
	send_attr.user_comp = attr->requst_comp;
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

	ctrl = mlx5dr_send_engine_post_start(&ctx->send_queue[attr->queue_id]);
	mlx5dr_send_engine_post_req_wqe(&ctrl, (void *)&wqe_ctrl, &wqe_len);
	mlx5dr_send_engine_post_req_wqe(&ctrl, (void *)&wqe_data, &wqe_len);

	wqe_ctrl->op_dirix = htobe32(0x1 << 28); /* Destroy */

	memcpy(wqe_data->tag, rule->match_tag, MLX5DR_MATCH_TAG_SZ);

	send_attr.rule = rule;
	send_attr.opcode = 0x2c;
	send_attr.len = 48 + 64;
	send_attr.notify_hw = 1;
	send_attr.user_comp = attr->requst_comp;

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

	if (mlx5dr_table_is_root(matcher->tbl))
		return mlx5dr_rule_create_root(rule_handle,
					       items,
					       rule_actions,
					       num_of_actions);
	else
		return mlx5dr_rule_create_hws(rule_handle,
					      items,
					      attr,
					      rule_actions,
					      num_of_actions);

	rte_errno = ENOTSUP;
	return rte_errno;
}

int mlx5dr_rule_destroy(struct mlx5dr_rule *rule,
			struct mlx5dr_rule_attr *attr)
{
	if (mlx5dr_table_is_root(rule->matcher->tbl))
		return mlx5dr_rule_destroy_root(rule);
	else
		return mlx5dr_rule_destroy_hws(rule, attr);

	rte_errno = ENOTSUP;
	return rte_errno;
}
