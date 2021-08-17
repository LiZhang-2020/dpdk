/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_internal.h"

static int mlx5dr_matcher_create_end_ft(struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_cmd_ft_create_attr ft_attr = {0};
	struct mlx5dr_table *tbl = matcher->tbl;

	ft_attr.type = tbl->fw_ft_type;
	ft_attr.wqe_based_flow_update = true;
	ft_attr.level = MLX5DR_DEFAULT_LEVEL;
	// TODO Need to support default miss behaviour for FDB

	matcher->end_ft = mlx5dr_cmd_flow_table_create(tbl->ctx->ibv_ctx, &ft_attr);
	if (!matcher->end_ft) {
		DRV_LOG(ERR, "Failed to create matcher end flow table");
		return rte_errno;
	}
	return 0;
}

static int mlx5dr_matcher_destroy_end_ft(struct mlx5dr_matcher *matcher)
{
	return mlx5dr_cmd_destroy_obj(matcher->end_ft);
}

static int mlx5dr_matcher_connect(struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_cmd_ft_modify_attr ft_attr = {0};
	struct mlx5dr_table *tbl = matcher->tbl;
	struct mlx5dr_matcher *prev = NULL;
	struct mlx5dr_matcher *next = NULL;
	struct mlx5dr_matcher *tmp_matcher;
	struct mlx5dr_devx_obj *ft;
	int ret;

	/* Connect lists */
	if (LIST_EMPTY(&tbl->head)) {
		LIST_INSERT_HEAD(&tbl->head, matcher, next);
		goto connect;
	}

	LIST_FOREACH(tmp_matcher, &tbl->head, next) {
		if (tmp_matcher->attr.priority >= matcher->attr.priority) {
			next = tmp_matcher;
			break;
		}
		prev = tmp_matcher;
	}

	if (next)
		LIST_INSERT_BEFORE(next, matcher, next);
	else
		LIST_INSERT_AFTER(prev, matcher, next);

connect:
	/* Connect to next */
	if (next) {
		ft_attr.modify_fs = MLX5_IFC_MODIFY_FLOW_TABLE_RTC_ID;
		ft_attr.type = tbl->fw_ft_type;
		ft_attr.wqe_based_flow_update = true;

		if (next->rx.rtc)
			ft_attr.rtc_id = next->rx.rtc->id;
		if (next->tx.rtc)
			ft_attr.rtc_id = next->tx.rtc->id;

		ret = mlx5dr_cmd_flow_table_modify(matcher->end_ft, &ft_attr);
		if (ret) {
			DRV_LOG(ERR, "Failed to connect new matcher to next RTC");
			goto remove_from_list;
		}
	}

	/* Connect to previous */
	ft = prev ? prev->end_ft : tbl->ft;
	ft_attr.modify_fs = MLX5_IFC_MODIFY_FLOW_TABLE_RTC_ID;
	ft_attr.type = tbl->fw_ft_type;
	ft_attr.wqe_based_flow_update = true;

	if (matcher->rx.rtc)
		ft_attr.rtc_id = matcher->rx.rtc->id;
	if (matcher->tx.rtc)
		ft_attr.rtc_id = matcher->tx.rtc->id;

	ret = mlx5dr_cmd_flow_table_modify(ft, &ft_attr);
	if (ret) {
		DRV_LOG(ERR, "Failed to connect new matcher to previous FT");
		goto remove_from_list;
	}

	return 0;

remove_from_list:
	LIST_REMOVE(matcher, next);
	return ret;
}

static int mlx5dr_matcher_disconnect(struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_cmd_ft_modify_attr ft_attr = {0};
	struct mlx5dr_devx_obj *prev_ft;
	struct mlx5dr_matcher *next;
	int ret;

	if (LIST_FIRST(&matcher->tbl->head) == matcher)
		prev_ft = matcher->tbl->ft;
	else
		prev_ft = (*matcher->next.le_prev)->end_ft;

	next = matcher->next.le_next;

	ft_attr.modify_fs = MLX5_IFC_MODIFY_FLOW_TABLE_RTC_ID;
	ft_attr.type = matcher->tbl->fw_ft_type;
	ft_attr.wqe_based_flow_update = true;

	/* Connect previous end FT to next RTC if exists */
	if (next) {
		if (next->rx.rtc)
			ft_attr.rtc_id = next->rx.rtc->id;
		if (next->tx.rtc)
			ft_attr.rtc_id = next->tx.rtc->id;
	}

	ret = mlx5dr_cmd_flow_table_modify(prev_ft, &ft_attr);
	if (ret) {
		DRV_LOG(ERR, "Failed to disconnect matcher");
		return ret;
	}

	LIST_REMOVE(matcher, next);

	return 0;
}

static int mlx5dr_matcher_create_rtc_nic(struct mlx5dr_matcher *matcher,
					 struct mlx5dr_matcher_nic *nic_matcher,
					 struct mlx5dr_table_nic *nic_tbl)
{
	struct mlx5dr_cmd_rtc_create_attr rtc_attr = {0};
	struct mlx5dr_table *tbl = matcher->tbl;
	struct mlx5dr_context *ctx = tbl->ctx;
	struct mlx5dr_devx_obj *devx_obj;
	struct mlx5dr_pool *ste_pool;
	struct mlx5dr_pool *stc_pool;
	int ret;

	ste_pool = ctx->ste_pool[tbl->type];
	stc_pool = ctx->stc_pool[tbl->type];

	nic_matcher->ste.order = matcher->attr.sz_hint_col_log +
				 matcher->attr.sz_hint_row_log;

	ret = mlx5dr_pool_chunk_alloc(ste_pool, &nic_matcher->ste);
	if (ret) {
		DRV_LOG(ERR, "Failed to allocate STE for matcher RTC");
		return ret;
	}

	devx_obj = mlx5dr_pool_chunk_get_base_devx_obj(ste_pool, &nic_matcher->ste);

	rtc_attr.ste_base = devx_obj->id;
	rtc_attr.ste_offset = nic_matcher->ste.offset;
	rtc_attr.definer_id = matcher->definer->id;
	rtc_attr.miss_ft_id = matcher->end_ft->id;
	rtc_attr.update_index_mode = MLX5_IFC_RTC_STE_UPDATE_MODE_BY_HASH;
	rtc_attr.log_depth = matcher->attr.sz_hint_col_log;
	rtc_attr.log_size = matcher->attr.sz_hint_row_log;
	rtc_attr.table_type = tbl->fw_ft_type;
	rtc_attr.pd = ctx->pd_num;

	devx_obj = mlx5dr_pool_chunk_get_base_devx_obj(stc_pool, &nic_tbl->stc);
	rtc_attr.stc_base = devx_obj->id;

	nic_matcher->rtc = mlx5dr_cmd_rtc_create(ctx->ibv_ctx, &rtc_attr);
	if (!nic_matcher->rtc) {
		DRV_LOG(ERR, "Failed to create matcher RTC");
		return errno;
	}
	return 0;
}

static void mlx5dr_matcher_destroy_rtc_nic(struct mlx5dr_matcher *matcher,
					   struct mlx5dr_matcher_nic *nic_matcher)
{
	struct mlx5dr_context *ctx = matcher->tbl->ctx;
	struct mlx5dr_table *tbl = matcher->tbl;

	mlx5dr_cmd_destroy_obj(nic_matcher->rtc);
	mlx5dr_pool_chunk_free(ctx->ste_pool[tbl->type], &nic_matcher->ste);
}

static int mlx5dr_matcher_init_fdb(struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_table *tbl = matcher->tbl;
	int ret;

	ret = mlx5dr_matcher_create_rtc_nic(matcher, &matcher->rx, &tbl->rx);
	if (ret)
		return ret;

	ret = mlx5dr_matcher_create_rtc_nic(matcher, &matcher->tx, &tbl->tx);
	if (ret)
		goto cleanup_rx;

	return 0;

cleanup_rx:
	mlx5dr_matcher_destroy_rtc_nic(matcher, &matcher->rx);
	return ret;
}

static int mlx5dr_matcher_uninit_fdb(struct mlx5dr_matcher *matcher)
{
	mlx5dr_matcher_destroy_rtc_nic(matcher, &matcher->rx);
	mlx5dr_matcher_destroy_rtc_nic(matcher, &matcher->tx);
	return 0;
}

static int mlx5dr_matcher_create_rtc(struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_table *tbl = matcher->tbl;
	int ret;

	switch (tbl->type) {
	case MLX5DR_TABLE_TYPE_NIC_RX:
		ret = mlx5dr_matcher_create_rtc_nic(matcher, &matcher->rx, &tbl->rx);
		break;
	case MLX5DR_TABLE_TYPE_NIC_TX:
		ret = mlx5dr_matcher_create_rtc_nic(matcher, &matcher->tx, &tbl->tx);
		break;
	case MLX5DR_TABLE_TYPE_FDB:
		ret = mlx5dr_matcher_init_fdb(matcher);
		break;
	default:
		assert(0);
		break;
	}
	return ret;
}

static void mlx5dr_matcher_destroy_rtc(struct mlx5dr_matcher *matcher)
{
	switch (matcher->tbl->type) {
	case MLX5DR_TABLE_TYPE_NIC_RX:
		mlx5dr_matcher_destroy_rtc_nic(matcher, &matcher->rx);
		break;
	case MLX5DR_TABLE_TYPE_NIC_TX:
		mlx5dr_matcher_destroy_rtc_nic(matcher, &matcher->tx);
		break;
	case MLX5DR_TABLE_TYPE_FDB:
		mlx5dr_matcher_uninit_fdb(matcher);
		break;
	default:
		assert(0);
		break;
	}
}

static int mlx5dr_matcher_init(struct mlx5dr_matcher *matcher,
			       struct rte_flow_item *items)
{
	struct mlx5dr_context *ctx = matcher->tbl->ctx;
	int ret;

	pthread_spin_lock(&ctx->ctrl_lock);

	/* Select and create the definers for current matcher */
	ret = mlx5dr_definer_create(matcher, items);
	if (ret)
		goto unlock_err;

	/* Create matcher end flow table anchor */
	ret = mlx5dr_matcher_create_end_ft(matcher);
	if (ret)
		goto clear_builders;

	/* Allocate the RTC for the new matcher */
	ret = mlx5dr_matcher_create_rtc(matcher);
	if (ret)
		goto destroy_end_ft;

	/* Connect the matcher to the matcher list */
	ret = mlx5dr_matcher_connect(matcher);
	if (ret)
		goto destroy_rtc;

	pthread_spin_unlock(&ctx->ctrl_lock);

	return 0;

destroy_rtc:
	mlx5dr_matcher_destroy_rtc(matcher);
destroy_end_ft:
	mlx5dr_matcher_destroy_end_ft(matcher);
clear_builders:
	mlx5dr_definer_destroy(matcher);
unlock_err:
	pthread_spin_unlock(&ctx->ctrl_lock);
	return ret;
}

static int mlx5dr_matcher_uninit(struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_context *ctx = matcher->tbl->ctx;

	pthread_spin_lock(&ctx->ctrl_lock);
	mlx5dr_matcher_disconnect(matcher);
	mlx5dr_matcher_destroy_rtc(matcher);
	mlx5dr_matcher_destroy_end_ft(matcher);
	mlx5dr_definer_destroy(matcher);
	pthread_spin_unlock(&ctx->ctrl_lock);

	return 0;
}

static int mlx5dr_matcher_init_root(struct mlx5dr_matcher *matcher,
				    struct rte_flow_item *items)
{
	enum mlx5dr_table_type type = matcher->tbl->type;
	struct mlx5dr_context *ctx = matcher->tbl->ctx;
	struct mlx5dv_flow_matcher_attr attr = {0};
	struct mlx5dv_flow_match_parameters *mask;
	struct mlx5_flow_attr flow_attr = {0};
	enum mlx5dv_flow_table_type ft_type;
	struct rte_flow_error rte_error;
	uint8_t match_criteria;
	int ret;

	switch (type) {
	case MLX5DR_TABLE_TYPE_NIC_RX:
		ft_type = MLX5_IB_UAPI_FLOW_TABLE_TYPE_NIC_RX;
		break;
	case MLX5DR_TABLE_TYPE_NIC_TX:
		ft_type = MLX5_IB_UAPI_FLOW_TABLE_TYPE_NIC_TX;
		break;
	case MLX5DR_TABLE_TYPE_FDB:
		ft_type = MLX5_IB_UAPI_FLOW_TABLE_TYPE_FDB;
		break;
	default:
		assert(0);
		break;
	}

	mask = simple_calloc(1, MLX5_ST_SZ_BYTES(fte_match_param) +
			     offsetof(struct mlx5dv_flow_match_parameters, match_buf));
	if (!mask) {
		rte_errno = ENOMEM;
		return rte_errno;
	}

	flow_attr.tbl_type = type;

	ret = flow_dv_translate_items_hws(items, &flow_attr, mask->match_buf,
					  MLX5_SET_MATCHER_HS_M, NULL,
					  &match_criteria,
					  &rte_error);
	if (ret) {
		DRV_LOG(ERR, "Failed to convert items to PRM [%s]", rte_error.message);
		goto free_mask;
	}

	mask->match_sz = MLX5_ST_SZ_BYTES(fte_match_param);
	attr.match_mask = mask;
	attr.match_criteria_enable = match_criteria;
	attr.ft_type = ft_type;
	attr.type = IBV_FLOW_ATTR_NORMAL;
	attr.priority = matcher->attr.priority;
	attr.comp_mask = MLX5DV_FLOW_MATCHER_MASK_FT_TYPE;

	matcher->dv_matcher = mlx5dv_create_flow_matcher(ctx->ibv_ctx, &attr);
	if (!matcher->dv_matcher) {
		DRV_LOG(ERR, "Failed to create DV flow matcher");
		rte_errno = errno;
		goto free_mask;
	}

	simple_free(mask);

	pthread_spin_lock(&ctx->ctrl_lock);
	LIST_INSERT_HEAD(&matcher->tbl->head, matcher, next);
	pthread_spin_unlock(&ctx->ctrl_lock);

	return 0;

free_mask:
	simple_free(mask);
	return rte_errno;
}

static int mlx5dr_matcher_uninit_root(struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_context *ctx = matcher->tbl->ctx;
	int ret;

	pthread_spin_lock(&ctx->ctrl_lock);
	LIST_REMOVE(matcher, next);
	pthread_spin_unlock(&ctx->ctrl_lock);

	ret = mlx5dv_destroy_flow_matcher(matcher->dv_matcher);
	if (ret) {
		DRV_LOG(ERR, "Failed to Destroy DV flow matcher");
		rte_errno = errno;
	}

	return ret;
}

struct mlx5dr_matcher *mlx5dr_matcher_create(struct mlx5dr_table *tbl,
					     struct rte_flow_item items[],
					     struct mlx5dr_matcher_attr *attr)
{
	struct mlx5dr_matcher *matcher;
	int ret;

	matcher = simple_calloc(1, sizeof(*matcher));
	if (!matcher) {
		rte_errno = ENOMEM;
		return NULL;
	}

	matcher->tbl = tbl;
	matcher->attr = *attr;

	if (mlx5dr_table_is_root(matcher->tbl))
		ret = mlx5dr_matcher_init_root(matcher, items);
	else
		ret = mlx5dr_matcher_init(matcher, items);

	if (ret) {
		DRV_LOG(ERR, "Failed to initialise matcher: %d", ret);
		goto free_matcher;
	}

	return matcher;

free_matcher:
	simple_free(matcher);
	return NULL;
}

int mlx5dr_matcher_destroy(struct mlx5dr_matcher *matcher)
{
	if (mlx5dr_table_is_root(matcher->tbl))
		mlx5dr_matcher_uninit_root(matcher);
	else
		mlx5dr_matcher_uninit(matcher);

	simple_free(matcher);
	return 0;
}