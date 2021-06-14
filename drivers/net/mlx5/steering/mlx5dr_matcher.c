/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

struct mlx5dr_matcher_nic {
	struct mlx5dv_devx_obj *rtc;
	struct mlx5dv_devx_obj *ste_id;
};

struct mlx5dr_matcher {
	struct mlx5dr_table *tbl;
	struct mlx5dr_matcher_attr attr;
	struct mlx5dv_flow_matcher *dv_matcher;
	struct mlx5dv_devx_obj *definer;
	struct mlx5dv_devx_obj *start_ft;
	struct mlx5dv_devx_obj *end_ft;
	struct mlx5dr_matcher_nic rx;
	struct mlx5dr_matcher_nic tx;
};

int mlx5dr_matcher_create_start_ft(struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_cmd_flow_table_attr ft_attr = {};
	struct mlx5dr_table *tbl = matcher->tbl;

	ft_attr.type = tbl->fw_ft_type;
	ft_attr.wqe_based_flow_update = true;
	// TODO Need to support default miss behaviour for FDB

	if (matcher->rx.rtc)
		ft_attr.rx_rtc_id = mlx5dv_devx_obj_get_id(matcher->rx.rtc);

	if (matcher->tx.rtc)
		ft_attr.tx_rtc_id = mlx5dv_devx_obj_get_id(matcher->tx.rtc);

	matcher->start_ft = mlx5dr_cmd_flow_table_create(tbl->ctx->ibv_ctx, &ft_attr);
	if (!matcher->start_ft) {
		DRV_LOG(ERR, "Failed to create matcher start flow table\n");
		return errno;
	}
	return 0;


int mlx5dr_matcher_create_end_ft(struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_cmd_flow_table_attr ft_attr = {};
	struct mlx5dr_table *tbl = matcher->tbl;

	ft_attr.type = tbl->fw_ft_type;
	// TODO Need to support default miss behaviour for FDB

	matcher->end_ft = mlx5dr_cmd_flow_table_create(tbl->ctx->ibv_ctx, &ft_attr);
	if (!matcher->end_ft) {
		DRV_LOG(ERR, "Failed to create matcher end flow table\n");
		return errno;
	}
	return 0;
}

int mlx5dr_matcher_clear_builders(struct mlx5dr_matcher *matcher)
{
	return EINVAL;
}

int mlx5dr_matcher_set_builders(struct mlx5dr_matcher *matcher)
{
	// TODO create definer
	return EINVAL;
}

static void mlx5dr_matcher_disconnect(struct mlx5dr_matcher_nic *nic_matcher)
{

}

static int mlx5dr_matcher_connect(struct mlx5dr_matcher_nic *nic_matcher)
{

}

static void mlx5dr_matcher_destroy_rtc_nic(struct mlx5dr_matcher_nic *nic_matcher)
{
	mlx5_glue->devx_obj_destroy(nic_matcher->rtc);
}

static int mlx5dr_matcher_create_rtc_nic(struct mlx5dr_matcher *matcher,
				   struct mlx5dr_matcher_nic *nic_matcher)
{
	struct mlx5dr_cmd_rtc_create_attr rtc_attr = {};
	struct mlx5dr_context *ctx = matcher->tbl->ctx;

	// TODO allocate STE chunk

	rtc_attr.definer_id = mlx5dv_devx_obj_get_id(matcher->definer);
	rtc_attr.miss_ft_id = mlx5dv_devx_obj_get_id(matcher->end_ft);
	rtc_attr.update_index_mode = MLX5_IFC_RTC_STE_UPDATE_MODE_BY_HASH;
	rtc_attr.log_depth = matcher->attr.size_hint_column_log;
	rtc_attr.log_size = matcher->attr.size_hint_rows_log;
	rtc_attr.table_type = matcher->tbl->fw_ft_type;
	rtc_attr.pd = ctx->pd_num;

	rtc_attr.ste_offset = -1; // TODO get from allocated chunk
	rtc_attr.ste_base = -1; // TODO get from allocated chunk
	rtc_attr.stc_id = -1; // TODO get from ctx

	nic_matcher->rtc = mlx5dr_cmd_rtc_create(ctx->ibv_ctx, &rtc_attr);
	if (!nic_matcher->rtc) {
		DRV_LOG(ERR, "Failed to create matcher RTC\n");
		return errno;
	}
	return 0;
}

static int mlx5dr_matcher_uninit_fdb(struct mlx5dr_matcher *matcher)
{
	mlx5dr_matcher_destroy_rtc_nic(matcher, &matcher->rx);
	mlx5dr_matcher_destroy_rtc_nic(matcher, &matcher->tx);
	return 0;
}

static int mlx5dr_matcher_init_fdb(struct mlx5dr_matcher *matcher)
{
	int ret;

	ret = mlx5dr_matcher_create_rtc_nic(matcher, &matcher->rx);
	if (ret)
		return ret;

	ret = mlx5dr_matcher_create_rtc_nic(matcher, &matcher->tx);
	if (ret)
		goto cleanup_rx;

	return 0;

cleanup_rx:
	mlx5dr_matcher_destroy_rtc_nic(matcher, &matcher->rx);
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
	}
}

static int mlx5dr_matcher_create_rtc(struct mlx5dr_matcher *matcher)
{
	switch (matcher->tbl->type) {
	case MLX5DR_TABLE_TYPE_NIC_RX:
		ret = mlx5dr_matcher_create_rtc_nic(matcher, &matcher->rx);
		break;
	case MLX5DR_TABLE_TYPE_NIC_TX:
		ret = mlx5dr_matcher_create_rtc_nic(matcher, &matcher->tx);
		break;
	case MLX5DR_TABLE_TYPE_FDB:
		ret = mlx5dr_matcher_init_fdb(matcher);
		break;
	}
	return ret;
}

static int dr_matcher_uninit_root(struct mlx5dr_matcher *matcher)
{
	return mlx5dv_destroy_flow_matcher(matcher->dv_matcher);
}

static int mlx5dr_matcher_init_root(struct mlx5dr_matcher *matcher)
{
	enum mlx5dr_table_type type = matcher->tbl->type;
	struct mlx5dv_flow_matcher_attr attr = {};
	enum mlx5dv_flow_table_type ft_type;

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
	}

	if (matcher->attr.priority >> 16) {
		DRV_LOG(ERR, "Root matcher priority exceeds allowed value\n");
		errno = EINVAL;
		return errno;
	}

	// TODO Need to covnert rte_flow -> match
	// attr.match_mask = mask;
	// attr.match_criteria_enable = matcher->match_criteria;
	attr.ft_type = ft_type;
	attr.type = IBV_FLOW_ATTR_NORMAL;
	attr.priority = matcher->attr.priority;
	attr.comp_mask = MLX5DV_FLOW_MATCHER_MASK_FT_TYPE;

	matcher->dv_matcher = mlx5dv_create_flow_matcher(dmn->ctx, &attr);
	if (!matcher->dv_matcher)
		return errno;

	return 0;
}

static int mlx5dr_matcher_uninit(struct mlx5dr_matcher *matcher)
{

	mlx5dr_matcher_disconnect(matcher);

	mlx5dr_matcher_destroy_rtc(matcher);

	ret = mlx5dr_matcher_destory_anchors(matcher); // Allocate FTs
}

static int mlx5dr_matcher_init(struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_context *ctx = matcher->tbl->ctx;
	int ret;

	ret = mlx5dr_matcher_set_builders(matcher);	// Definer

	ret = mlx5dr_matcher_create_end_ft(matcher);	// Allocate end FT

	ret = mlx5dr_matcher_create_rtc(matcher); 	// RTCs

	ret = mlx5dr_matcher_create_start_ft(matcher);	// Allocate start FT

	ret = mlx5dr_matcher_connect(matcher);		// Connect matchers


out:
	return ret;
}

struct mlx5dr_matcher *mlx5dr_matcher_create(struct mlx5dr_table *tbl,
					     struct rte_flow_item items[],
					     struct mlx5dr_matcher_attr *attr)
{
	struct mlx5dr_matcher *matcher;
	int ret;

	matcher = simple_malloc(sizeof(*matcher));
	if (!matcher)
		return NULL;

	matcher->tbl = tbl;
	matcher->attr = *attr;

	if (matcher->tbl->level == MLX5DR_ROOT_LEVEL)
		ret = mlx5dr_matcher_init_root(matcher);
	else
		ret = mlx5dr_matcher_init(matcher);

	if (ret) {
		DRV_LOG(ERR, "Failed to initialise matcher: %d\n", ret);
		goto free_matcher;
	}

	return matcher;

free_matcher:
	simple_free(matcher);
	return NULL;
}

int mlx5dr_matcher_destroy(struct mlx5dr_matcher *matcher);
{
	if (matcher->tbl->level == MLX5DR_ROOT_LEVEL)
		mlx5dr_matcher_uninit_root(matcher);
	else
		mlx5dr_matcher_uninit(matcher);

	simple_free(matcher);
	return 0;
}
