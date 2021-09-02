/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_internal.h"

static int mlx5dr_table_init_nic(struct mlx5dr_table *tbl,
				 struct mlx5dr_table_nic *nic_tbl)
{
	struct mlx5dr_cmd_stc_modify_attr stc_attr = {0};
	struct mlx5dr_devx_obj *devx_obj;
	struct mlx5dr_pool *stc_pool;
	int ret;

	stc_pool = tbl->ctx->stc_pool[tbl->type];
	ret = mlx5dr_pool_chunk_alloc(stc_pool, &nic_tbl->stc);
	if (ret) {
		DRV_LOG(ERR, "Failed to allocate go to FT STC");
		return rte_errno;
	}

	stc_attr.stc_offset = nic_tbl->stc.offset;
	stc_attr.action_type = MLX5_IFC_STC_ACTION_TYPE_JUMP_TO_FT;
	stc_attr.dest_table_id = tbl->ft->id;
	devx_obj = mlx5dr_pool_chunk_get_base_devx_obj(stc_pool, &nic_tbl->stc);

	ret = mlx5dr_cmd_stc_modify(devx_obj, &stc_attr);
	if (ret) {
		DRV_LOG(ERR, "Failed to modify STC to jump for FT");
		 goto free_chunk;
	}

	return 0;

free_chunk:
	mlx5dr_pool_chunk_free(stc_pool, &nic_tbl->stc);
	return rte_errno;
}

static void mlx5dr_table_uninit_nic(struct mlx5dr_table *tbl,
				    struct mlx5dr_table_nic *nic_tbl)
{
	struct mlx5dr_pool *stc_pool;

	stc_pool = tbl->ctx->stc_pool[tbl->type];
	mlx5dr_pool_chunk_free(stc_pool, &nic_tbl->stc);
}

static int mlx5dr_table_init(struct mlx5dr_table *tbl)
{
	struct mlx5dr_cmd_ft_create_attr ft_attr = {0};
	struct mlx5dr_context *ctx = tbl->ctx;
	struct mlx5dr_table_nic *nic_tbl;
	int ret;

	if (mlx5dr_table_is_root(tbl))
		return 0;

	if (!(tbl->ctx->flags & MLX5DR_CONTEXT_FLAG_HWS_SUPPORT)) {
		rte_errno = EOPNOTSUPP;
		return rte_errno;
	}

	switch (tbl->type) {
	case MLX5DR_TABLE_TYPE_NIC_RX:
		tbl->fw_ft_type = FS_FT_NIC_RX;
		nic_tbl = &tbl->rx;
		break;
	case MLX5DR_TABLE_TYPE_NIC_TX:
		tbl->fw_ft_type = FS_FT_NIC_TX;
		nic_tbl = &tbl->tx;
		break;
	default:
		assert(0);
		break;
	}

	ft_attr.type = tbl->fw_ft_type;
	ft_attr.wqe_based_flow_update = true;
	ft_attr.level = MLX5DR_DEFAULT_LEVEL; // TODO use cap max_ft_level -1 ?
	// TODO Need to support default miss behaviour for FDB

	tbl->ft = mlx5dr_cmd_flow_table_create(ctx->ibv_ctx, &ft_attr);
	if (!tbl->ft) {
		DRV_LOG(ERR, "Failed to create flow table devx object");
		return rte_errno;
	}

	ret = mlx5dr_table_init_nic(tbl, nic_tbl);
	if (ret)
		goto tbl_destroy;

	return 0;

tbl_destroy:
	mlx5dr_cmd_destroy_obj(tbl->ft);
	return rte_errno;
}

static void mlx5dr_table_uninit(struct mlx5dr_table *tbl)
{
	struct mlx5dr_table_nic *nic_tbl;

	if (mlx5dr_table_is_root(tbl))
		return;

	switch (tbl->type) {
	case MLX5DR_TABLE_TYPE_NIC_RX:
		nic_tbl = &tbl->rx;
		break;
	case MLX5DR_TABLE_TYPE_NIC_TX:
		nic_tbl = &tbl->tx;
		break;
	default:
		assert(0);
		break;
	}

	mlx5dr_cmd_destroy_obj(tbl->ft);
	mlx5dr_table_uninit_nic(tbl, nic_tbl);
}

struct mlx5dr_table *mlx5dr_table_create(struct mlx5dr_context *ctx,
					 struct mlx5dr_table_attr *attr)
{
	struct mlx5dr_table *tbl;
	int ret;

	if (attr->type >= MLX5DR_TABLE_TYPE_FDB) {
		DRV_LOG(ERR, "Invalid table type %d", attr->type);
		return NULL;
	}

	tbl = simple_malloc(sizeof(*tbl));
	if (!tbl) {
		rte_errno = ENOMEM;
		return NULL;
	}

	tbl->ctx = ctx;
	tbl->type = attr->type;
	tbl->level = attr->level;
	LIST_INIT(&tbl->head);

	ret = mlx5dr_table_init(tbl);
	if (ret) {
		DRV_LOG(ERR, "Failed to initialise table");
		goto free_tbl;
	}

	pthread_spin_lock(&ctx->ctrl_lock);
	LIST_INSERT_HEAD(&ctx->head, tbl, next);
	pthread_spin_unlock(&ctx->ctrl_lock);

	return tbl;

free_tbl:
	simple_free(tbl);
	return NULL;
}

int mlx5dr_table_destroy(struct mlx5dr_table *tbl)
{
	struct mlx5dr_context *ctx = tbl->ctx;

	pthread_spin_lock(&ctx->ctrl_lock);
	LIST_REMOVE(tbl, next);
	pthread_spin_unlock(&ctx->ctrl_lock);
	mlx5dr_table_uninit(tbl);
	simple_free(tbl);

	return 0;
}
