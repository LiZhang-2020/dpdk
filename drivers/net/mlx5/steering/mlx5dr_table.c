/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_internal.h"

static int mlx5dr_table_uninit(struct mlx5dr_table *tbl)
{
	if (tbl->level == MLX5DR_ROOT_LEVEL)
		return 0;

	return mlx5dr_cmd_destroy_obj(tbl->ft);
}

static int mlx5dr_table_init(struct mlx5dr_table *tbl)
{
	struct mlx5dr_cmd_ft_create_attr ft_attr = {0};

	if (tbl->level == MLX5DR_ROOT_LEVEL)
		return 0;

	if (!(tbl->ctx->flags & MLX5DR_CONTEXT_FLAG_HWS_SUPPORT)) {
		errno = EOPNOTSUPP;
		return errno;
	}

	switch (tbl->type) {
	case MLX5DR_TABLE_TYPE_NIC_RX:
		tbl->fw_ft_type = FS_FT_NIC_RX;
		break;
	case MLX5DR_TABLE_TYPE_NIC_TX:
		tbl->fw_ft_type = FS_FT_NIC_TX;
		break;
	case MLX5DR_TABLE_TYPE_FDB:
		tbl->fw_ft_type = FS_FT_FDB;
		break;
	default:
		assert(false);
		break;
	}

	ft_attr.type = tbl->fw_ft_type;
	ft_attr.wqe_based_flow_update = true;
	// TODO Need to support default miss behaviour for FDB

	tbl->ft = mlx5dr_cmd_flow_table_create(tbl->ctx->ibv_ctx, &ft_attr);
	if (!tbl->ft) {
		DRV_LOG(ERR, "Failed to create flow table devx object\n");
		return errno;
	}

	return 0;
}

struct mlx5dr_table *mlx5dr_table_create(struct mlx5dr_context *ctx,
					 struct mlx5dr_table_attr *attr)
{
	struct mlx5dr_table *tbl;
	int ret;

	if (attr->type >= MLX5DR_TABLE_TYPE_FDB) {
		DRV_LOG(ERR, "Invalid table type %d\n", attr->type);
		return NULL;
	}

	tbl = simple_malloc(sizeof(*tbl));
	if (!tbl)
		return NULL;

	tbl->ctx = ctx;
	tbl->type = attr->type;
	tbl->level = attr->level;
	LIST_INIT(&tbl->head);

	ret = mlx5dr_table_init(tbl);
	if (ret) {
		DRV_LOG(ERR, "Failed to initialise table\n");
		goto free_tbl;
	}

	return tbl;

free_tbl:
	simple_free(tbl);
	return NULL;
}

int mlx5dr_table_destroy(struct mlx5dr_table *tbl)
{
	mlx5dr_table_uninit(tbl);
	simple_free(tbl);

	return 0;
}
