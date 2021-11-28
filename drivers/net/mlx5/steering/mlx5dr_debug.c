/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_internal.h"

static int mlx5dr_debug_dump_matcher_nic(FILE *f,
					 enum mlx5dr_debug_res_type type,
					 struct mlx5dr_matcher *matcher,
					 struct mlx5dr_matcher_nic *matcher_nic)
{
	struct mlx5dr_pool *pool = matcher->tbl->ctx->ste_pool[matcher->tbl->type];
	struct mlx5dr_devx_obj *ste_obj;
	int ret;

	ste_obj = pool->resource[matcher_nic->ste.resource_idx]->devx_obj;

	ret = fprintf(f, "%d,0x%" PRIx64 ",%d,%d\n",
		      type,
		      (uint64_t)(uintptr_t)matcher,
		      (matcher->tbl->level == MLX5DR_ROOT_LEVEL) ? 0 : matcher_nic->rtc->id,
		      ste_obj->id);
	if (ret < 0) {
		rte_errno = EINVAL;
		return rte_errno;
	}

	return 0;
}

static int mlx5dr_debug_dump_matcher_template_definer(FILE *f,
						      struct mlx5dr_match_template *mt)
{
	struct mlx5dr_definer *definer = mt->definer;
	int i, ret;

	ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 ",%d,%d,",
		      MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE_DEFINER,
		      (uint64_t)(uintptr_t)definer,
		      (uint64_t)(uintptr_t)mt,
		      definer->obj->id,
		      0); /*definer type: for now zero is for match */
	if (ret < 0) {
		rte_errno = EINVAL;
		return rte_errno;
	}

	for (i = 0; i < DW_SELECTORS; i++) {
		ret = fprintf(f, "0x%x%s", definer->dw_selector[i],
			      (i == DW_SELECTORS - 1) ? "," : "-");
		if (ret < 0) {
			rte_errno = EINVAL;
			return rte_errno;
		}
	}

	for (i = 0; i < BYTE_SELECTORS; i++) {
		ret = fprintf(f, "0x%x%s", definer->byte_selector[i],
			      (i == BYTE_SELECTORS - 1) ? "," : "-");
		if (ret < 0) {
			rte_errno = EINVAL;
			return rte_errno;
		}
	}

	for (i = 0; i < MLX5DR_MATCH_TAG_SZ; i++) {
		ret = fprintf(f, "%02x", definer->mask_tag[i]);
		if (ret < 0) {
			rte_errno = EINVAL;
			return rte_errno;
		}
	}

	ret = fprintf(f, "\n");
	if (ret < 0) {
		rte_errno = EINVAL;
		return rte_errno;
	}

	return 0;
}

static int mlx5dr_debug_dump_matcher_template(FILE *f, struct mlx5dr_matcher *matcher)
{
	bool is_root = matcher->tbl->level == MLX5DR_ROOT_LEVEL;
	int i, ret;

	for (i = 0; i < matcher->num_of_mt; i++) {
		struct mlx5dr_match_template *mt = matcher->mt[i];

		ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 ",%d,%d\n",
			      MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE,
			      (uint64_t)(uintptr_t)mt,
			      (uint64_t)(uintptr_t)matcher,
			      is_root ? 0 : mt->fc_sz,
			      mt->flags);
		if (ret < 0) {
			rte_errno = EINVAL;
			return rte_errno;
		}

		if (!is_root) {
			ret = mlx5dr_debug_dump_matcher_template_definer(f, mt);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int mlx5dr_debug_dump_matcher_attr(FILE *f, struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_matcher_attr *attr = &matcher->attr;
	int ret;

	ret = fprintf(f, "%d,0x%" PRIx64 ",%d,%d,%d,%d\n",
		      MLX5DR_DEBUG_RES_TYPE_MATCHER_ATTR,
		      (uint64_t)(uintptr_t)matcher,
		      attr->priority,
		      attr->mode,
		      attr->table.sz_row_log,
		      attr->table.sz_col_log);
	if (ret < 0) {
		rte_errno = EINVAL;
		return rte_errno;
	}

	return 0;
}

static int mlx5dr_debug_dump_matcher(FILE *f, struct mlx5dr_matcher *matcher)
{
	bool is_root = matcher->tbl->level == MLX5DR_ROOT_LEVEL;
	enum mlx5dr_table_type tbl_type = matcher->tbl->type;
	int ret;

	ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 ",%d,%d,0x%" PRIx64 "\n",
		      MLX5DR_DEBUG_RES_TYPE_MATCHER,
		      (uint64_t)(uintptr_t)matcher,
		      (uint64_t)(uintptr_t)matcher->tbl,
		      matcher->num_of_mt,
		      is_root ? 0 : matcher->end_ft->id,
		      matcher->col_matcher ? (uint64_t)(uintptr_t)matcher->col_matcher : 0);
	if (ret < 0) {
		rte_errno = EINVAL;
		return rte_errno;
	}

	ret = mlx5dr_debug_dump_matcher_attr(f, matcher);
	if (ret)
		return ret;

	ret = mlx5dr_debug_dump_matcher_template(f, matcher);
	if (ret)
		return ret;

	if (tbl_type == MLX5DR_TABLE_TYPE_NIC_RX ||
	    tbl_type == MLX5DR_TABLE_TYPE_FDB) {
		ret = mlx5dr_debug_dump_matcher_nic(f,
				MLX5DR_DEBUG_RES_TYPE_MATCHER_NIC_RX,
				matcher, &matcher->rx);
		if (ret)
			return ret;
	}

	if (tbl_type == MLX5DR_TABLE_TYPE_NIC_TX ||
	    tbl_type == MLX5DR_TABLE_TYPE_FDB) {
		ret = mlx5dr_debug_dump_matcher_nic(f,
				MLX5DR_DEBUG_RES_TYPE_MATCHER_NIC_TX,
				matcher, &matcher->tx);
		if (ret)
			return ret;
	}

	return 0;
}

static int mlx5dr_debug_dump_table_nic(FILE *f,
				       enum mlx5dr_debug_res_type type,
				       struct mlx5dr_table *tbl)
{
	int ret;

	ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 ",%d\n",
		      type,
		      (uint64_t)(uintptr_t)tbl,
		      (uint64_t)(uintptr_t)tbl,
		      tbl->level == MLX5DR_ROOT_LEVEL ? 0 : tbl->ft->id);
	if (ret < 0) {
		rte_errno = EINVAL;
		return rte_errno;
	}

	return 0;
}

static int mlx5dr_debug_dump_table(FILE *f, struct mlx5dr_table *tbl)
{
	bool is_root = tbl->level == MLX5DR_ROOT_LEVEL;
	struct mlx5dr_matcher *matcher;
	int ret;

	ret = fprintf(f, "%d,0x%" PRIx64 ",0x%" PRIx64 ",%d,%d,%d,%d\n",
		      MLX5DR_DEBUG_RES_TYPE_TABLE,
		      (uint64_t)(uintptr_t)tbl,
		      (uint64_t)(uintptr_t)tbl->ctx,
		      is_root ? 0 : tbl->ft->id,
		      tbl->type,
		      is_root ? 0 : tbl->fw_ft_type,
		      tbl->level);
	if (ret < 0) {
		rte_errno = EINVAL;
		return rte_errno;
	}

	if (tbl->type == MLX5DR_TABLE_TYPE_NIC_RX ||
			tbl->type == MLX5DR_TABLE_TYPE_FDB) {
		ret = mlx5dr_debug_dump_table_nic(f, MLX5DR_DEBUG_RES_TYPE_TABLE_NIC_RX,
						  tbl);
		if (ret)
			return ret;
	}

	if (tbl->type == MLX5DR_TABLE_TYPE_NIC_TX ||
			tbl->type == MLX5DR_TABLE_TYPE_FDB) {
		ret = mlx5dr_debug_dump_table_nic(f, MLX5DR_DEBUG_RES_TYPE_TABLE_NIC_TX,
						  tbl);
		if (ret)
			return ret;
	}

	LIST_FOREACH(matcher, &tbl->head, next) {
		ret = mlx5dr_debug_dump_matcher(f, matcher);
		if (ret)
			return ret;
	}

	return 0;
}

static int mlx5dr_debug_dump_context_send_engine(FILE *f, struct mlx5dr_context *ctx)
{
	struct mlx5dr_send_engine *send_queue;
	int ret, i, j;

	for (i = 0; i < (int)ctx->queues; i++) {
		send_queue = &ctx->send_queue[i];
		ret = fprintf(f, "%d,0x%" PRIx64 ",%d,%d,%d,%d,%d,%d,%d,%d,%d\n",
			      MLX5DR_DEBUG_RES_TYPE_CONTEXT_SEND_ENGINE,
			      (uint64_t)(uintptr_t)ctx,
			      i,
			      send_queue->used_entries,
			      send_queue->th_entries,
			      send_queue->rings,
			      send_queue->num_entries,
			      send_queue->err,
			      send_queue->completed.ci,
			      send_queue->completed.pi,
			      send_queue->completed.mask);
		if (ret < 0) {
			rte_errno = EINVAL;
			return rte_errno;
		}

		for (j = 0; j < MLX5DR_NUM_SEND_RINGS; j++) {
			struct mlx5dr_send_ring *send_ring = &send_queue->send_ring[j];
			struct mlx5dr_send_ring_cq *cq = &send_ring->send_cq;
			struct mlx5dr_send_ring_sq *sq = &send_ring->send_sq;

			ret = fprintf(f, "%d,0x%" PRIx64 ",%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",
				      MLX5DR_DEBUG_RES_TYPE_CONTEXT_SEND_RING,
				      (uint64_t)(uintptr_t)ctx,
				      j,
				      i,
				      cq->cqn,
				      cq->cons_index,
				      cq->ncqe_mask,
				      cq->buf_sz,
				      cq->ncqe,
				      cq->cqe_log_sz,
				      cq->poll_wqe,
				      cq->cqe_sz,
				      sq->sqn,
				      sq->obj->id,
				      sq->cur_post,
				      sq->buf_mask);
			if (ret < 0) {
				rte_errno = EINVAL;
				return rte_errno;
			}
		}
	}

	return 0;
}

static int mlx5dr_debug_dump_context_caps(FILE *f, struct mlx5dr_context *ctx)
{
	struct mlx5dr_cmd_query_caps *caps = ctx->caps;
	int ret;

	ret = fprintf(f, "%d,0x%" PRIx64 ",%s,%d,%d,%d,%d,",
		      MLX5DR_DEBUG_RES_TYPE_CONTEXT_CAPS,
		      (uint64_t)(uintptr_t)ctx,
		      caps->fw_ver,
		      caps->wqe_based_update,
		      caps->ste_format,
		      caps->ste_alloc_log_max,
		      caps->log_header_modify_argument_max_alloc);
	if (ret < 0) {
		rte_errno = EINVAL;
		return rte_errno;
	}

	ret = fprintf(f, "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",
		      caps->flex_protocols,
		      caps->rtc_reparse_mode,
		      caps->rtc_index_mode,
		      caps->ste_alloc_log_gran,
		      caps->stc_alloc_log_max,
		      caps->stc_alloc_log_gran,
		      caps->rtc_log_depth_max,
		      caps->flex_parser_id_gtpu_dw_0,
		      caps->flex_parser_id_gtpu_teid,
		      caps->flex_parser_id_gtpu_dw_2,
		      caps->flex_parser_id_gtpu_first_ext_dw_0,
		      caps->nic_ft.max_level,
		      caps->nic_ft.reparse,
		      caps->fdb_ft.max_level,
		      caps->fdb_ft.reparse,
		      caps->log_header_modify_argument_granularity);
	if (ret < 0) {
		rte_errno = EINVAL;
		return rte_errno;
	}

	return 0;
}

static int mlx5dr_debug_dump_context_attr(FILE *f, struct mlx5dr_context *ctx)
{
	int ret;

	ret = fprintf(f, "%u,0x%" PRIx64 ",%d,%zu,%d\n",
		      MLX5DR_DEBUG_RES_TYPE_CONTEXT_ATTR,
		      (uint64_t)(uintptr_t)ctx,
		      ctx->pd_num,
		      ctx->queues,
		      ctx->send_queue->num_entries);
	if (ret < 0) {
		rte_errno = EINVAL;
		return rte_errno;
	}

	return 0;
}

static int mlx5dr_debug_dump_context_info(FILE *f, struct mlx5dr_context *ctx)
{
	int ret;

	ret = fprintf(f, "%d,0x%" PRIx64 ",%d,%s,%s\n",
		      MLX5DR_DEBUG_RES_TYPE_CONTEXT,
		      (uint64_t)(uintptr_t)ctx,
		      ctx->flags & MLX5DR_CONTEXT_FLAG_HWS_SUPPORT,
		      mlx5_glue->get_device_name(ctx->ibv_ctx->device),
		      DEBUG_VERSION);
	if (ret < 0) {
		rte_errno = EINVAL;
		return rte_errno;
	}

	ret = mlx5dr_debug_dump_context_attr(f, ctx);
	if (ret)
		return ret;

	ret = mlx5dr_debug_dump_context_caps(f, ctx);
	if (ret)
		return ret;

	return 0;
}

static int mlx5dr_debug_dump_context(FILE *f, struct mlx5dr_context *ctx)
{
	struct mlx5dr_table *tbl;
	int ret;

	ret = mlx5dr_debug_dump_context_info(f, ctx);
	if (ret)
		return ret;

	ret = mlx5dr_debug_dump_context_send_engine(f, ctx);
	if (ret)
		return ret;

	LIST_FOREACH(tbl, &ctx->head, next) {
		ret = mlx5dr_debug_dump_table(f, tbl);
		if (ret)
			return ret;
	}

	return 0;
}

int mlx5dr_debug_dump(FILE *f, struct mlx5dr_context *ctx)
{
	int ret;

	if (!f || !ctx) {
		rte_errno = EINVAL;
		return -rte_errno;
	}

	pthread_spin_lock(&ctx->ctrl_lock);
	ret = mlx5dr_debug_dump_context(f, ctx);
	pthread_spin_unlock(&ctx->ctrl_lock);

	return -ret;
}
