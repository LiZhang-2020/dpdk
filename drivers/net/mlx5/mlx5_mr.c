/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2016 6WIND S.A.
 * Copyright 2016 Mellanox Technologies, Ltd
 */

#include <rte_eal_memconfig.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_rwlock.h>

#include <mlx5_common_mp.h>
#include <mlx5_common_mr.h>

#include "mlx5.h"
#include "mlx5_rxtx.h"

/**
 * Bottom-half of LKey search on Tx.
 *
 * @param txq
 *   Pointer to Tx queue structure.
 * @param addr
 *   Search key.
 *
 * @return
 *   Searched LKey on success, UINT32_MAX on no match.
 */
static uint32_t
mlx5_tx_addr2mr_bh(struct mlx5_txq_data *txq, uintptr_t addr)
{
	struct mlx5_txq_ctrl *txq_ctrl =
		container_of(txq, struct mlx5_txq_ctrl, txq);
	struct mlx5_mr_ctrl *mr_ctrl = &txq->mr_ctrl;
	struct mlx5_priv *priv = txq_ctrl->priv;

	return mlx5_mr_addr2mr_bh(mr_ctrl, &priv->mp_id, addr);
}

/**
 * Bottom-half of LKey search on Tx. If it can't be searched in the memseg
 * list, register the mempool of the mbuf as externally allocated memory.
 *
 * @param txq
 *   Pointer to Tx queue structure.
 * @param mb
 *   Pointer to mbuf.
 *
 * @return
 *   Searched LKey on success, UINT32_MAX on no match.
 */
uint32_t
mlx5_tx_mb2mr_bh(struct mlx5_txq_data *txq, struct rte_mbuf *mb)
{
	struct mlx5_mr_ctrl *mr_ctrl = &txq->mr_ctrl;
	uintptr_t addr = (uintptr_t)mb->buf_addr;
	struct mlx5_mr_share_cache *share_cache =
		container_of(mr_ctrl->dev_gen_ptr, struct mlx5_mr_share_cache,
			     dev_gen);
	struct mlx5_common_device *cdev =
		container_of(share_cache, struct mlx5_common_device, mr_scache);
	uint32_t lkey;

	if (cdev->config.mr_mempool_reg_en) {
		struct rte_mempool *mp = NULL;
		struct mlx5_mprq_buf *buf;

		if (!RTE_MBUF_HAS_EXTBUF(mb)) {
			mp = mlx5_mb2mp(mb);
		} else if (mb->shinfo->free_cb == mlx5_mprq_buf_free_cb) {
			/* Recover MPRQ mempool. */
			buf = mb->shinfo->fcb_opaque;
			mp = buf->mp;
		}
		if (mp != NULL) {
			lkey = mlx5_mr_mempool2mr_bh(mr_ctrl, mp, addr);
			/*
			 * Lookup can only fail on invalid input, e.g. "addr"
			 * is not from "mp" or "mp" has MEMPOOL_F_NON_IO set.
			 */
			if (lkey != UINT32_MAX)
				return lkey;
		}
		/* Fallback for generic mechanism in corner cases. */
	}
	return mlx5_tx_addr2mr_bh(txq, addr);
}
