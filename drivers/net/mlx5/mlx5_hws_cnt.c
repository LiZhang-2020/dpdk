/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <stdint.h>
#include <rte_malloc.h>
#include <mlx5_malloc.h>

#include "mlx5_utils.h"
#include "mlx5_hws_cnt.h"

struct mlx5_hws_cnt_pool *
mlx5_hws_cnt_pool_init(const struct mlx5_hws_cnt_pool_cfg *pcfg,
		const struct mlx5_hws_cache_param *ccfg)
{
	char mz_name[RTE_MEMZONE_NAMESIZE];
	struct mlx5_hws_cnt_pool *cntp;
	uint64_t cnt_num = 0;
	uint32_t qidx;

	MLX5_ASSERT(pcfg);
	MLX5_ASSERT(ccfg);
	cntp = mlx5_malloc(MLX5_MEM_ANY | MLX5_MEM_ZERO, sizeof(*cntp), 0,
			   SOCKET_ID_ANY);
	if (cntp == NULL)
		return NULL;

	cntp->cfg = *pcfg;
	cntp->cache = mlx5_malloc(MLX5_MEM_ANY | MLX5_MEM_ZERO,
			sizeof(*cntp->cache) +
			sizeof(((struct mlx5_hws_cnt_pool_caches *)0)->qcache[0])
				* ccfg->q_num, 0, SOCKET_ID_ANY);
	if (cntp->cache == NULL)
		goto error;
	 /* store the necessary cache parameters. */
	cntp->cache->fetch_sz = ccfg->fetch_sz;
	cntp->cache->preload_sz = ccfg->preload_sz;
	cntp->cache->threshold = ccfg->threshold;
	cntp->cache->q_num = ccfg->q_num;
	cnt_num = pcfg->request_num * (100 + pcfg->alloc_factor) / 100;
	if (cnt_num > UINT32_MAX) {
		DRV_LOG(ERR, "counter number %lu is out of 32bit range",
			cnt_num);
		goto error;
	}
	cntp->pool = mlx5_malloc(MLX5_MEM_ANY | MLX5_MEM_ZERO,
			sizeof(struct mlx5_hws_cnt) *
			pcfg->request_num * (100 + pcfg->alloc_factor) / 100,
			0, SOCKET_ID_ANY);
	if (cntp->pool == NULL)
		goto error;
	snprintf(mz_name, sizeof(mz_name), "%s_F_RING", pcfg->name);
	cntp->free_list = rte_ring_create_elem(mz_name, sizeof(cnt_id_t),
			(uint32_t)cnt_num, SOCKET_ID_ANY,
			RING_F_SP_ENQ | RING_F_MC_HTS_DEQ | RING_F_EXACT_SZ);
	if (cntp->free_list == NULL) {
		DRV_LOG(ERR, "failed to create free list ring");
		goto error;
	}
	snprintf(mz_name, sizeof(mz_name), "%s_R_RING", pcfg->name);
	cntp->wait_reset_list = rte_ring_create_elem(mz_name, sizeof(cnt_id_t),
			(uint32_t)cnt_num, SOCKET_ID_ANY,
			RING_F_MP_HTS_ENQ | RING_F_SC_DEQ | RING_F_EXACT_SZ);
	if (cntp->wait_reset_list == NULL) {
		DRV_LOG(ERR, "failed to create free list ring");
		goto error;
	}
	for (qidx = 0; qidx < ccfg->q_num; qidx++) {
		snprintf(mz_name, sizeof(mz_name), "%s_cache/%u", pcfg->name,
				qidx);
		cntp->cache->qcache[qidx] = rte_ring_create(mz_name, ccfg->size,
				SOCKET_ID_ANY,
				RING_F_SP_ENQ | RING_F_SC_DEQ |
				RING_F_EXACT_SZ);
		if (cntp->cache->qcache[qidx] == NULL)
			goto error;
	}
	return cntp;
error:
	mlx5_hws_cnt_pool_deinit(cntp);
	return NULL;
}

void
mlx5_hws_cnt_pool_deinit(struct mlx5_hws_cnt_pool * const cntp)
{
	uint32_t qidx = 0;
	if (cntp == NULL)
		return;
	rte_ring_free(cntp->free_list);
	rte_ring_free(cntp->wait_reset_list);
	if (cntp->cache) {
		for (qidx = 0; qidx < cntp->cache->q_num; qidx++)
			rte_ring_free(cntp->cache->qcache[qidx]);
	}
	mlx5_free(cntp->cache);
	mlx5_free(cntp->raw_mng);
	mlx5_free(cntp->pool);
	mlx5_free(cntp);
}
