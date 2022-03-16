/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <stdint.h>
#include <rte_malloc.h>
#include <mlx5_malloc.h>
#include <rte_ring.h>

#include "mlx5_utils.h"
#include "mlx5_hws_cnt.h"

static void
__mlx5_hws_cnt_svc(struct mlx5_dev_ctx_shared *sh,
		struct mlx5_hws_cnt_pool *cpool)
{
	struct rte_ring *reset_list = cpool->wait_reset_list;
	struct rte_ring *free_list = cpool->free_list;
	uint32_t reset_cnt_num;
	struct rte_ring_zc_data zcdr = {0};
	struct rte_ring_zc_data zcdf = {0};

	reset_cnt_num = rte_ring_count(reset_list);
	do {
		cpool->query_gen++;
		mlx5_hws_cnt_pool_aso_query(sh, cpool);
		zcdr.n1 = 0;
		zcdf.n1 = 0;
		rte_ring_enqueue_zc_burst_elem_start(free_list,
				sizeof(cnt_id_t), reset_cnt_num, &zcdf,
				NULL);
		rte_ring_dequeue_zc_burst_elem_start(reset_list,
				sizeof(cnt_id_t), reset_cnt_num, &zcdr,
				NULL);
		__hws_cnt_r2rcpy(&zcdf, &zcdr, reset_cnt_num);
		rte_ring_dequeue_zc_elem_finish(reset_list,
				reset_cnt_num);
		rte_ring_enqueue_zc_elem_finish(free_list,
				reset_cnt_num);
		reset_cnt_num = rte_ring_count(reset_list);
	} while (reset_cnt_num > 0);
}

static void *
mlx5_hws_cnt_svc(void *opaque)
{
	struct mlx5_dev_ctx_shared *sh =
		(struct mlx5_dev_ctx_shared *)opaque;
	uint32_t interval = sh->cnt_svc->query_interval;
	uint16_t port_id;
	uint64_t start_cycle, query_cycle = 0;
	uint64_t query_us;
	uint64_t sleep_us;

	while (sh->cnt_svc->svc_running != 0) {
		start_cycle = rte_rdtsc();
		MLX5_ETH_FOREACH_DEV(port_id, sh->cdev->dev) {
			struct mlx5_priv *opriv =
				rte_eth_devices[port_id].data->dev_private;
			if (opriv != NULL &&
			    opriv->sh == sh &&
			    opriv->hws_cpool != NULL) {
				__mlx5_hws_cnt_svc(sh, opriv->hws_cpool);
			}
		}
		query_cycle = rte_rdtsc() - start_cycle;
		query_us = query_cycle / (rte_get_timer_hz() / US_PER_S);
		sleep_us = interval - query_us;
		if (interval > query_us)
			rte_delay_us_sleep(sleep_us);
	}
	return NULL;
}

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

int
mlx5_hws_cnt_service_thread_create(struct mlx5_dev_ctx_shared *sh)
{
	char name[NAME_MAX];
	cpu_set_t cpuset;
	int ret;
	uint32_t service_core = sh->cnt_svc->service_core;

	CPU_ZERO(&cpuset);
	sh->cnt_svc->svc_running = 1;
	ret = pthread_create(&sh->cnt_svc->service_thread, NULL,
			mlx5_hws_cnt_svc, sh);
	if (ret != 0) {
		DRV_LOG(ERR, "Failed to create HW steering's counter service thread.");
		return -ENOSYS;
	}
	snprintf(name, NAME_MAX - 1, "%s/svc@%d",
		 sh->ibdev_name, service_core);
	rte_thread_setname(sh->cnt_svc->service_thread, name);
	CPU_SET(service_core, &cpuset);
	pthread_setaffinity_np(sh->cnt_svc->service_thread, sizeof(cpuset),
				&cpuset);
	return 0;
}

void
mlx5_hws_cnt_service_thread_destroy(struct mlx5_dev_ctx_shared *sh)
{
	if (sh->cnt_svc->service_thread == 0)
		return;
	sh->cnt_svc->svc_running = 0;
	pthread_join(sh->cnt_svc->service_thread, NULL);
	sh->cnt_svc->service_thread = 0;
}

int
mlx5_hws_cnt_pool_aso_query(struct mlx5_dev_ctx_shared *sh,
			    struct mlx5_hws_cnt_pool *cpool)
{
	/* To be added later. */
	RTE_SET_USED(sh);
	RTE_SET_USED(cpool);
	return 0;
}
