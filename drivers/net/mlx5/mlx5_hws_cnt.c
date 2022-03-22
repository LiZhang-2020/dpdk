/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <stdint.h>
#include <rte_malloc.h>
#include <mlx5_malloc.h>
#include <rte_ring.h>
#include <mlx5_devx_cmds.h>
#include <rte_cycles.h>

#include "mlx5_utils.h"
#include "mlx5_hws_cnt.h"

#define HWS_CNT_CACHE_SZ_DEFAULT 511
#define HWS_CNT_CACHE_PRELOAD_DEFAULT 254
#define HWS_CNT_CACHE_FETCH_DEFAULT 254
#define HWS_CNT_CACHE_THRESHOLD_DEFAULT 254
#define HWS_CNT_ALLOC_FACTOR_DEFAULT 20

static void
__hws_cnt_id_load(struct mlx5_hws_cnt_pool *cpool)
{
	uint32_t preload;
	uint32_t q_num = cpool->cache->q_num;
	uint32_t cnt_num = mlx5_hws_cnt_pool_get_size(cpool);
	cnt_id_t cnt_id, iidx = 0;
	uint32_t qidx;
	struct rte_ring *qcache = NULL;

	preload = RTE_MIN(cpool->cache->preload_sz, cnt_num / q_num);
	for (qidx = 0; qidx < q_num; qidx++) {
		for (; iidx < preload * (qidx + 1); iidx++) {
			cnt_id = (MLX5_INDIRECT_ACTION_TYPE_COUNT <<
				  MLX5_INDIRECT_ACTION_TYPE_OFFSET) | iidx;
			qcache = cpool->cache->qcache[qidx];
			if (qcache)
				rte_ring_enqueue_elem(qcache, &cnt_id,
						sizeof(cnt_id));
		}
	}
	for (; iidx < cnt_num; iidx++) {
		cnt_id = (MLX5_INDIRECT_ACTION_TYPE_COUNT <<
			  MLX5_INDIRECT_ACTION_TYPE_OFFSET) | iidx;
		rte_ring_enqueue_elem(cpool->free_list, &cnt_id,
				sizeof(cnt_id));
	}
}

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

static void
mlx5_hws_cnt_raw_data_free(struct mlx5_dev_ctx_shared *sh,
			   struct mlx5_hws_cnt_raw_data_mng *mng)
{
	if (mng == NULL)
		return;
	sh->cdev->mr_scache.dereg_mr_cb(&mng->mr);
	mlx5_free(mng->raw);
	mlx5_free(mng);
}

__rte_unused
static struct mlx5_hws_cnt_raw_data_mng *
mlx5_hws_cnt_raw_data_alloc(struct mlx5_dev_ctx_shared *sh, uint32_t n)
{
	struct mlx5_hws_cnt_raw_data_mng *mng = NULL;
	int ret;
	size_t sz = n * sizeof(struct flow_counter_stats);

	mng = mlx5_malloc(MLX5_MEM_ANY | MLX5_MEM_ZERO, sizeof(*mng), 0,
			SOCKET_ID_ANY);
	if (mng == NULL)
		goto error;
	mng->raw = mlx5_malloc(MLX5_MEM_ANY | MLX5_MEM_ZERO, sz, 0,
			SOCKET_ID_ANY);
	if (mng->raw == NULL)
		goto error;
	ret = sh->cdev->mr_scache.reg_mr_cb(sh->cdev->pd, mng->raw, sz,
					    &mng->mr);
	if (ret) {
		rte_errno = errno;
		goto error;
	}
	return mng;
error:
	mlx5_hws_cnt_raw_data_free(sh, mng);
	return NULL;
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
mlx5_hws_cnt_pool_dcs_alloc(struct mlx5_dev_ctx_shared *sh,
			    struct mlx5_hws_cnt_pool *cpool)
{
	struct mlx5_hca_attr *hca_attr = &sh->cdev->config.hca_attr;
	uint32_t max_log_bulk_sz = 0;
	uint32_t log_bulk_sz;
	uint32_t idx, alloced = 0;
	unsigned int cnt_num = mlx5_hws_cnt_pool_get_size(cpool);
	struct mlx5_devx_counter_attr attr = {0};
	struct mlx5_devx_obj *dcs;

	if (hca_attr->flow_counter_bulk_log_max_alloc == 0) {
		DRV_LOG(ERR,
			"Fw doesn't support bulk log max alloc");
		return -1;
	}
	max_log_bulk_sz = 23; /* hard code to 8M (1 << 23). */
	cnt_num = RTE_ALIGN_CEIL(cnt_num, 4); /* minimal 4 counter in bulk. */
	log_bulk_sz = RTE_MIN(max_log_bulk_sz, rte_log2_u32(cnt_num));
	attr.pd = sh->cdev->pdn;
	attr.pd_valid = 1;
	attr.bulk_log_max_alloc = 1;
	attr.flow_counter_bulk_log_size = log_bulk_sz;
	idx = 0;
	dcs = mlx5_devx_cmd_flow_counter_alloc_general(sh->cdev->ctx, &attr);
	if (dcs == NULL)
		goto error;
	cpool->dcs_mng.dcs[idx].obj = dcs;
	cpool->dcs_mng.dcs[idx].batch_sz = (1 << log_bulk_sz);
	cpool->dcs_mng.batch_total++;
	idx++;
	alloced = cpool->dcs_mng.dcs[0].batch_sz;
	if (cnt_num > cpool->dcs_mng.dcs[0].batch_sz) {
		for (; idx < MLX5_HWS_CNT_DCS_NUM; idx++) {
			attr.flow_counter_bulk_log_size = --max_log_bulk_sz;
			dcs = mlx5_devx_cmd_flow_counter_alloc_general
				(sh->cdev->ctx, &attr);
			if (dcs == NULL)
				goto error;
			cpool->dcs_mng.dcs[idx].obj = dcs;
			cpool->dcs_mng.dcs[idx].batch_sz =
				(1 << max_log_bulk_sz);
			alloced += cpool->dcs_mng.dcs[idx].batch_sz;
			cpool->dcs_mng.batch_total++;
		}
	}
	return 0;
error:
	DRV_LOG(DEBUG,
		"Cannot alloc device counter, allocated[%" PRIu32 "] request[%" PRIu32 "]",
		alloced, cnt_num);
	for (idx = 0; idx < cpool->dcs_mng.batch_total; idx++) {
		mlx5_devx_cmd_destroy(cpool->dcs_mng.dcs[idx].obj);
		cpool->dcs_mng.dcs[idx].obj = NULL;
		cpool->dcs_mng.dcs[idx].batch_sz = 0;
	}
	cpool->dcs_mng.batch_total = 0;
	return -1;
}

void
mlx5_hws_cnt_pool_dcs_free(struct mlx5_dev_ctx_shared *sh,
			   struct mlx5_hws_cnt_pool *cpool)
{
	uint32_t idx;

	if (cpool == NULL)
		return;
	for (idx = 0; idx < MLX5_HWS_CNT_DCS_NUM; idx++)
		mlx5_devx_cmd_destroy(cpool->dcs_mng.dcs[idx].obj);
	if (cpool->raw_mng) {
		mlx5_hws_cnt_raw_data_free(sh, cpool->raw_mng);
		cpool->raw_mng = NULL;
	}
}

static int
mlx5_aso_cq_create(void *ctx, struct mlx5_aso_cq *cq, uint16_t log_desc_n,
		   int socket, int uar_page_id)
{
	struct mlx5_devx_cq_attr attr = {
		.uar_page_id = uar_page_id,
	};

	cq->log_desc_n = log_desc_n;
	cq->cq_ci = 0;
	return mlx5_devx_cq_create(ctx, &cq->cq_obj, log_desc_n, &attr, socket);
}

static void
mlx5_aso_cq_destroy(struct mlx5_aso_cq *cq)
{
	if (cq->cq_obj.cq)
		mlx5_devx_cq_destroy(&cq->cq_obj);
	memset(cq, 0, sizeof(*cq));
}

static void
mlx5_aso_destroy_sq(struct mlx5_aso_sq *sq)
{
	mlx5_devx_sq_destroy(&sq->sq_obj);
	mlx5_aso_cq_destroy(&sq->cq);
	memset(sq, 0, sizeof(*sq));
}

static int
mlx5_aso_sq_create(void *ctx, struct mlx5_aso_sq *sq, int socket, void *uar,
		   uint32_t pdn, uint16_t log_desc_n, uint32_t ts_format)
{
	struct mlx5_devx_create_sq_attr attr = {
		.user_index = 0xFFFF,
		.wq_attr = (struct mlx5_devx_wq_attr){
			.pd = pdn,
			.uar_page = mlx5_os_get_devx_uar_page_id(uar),
		},
		.ts_format = mlx5_ts_format_conv(ts_format),
	};
	struct mlx5_devx_modify_sq_attr modify_attr = {
		.state = MLX5_SQC_STATE_RDY,
	};
	uint16_t log_wqbb_n;
	int ret;

	if (mlx5_aso_cq_create(ctx, &sq->cq, log_desc_n, socket,
			       mlx5_os_get_devx_uar_page_id(uar)))
		goto error;
	sq->log_desc_n = log_desc_n;
	attr.cqn = sq->cq.cq_obj.cq->id;
	/* for mlx5_aso_wqe that is twice the size of mlx5_wqe */
	log_wqbb_n = log_desc_n + 1;
	ret = mlx5_devx_sq_create(ctx, &sq->sq_obj, log_wqbb_n, &attr, socket);
	if (ret) {
		DRV_LOG(ERR, "Can't create SQ object.");
		rte_errno = ENOMEM;
		goto error;
	}
	ret = mlx5_devx_cmd_modify_sq(sq->sq_obj.sq, &modify_attr);
	if (ret) {
		DRV_LOG(ERR, "Can't change SQ state to ready.");
		rte_errno = ENOMEM;
		goto error;
	}
	sq->pi = 0;
	sq->head = 0;
	sq->tail = 0;
	sq->sqn = sq->sq_obj.sq->id;
	rte_spinlock_init(&sq->sqsl);
	return 0;
error:
	mlx5_aso_destroy_sq(sq);
	return -1;
}

static void
mlx5_hws_cnt_aso_init_sq(struct mlx5_aso_sq *sq)
{
	volatile struct mlx5_aso_wqe *restrict wqe;
	int i;
	int size = 1 << sq->log_desc_n;

	/* All the next fields state should stay constant. */
	for (i = 0, wqe = &sq->sq_obj.aso_wqes[0]; i < size; ++i, ++wqe) {
		wqe->general_cseg.sq_ds = rte_cpu_to_be_32((sq->sqn << 8) |
							  (sizeof(*wqe) >> 4));
		wqe->aso_cseg.operand_masks = rte_cpu_to_be_32
			(0u |
			 (ASO_OPER_LOGICAL_OR << ASO_CSEG_COND_OPER_OFFSET) |
			 (ASO_OP_ALWAYS_FALSE << ASO_CSEG_COND_1_OPER_OFFSET) |
			 (ASO_OP_ALWAYS_FALSE << ASO_CSEG_COND_0_OPER_OFFSET) |
			 (BYTEWISE_64BYTE << ASO_CSEG_DATA_MASK_MODE_OFFSET));
		wqe->aso_cseg.data_mask = RTE_BE64(UINT64_MAX);
	}
}

static void
mlx5_aso_dump_err_objs(volatile uint32_t *cqe, volatile uint32_t *wqe)
{
	int i;

	DRV_LOG(ERR, "Error cqe:");
	for (i = 0; i < 16; i += 4)
		DRV_LOG(ERR, "%08X %08X %08X %08X", cqe[i], cqe[i + 1],
			cqe[i + 2], cqe[i + 3]);
	DRV_LOG(ERR, "\nError wqe:");
	for (i = 0; i < (int)sizeof(struct mlx5_aso_wqe) / 4; i += 4)
		DRV_LOG(ERR, "%08X %08X %08X %08X", wqe[i], wqe[i + 1],
			wqe[i + 2], wqe[i + 3]);
}

static void
mlx5_aso_cqe_err_handle(struct mlx5_aso_sq *sq)
{
	struct mlx5_aso_cq *cq = &sq->cq;
	uint32_t idx = cq->cq_ci & ((1 << cq->log_desc_n) - 1);
	volatile struct mlx5_err_cqe *cqe =
			(volatile struct mlx5_err_cqe *)&cq->cq_obj.cqes[idx];

	cq->errors++;
	idx = rte_be_to_cpu_16(cqe->wqe_counter) & (1u << sq->log_desc_n);
	mlx5_aso_dump_err_objs((volatile uint32_t *)cqe,
			       (volatile uint32_t *)&sq->sq_obj.aso_wqes[idx]);
}

static uint16_t
__mlx5_aso_completion_handle(struct mlx5_aso_sq *sq)
{
	struct mlx5_aso_cq *cq = &sq->cq;
	volatile struct mlx5_cqe *restrict cqe;
	const unsigned int cq_size = 1 << cq->log_desc_n;
	const unsigned int mask = cq_size - 1;
	uint32_t idx;
	uint32_t next_idx = cq->cq_ci & mask;
	const uint16_t max = (uint16_t)(sq->head - sq->tail);
	uint16_t i = 0;
	int ret;
	if (unlikely(!max))
		return 0;
	do {
		idx = next_idx;
		next_idx = (cq->cq_ci + 1) & mask;
		rte_prefetch0(&cq->cq_obj.cqes[next_idx]);
		cqe = &cq->cq_obj.cqes[idx];
		ret = check_cqe(cqe, cq_size, cq->cq_ci);
		/*
		 * Be sure owner read is done before any other cookie field or
		 * opaque field.
		 */
		rte_io_rmb();
		if (unlikely(ret != MLX5_CQE_STATUS_SW_OWN)) {
			if (likely(ret == MLX5_CQE_STATUS_HW_OWN))
				break;
			mlx5_aso_cqe_err_handle(sq);
			i += sq->elts[(sq->tail + i) & mask].burst_size;
		} else {
			i += sq->elts[(sq->tail + i) & mask].burst_size;
		}
		cq->cq_ci++;
	} while (0);
	if (likely(i)) {
		sq->tail += i;
		rte_io_wmb();
		cq->cq_obj.db_rec[0] = rte_cpu_to_be_32(cq->cq_ci);
	}
	return i;
}

static int
__hws_cnt_get_dcs_id(struct mlx5_hws_cnt_pool *cpool, cnt_id_t cnt_id)
{
	struct mlx5_hws_cnt_dcs_mng *dcs_mng = &cpool->dcs_mng;
	uint16_t idx, offset;

	offset = cnt_id & ((1 << MLX5_INDIRECT_ACTION_TYPE_OFFSET) - 1);
	for (idx = 0; idx < dcs_mng->batch_total; idx++) {
		if (dcs_mng->dcs[idx].batch_sz <= offset)
			offset -= dcs_mng->dcs[idx].batch_sz;
		else
			return (dcs_mng->dcs[idx].obj->id + offset);
	}
	return -1;
}

static uint16_t
mlx5_hws_cnt_aso_sq_enqueue_burst(struct mlx5_hws_cnt_pool *cpool,
		struct mlx5_dev_ctx_shared *sh,
		struct mlx5_aso_sq *sq, uint16_t n,
		uint32_t offset)
{
	volatile struct mlx5_aso_wqe *wqe;
	uint16_t size = 1 << sq->log_desc_n;
	uint16_t mask = size - 1;
	uint16_t max;
	uint16_t start_head = sq->head;
	uint32_t upper_offset = offset;
	uint64_t addr;
	uint32_t ctrl_gen_id = 0;
	uint8_t opcmod = sh->cdev->config.hca_attr.flow_access_aso_opc_mod;
	rte_be32_t lkey = rte_cpu_to_be_32(cpool->raw_mng->mr.lkey);

	max = RTE_MIN(size - (uint16_t)(sq->head - sq->tail), n);
	if (unlikely(!max))
		return 0;
	max = RTE_ALIGN_CEIL(max, 4);
	upper_offset += max;
	sq->elts[start_head & mask].burst_size = max / 4;
	do {
		ctrl_gen_id = __hws_cnt_get_dcs_id(cpool, upper_offset - max);
		ctrl_gen_id /= 4;
		wqe = &sq->sq_obj.aso_wqes[sq->head & mask];
		rte_prefetch0(&sq->sq_obj.aso_wqes[(sq->head + 1) & mask]);
		wqe->general_cseg.misc = rte_cpu_to_be_32(ctrl_gen_id);
		wqe->general_cseg.flags = RTE_BE32(MLX5_COMP_ONLY_FIRST_ERR <<
							 MLX5_COMP_MODE_OFFSET);
		wqe->general_cseg.opcode = rte_cpu_to_be_32
						(MLX5_OPCODE_ACCESS_ASO |
						 (opcmod <<
						  WQE_CSEG_OPC_MOD_OFFSET) |
						 (sq->pi <<
						  WQE_CSEG_WQE_INDEX_OFFSET));
		addr = (uint64_t)RTE_PTR_ADD(cpool->raw_mng->raw,
				(upper_offset - max) *
				sizeof(struct flow_counter_stats));
		wqe->aso_cseg.va_h = rte_cpu_to_be_32((uint32_t)(addr >> 32));
		wqe->aso_cseg.va_l_r = rte_cpu_to_be_32((uint32_t)addr | 1u);
		wqe->aso_cseg.lkey = lkey;
		sq->pi += 2; /* Each WQE contains 2 WQEBB's. */
		sq->head++;
		sq->next++;
		max -= 4;
	} while (max);
	wqe->general_cseg.flags = RTE_BE32(MLX5_COMP_ALWAYS <<
							 MLX5_COMP_MODE_OFFSET);
	mlx5_doorbell_ring(&sh->tx_uar.bf_db, *(volatile uint64_t *)wqe,
			   sq->pi, &sq->sq_obj.db_rec[MLX5_SND_DBR],
			   !sh->tx_uar.dbnc);
	return sq->elts[start_head & mask].burst_size;
}

int
mlx5_hws_cnt_pool_aso_query(struct mlx5_dev_ctx_shared *sh,
			    struct mlx5_hws_cnt_pool *cpool)
{
	uint32_t cnt_num = mlx5_hws_cnt_pool_get_size(cpool);
	uint64_t burst_sz = (1 << MLX5_ASO_QUEUE_LOG_DESC) * 4 *
		sh->cnt_svc->aso_mng.sq_num;
	uint16_t sq_idx;
	uint64_t left;
	uint64_t qburst_sz = burst_sz / sh->cnt_svc->aso_mng.sq_num;
	uint64_t n;
	uint16_t mask = 0;
	struct mlx5_aso_sq *sq;

	left = cnt_num;
	while (left) {
		for (sq_idx = 0; sq_idx < sh->cnt_svc->aso_mng.sq_num;
				sq_idx++) {
			if (left == 0) {
				mask |= (1 << sq_idx);
				continue;
			}
			n = RTE_MIN(left, qburst_sz);
			mlx5_hws_cnt_aso_sq_enqueue_burst(cpool, sh,
					&sh->cnt_svc->aso_mng.sqs[sq_idx], n,
					cnt_num - left);
			left -= n;
		}
		do {
			for (sq_idx = 0; sq_idx < sh->cnt_svc->aso_mng.sq_num;
					sq_idx++) {
				sq = &sh->cnt_svc->aso_mng.sqs[sq_idx];
				if (__mlx5_aso_completion_handle(sq))
					mask |= (1 << sq_idx);
			}
		} while (mask < ((1 << sh->cnt_svc->aso_mng.sq_num) - 1));
	}
	return 0;
}

int
mlx5_hws_cnt_aso_access_alloc(struct mlx5_dev_ctx_shared *sh)
{
	struct mlx5_hws_aso_mng *aso_mng = NULL;
	uint8_t idx;
	struct mlx5_aso_sq *sq;

	MLX5_ASSERT(sh);
	MLX5_ASSERT(sh->cnt_svc);
	aso_mng = &sh->cnt_svc->aso_mng;
	aso_mng->sq_num = HWS_CNT_ASO_SQ_NUM;
	for (idx = 0; idx < HWS_CNT_ASO_SQ_NUM; idx++) {
		sq = &aso_mng->sqs[idx];
		if (mlx5_aso_sq_create(sh->cdev->ctx, sq, 0,
				sh->tx_uar.obj, sh->cdev->pdn,
				MLX5_ASO_QUEUE_LOG_DESC,
				sh->cdev->config.hca_attr.sq_ts_format)) {
			goto error;
		}
		mlx5_hws_cnt_aso_init_sq(sq);
	}
	return 0;
error:
	mlx5_hws_cnt_aso_free(sh);
	return -1;
}

void
mlx5_hws_cnt_aso_free(struct mlx5_dev_ctx_shared *sh)
{
	uint16_t idx;

	for (idx = 0; idx < sh->cnt_svc->aso_mng.sq_num; idx++)
		mlx5_aso_destroy_sq(&sh->cnt_svc->aso_mng.sqs[idx]);
	sh->cnt_svc->aso_mng.sq_num = 0;
}

int
mlx5_hws_cnt_pool_action_create(struct mlx5_priv *priv,
		struct mlx5_hws_cnt_pool *cpool)
{
	uint32_t idx;
	int ret = 0;
	struct mlx5_hws_cnt_dcs *dcs;

	for (idx = 0; idx < cpool->dcs_mng.batch_total; idx++) {
		dcs = &cpool->dcs_mng.dcs[idx];
		dcs->dr_action = mlx5dr_action_create_counter(priv->dr_ctx,
					(struct mlx5dr_devx_obj *)dcs->obj,
					MLX5DR_ACTION_FLAG_HWS_RX |
					MLX5DR_ACTION_FLAG_HWS_TX |
					MLX5DR_ACTION_FLAG_HWS_FDB);
		if (dcs->dr_action == NULL) {
			mlx5_hws_cnt_pool_action_destroy(cpool);
			ret = -ENOSYS;
			break;
		}
	}
	return ret;
}

void
mlx5_hws_cnt_pool_action_destroy(struct mlx5_hws_cnt_pool *cpool)
{
	uint32_t idx;
	struct mlx5_hws_cnt_dcs *dcs;

	for (idx = 0; idx < cpool->dcs_mng.batch_total; idx++) {
		dcs = &cpool->dcs_mng.dcs[idx];
		if (dcs->dr_action != NULL) {
			mlx5dr_action_destroy(dcs->dr_action);
			dcs->dr_action = NULL;
		}
	}
}

struct mlx5_hws_cnt_pool *
mlx5_hws_cnt_pool_create(struct rte_eth_dev *dev,
		const struct rte_flow_port_attr *pattr, uint16_t nb_queue)
{
	struct mlx5_hws_cnt_pool *cpool = NULL;
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_hws_cache_param cparam = {0};
	struct mlx5_hws_cnt_pool_cfg pcfg = {0};
	int ret = 0;
	size_t sz;

	/* init cnt service if not. */
	if (priv->sh->cnt_svc == NULL) {
		ret = mlx5_hws_cnt_svc_init(priv->sh);
		if (ret != 0)
			return NULL;
	}
	cparam.fetch_sz = HWS_CNT_CACHE_FETCH_DEFAULT;
	cparam.preload_sz = HWS_CNT_CACHE_PRELOAD_DEFAULT;
	cparam.q_num = nb_queue;
	cparam.threshold = HWS_CNT_CACHE_THRESHOLD_DEFAULT;
	cparam.size = HWS_CNT_CACHE_SZ_DEFAULT;
	pcfg.alloc_factor = HWS_CNT_ALLOC_FACTOR_DEFAULT;
	pcfg.name = "MLX5_HWS_CNT_POOL";
	pcfg.request_num = pattr->nb_counters;
	cpool = mlx5_hws_cnt_pool_init(&pcfg, &cparam);
	if (cpool == NULL)
		goto error;
	ret = mlx5_hws_cnt_pool_dcs_alloc(priv->sh, cpool);
	if (ret != 0)
		goto error;
	sz = RTE_ALIGN_CEIL(mlx5_hws_cnt_pool_get_size(cpool), 4);
	cpool->raw_mng = mlx5_hws_cnt_raw_data_alloc(priv->sh, sz);
	if (cpool->raw_mng == NULL)
		goto error;
	__hws_cnt_id_load(cpool);
	ret = mlx5_hws_cnt_pool_action_create(priv, cpool);
	if (ret != 0)
		goto error;
	priv->sh->cnt_svc->refcnt++;
	return cpool;
error:
	mlx5_hws_cnt_pool_destroy(priv->sh, cpool);
	return NULL;
}

void
mlx5_hws_cnt_pool_destroy(struct mlx5_dev_ctx_shared *sh,
		struct mlx5_hws_cnt_pool *cpool)
{
	if (cpool == NULL)
		return;
	if (--sh->cnt_svc->refcnt == 0)
		mlx5_hws_cnt_svc_deinit(sh);
	mlx5_hws_cnt_pool_action_destroy(cpool);
	mlx5_hws_cnt_pool_dcs_free(sh, cpool);
	mlx5_hws_cnt_raw_data_free(sh, cpool->raw_mng);
	mlx5_hws_cnt_pool_deinit(cpool);
}

int
mlx5_hws_cnt_svc_init(struct mlx5_dev_ctx_shared *sh)
{
	int ret;

	sh->cnt_svc = mlx5_malloc(MLX5_MEM_ANY | MLX5_MEM_ZERO,
			sizeof(*sh->cnt_svc), 0, SOCKET_ID_ANY);
	if (sh->cnt_svc == NULL)
		return -1;
	sh->cnt_svc->query_interval = sh->config.cnt_svc.cycle_time;
	sh->cnt_svc->service_core = sh->config.cnt_svc.service_core;
	ret = mlx5_hws_cnt_aso_access_alloc(sh);
	if (ret != 0) {
		mlx5_free(sh->cnt_svc);
		sh->cnt_svc = NULL;
		return -1;
	}
	ret = mlx5_hws_cnt_service_thread_create(sh);
	if (ret != 0) {
		mlx5_hws_cnt_aso_free(sh);
		mlx5_free(sh->cnt_svc);
		sh->cnt_svc = NULL;
	}
	return 0;
}

void
mlx5_hws_cnt_svc_deinit(struct mlx5_dev_ctx_shared *sh)
{
	if (sh->cnt_svc == NULL)
		return;
	mlx5_hws_cnt_service_thread_destroy(sh);
	mlx5_hws_cnt_aso_free(sh);
	mlx5_free(sh->cnt_svc);
	sh->cnt_svc = NULL;
}
