/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2022 Mellanox Technologies, Ltd
 */

#ifndef _MLX5_HWS_CNT_H_
#define _MLX5_HWS_CNT_H_

#include <rte_ring.h>
#include "mlx5_utils.h"
#include "mlx5_flow.h"

/*
 * COUNTER ID's layout
 *       3                   2                   1                   0
 *     1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    | T |                                                           |
 *    ~ Y |                                IDX                        ~
 *    | P |                                                           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *    Bit 31:30 = TYPE = MLX5_INDIRECT_ACTION_TYPE_COUNT = b'10
 *    Bit 29:0 = IDX, for internal index usage, moronically increase.
 */
typedef uint32_t cnt_id_t;

#define MLX5_HWS_CNT_DCS_NUM 4

struct mlx5_hws_cnt_dcs {
	void *dr_action;
	uint32_t batch_sz;
	struct mlx5_devx_obj *obj;
};

struct mlx5_hws_cnt_dcs_mng {
	uint32_t batch_total;
	struct mlx5_hws_cnt_dcs dcs[MLX5_HWS_CNT_DCS_NUM];
};

struct mlx5_hws_cnt {
	struct flow_counter_stats reset;
	union {
		uint32_t share: 1;
		/*
		 * share will be set to 1 when this counter is used as indirect
		 * action. Only meaningful when user own this counter.
		 */
		uint32_t query_gen_when_free;
		/*
		 * When PMD own this counter (user put back counter to PMD
		 * counter pool, i.e), this field recorded value of counter
		 * pools query generation at time user release the counter.
		 */
	};
};

struct mlx5_hws_cnt_raw_data_mng {
	struct flow_counter_stats *raw;
	struct mlx5_pmd_mr mr;
};

struct mlx5_hws_cache_param {
	uint32_t size;
	uint32_t q_num;
	uint32_t fetch_sz;
	uint32_t threshold;
	uint32_t preload_sz;
};

struct mlx5_hws_cnt_pool_cfg {
	const char *name;
	uint32_t request_num;
	uint32_t alloc_factor;
};

struct mlx5_hws_cnt_pool_caches {
	uint32_t fetch_sz;
	uint32_t threshold;
	uint32_t preload_sz;
	uint32_t q_num;
	struct rte_ring *qcache[];
};

struct mlx5_hws_cnt_pool {
	struct mlx5_hws_cnt_pool_cfg cfg __rte_cache_aligned;
	struct mlx5_hws_cnt_dcs_mng dcs_mng __rte_cache_aligned;
	uint32_t query_gen __rte_cache_aligned;
	struct mlx5_hws_cnt *pool;
	struct mlx5_hws_cnt_raw_data_mng *raw_mng;
	struct rte_ring *free_list;
	struct rte_ring *wait_reset_list;
	struct mlx5_hws_cnt_pool_caches *cache;
} __rte_cache_aligned;

/**
 * Copy elems from one zero-copy ring to zero-copy ring in place.
 *
 * The input is a rte ring zero-copy data struct, which has two pointer.
 * in case of the wrapper happened, the ptr2 will be meaningful.
 *
 * So this rountin needs to consider the situation that the address given by
 * source and destination could be both wrapped.
 * First, calculate the first number of element needs to be copied until wrapped
 * address, which could be in source or destination.
 * Second, copy left number of element until second wrapped address. If in first
 * step the wrapped address is source, then this time it must be in destination.
 * and vice-vers.
 * Third, copy all left numbe of element.
 *
 * In worst case, we need copy three pieces of continuous memory.
 *
 * @param zcdd
 *   A pointer to zero-copy data of dest ring.
 * @param zcds
 *   A pointer to zero-copy data of source ring.
 * @param n
 *   Number of elems to copy.
 */
static __rte_always_inline void
__hws_cnt_r2rcpy(struct rte_ring_zc_data *zcdd, struct rte_ring_zc_data *zcds,
		unsigned int n)
{
	unsigned int n1, n2, n3;
	void *s1, *s2, *s3;
	void *d1, *d2, *d3;

	s1 = zcds->ptr1;
	d1 = zcdd->ptr1;
	n1 = RTE_MIN(zcdd->n1, zcds->n1);
	if (zcds->n1 > n1) {
		n2 = zcds->n1 - n1;
		s2 = RTE_PTR_ADD(zcds->ptr1, sizeof(cnt_id_t) * n1);
		d2 = zcdd->ptr2;
		n3 = n - n1 - n2;
		s3 = zcds->ptr2;
		d3 = RTE_PTR_ADD(zcdd->ptr2, sizeof(cnt_id_t) * n2);
	} else {
		n2 = zcdd->n1 - n1;
		s2 = zcds->ptr2;
		d2 = RTE_PTR_ADD(zcdd->ptr1, sizeof(cnt_id_t) * n1);
		n3 = n - n1 - n2;
		s3 = RTE_PTR_ADD(zcds->ptr2, sizeof(cnt_id_t) * n2);
		d3 = zcdd->ptr2;
	}
	memcpy(d1, s1, n1 * sizeof(cnt_id_t));
	if (n2 != 0) {
		memcpy(d2, s2, n2 * sizeof(cnt_id_t));
		if (n3 != 0)
			memcpy(d3, s3, n3 * sizeof(cnt_id_t));
	}
}

static __rte_always_inline int
mlx5_hws_cnt_pool_cache_flush(struct mlx5_hws_cnt_pool *cpool,
			      uint32_t queue_id)
{
	unsigned int ret;
	struct rte_ring_zc_data zcdr = {0};
	struct rte_ring_zc_data zcdc = {0};
	struct rte_ring *reset_list = NULL;
	struct rte_ring *qcache = cpool->cache->qcache[queue_id];

	ret = rte_ring_dequeue_zc_burst_elem_start(qcache,
			sizeof(cnt_id_t), rte_ring_count(qcache), &zcdc,
			NULL);
	MLX5_ASSERT(ret);
	reset_list = cpool->wait_reset_list;
	rte_ring_enqueue_zc_burst_elem_start(reset_list,
			sizeof(cnt_id_t), ret, &zcdr, NULL);
	__hws_cnt_r2rcpy(&zcdc, &zcdr, ret);
	rte_ring_enqueue_zc_elem_finish(reset_list, ret);
	rte_ring_dequeue_zc_elem_finish(qcache, ret);
	return 0;
}

static __rte_always_inline int
mlx5_hws_cnt_pool_cache_fetch(struct mlx5_hws_cnt_pool *cpool,
			      uint32_t queue_id)
{
	struct rte_ring *qcache = cpool->cache->qcache[queue_id];
	struct rte_ring *free_list = NULL;
	struct rte_ring_zc_data zcdf = {0};
	struct rte_ring_zc_data zcdc = {0};
	struct mlx5_hws_cnt_pool_caches *cache = cpool->cache;
	unsigned int ret;

	free_list = cpool->free_list;
	ret = rte_ring_dequeue_zc_burst_elem_start(free_list,
			sizeof(cnt_id_t), cache->fetch_sz, &zcdf, NULL);
	if (unlikely(ret == 0)) { /* no free counter. */
		rte_ring_dequeue_zc_elem_finish(free_list, 0);
		if (rte_ring_count(cpool->wait_reset_list))
			return -EAGAIN;
		return -ENOENT;
	}
	rte_ring_enqueue_zc_burst_elem_start(qcache, sizeof(cnt_id_t),
			ret, &zcdc, NULL);
	__hws_cnt_r2rcpy(&zcdc, &zcdf, ret);
	rte_ring_dequeue_zc_elem_finish(free_list, ret);
	rte_ring_enqueue_zc_elem_finish(qcache, ret);
	return 0;
}

static __rte_always_inline int
__mlx5_hws_cnt_pool_enqueue_revert(struct rte_ring *r, unsigned int n,
		struct rte_ring_zc_data *zcd)
{
	uint32_t current_head = 0;
	uint32_t revert2head = 0;

	MLX5_ASSERT(r->prod.sync_type == RTE_RING_SYNC_ST);
	MLX5_ASSERT(r->cons.sync_type == RTE_RING_SYNC_ST);
	current_head = __atomic_load_n(&r->prod.head, __ATOMIC_RELAXED);
	MLX5_ASSERT(n <= r->capacity);
	MLX5_ASSERT(n <= rte_ring_count(r));
	revert2head = current_head - n;
	r->prod.head = revert2head; /* This ring should be SP. */
	__rte_ring_get_elem_addr(r, revert2head, sizeof(cnt_id_t), n,
			&zcd->ptr1, &zcd->n1, &zcd->ptr2);
	/* Update tail */
	__atomic_store_n(&r->prod.tail, revert2head, __ATOMIC_RELEASE);
	return n;
}

/**
 * Put one counter back in the mempool.
 *
 * @param cpool
 *   A pointer to the counter pool structure.
 * @param cnt_id
 *   A counter id to be added.
 * @return
 *   - 0: Success; object taken
 *   - -ENOENT: not enough entry in pool
 */
static __rte_always_inline int
mlx5_hws_cnt_pool_put(struct mlx5_hws_cnt_pool *cpool,
		uint32_t *queue, cnt_id_t *cnt_id)
{
	unsigned int ret = 0;
	struct rte_ring_zc_data zcdc = {0};
	struct rte_ring_zc_data zcdr = {0};
	struct rte_ring *qcache = NULL;
	unsigned int wb_num = 0; /* cache write-back number. */
	cnt_id_t iidx;

	iidx = *cnt_id & ((1 << MLX5_INDIRECT_ACTION_TYPE_OFFSET) - 1);
	cpool->pool[iidx].query_gen_when_free =
		__atomic_load_n(&cpool->query_gen, __ATOMIC_RELAXED);
	if (likely(queue != NULL))
		qcache = cpool->cache->qcache[*queue];
	if (unlikely(qcache == NULL)) {
		ret = rte_ring_enqueue_elem(cpool->wait_reset_list, cnt_id,
				sizeof(cnt_id_t));
		MLX5_ASSERT(ret == 0);
	}
	ret = rte_ring_enqueue_burst_elem(qcache, cnt_id, sizeof(cnt_id_t), 1,
					  NULL);
	if (unlikely(ret == 0)) { /* cache is full. */
		wb_num = rte_ring_count(qcache) - cpool->cache->threshold;
		MLX5_ASSERT(wb_num < rte_ring_count(qcache));
		__mlx5_hws_cnt_pool_enqueue_revert(qcache, wb_num, &zcdc);
		rte_ring_enqueue_zc_burst_elem_start(cpool->wait_reset_list,
				sizeof(cnt_id_t), wb_num, &zcdr, NULL);
		__hws_cnt_r2rcpy(&zcdr, &zcdc, wb_num);
		rte_ring_enqueue_zc_elem_finish(cpool->wait_reset_list, wb_num);
		/* write-back THIS counter too */
		ret = rte_ring_enqueue_burst_elem(cpool->wait_reset_list,
				cnt_id, sizeof(cnt_id_t), 1, NULL);
	}
	return ret == 1 ? 0 : -ENOENT;
}

/**
 * Get one counter from the pool.
 *
 * If @param queue is not null, objects will be retrieved first from queue's
 * cache, subsequently from the common pool. Note that it can return -ENOENT
 * when the local cache and common pool are empty, even if cache from other
 * queue are full.
 *
 * @param cntp
 *   A pointer to the counter pool structure.
 * @param queue
 *   A pointer to HWS queue. If null, it means fetch from common pool.
 * @param cnt_id
 *   A pointer to a cnt_id_t * pointer (counter id) that will be filled.
 * @return
 *   - 0: Success; objects taken.
 *   - -ENOENT: Not enough entries in the mempool; no object is retrieved.
 *   - -EAGAIN: counter is not ready; try again.
 */
static __rte_always_inline int
mlx5_hws_cnt_pool_get(struct mlx5_hws_cnt_pool *cpool,
		uint32_t *queue, cnt_id_t *cnt_id)
{
	unsigned int ret;
	struct rte_ring_zc_data zcdc = {0};
	struct rte_ring *qcache = NULL;
	uint32_t query_gen = 0;
	cnt_id_t iidx, tmp_cid = 0;

	if (likely(queue != NULL))
		qcache = cpool->cache->qcache[*queue];
	if (unlikely(qcache == NULL)) {
		ret = rte_ring_dequeue_elem(cpool->free_list, &tmp_cid,
				sizeof(cnt_id_t));
		if (unlikely(ret != 0)) {
			if (rte_ring_count(cpool->wait_reset_list))
				return -EAGAIN;
			return -ENOENT;
		}
		*cnt_id = tmp_cid;
		return 0;
	}
	ret = rte_ring_dequeue_zc_burst_elem_start(qcache, sizeof(cnt_id_t), 1,
			&zcdc, NULL);
	if (unlikely(ret == 0)) { /* local cache is empty. */
		rte_ring_dequeue_zc_elem_finish(qcache, 0);
		/* let's fetch from global free list. */
		ret = mlx5_hws_cnt_pool_cache_fetch(cpool, *queue);
		if (unlikely(ret != 0))
			return ret;
		rte_ring_dequeue_zc_burst_elem_start(qcache, sizeof(cnt_id_t),
				1, &zcdc, NULL);
	}
	/* get one from local cache. */
	*cnt_id = (*(cnt_id_t *)zcdc.ptr1);
	iidx = *cnt_id & ((1 << MLX5_INDIRECT_ACTION_TYPE_OFFSET) - 1);
	query_gen = cpool->pool[iidx].query_gen_when_free;
	if (cpool->query_gen == query_gen) { /* counter is waiting to reset. */
		rte_ring_dequeue_zc_elem_finish(qcache, 0);
		/* write-back counter to reset list. */
		mlx5_hws_cnt_pool_cache_flush(cpool, *queue);
		/* let's fetch from global free list. */
		ret = mlx5_hws_cnt_pool_cache_fetch(cpool, *queue);
		if (unlikely(ret != 0))
			return ret;
		rte_ring_dequeue_zc_burst_elem_start(qcache, sizeof(cnt_id_t),
				1, &zcdc, NULL);
		*cnt_id = *(cnt_id_t *)zcdc.ptr1;
	}
	rte_ring_dequeue_zc_elem_finish(qcache, 1);
	return 0;
}

static __always_inline unsigned int
mlx5_hws_cnt_pool_get_size(struct mlx5_hws_cnt_pool *cpool)
{
	return rte_ring_get_capacity(cpool->free_list);
}

/* init HWS counter pool. */
struct mlx5_hws_cnt_pool *
mlx5_hws_cnt_pool_init(const struct mlx5_hws_cnt_pool_cfg *pcfg,
		const struct mlx5_hws_cache_param *ccfg);

void
mlx5_hws_cnt_pool_deinit(struct mlx5_hws_cnt_pool *cntp);

int
mlx5_hws_cnt_service_thread_create(struct mlx5_dev_ctx_shared *sh);

void
mlx5_hws_cnt_service_thread_destroy(struct mlx5_dev_ctx_shared *sh);

int
mlx5_hws_cnt_pool_aso_query(struct mlx5_dev_ctx_shared *sh,
			    struct mlx5_hws_cnt_pool *cpool);

int
mlx5_hws_cnt_pool_dcs_alloc(struct mlx5_dev_ctx_shared *sh,
		struct mlx5_hws_cnt_pool *cpool);
void
mlx5_hws_cnt_pool_dcs_free(struct mlx5_hws_cnt_pool *cpool);

#endif /* _MLX5_HWS_CNT_H_ */
