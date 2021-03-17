/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */
#include <string.h>

#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_debug.h>

#include "sft_utils.h"

#define SFT_MIN_ID_POOL_SIZE 512
#define SFT_ID_GENERATION_ARRAY_FACTOR 16

/**
 * Allocate ID pool structure.
 *
 * @param[in] max_id
 *   The maximum id can be allocated from the pool.
 *
 * @return
 *   Pointer to pool object, NULL value otherwise.
 */
struct sft_id_pool *
sft_id_pool_alloc(uint32_t max_id)
{
	struct sft_id_pool *pool;
	void *mem;

	pool = rte_malloc("sft_id_pool", sizeof(*pool), RTE_CACHE_LINE_SIZE);
	if (!pool) {
		rte_errno  = ENOMEM;
		return NULL;
	}
	mem = rte_malloc("uint32_t",
			  SFT_MIN_ID_POOL_SIZE * sizeof(uint32_t),
			  RTE_CACHE_LINE_SIZE);
	if (!mem) {
		rte_errno  = ENOMEM;
		goto error;
	}
	pool->free_arr = mem;
	pool->curr = pool->free_arr;
	pool->last = pool->free_arr + SFT_MIN_ID_POOL_SIZE;
	pool->base_index = 0;
	pool->max_id = max_id;
	return pool;
error:
	rte_free(pool);
	return NULL;
}

void
sft_id_pool_release(struct sft_id_pool *pool)
{
	rte_free(pool->free_arr);
	rte_free(pool);
}

uint32_t
sft_id_get(struct sft_id_pool *pool, uint32_t *id)
{
	if (pool->curr == pool->free_arr) {
		if (pool->base_index == pool->max_id) {
			rte_errno  = ENOMEM;
			return -rte_errno;
		}
		*id = ++pool->base_index;
		return 0;
	}
	*id = *(--pool->curr);
	return 0;
}

uint32_t
sft_id_release(struct sft_id_pool *pool, uint32_t id)
{
	uint32_t size;
	uint32_t size2;
	void *mem;

	if (pool->curr == pool->last) {
		size = pool->curr - pool->free_arr;
		size2 = size * SFT_ID_GENERATION_ARRAY_FACTOR;
		RTE_VERIFY(size2 > size);
		mem = rte_malloc("uint32_t", size2 * sizeof(uint32_t), 0);
		if (!mem) {
			rte_errno  = ENOMEM;
			return -rte_errno;
		}
		memcpy(mem, pool->free_arr, size * sizeof(uint32_t));
		rte_free(pool->free_arr);
		pool->free_arr = mem;
		pool->curr = pool->free_arr + size;
		pool->last = pool->free_arr + size2;
	}
	*pool->curr = id;
	pool->curr++;
	return 0;
}

const char *
sft_ct_state_name(enum sft_ct_state state)
{
	static const char * const ct_names[] = {
		"NEW", "ESTABLISHING", "TRACKING", "HALF_DUPLEX", "CLOSING",
		"CLOSED", "OFFLOADED", "ERROR"
	};

	return state > SFT_CT_STATE_OFFLOADED ? "UNKNOWN" : ct_names[state];
}

