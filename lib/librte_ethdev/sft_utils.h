/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _SFT_UTILS_H_
#define _SFT_UTILS_H_

#include <rte_common.h>

/**
 * @file
 * SFT utilities
 */

/* ID generation structure. */
struct sft_id_pool {
	uint32_t *free_arr; /**< Pointer to the a array of free values. */
	uint32_t base_index;
	/**< The next index that can be used without any free elements. */
	uint32_t *curr; /**< Pointer to the index to pop. */
	uint32_t *last; /**< Pointer to the last element in the empty arrray. */
	uint32_t max_id; /**< Maximum id can be allocated from the pool. */
};


struct sft_id_pool *sft_id_pool_alloc(uint32_t max_id);
void sft_id_pool_release(struct sft_id_pool *pool);
uint32_t sft_id_get(struct sft_id_pool *pool, uint32_t *id);
uint32_t sft_id_release(struct sft_id_pool *pool, uint32_t id);
#endif /* _SFT_UTILS_H_*/

