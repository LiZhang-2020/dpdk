/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */
#include <string.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_hash_crc.h>

#include "rte_lhash.h"

struct rte_lhash_entry {
	LIST_ENTRY(rte_lhash_entry) next; /* entry pointers in the list. */
	uint64_t value;
	uint32_t hash_key;
	uint8_t key[];
};

static __rte_always_inline uint32_t
key_hash(const struct rte_lhash *h, const void *key)
{
	return h->direct_key ? rte_hash_crc_8byte((uint64_t)key, 0) :
			       rte_hash_crc(key, h->key_size, 0);
}

static __rte_always_inline uint32_t
lhash_key_to_idx(const struct rte_lhash *h, const void *key)
{
	uint32_t mask = h->buckets_num - 1;
	uint32_t hash = key_hash(h, key);

	return hash & mask;
}

static __rte_always_inline bool
lhash_compare_keys(const struct rte_lhash *h,
		   struct rte_lhash_entry *e, const void *key)
{
	uint64_t *qptr = (typeof(qptr))e->key;
	return h->direct_key ? *qptr == (uint64_t)key :
	       (rte_hash_crc(key, h->key_size, 0) == e->hash_key &&
	        !memcmp(e->key, key, h->key_size));
}

/*
 * @return:
 */

static struct rte_lhash_entry *
lhash_lookup(const struct rte_lhash *h, const void *key)
{
	struct rte_lhash_entry *e;
	uint32_t idx = lhash_key_to_idx(h, key);

	LIST_FOREACH(e, &h->heads[idx], next) {
		if (lhash_compare_keys(h, e, key)) {
			return e;
		}
	}

	return NULL;
}


int
rte_lhash_lookup(const struct rte_lhash *h, const void *key, uint64_t *data)
{
	struct rte_lhash_entry *e = lhash_lookup(h, key);

	if (e) {
		if (data)
			*data = e->value;
		return 0;
	}
	return -ENOENT;
}

int
rte_lhash_del_key(const struct rte_lhash *h, const void * key, uint64_t *data)
{
	int ret;
	struct rte_lhash_entry *e = lhash_lookup(h, key);

	if (e) {
		LIST_REMOVE(e, next);
		if (data)
			*data = e->value;
		rte_free(e);
		ret = 0;	
	} else {
		ret = -ENOENT;
	}

	return ret;
}

int
rte_lhash_add_key_data(const struct rte_lhash *h, const void *key, uint64_t data)
{
	uint32_t idx = lhash_key_to_idx(h, key);
	
	struct rte_lhash_entry *e = lhash_lookup(h, key);
	if (e)
		return 0;
	e = rte_malloc("rte_lhash_entry", sizeof(*e) + h->key_size, 0);
	if (!e)
		return -ENOMEM;
	if (h->direct_key) {
		uint64_t *qptr = (typeof(qptr))e->key;
		*qptr = (uint64_t)key;
	} else {
		memcpy(e->key, key, h->key_size);
	}
	e->value = data;
	e->hash_key = key_hash(h, key);
	LIST_INSERT_HEAD(&h->heads[idx], e, next);

	return 0;
}

struct rte_lhash *
rte_lhash_create(const struct rte_lhash_parameters *param)
{
	struct rte_lhash *h;

	if (!param->buckets_num)
		return NULL;
	h = rte_zmalloc("rte_lhash", sizeof(*h), 0);
	if (!h) {
		RTE_LOG(ERR, HASH, "No memory for hash %s creation",
			param->name ? param->name : "none");
		return NULL;
	}
	/* Align to the next power of 2, 32bits integer is enough now. */
	if (!rte_is_power_of_2(param->buckets_num)) {
		h->buckets_num = rte_align32pow2(param->buckets_num);
		RTE_LOG(INFO, HASH, "%s align buckets to %u", 
			param->name, h->buckets_num);
	} else {
		h->buckets_num = param->buckets_num;
	}
	h->heads = rte_zmalloc("rte_lhash_head",
			       sizeof(h->heads[0]) * param->buckets_num, 0);
			
	if (!h->heads) {
		RTE_LOG(ERR, HASH, "No memory for hash %s buckets",
			param->name ? param->name : "none");
		rte_free(h);
		return NULL;
	}
	h->key_size = param->key_size;
	h->direct_key = param->key_size <= sizeof(uint64_t);
	if (param->name)
		snprintf(h->name, sizeof(h->name), "%s", param->name);
	
	RTE_LOG(DEBUG, HASH, "lhash %s created", h->name);
	return h;
}

void
rte_lhash_flush(struct rte_lhash *h)
{
	uint32_t i;

	for (i = 0; i < h->buckets_num; i++) {
		while (!LIST_EMPTY(&h->heads[i])) {
			struct rte_lhash_entry *e;

			e = LIST_FIRST(&h->heads[i]); 
			LIST_REMOVE(e, next);
			rte_free(e);
		}
	}
}

int
rte_lhash_free(struct rte_lhash *h)
{
	uint32_t i;

	for (i = 0; i < h->buckets_num; i++)
		if (!LIST_EMPTY(&h->heads[i])) {
			RTE_LOG(INFO, HASH, "hash %s not empty", h->name);
			return EEXIST;
		}
	rte_free(h->heads);
	rte_free(h);

	return 0;
}

