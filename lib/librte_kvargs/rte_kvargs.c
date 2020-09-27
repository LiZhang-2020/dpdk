/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2013 Intel Corporation.
 * Copyright(c) 2014 6WIND S.A.
 */

#include <string.h>
#include <stdlib.h>

#include <rte_string_fns.h>

#include "rte_kvargs.h"

/*
 * Receive a string with a list of arguments following the pattern
 * key=value,key=value,... and insert them into the list.
 * Params string will be copied to be modified.
 * Supported examples:
 *   k1=v1,k2=v2
 *   v1
 *   v1,
 *   ,v1
 *   k1=
 *   =v1
 *   k1=x[a,c-d,e]y[m,n-o,p]z,k2=v2
 */
static int
rte_kvargs_tokenize(struct rte_kvargs *kvlist, const char *params)
{
	unsigned i;
	char *str, *start;
	int in_list = 0, end_k = 0, end_v = 0;

	/* Copy the const char *params to a modifiable string
	 * to pass to rte_strsplit
	 */
	kvlist->str = strdup(params);
	if (kvlist->str == NULL)
		return -1;

	/* browse each key/value pair and add it in kvlist */
	str = kvlist->str;
	start = str;
	while (1) {
		switch (*str) {
		case RTE_KVARGS_KV_DELIM: /* = */
			end_k = 1;
			break;
		case RTE_KVARGS_PAIRS_DELIM: /* , */
			/* Skip comma in middle of range */
			if (!in_list)
				end_v = 1;
			break;
		case '[':
			in_list++;
			break;
		case ']':
			if (in_list)
				in_list--;
			break;
		case 0: /* end of string */
			end_v = 1;
			break;
		default:
			break;
		}

		if (!end_k && !end_v) {
			str++;
			continue;
		}

		i = kvlist->count;
		if (i >= RTE_KVARGS_MAX)
			return -1;

		if (start == str)
			start = NULL;

		if (end_k) {
			kvlist->pairs[i].key = start;
			end_k = 0;
		} else if (end_v) {
			if (kvlist->pairs[i].key || start) {
				kvlist->pairs[i].value = start;
				kvlist->count++;
			}
			end_v = 0;
		}

		if (!*str)
			break; /* End of string. */
		*str = 0;
		str++;
		start = str;
	}

	return 0;
}

/*
 * Determine whether a key is valid or not by looking
 * into a list of valid keys.
 */
static int
is_valid_key(const char * const valid[], const char *key_match)
{
	const char * const *valid_ptr;

	for (valid_ptr = valid; *valid_ptr != NULL; valid_ptr++) {
		if (strcmp(key_match, *valid_ptr) == 0)
			return 1;
	}
	return 0;
}

/*
 * Determine whether all keys are valid or not by looking
 * into a list of valid keys.
 */
static int
check_for_valid_keys(struct rte_kvargs *kvlist,
		const char * const valid[])
{
	unsigned i, ret;
	struct rte_kvargs_pair *pair;

	for (i = 0; i < kvlist->count; i++) {
		pair = &kvlist->pairs[i];
		ret = is_valid_key(valid, pair->key);
		if (!ret)
			return -1;
	}
	return 0;
}

/*
 * Return the number of times a given arg_name exists in the key/value list.
 * E.g. given a list = { rx = 0, rx = 1, tx = 2 } the number of args for
 * arg "rx" will be 2.
 */
unsigned
rte_kvargs_count(const struct rte_kvargs *kvlist, const char *key_match)
{
	const struct rte_kvargs_pair *pair;
	unsigned i, ret;

	ret = 0;
	for (i = 0; i < kvlist->count; i++) {
		pair = &kvlist->pairs[i];
		if (key_match == NULL || strcmp(pair->key, key_match) == 0)
			ret++;
	}

	return ret;
}

/*
 * For each matching key, call the given handler function.
 */
int
rte_kvargs_process(const struct rte_kvargs *kvlist,
		const char *key_match,
		arg_handler_t handler,
		void *opaque_arg)
{
	const struct rte_kvargs_pair *pair;
	unsigned i;

	if (kvlist == NULL)
		return 0;

	for (i = 0; i < kvlist->count; i++) {
		pair = &kvlist->pairs[i];
		if (key_match == NULL || strcmp(pair->key, key_match) == 0) {
			if ((*handler)(pair->key, pair->value, opaque_arg) < 0)
				return -1;
		}
	}
	return 0;
}

/* free the rte_kvargs structure */
void
rte_kvargs_free(struct rte_kvargs *kvlist)
{
	if (!kvlist)
		return;

	free(kvlist->str);
	free(kvlist);
}

/* find value by key */
const char *
rte_kvargs_get(struct rte_kvargs *kvlist, const char *key)
{
	unsigned int i;

	if (!kvlist)
		return NULL;
	for (i = 0; i < kvlist->count; ++i) {
		/* Allows key to be NULL. */
		if (!key && !kvlist->pairs[i].key)
			return kvlist->pairs[i].value;
		if (!key || !kvlist->pairs[i].key)
			continue;
		if (!strcmp(kvlist->pairs[i].key, key))
			return kvlist->pairs[i].value;
	}
	return NULL;
}

/*
 * Parse the arguments "key=value,key=value,..." string and return
 * an allocated structure that contains a key/value list. Also
 * check if only valid keys were used.
 */
struct rte_kvargs *
rte_kvargs_parse(const char *args, const char * const valid_keys[])
{
	struct rte_kvargs *kvlist;

	kvlist = malloc(sizeof(*kvlist));
	if (kvlist == NULL)
		return NULL;
	memset(kvlist, 0, sizeof(*kvlist));

	if (rte_kvargs_tokenize(kvlist, args) < 0) {
		rte_kvargs_free(kvlist);
		return NULL;
	}

	if (valid_keys != NULL && check_for_valid_keys(kvlist, valid_keys) < 0) {
		rte_kvargs_free(kvlist);
		return NULL;
	}

	return kvlist;
}

struct rte_kvargs *
rte_kvargs_parse_delim(const char *args, const char * const valid_keys[],
		       const char *valid_ends)
{
	struct rte_kvargs *kvlist = NULL;
	char *copy;
	size_t len;

	if (valid_ends == NULL)
		return rte_kvargs_parse(args, valid_keys);

	copy = strdup(args);
	if (copy == NULL)
		return NULL;

	len = strcspn(copy, valid_ends);
	copy[len] = '\0';

	kvlist = rte_kvargs_parse(copy, valid_keys);

	free(copy);
	return kvlist;
}

int
rte_kvargs_strcmp(const char *key __rte_unused,
		  const char *value, void *opaque)
{
	const char *str = opaque;

	return -abs(strcmp(str, value));
}
