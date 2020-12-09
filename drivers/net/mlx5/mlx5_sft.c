/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <rte_sft.h>
#include <rte_sft_driver.h>
#include <rte_flow.h>

#include "mlx5.h"
#include "mlx5_flow.h"
#include "mlx5_malloc.h"
#include "mlx5_rxtx.h"
#include "mlx5_sft.h"

struct rte_flow *g_sft_flow;

static int mlx5_sft_start(struct rte_eth_dev *dev, uint16_t nb_queue,
			  uint16_t data_len, struct rte_sft_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_dev_ctx_shared *sh = priv->sh;
	uint16_t i = 0;
	uint32_t idx;
	struct rte_flow_error flow_error;
	struct mlx5_rte_flow_action_set_tag set_state;
	struct mlx5_indexed_pool_config cfg = {
		.size = sizeof(struct rte_sft_entry),
		.trunk_size = 1024,
		.need_lock = 0,
		.release_mem_en = 1,
		.malloc = mlx5_malloc,
		.free = mlx5_free,
		.type = "sft_entry_pool",
	};
	/* The default flow has the lowest priority. */
	struct rte_flow_attr attr = {
		.ingress = 1,
		.priority = 3,
		.group = MLX5_FLOW_TABLE_LEVEL_SFT,
	};
	struct rte_flow_item_eth all_eth = {
		.dst.addr_bytes = "\x00\x00\x00\x00\x00\x00",
		.src.addr_bytes = "\x00\x00\x00\x00\x00\x00",
		.type = 0,
	};
	struct rte_flow_item items[] = {
		[0] = {
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = &all_eth,
			.last = NULL,
			.mask = &all_eth,
		},
		[1] = {
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};
	/*
	 * In legacy mode, MARK cannot be used for matching and TAG cannot
	 * be visible to software. Currently, they should have the same value.
	 * There is no need to touch METADATA and it is set in the RTE flow.
	 * Application state for MARK should be with the default value 0.
	 */
	struct rte_flow_action actions[] = {
		[0] = {
			.type = (enum rte_flow_action_type)
				RTE_FLOW_ACTION_TYPE_MARK,
			.conf = &(struct rte_flow_action_mark){
				.id = RTE_SFT_STATE_FLAG_ZONE_VALID <<
				      MLX5_SFT_FID_ZONE_STAT_SHIFT,
			},
		},
		[1] = {
			.type = (enum rte_flow_action_type)
				MLX5_RTE_FLOW_ACTION_TYPE_TAG,
			.conf = &set_state,
		},
		[2] = {
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &(struct rte_flow_action_jump){
				.group = MLX5_FLOW_TABLE_LEVEL_POST_SFT,
			},
		},
		[3] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};

	if (data_len > 1 || nb_queue > MLX5_SFT_QUEUE_MAX)
		return rte_sft_error_set(error, EINVAL,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
					 NULL, NULL);
	/* Same value as RTE_FLOW_ACTION_TYPE_MARK. */
	set_state.id = REG_C_1;
	set_state.data = RTE_SFT_STATE_FLAG_ZONE_VALID <<
			 MLX5_SFT_FID_ZONE_STAT_SHIFT;
	/* To prevent the registers from being used by other modules. */
	priv->sft_en = 1;
	/*
	 * Default flow in SFT table:
	 * Matching all the ETH and set the miss state only with ZONE valid.
	 * Creating tables for SFT and post-SFT inside the flow creation.
	 * The flow should not be impacted by the flow flush action.
	 */
	g_sft_flow = mlx5_sft_ctrl_flow_create(dev, &attr, items,
					       actions, &flow_error);
	if (g_sft_flow == NULL)
		return rte_sft_error_set(error, flow_error.type,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
					 flow_error.cause, flow_error.message);
	sh->ipool_sft = (struct mlx5_indexed_pool **)mlx5_malloc(
				MLX5_MEM_SYS | MLX5_MEM_ZERO,
				nb_queue * sizeof(struct mlx5_indexed_pool *),
				MLX5_MALLOC_ALIGNMENT, SOCKET_ID_ANY);
	if (sh->ipool_sft == NULL) {
		rte_errno = ENOMEM;
		goto error_out;
	}
	priv->sft_lists = (uint32_t *)mlx5_malloc(
				MLX5_MEM_SYS | MLX5_MEM_ZERO,
				nb_queue * sizeof(uint32_t),
				MLX5_MALLOC_ALIGNMENT, SOCKET_ID_ANY);
	if (priv->sft_lists == NULL) {
		rte_errno = ENOMEM;
		goto error_out;
	}
	/* Allocate memory pool to save the entry. */
	for (; i < nb_queue; i++) {
		sh->ipool_sft[i] = mlx5_ipool_create(&cfg);
		if (sh->ipool_sft[i] == NULL) {
			rte_errno = ENOMEM;
			goto error_out;
		}
		/* Initialize ILIST for each entry queue. */
		priv->sft_lists[i] = 0;
	}
	/* Enable MARK for all Rx queues. */
	for (idx = 0; idx < priv->rxqs_n; idx++) {
		struct mlx5_rxq_ctrl *rxq_ctrl =
			container_of((*priv->rxqs)[idx],
				     struct mlx5_rxq_ctrl, rxq);

		rxq_ctrl->rxq.mark = 1;
		rxq_ctrl->flow_mark_n++;
	}
	sh->nb_sft_queue = nb_queue;
	return 0;
error_out:
	if (g_sft_flow != NULL)
		mlx5_flow_remove_post_sft_rule(dev,
					       (uintptr_t)(void *)g_sft_flow);
	do {
		if (sh->ipool_sft[i] != NULL)
			mlx5_ipool_destroy(sh->ipool_sft[i]);
	} while (i--);
	mlx5_free(sh->ipool_sft);
	mlx5_free(priv->sft_lists);
	sh->ipool_sft = NULL;
	priv->sft_lists = NULL;
	sh->nb_sft_queue = 0;
	priv->sft_en = 0;
	return rte_sft_error_set(error, rte_errno,
				 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				 NULL, NULL);
}

static int mlx5_sft_stop(struct rte_eth_dev *dev, struct rte_sft_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_dev_ctx_shared *sh = priv->sh;
	uint16_t i;
	uint32_t idx;
	RTE_SET_USED(error);

	/* All the SFT entries should be destroyed before stop. */
	for (i = 0; i < sh->nb_sft_queue; i++) {
		uint32_t list = priv->sft_lists[i];
		struct rte_sft_entry *entry;

		while (list) {
			uint32_t *plist = &list;

			entry = mlx5_ipool_get(sh->ipool_sft[i], list);
			ILIST_REMOVE(sh->ipool_sft[i], plist,
				     list, entry, next);
			/* Try best to destroy all flows. */
			mlx5_flow_remove_post_sft_rule(dev,
					(uintptr_t)(void *)entry->flow);
			mlx5_flow_remove_post_sft_rule(dev,
					(uintptr_t)(void *)entry->itmd_flow);
			// TODO: destroy the miss condition flow
			mlx5_ipool_free(sh->ipool_sft[i], list);
		}
	}
	for (idx = 0; idx < priv->rxqs_n; idx++) {
		struct mlx5_rxq_ctrl *rxq_ctrl =
			container_of((*priv->rxqs)[idx],
				     struct mlx5_rxq_ctrl, rxq);

		rxq_ctrl->flow_mark_n--;
		rxq_ctrl->rxq.mark = !!rxq_ctrl->flow_mark_n;
	}
	for (i = 0; i < sh->nb_sft_queue; i++) {
		if (sh->ipool_sft[i] != NULL)
			mlx5_ipool_destroy(sh->ipool_sft[i]);
	}
	mlx5_free(sh->ipool_sft);
	mlx5_free(priv->sft_lists);
	/* Destroy the default flow. */
	mlx5_flow_remove_post_sft_rule(dev, (uintptr_t)(void *)g_sft_flow);
	sh->ipool_sft = NULL;
	priv->sft_lists = NULL;
	sh->nb_sft_queue = 0;
	priv->sft_en = 0;
	return 0;
}

static struct rte_sft_entry *
mlx5_sft_entry_create(struct rte_eth_dev *dev, uint32_t fid, uint16_t queue,
		      const struct rte_flow_item *pattern,
		      uint64_t miss_conditions,
		      const struct rte_flow_action *actions,
		      const struct rte_flow_action *miss_actions,
		      const uint32_t *data, uint16_t data_len,
		      uint8_t state, struct rte_sft_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_dev_ctx_shared *sh = priv->sh;
	struct mlx5_indexed_pool *pool;
	struct rte_sft_entry *entry;
	struct rte_flow_action *pa_sft;
	struct rte_flow_attr attr = {
		.ingress = 1,
		.priority = 0,
		.group = MLX5_FLOW_TABLE_LEVEL_ITMD_SFT,
	};
	uint64_t item_flags = 0;
	uint64_t action_flags = 0;
	uint32_t idx;
	int32_t reg_data;
	uint32_t nb_actions;
	struct mlx5_rte_flow_item_tag tag_v;
	struct mlx5_rte_flow_item_tag tag_m;
	const struct rte_flow_item itmd_pattern[] = {
		{
			.type = (enum rte_flow_item_type)
				MLX5_RTE_FLOW_ITEM_TYPE_TAG,
			.spec = &tag_v,
			.mask = &tag_m,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};
	struct rte_flow_action_mark mark;
	struct mlx5_rte_flow_action_set_tag set_data;
	struct mlx5_rte_flow_action_set_tag set_state;
	struct mlx5_rte_flow_action_set_tag set_tag;
	struct rte_flow_action itmd_actions[] = {
		[0] = {
			.type = (enum rte_flow_action_type)
				RTE_FLOW_ACTION_TYPE_MARK,
			/* User state will be changed in modification. */
			.conf = &mark,
		},
		[1] = {
			.type = (enum rte_flow_action_type)
				MLX5_RTE_FLOW_ACTION_TYPE_TAG,
			.conf = &set_state,
		},
		[2] = {
			.type = (enum rte_flow_action_type)
				MLX5_RTE_FLOW_ACTION_TYPE_TAG,
			/* User data will be changed in modification. */
			.conf = &set_data,
		},
		[2] = {
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &(struct rte_flow_action_jump){
				.group = MLX5_FLOW_TABLE_LEVEL_POST_SFT,
			},
		},
		[3] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	union {
		struct rte_flow_action actions[24];
		uint8_t buffer[2048];
	} actions_sft;
	/*
	union {
		struct rte_flow_action actions[MLX5_MAX_SPLIT_ACTIONS];
		uint8_t buffer[2048];
	} actions_miss; */
	struct rte_flow_action_set_meta meta;
	struct rte_flow_action_jump jump;
	struct rte_flow_error flow_error = {0};
	const struct rte_flow_item *l_pattern = pattern;
	const struct rte_flow_action *l_actions = actions;
	const struct rte_flow_action *lm_actions = miss_actions;
	RTE_SET_USED(miss_conditions);

	if (queue > sh->nb_sft_queue || data_len > 1) {
		rte_sft_error_set(error, EINVAL,
				  RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				  NULL, NULL);
		return NULL;
	}
	/* 5-tuple is mandatory, mask should also be checked. */
	for (; l_pattern->type != RTE_FLOW_ITEM_TYPE_END; l_pattern++) {
		switch (l_pattern->type) {
		case RTE_FLOW_ITEM_TYPE_IPV4:
			item_flags |= MLX5_FLOW_LAYER_OUTER_L3_IPV4;
			break;
		case RTE_FLOW_ITEM_TYPE_IPV6:
			item_flags |= MLX5_FLOW_LAYER_OUTER_L3_IPV6;
			break;
		case RTE_FLOW_ITEM_TYPE_TCP:
			item_flags |= MLX5_FLOW_LAYER_OUTER_L4_TCP;
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			item_flags |= MLX5_FLOW_LAYER_OUTER_L4_UDP;
			break;
		case RTE_FLOW_ITEM_TYPE_META:
		case RTE_FLOW_ITEM_TYPE_TAG:
			rte_sft_error_set(error, EINVAL,
					  RTE_SFT_ERROR_TYPE_UNSPECIFIED,
					  NULL, NULL);
			return NULL;
		default:
			break;
		}
	}
	if ((item_flags & MLX5_FLOW_LAYER_OUTER_L3) == 0 ||
	    (item_flags & MLX5_FLOW_LAYER_OUTER_L4) == 0) {
		rte_sft_error_set(error, EINVAL,
				  RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				  NULL, NULL);
		return NULL;
	}
	/*
	 * The JUMP action should be supported, and added implicitly.
	 * No other termination actions could be in the list.
	 * NAT actions are supported, Encap / Decap are not supported now.
	 */
	nb_actions = 0;
	for (; l_actions->type != RTE_FLOW_ACTION_TYPE_END; l_actions++) {
		int type = l_actions->type;

		switch (type) {
		case RTE_FLOW_ACTION_TYPE_DROP:
			action_flags |= MLX5_FLOW_ACTION_DROP;
			break;
		case RTE_FLOW_ACTION_TYPE_JUMP:
			action_flags |= MLX5_FLOW_ACTION_JUMP;
			break;
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			action_flags |= MLX5_FLOW_ACTION_QUEUE;
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
			action_flags |= MLX5_FLOW_ACTION_RSS;
			break;
		case MLX5_RTE_FLOW_ACTION_TYPE_DEFAULT_MISS:
			action_flags |= MLX5_FLOW_ACTION_DEFAULT_MISS;
			break;
		default:
			nb_actions++;
			break;
		}
	}
	if ((action_flags & MLX5_FLOW_FATE_ACTIONS) != 0) {
		rte_sft_error_set(error, EINVAL,
				  RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				  NULL, NULL);
		return NULL;
	}
	// TODO: what should be checked for the MISS actions
	for (; lm_actions->type != RTE_FLOW_ACTION_TYPE_END; lm_actions++) {
		switch (lm_actions->type) {
		default:
			break;
		}
	}
	/* Create the entry firstly then create the flow. */
	pool = sh->ipool_sft[queue];
	if (pool == NULL) {
		rte_sft_error_set(error, ENOMEM,
				  RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				  NULL, NULL);
		return NULL;
	}
	entry = (struct rte_sft_entry *)mlx5_ipool_zmalloc(pool, &idx);
	if (entry == NULL) {
		rte_sft_error_set(error, ENOMEM,
				  RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				  NULL, NULL);
		return NULL;
	}
	/* Create the 2nd flow in the intermediate SFT table firstly. */
	reg_data = REG_C_5;
	tag_v.id = reg_data;
	tag_v.data = fid;
	/* mask of Reg ID could be skipped. */
	tag_m.id = UINT16_MAX;
	tag_m.data = UINT32_MAX;
	/* Action #1: MARK for user state + FID validity. */
	mark.id = MLX5_SFT_ENCODE_MARK(RTE_SFT_STATE_FLAG_FID_VALID, state);
	/* Action #3: Set the user data by using REG_C_x. */
	reg_data = REG_C_0;
	if (data != NULL) {
		set_data.id = reg_data;
		set_data.data = *data;
	} else {
		itmd_actions[2].type = RTE_FLOW_ACTION_TYPE_VOID;
	}
	/* Action #2: Using REG_C_1 for matching the FID validity. */
	reg_data = REG_C_1;
	set_state.id = reg_data;
	set_state.data = mark.id;
	entry->itmd_flow = mlx5_sft_ctrl_flow_create(dev, &attr, itmd_pattern,
						itmd_actions, &flow_error);
	if (entry->itmd_flow == NULL) {
		rte_sft_error_set(error, flow_error.type,
				  RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				  flow_error.cause, flow_error.message);
		goto error_out;
	}
	/* Create the 1st flow in the SFT table then. */
	rte_memcpy(&actions_sft.actions, actions,
		   sizeof(struct rte_flow_action) * nb_actions);
	pa_sft = &actions_sft.actions[nb_actions];
	/* Metadata for FID only. */
	meta.data = fid;
	meta.mask = UINT32_MAX;
	pa_sft->type = RTE_FLOW_ACTION_TYPE_SET_META;
	pa_sft->conf = &meta;
	/* Using REG_C_5' for the 2nd flow matching by using FID. */
	pa_sft++;
	reg_data = REG_C_5;
	set_tag.id = reg_data;
	set_tag.data = fid;
	pa_sft->type = (enum rte_flow_action_type)
			MLX5_RTE_FLOW_ACTION_TYPE_TAG;
	pa_sft->conf = &set_tag;
	/* Jump to the intermediate-SFT table. */
	pa_sft++;
	jump.group = MLX5_FLOW_TABLE_LEVEL_ITMD_SFT;
	pa_sft->type = RTE_FLOW_ACTION_TYPE_JUMP;
	pa_sft->conf = &jump;
	/* Add the END action. */
	pa_sft++;
	*pa_sft = actions[nb_actions];
	/* SFT table -> Intermediate SFT table. */
	attr.group = MLX5_FLOW_TABLE_LEVEL_SFT;
	// TODO: Is FID unique global or in each queue.
	entry->flow = mlx5_sft_ctrl_flow_create(dev, &attr, pattern,
					actions_sft.actions, &flow_error);
	if (entry->flow == NULL) {
		rte_sft_error_set(error, flow_error.type,
				  RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				  flow_error.cause, flow_error.message);
		goto error_out;
	}
	/* Store the entry for debugging purpose. */
	entry->idx = idx;
	entry->state = mark.id;
	entry->fid_zone = fid;
	ILIST_INSERT(sh->ipool_sft[queue], &priv->sft_lists[queue], idx,
		     entry, next);
	return entry;
error_out:
	if (entry->itmd_flow != NULL)
		mlx5_flow_remove_post_sft_rule(dev,
				(uintptr_t)(void *)entry->itmd_flow);
	if (idx != 0)
		mlx5_ipool_free(pool, idx);
	return NULL;
}

static int mlx5_sft_entry_destroy(struct rte_eth_dev *dev,
				  struct rte_sft_entry *entry, uint16_t queue,
				  struct rte_sft_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_dev_ctx_shared *sh = priv->sh;
	RTE_SET_USED(queue);

	if (entry == NULL || queue > sh->nb_sft_queue)
		return rte_sft_error_set(error, EINVAL,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
					 NULL, NULL);
	mlx5_flow_remove_post_sft_rule(dev,
				(uintptr_t)(void *)entry->flow);
	mlx5_flow_remove_post_sft_rule(dev,
				(uintptr_t)(void *)entry->itmd_flow);
	// TODO: Remove the miss flow
	/* Entry index could be checked. */
	ILIST_REMOVE(sh->ipool_sft[queue], &priv->sft_lists[queue],
		     entry->idx, entry, next);
	mlx5_ipool_free(sh->ipool_sft[queue], entry->idx);
	return 0;
}

static int mlx5_sft_entry_decode(struct rte_eth_dev *dev, uint16_t queue,
				 struct rte_mbuf *mbuf,
				 struct rte_sft_decode_info *info,
				 struct rte_sft_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_dev_ctx_shared *sh = priv->sh;
	uint32_t mark;
	uint32_t meta;
	RTE_SET_USED(queue);

	if (mbuf == NULL || info == NULL || queue > sh->nb_sft_queue)
		return rte_sft_error_set(error, EINVAL,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
					 NULL, NULL);
	/* Datapath: MARK & METADATA are both in the host byte order. */
	mark = mbuf->hash.fdir.hi;
	/* Adjust the mark to the default invalid one with 0. */
	if (mark >= MLX5_FLOW_MARK_DEFAULT)
		mark = 0;
	meta = *RTE_MBUF_DYNFIELD(mbuf, rte_flow_dynf_metadata_offs,
				  uint32_t *);
	info->state = (mark >> MLX5_SFT_FID_ZONE_STAT_SHIFT) &
		      MLX5_SFT_FID_ZONE_STAT_MASK;
	/* ZONE / FID will take all the 32bits. */
	if (info->state & RTE_SFT_STATE_FLAG_ZONE_VALID) {
		MLX5_ASSERT(!(info->state & RTE_SFT_STATE_FLAG_FID_VALID));
		info->zone = meta;
	} else if (info->state & RTE_SFT_STATE_FLAG_FID_VALID) {
		MLX5_ASSERT(!(info->state & RTE_SFT_STATE_FLAG_ZONE_VALID));
		info->fid = meta;
	} else {
		MLX5_ASSERT(meta == 0);
		info->fid = 0;
	}
	return 0;
}

static int mlx5_sft_entry_modify(struct rte_eth_dev *dev, uint16_t queue,
				 struct rte_sft_entry *entry,
				 const uint32_t *data, uint16_t data_len,
				 uint8_t state, struct rte_sft_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_dev_ctx_shared *sh = priv->sh;
	struct rte_flow_action_mark mark;
	int32_t reg_data;
	struct mlx5_rte_flow_action_set_tag set_state;
	struct mlx5_rte_flow_action_set_tag set_data;
	struct rte_flow_attr attr = {
		.ingress = 1,
		.priority = 0,
		.group = MLX5_FLOW_TABLE_LEVEL_ITMD_SFT,
	};
	struct mlx5_rte_flow_item_tag tag_v;
	struct mlx5_rte_flow_item_tag tag_m;
	const struct rte_flow_item itmd_pattern[] = {
		{
			.type = (enum rte_flow_item_type)
				MLX5_RTE_FLOW_ITEM_TYPE_TAG,
			.spec = &tag_v,
			.mask = &tag_m,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};
	struct rte_flow_action itmd_actions[] = {
		[0] = {
			.type = (enum rte_flow_action_type)
				RTE_FLOW_ACTION_TYPE_MARK,
			/* User state will be changed in modification. */
			.conf = &mark,
		},
		[1] = {
			.type = (enum rte_flow_action_type)
				MLX5_RTE_FLOW_ACTION_TYPE_TAG,
			.conf = &set_state,
		},
		[2] = {
			.type = (enum rte_flow_action_type)
				MLX5_RTE_FLOW_ACTION_TYPE_TAG,
			/* User data will be changed in modification. */
			.conf = &set_data,
		},
		[3] = {
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &(struct rte_flow_action_jump){
				.group = MLX5_FLOW_TABLE_LEVEL_POST_SFT,
			},
		},
		[4] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow_error flow_error = {0};
	struct rte_flow *old_flow;

	if (queue > sh->nb_sft_queue || entry == NULL || data_len > 1)
		return rte_sft_error_set(error, EINVAL,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
					 NULL, NULL);
	/*
	 * The SFT state should be considered as FID valid.
	 * No flag to indicate if application state is to be changed or not.
	 * Right now, the application will always be modified.
	 */
	mark.id = MLX5_SFT_ENCODE_MARK(RTE_SFT_STATE_FLAG_FID_VALID, state);
	// TODO: replaced with changing ID
	reg_data = REG_C_1;
	set_state.id = reg_data;
	set_state.data = mark.id;
	if (data == NULL) {
		itmd_actions[2].type = RTE_FLOW_ACTION_TYPE_VOID;
	} else {
		reg_data = REG_C_0;
		set_data.id = reg_data;
		set_data.data = *data;
	}
	/* FID is still used for matching. */
	reg_data = REG_C_5;
	tag_v.id = reg_data;
	tag_v.data = entry->fid_zone;
	/* mask of Reg ID could be skipped. */
	tag_m.id = reg_data;
	tag_m.data = UINT32_MAX;
	old_flow = entry->itmd_flow;
	entry->itmd_flow = mlx5_sft_ctrl_flow_create(dev, &attr, itmd_pattern,
						     itmd_actions, &flow_error);
	if (entry->itmd_flow == NULL) {
		/* Restore the old information. */
		entry->itmd_flow = old_flow;
		return rte_sft_error_set(error, flow_error.type,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
					 flow_error.cause, flow_error.message);
	}
	/* Currently, the return value of flow destroy is not checked. */
	mlx5_flow_remove_post_sft_rule(dev, (uintptr_t)(void *)old_flow);
	entry->state = mark.id;
	return 0;
}

static const struct rte_sft_ops mlx5_sft_ops = {
	.sft_start = mlx5_sft_start,
	.sft_stop = mlx5_sft_stop,
	.sft_create_entry = mlx5_sft_entry_create,
	.sft_entry_modify = mlx5_sft_entry_modify,
	.sft_entry_destroy = mlx5_sft_entry_destroy,
	.sft_entry_decode = mlx5_sft_entry_decode,
};

/*
 * Get SFT operations.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param arg
 *   Pointer to set the sft operations.
 *
 * @return
 *   Always 0.
 */
int
mlx5_sft_ops_get(struct rte_eth_dev *dev __rte_unused, void *arg)
{
	*(const struct rte_sft_ops **)arg = &mlx5_sft_ops;
	return 0;
}
