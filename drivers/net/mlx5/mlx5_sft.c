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
#include "mlx5_rx.h"
#include "mlx5_sft.h"

#define MLX5_SFT_TABLE_FRAGMENT_FLOW_PRIORITY 0
#define MLX5_SFT_TABLE_APP_RULE_FLOW_PRIORITY 1
#define MLX5_SFT_TABLE_MISS_FLOW_PRIORITY 3

static int
mlx5_sft_entry_destroy(struct rte_eth_dev *dev,
		       struct rte_sft_entry *entry, uint16_t queue,
		       struct rte_sft_error *error);

static uint32_t *
sft_flow_list(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	return priv->sft_flows ? &priv->sft_flows->idx_list : NULL;
}

static uint32_t
sft_fragment_flow(struct rte_eth_dev *dev, const struct rte_flow_item pattern[],
		  struct rte_flow_error *error)
{
	int state_reg = mlx5_flow_get_reg_id(dev, MLX5_SFT_APP_STATE, 0, error);
	uint32_t *flow_list = sft_flow_list(dev);
	const struct rte_flow_attr attr = {
		.ingress = 1,
		.group = MLX5_FLOW_TABLE_SFT_L0,
		.priority = MLX5_SFT_TABLE_FRAGMENT_FLOW_PRIORITY
	};
	const union sft_mark mark = {
		.zone_valid = 1,
		.fragment = 1,
		.app_state = RTE_SFT_APP_ERR_STATE
	};
	const struct rte_flow_action actions[] = {
		[0] = {
			.type = mlx5_sft_dbg_enabled(dev) ?
				RTE_FLOW_ACTION_TYPE_COUNT :
				RTE_FLOW_ACTION_TYPE_VOID
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_MARK,
			.conf = &(const struct rte_flow_action_mark) {
				.id = mark.val
			}
		},
		[2] = {
			.type = (enum rte_flow_action_type)
				MLX5_RTE_FLOW_ACTION_TYPE_TAG,
			.conf = &(const struct mlx5_rte_flow_action_set_tag){
				.id = (enum modify_reg)state_reg,
				.data = mark.val,
				.length = MLX5_REG_BITS,
				.offset = 0
			}
		},
		[3] = {
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &(const struct rte_flow_action_jump) {
				.group = MLX5_FLOW_TABLE_SFT_L2
			}
		},
		[4] = { .type = RTE_FLOW_ACTION_TYPE_END }
	};

	if (state_reg < 0 || !flow_list)
		return 0;
	return mlx5_flow_list_create(dev, MLX5_FLOW_TYPE_SFT, &attr, pattern,
				     actions, false, error);
}

static uint32_t
sft_l0_ipv6_fragment_rule(struct rte_eth_dev *dev, struct rte_flow_error *error)
{
	/* reference: 4bdd265768f9 ("app/testpmd: support IPv6 fragments") */
	const struct rte_flow_item_ipv6 ipv6_spec = {
		.has_frag_ext = 1
	};
	const struct rte_flow_item_ipv6 ipv6_mask = {
		.has_frag_ext = 1
	};
	const struct rte_flow_item pattern[] = {
		[0] = {
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = NULL,
			.last = NULL,
			.mask = NULL
		},
		[1] = {
			.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.spec = (const void *)&ipv6_spec,
			.last = NULL,
			.mask = (const void *)&ipv6_mask
		},
		[2] = { .type = RTE_FLOW_ITEM_TYPE_END }
	};

	return sft_fragment_flow(dev, pattern, error);
}

static uint32_t
sft_l0_ipv4_fragment_rule(struct rte_eth_dev *dev, struct rte_flow_error *error)
{
	/* reference: b3259edcf878 ("app/testpmd: support IPv4 fragments") */
	const struct rte_flow_item_ipv4 ipv4_spec = {
		.hdr.fragment_offset = rte_cpu_to_be_16(1)
	};
	const struct rte_flow_item_ipv4 ipv4_last = {
		.hdr.fragment_offset = rte_cpu_to_be_16(0x3fff)
	};
	const struct rte_flow_item_ipv4 ipv4_mask = {
		.hdr.fragment_offset = rte_cpu_to_be_16(0x3fff)
	};
	const struct rte_flow_item pattern[] = {
		[0] = {
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = NULL,
			.last = NULL,
			.mask = NULL
		},
		[1] = {
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.spec = (const void *)&ipv4_spec,
			.last = (const void *)&ipv4_last,
			.mask = (const void *)&ipv4_mask
		},
		[2] = { .type = RTE_FLOW_ITEM_TYPE_END }
	};

	return sft_fragment_flow(dev, pattern, error);
}

static uint32_t
sft_l0_dflt_zone_rule(struct rte_eth_dev *dev, struct rte_flow_error *error)
{
	int state_reg = mlx5_flow_get_reg_id(dev, MLX5_SFT_APP_STATE, 0, error);
	uint32_t *flow_list = sft_flow_list(dev);
	const struct rte_flow_attr attr = {
		.ingress = 1,
		.group = MLX5_FLOW_TABLE_SFT_L0,
		.priority = MLX5_SFT_TABLE_MISS_FLOW_PRIORITY
	};
	const union sft_mark mark = { .zone_valid = 1 };
	const struct rte_flow_item pattern[] = {
		[0] = {
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = NULL,
			.last = NULL,
			.mask = NULL
		},
		[1] = { .type = RTE_FLOW_ITEM_TYPE_END }
	};
	/*
	 * In legacy mode, MARK cannot be used for matching and TAG cannot
	 * be visible to software. Currently, they should have the same value.
	 * There is no need to touch METADATA and it is set in the RTE flow.
	 * Application state for MARK should be with the default value 0.
	 */
	const struct rte_flow_action actions[] = {
		[0] = {
			.type = mlx5_sft_dbg_enabled(dev) ?
				RTE_FLOW_ACTION_TYPE_COUNT :
				RTE_FLOW_ACTION_TYPE_VOID
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_MARK,
			.conf = &(struct rte_flow_action_mark){
				.id = mark.val,
			},
		},
		[2] = {
			.type = (enum rte_flow_action_type)
				MLX5_RTE_FLOW_ACTION_TYPE_TAG,
			.conf = &(const struct mlx5_rte_flow_action_set_tag) {
				.id = (enum modify_reg)state_reg,
				.data = mark.val,
				.length = MLX5_REG_BITS,
				.offset = 0
			}
		},
		[3] = {
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &(struct rte_flow_action_jump){
				.group = MLX5_FLOW_TABLE_SFT_L2,
			},
		},
		[4] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		}
	};
	if (state_reg < 0 || !flow_list)
		return 0;
	return mlx5_flow_list_create(dev, MLX5_FLOW_TYPE_SFT, &attr, pattern,
				     actions, false, error);
}

static uint32_t
(*mlx5_sft_l0_cb[MLX5_SFT_L0_DFLT_FLOWS_NUM])(struct rte_eth_dev *,
					      struct rte_flow_error *) = {
	[MLX5_SFT_L0_DFLT_ZONE_FLOW]      = sft_l0_dflt_zone_rule,
	[MLX5_SFT_L0_DFLT_IPV4_FRAG_FLOW] = sft_l0_ipv4_fragment_rule,
	[MLX5_SFT_L0_DFLT_IPV6_FRAG_FLOW] = sft_l0_ipv6_fragment_rule,
};

static void
mlx5_destroy_sft_l0_flows(struct rte_eth_dev *dev, struct rte_sft_error *err)
{
	int i;
	struct mlx5_priv *priv = dev->data->dev_private;

	RTE_SET_USED(err);
	for (i = 0; i < MLX5_SFT_L0_DFLT_FLOWS_NUM; i++) {
		if (!priv->sft_flows->l0_flows[i])
			break;
		mlx5_flow_list_destroy(dev, MLX5_FLOW_TYPE_SFT,
				       priv->sft_flows->l0_flows[i]);
	}
}

static int
mlx5_create_sft_l0_flows(struct rte_eth_dev *dev,
			 struct rte_sft_error *sft_err)
{
	int i;
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_flow_error rte_err;

	for (i = 0; i < MLX5_SFT_L0_DFLT_FLOWS_NUM; i++) {
		uint32_t sft_flow = mlx5_sft_l0_cb[i](dev, &rte_err);
		if (sft_flow) {
			priv->sft_flows->l0_flows[i] = sft_flow;
		} else {
			mlx5_destroy_sft_l0_flows(dev, sft_err);
			rte_sft_error_set(sft_err, rte_errno,
					  RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					  "cannot create sft table rules");
			return -1;
		}
	}

	return 0;
}

/*
 * if packet entered SFT L1 table, there is FID value in META register
 */
static uint32_t
mlx5_create_sft_l1_miss_flow(struct rte_eth_dev *dev)
{
	struct rte_flow_error rte_err;
	int state_reg = mlx5_flow_get_reg_id(dev, MLX5_SFT_APP_STATE, 0,
					     &rte_err);
	uint32_t *flow_list = sft_flow_list(dev);
	const union sft_mark mark = {
		.fid_valid = 1,
		.app_state = RTE_SFT_APP_ERR_STATE,
	};
	const struct rte_flow_attr l1_attr = {
		.ingress = 1,
		.group = MLX5_FLOW_TABLE_SFT_L1,
		.priority = MLX5_SFT_TABLE_MISS_FLOW_PRIORITY
	};
	const struct rte_flow_item l1_pattern[] = {
		[0] = {
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = NULL, .last = NULL, .mask = NULL
		},
		[1] = { .type = RTE_FLOW_ITEM_TYPE_END }
	};
	const struct rte_flow_action l1_actions[] = {
		[0] = {
			.type = mlx5_sft_dbg_enabled(dev) ?
				RTE_FLOW_ACTION_TYPE_COUNT :
				RTE_FLOW_ACTION_TYPE_VOID

		},
		[1] = {
			.type = (enum rte_flow_action_type)
				MLX5_RTE_FLOW_ACTION_TYPE_TAG,
			.conf = &(const struct mlx5_rte_flow_action_set_tag){
				.id = (enum modify_reg)state_reg,
				.data = mark.val,
				.length = MLX5_REG_BITS,
				.offset = 0
			}
		},
		[2] = {
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &(const struct rte_flow_action_jump) {
				.group = MLX5_FLOW_TABLE_SFT_L2
			}
		},
		[3] = { .type = RTE_FLOW_ACTION_TYPE_END }
	};
	if (state_reg < 0 || !flow_list)
		return 0;
	return mlx5_flow_list_create(dev, MLX5_FLOW_TYPE_SFT, &l1_attr,
				     l1_pattern, l1_actions, false, &rte_err);
}

static int
mlx5_create_sft_l1_flows(struct rte_eth_dev *dev, struct rte_sft_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;

	priv->sft_flows->l1_flow = mlx5_create_sft_l1_miss_flow(dev);
	if (!priv->sft_flows->l1_flow)
		return rte_sft_error_set(error, rte_errno,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "failed to create L1 flows");

	return 0;
}

static void
mlx5_destroy_sft_flows(struct rte_eth_dev *dev, struct rte_sft_error *sft_err)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	uint32_t *flow_list = sft_flow_list(dev);

	if (!flow_list)
		return;
	mlx5_destroy_sft_l0_flows(dev, sft_err);
	mlx5_flow_list_destroy(dev, MLX5_FLOW_TYPE_SFT,
			       priv->sft_flows->l1_flow);
}

static int
mlx5_create_sft_flows(struct rte_eth_dev *dev, struct rte_sft_error *error)
{
	if (mlx5_create_sft_l0_flows(dev, error))
		goto err0;
	if (mlx5_create_sft_l1_flows(dev, error))
		goto err1;

	return 0;

err1:
	mlx5_destroy_sft_l0_flows(dev, error);
err0:
	return -rte_errno;
}

static void
mlx5_sft_release_mem(struct rte_eth_dev *dev, uint16_t nb_queue,
		     struct rte_sft_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_dev_ctx_shared *sh = priv->sh;
	uint16_t i;

	RTE_SET_USED(error);
	if (!priv->sft_flows)
		return;
	for (i = 0; i < nb_queue; i++)
		mlx5_ipool_destroy(sh->ipool_sft[i]);
	mlx5_free(sh->ipool_sft);
	sh->ipool_sft = NULL;
	mlx5_free(priv->sft_lists);
	priv->sft_lists = NULL;
	mlx5_free(priv->sft_flows);
	priv->sft_flows = NULL;
}

static int
mlx5_sft_alloc_mem(struct rte_eth_dev *dev, uint16_t nb_queue,
		   struct rte_sft_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_dev_ctx_shared *sh = priv->sh;
	uint16_t i;
	struct mlx5_indexed_pool_config pool_cfg = {
		.size = sizeof(struct rte_sft_entry),
		.trunk_size = 1024,
		.need_lock = 0,
		.release_mem_en = 1,
		.malloc = mlx5_malloc,
		.free = mlx5_free,
		.type = "sft_entry_pool",
	};

	priv->sft_flows = mlx5_malloc(MLX5_MEM_SYS | MLX5_MEM_ZERO,
				      sizeof(*priv->sft_flows),
				      0, SOCKET_ID_ANY);
	if (!priv->sft_flows)
		goto err1;
	priv->sft_lists = mlx5_malloc(MLX5_MEM_SYS | MLX5_MEM_ZERO,
				      nb_queue * sizeof(uint32_t),
				      MLX5_MALLOC_ALIGNMENT, SOCKET_ID_ANY);
	if (!priv->sft_lists)
		goto err2;
	sh->ipool_sft = mlx5_malloc(MLX5_MEM_SYS | MLX5_MEM_ZERO,
				    nb_queue * sizeof(sh->ipool_sft[0]),
				    MLX5_MALLOC_ALIGNMENT, SOCKET_ID_ANY);
	if (!sh->ipool_sft)
		goto err3;
	/* Allocate memory pool to save the entry. */
	for (i = 0; i < nb_queue; i++) {
		sh->ipool_sft[i] = mlx5_ipool_create(&pool_cfg);
		if (!sh->ipool_sft[i])
			goto err4;
		/* Initialize ILIST for each entry queue. */
		priv->sft_lists[i] = 0;
	}

	return 0;

err4:
	for (i = 0; i < nb_queue; i++) {
		if (!sh->ipool_sft[i])
			break;
		mlx5_ipool_destroy(sh->ipool_sft[i]);
	}
	mlx5_free(sh->ipool_sft);
	sh->ipool_sft = NULL;
err3:
	mlx5_free(priv->sft_lists);
	priv->sft_lists = NULL;
err2:
	mlx5_free(priv->sft_flows);
	priv->sft_flows = NULL;
err1:
	return rte_sft_error_set(error, ENOMEM, RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				 NULL, "failed to allocate sft memory");
}

static int
mlx5_sft_start(struct rte_eth_dev *dev, uint16_t nb_queue,
	       uint16_t data_len, struct rte_sft_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_dev_ctx_shared *sh = priv->sh;
	uint32_t idx;

	if (priv->sft_en)
		return 0;
	if (!priv->config.sft_en)
		return rte_sft_error_set(error, ENOTSUP,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "no PMD support for SFT");
	if (data_len > 1 || nb_queue > MLX5_SFT_QUEUE_MAX)
		return rte_sft_error_set(error, EINVAL,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
					 NULL, NULL);
	if (mlx5_sft_alloc_mem(dev, nb_queue, error))
		return rte_sft_error_set(error, ENOMEM,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "failed to allocate PMD sft memory");
	/* Enable MARK for all Rx queues. */
	for (idx = 0; idx < priv->rxqs_n; idx++) {
		struct mlx5_rxq_ctrl *rxq_ctrl = mlx5_rxq_ctrl_get(dev, idx);

		if (rxq_ctrl == NULL)
			continue;
		rxq_ctrl->rxq.mark = 1;
		rxq_ctrl->flow_mark_n++;
	}
	if (mlx5_create_sft_flows(dev, error))
		goto err;
	sh->nb_sft_queue = nb_queue;
	priv->sft_en = 1;
	return 0;

err:
	mlx5_sft_release_mem(dev, nb_queue, error);
	return -rte_errno;
}

static int mlx5_sft_stop(struct rte_eth_dev *dev, struct rte_sft_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_dev_ctx_shared *sh = priv->sh;
	uint32_t idx;

	if (!priv->config.sft_en)
		return rte_sft_error_set(error, ENOTSUP,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "no PMD support for SFT");
	mlx5_destroy_sft_flows(dev, error);
	for (idx = 0; idx < priv->rxqs_n; idx++) {
		struct mlx5_rxq_ctrl *rxq_ctrl = mlx5_rxq_ctrl_get(dev, idx);

		if (rxq_ctrl == NULL)
			continue;
		rxq_ctrl->flow_mark_n--;
		rxq_ctrl->rxq.mark = !!rxq_ctrl->flow_mark_n;
	}
	mlx5_sft_release_mem(dev, sh->nb_sft_queue, error);
	return 0;
}

struct sft_entry_ctx {
	struct rte_eth_dev *dev;
	uint32_t data;
	uint32_t fid;
	uint32_t zone;
	uint16_t data_len;
	uint16_t queue;
	uint8_t state;
	uint8_t hit_actions_num;
	union mlx5_sft_entry_flags flags;
	struct rte_flow_item *hit_pattern;
	struct rte_flow_action *hit_actions;
	struct rte_flow_item *l0_sft_item;
	struct rte_flow_action *l0_actions;
	uint64_t miss_conditions;
};

static int
mlx5_sft_entry_process_hit_pattern(struct sft_entry_ctx *ctx,
				   struct rte_sft_error *error)
{
	uint64_t item_flags = 0;
	struct rte_flow_item *item = ctx->hit_pattern;

	ctx->l0_sft_item = NULL;
	/* 5-tuple & zone are mandatory, mask should also be checked. */
	for (; item->type != RTE_FLOW_ITEM_TYPE_END; item++) {
		switch (item->type) {
		case RTE_FLOW_ITEM_TYPE_IPV4:
			ctx->flags.ipv4 = 1;
			item_flags |= MLX5_FLOW_LAYER_OUTER_L3_IPV4;
			break;
		case RTE_FLOW_ITEM_TYPE_IPV6:
			ctx->flags.ipv6 = 1;
			item_flags |= MLX5_FLOW_LAYER_OUTER_L3_IPV6;
			break;
		case RTE_FLOW_ITEM_TYPE_TCP:
			ctx->flags.tcp = 1;
			item_flags |= MLX5_FLOW_LAYER_OUTER_L4_TCP;
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			ctx->flags.udp = 1;
			item_flags |= MLX5_FLOW_LAYER_OUTER_L4_UDP;
			break;
		case RTE_FLOW_ITEM_TYPE_VOID:
			ctx->l0_sft_item = item;
			break;
		case RTE_FLOW_ITEM_TYPE_META:
		case RTE_FLOW_ITEM_TYPE_TAG:
			return rte_sft_error_set(error, EINVAL,
						 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
						 NULL, NULL);
		default:
			break;
		}
	}
	if (!(item_flags & MLX5_FLOW_LAYER_OUTER_L3) ||
	    !(item_flags & MLX5_FLOW_LAYER_OUTER_L4))
		return rte_sft_error_set(error, EINVAL,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "flow 5tuple not defined");
	else if (!ctx->l0_sft_item)
		return rte_sft_error_set(error, EINVAL,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
					 NULL, "no place for sft item");
	return 0;
}

#define MLX5_SFT_L0_ACTIONS_NUM (SFT_ACTIONS_NUM + 8)

static int
mlx5_sft_verify_hit_actions(const struct rte_flow_action *hit_actions,
			    struct rte_sft_error *error)
{
	uint16_t i = 0;
	uint64_t action_flags = 0;

	for (; hit_actions[i].type != RTE_FLOW_ACTION_TYPE_END; i++) {
		/*
		 * following switch() mixes RTE & MLX5 action types
		 * modern compiler can recognize that and issue
		 * -Wswitch warning
		 */
		uint32_t type = hit_actions[i].type;
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
			break;
		}
	}
	if ((action_flags & MLX5_FLOW_FATE_ACTIONS) != 0)
		rte_sft_error_set(error, EINVAL,
				  RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
				  "sft actions verification failed");

	return i;
}

static int
mlx5_sft_entry_process_hit_actions(struct sft_entry_ctx *ctx,
				   struct rte_sft_error *error)
{
	int ret;
	struct rte_flow_action *l0_actions;

	ret = mlx5_sft_verify_hit_actions(ctx->hit_actions, error);
	if (ret < 0)
		return -rte_errno;
	l0_actions = rte_calloc("mlx5_sft_l0_actions", MLX5_SFT_L0_ACTIONS_NUM,
				sizeof(l0_actions[0]), 0);
	if (!l0_actions)
		return rte_sft_error_set(error, ENOMEM,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "failed to allocate sft l0 actions");
	ctx->hit_actions_num = (typeof(ctx->hit_actions_num))ret;
	ctx->l0_actions = l0_actions;
	memcpy(l0_actions, ctx->hit_actions,
	       ctx->hit_actions_num * sizeof(l0_actions[0]));

	return 0;
}

/*
 * IF conn_track enabled:
 *  pattern tag(c5) fid / ip / tcp frags = 0
 *  actions set app_state / set app_data / jump group L2
 * ELSE
 *   pattern tag(c5) fid / end
 *  actions set app_state / set app_data / jump L2
 * END IF
 *
 * SFT flow rule L1 does not match on packet's 5-tuple.
 * This rule cannot be used for flow direction offload, because it fits
 * both directions
 */
static int
mlx5_sft_add_l1_rules(struct rte_eth_dev *dev, struct rte_sft_entry *entry,
		      uint32_t data, uint8_t state,
		      struct rte_sft_error *error)
{
	struct rte_flow_error rte_err;
	const struct rte_flow_attr l1_attr = {
		.ingress = 1,
		.group = MLX5_FLOW_TABLE_SFT_L1,
	};
	const union sft_mark mark = {
		.fid_valid = 1,
		.app_state = state,
	};
	int fid_reg = mlx5_flow_get_reg_id(dev, MLX5_SFT_FID, 0, &rte_err);
	int state_reg = mlx5_flow_get_reg_id(dev, MLX5_SFT_APP_STATE, 0,
					     &rte_err);
	int data_reg = mlx5_flow_get_reg_id(dev, MLX5_SFT_APP_DATA, 0,
					    &rte_err);
	struct rte_flow_item l1_pattern[] = {
		[0] = {
			.type = (enum rte_flow_item_type)
				MLX5_RTE_FLOW_ITEM_TYPE_TAG,
			.spec = &(const struct mlx5_rte_flow_item_tag){
				.id = (enum modify_reg)fid_reg,
				.data = entry->fid,
			},
			.mask = &(const struct mlx5_rte_flow_item_tag){
				.id = (enum modify_reg)UINT16_MAX,
				.data = UINT32_MAX
			}
		},
		[1] = { .type = RTE_FLOW_ITEM_TYPE_ETH },
		[2] = { .type = RTE_FLOW_ITEM_TYPE_END }
	};
	const struct rte_flow_action l1_actions[] = {
		[0] = {
			.type = mlx5_sft_dbg_enabled(dev) ?
				RTE_FLOW_ACTION_TYPE_COUNT :
				RTE_FLOW_ACTION_TYPE_VOID
		},
		[1] = {
			.type = (enum rte_flow_action_type)
				MLX5_RTE_FLOW_ACTION_TYPE_TAG,
			.conf = &(struct mlx5_rte_flow_action_set_tag){
				.id = (enum modify_reg)state_reg,
				.data = mark.val,
				.length = MLX5_REG_BITS,
				.offset = 0
			}
		},
		[2] = {
			.type = (enum rte_flow_action_type)
				MLX5_RTE_FLOW_ACTION_TYPE_TAG,
			.conf = &(struct mlx5_rte_flow_action_set_tag) {
				.id = (enum modify_reg)data_reg,
				.data = data,
				.length = MLX5_REG_BITS,
				.offset = 0
			}
		},
		[3] = {
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &(struct rte_flow_action_jump) {
				.group = MLX5_FLOW_TABLE_SFT_L2
			}
		},
		[4] = { .type = RTE_FLOW_ACTION_TYPE_END }
	};

	if (fid_reg < 0 || state_reg < 0 || data_reg < 0)
		rte_sft_error_set(error, rte_errno,
				  RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				  NULL, "failed fetch fid register");
	entry->sft_l1_flow = mlx5_flow_list_create(dev, MLX5_FLOW_TYPE_SFT,
						   &l1_attr, l1_pattern,
						   l1_actions, false, &rte_err);
	if (!entry->sft_l1_flow)
		rte_sft_error_set(error, rte_errno,
				  RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				  NULL, "failed to create sft L1 flow rule");

	return entry->sft_l1_flow ? 0 : -1;
}

/*
 * SFT L0:
 * priority APP
 * pattern <6-tuple>
 * actions <hit actions> /
 *         mark {fid.valid,direction} / set meta fid /
 *         tag(c5) fid/ tag(c1) {fid.valid,direction} / jump L1
 */
static int
mlx5_sft_add_l0_rules(struct sft_entry_ctx *ctx, struct rte_sft_entry *entry,
		      struct rte_sft_error *error)
{
	int zone_fid_reg, state_reg, i = ctx->hit_actions_num;
	struct rte_flow_error rte_err;
	union sft_mark mark = {
		.fid_valid = 1,
		.direction = ctx->flags.initiator
	};
	const struct rte_flow_attr l0_attr = {
		.ingress = 1,
		.priority = MLX5_SFT_TABLE_APP_RULE_FLOW_PRIORITY,
		.group = MLX5_FLOW_TABLE_SFT_L0,
	};
	zone_fid_reg = mlx5_flow_get_reg_id(ctx->dev, MLX5_SFT_ZONE, 0,
					    &rte_err);
	state_reg = mlx5_flow_get_reg_id(ctx->dev, MLX5_SFT_APP_STATE, 0,
					 &rte_err);
	if (zone_fid_reg < 0) {
		rte_sft_error_set(error, rte_errno,
				  RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				  NULL,
				  "no register for sft zone");
		goto out;
	}
	*ctx->l0_sft_item = (typeof(*ctx->l0_sft_item)) {
		.type = (enum rte_flow_item_type)
			MLX5_RTE_FLOW_ITEM_TYPE_TAG,
		.spec = &(struct mlx5_rte_flow_item_tag){
			.id = (enum modify_reg)zone_fid_reg,
			.data = ctx->zone
		},
		.mask = &(struct mlx5_rte_flow_item_tag){
			.id = (enum modify_reg)UINT16_MAX,
			.data = UINT32_MAX
		}
	};
	if (mlx5_sft_dbg_enabled(ctx->dev)) {
		ctx->l0_actions[i++] = (typeof(ctx->l0_actions[0])) {
			.type = RTE_FLOW_ACTION_TYPE_COUNT
		};
	}
	/* MARK & META actions are for application */
	ctx->l0_actions[i++] = (typeof(ctx->l0_actions[0])) {
		.type = RTE_FLOW_ACTION_TYPE_MARK,
		.conf = &(struct rte_flow_action_mark){ .id = mark.val }
	};
	ctx->l0_actions[i++] = (typeof(ctx->l0_actions[0])) {
		.type = RTE_FLOW_ACTION_TYPE_SET_META,
		.conf = &(struct rte_flow_action_set_meta) {
			.data = ctx->fid,
			.mask = UINT32_MAX
		}
	};
	ctx->l0_actions[i++] = (typeof(ctx->l0_actions[0])) {
		.type = (enum rte_flow_action_type)
			MLX5_RTE_FLOW_ACTION_TYPE_TAG,
		.conf = &(struct mlx5_rte_flow_action_set_tag){
			.id = (enum modify_reg)state_reg,
			.data = mark.val,
			.length = MLX5_REG_BITS,
			.offset = 0
		}
	};
	ctx->l0_actions[i++] = (typeof(ctx->l0_actions[0])) {
		.type = (enum rte_flow_action_type)
			MLX5_RTE_FLOW_ACTION_TYPE_TAG,
		.conf = &(const struct mlx5_rte_flow_action_set_tag) {
			.id = (enum modify_reg)zone_fid_reg,
			.data = ctx->fid,
			.length = MLX5_REG_BITS,
			.offset = 0
		}
	};
	ctx->l0_actions[i++] = (typeof(ctx->l0_actions[0])){
		.type = RTE_FLOW_ACTION_TYPE_JUMP,
		.conf = &(struct rte_flow_action_jump) {
			.group = MLX5_FLOW_TABLE_SFT_L1
		}
	};
	ctx->l0_actions[i++].type = RTE_FLOW_ACTION_TYPE_END;
	entry->sft_l0_flow = mlx5_flow_list_create(ctx->dev, MLX5_FLOW_TYPE_SFT,
						   &l0_attr, ctx->hit_pattern,
						   ctx->l0_actions, false,
						   &rte_err);
	if (!entry->sft_l0_flow)
		rte_sft_error_set(error, rte_errno,
				  RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				  NULL, "failed to create sft L0 flow rule");
out:
	rte_free(ctx->l0_actions);
	return entry->sft_l0_flow ? 0 : -rte_errno;
}

static inline void
mlx5_sft_entry_activate(struct rte_eth_dev *dev, uint16_t queue,
			struct rte_sft_entry *entry)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_dev_ctx_shared *sh = priv->sh;

	ILIST_INSERT(sh->ipool_sft[queue], &priv->sft_lists[queue], entry->idx,
		     entry, next);
}

static void
mlx5_sft_release_entry(struct rte_eth_dev *dev, uint16_t queue,
		       struct rte_sft_entry *entry)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_dev_ctx_shared *sh = priv->sh;
	struct mlx5_indexed_pool *pool = sh->ipool_sft[queue];

	if (entry)
		mlx5_ipool_free(pool, entry->idx);
}

static struct rte_sft_entry *
mlx5_sft_alloc_entry(struct sft_entry_ctx *ctx, struct rte_sft_error *error)
{
	struct mlx5_priv *priv = ctx->dev->data->dev_private;
	struct mlx5_dev_ctx_shared *sh = priv->sh;
	struct mlx5_indexed_pool *pool = sh->ipool_sft[ctx->queue];
	struct rte_sft_entry *entry;
	uint32_t idx;

	if (!pool) {
		rte_sft_error_set(error, EINVAL,
				  RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				  NULL, "memory pool was not allocated");
		return NULL;
	}
	entry = (struct rte_sft_entry *)mlx5_ipool_zmalloc(pool, &idx);
	if (entry == NULL) {
		rte_sft_error_set(error, ENOMEM,
				  RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				  NULL, NULL);
		return NULL;
	}
	entry->idx = idx;
	entry->fid = ctx->fid;
	entry->flags = ctx->flags;
	entry->miss_conditions = ctx->miss_conditions;
	return entry;
}

static struct rte_sft_entry *
mlx5_sft_entry_create(struct rte_eth_dev *dev, uint32_t fid, uint32_t zone,
		      uint16_t queue,
		      struct rte_flow_item *pattern, uint64_t miss_conditions,
		      struct rte_flow_action *actions,
		      struct rte_flow_action *miss_actions,
		      const uint32_t *data,
		      uint16_t data_len, uint8_t state, bool initiator,
		      struct rte_sft_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_dev_ctx_shared *sh = priv->sh;
	struct sft_entry_ctx ctx = {
		.dev = dev, .zone = zone, .fid = fid,
		.hit_pattern = pattern, .hit_actions = actions,
		.miss_conditions = miss_conditions,
		.data = data ? rte_cpu_to_be_32(*data) :
			rte_cpu_to_be_32(RTE_SFT_APP_ERR_DATA_VAL),
		.data_len = data_len, .queue = queue,
		.state = state,
		.flags.initiator = initiator,
	};
	struct rte_sft_entry *entry;

	RTE_SET_USED(miss_actions);
	if (!priv->config.sft_en) {
		rte_sft_error_set(error, ENOTSUP,
				  RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
				  "no PMD support for SFT");
		return NULL;
	} else if (queue > sh->nb_sft_queue ||
		   !data || data_len > sizeof(uint32_t)) {
		rte_sft_error_set(error, EINVAL, RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				  NULL, "invalid params");
		return NULL;
	}
	if (mlx5_sft_entry_process_hit_pattern(&ctx, error) ||
	    mlx5_sft_entry_process_hit_actions(&ctx, error))
		return NULL;
	entry = mlx5_sft_alloc_entry(&ctx, error);
	if (!entry)
		goto err0;
	if (mlx5_sft_add_l1_rules(ctx.dev, entry, ctx.data, ctx.state, error))
		goto err1;
	if (mlx5_sft_add_l0_rules(&ctx, entry, error))
		goto err2;
	mlx5_sft_entry_activate(dev, queue, entry);
	return entry;

err2:
	mlx5_flow_list_destroy(dev, MLX5_FLOW_TYPE_SFT, entry->sft_l1_flow);
err1:
	mlx5_sft_release_entry(dev, queue, entry);
err0:
	rte_free(ctx.l0_actions);
	return NULL;
}

static int
mlx5_sft_entry_destroy(struct rte_eth_dev *dev,
		       struct rte_sft_entry *entry, uint16_t queue,
		       struct rte_sft_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_dev_ctx_shared *sh = priv->sh;

	RTE_SET_USED(queue);
	if (!priv->config.sft_en)
		return rte_sft_error_set(error, ENOTSUP,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "no PMD support for SFT");
	if (entry == NULL || queue > sh->nb_sft_queue)
		return rte_sft_error_set(error, EINVAL,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
					 NULL, NULL);
	mlx5_flow_list_destroy(dev, MLX5_FLOW_TYPE_SFT, entry->sft_l0_flow);
	mlx5_flow_list_destroy(dev, MLX5_FLOW_TYPE_SFT, entry->sft_l1_flow);
	/* Entry index could be checked. */
	ILIST_REMOVE(sh->ipool_sft[queue], &priv->sft_lists[queue],
		     entry->idx, entry, next);
	mlx5_ipool_free(sh->ipool_sft[queue], entry->idx);
	return 0;
}

static int mlx5_sft_entry_decode(struct rte_eth_dev *dev, uint16_t queue,
				 const struct rte_mbuf *mbuf,
				 struct rte_sft_decode_info *info,
				 struct rte_sft_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_dev_ctx_shared *sh = priv->sh;
	union sft_mark mark;
	uint32_t meta;

	RTE_SET_USED(queue);
	if (!priv->config.sft_en) {
		info->state = 0;
		return 0;
	}
	if (mbuf == NULL || info == NULL || queue > sh->nb_sft_queue)
		return rte_sft_error_set(error, EINVAL,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
					 NULL, NULL);
	/* Datapath: MARK & METADATA are both in the host byte order. */
	mark.val = mbuf->hash.fdir.hi;
	/* Adjust the mark to the default invalid one with 0. */
	if (mark.val >= MLX5_FLOW_MARK_DEFAULT)
		mark.val = 0;
	meta = *RTE_MBUF_DYNFIELD(mbuf, rte_flow_dynf_metadata_offs,
				  uint32_t *);
	info->state = mark.val & RTE_SFT_STATE_MASK;
	/* ZONE / FID will take all the 32bits. */
	if (info->zone_valid) {
		MLX5_ASSERT(!mark.fid_valid);
		info->zone = meta;
	} else if (info->fid_valid) {
		MLX5_ASSERT(!mark.zone_valid);
		info->fid = meta;
	} else {
		MLX5_ASSERT(meta == 0);
		info->fid = 0;
	}
	return 0;
}

static int
mlx5_sft_entry_modify(struct rte_eth_dev *dev, uint16_t queue,
		      struct rte_sft_entry *entry,
		      const uint32_t *data, uint16_t data_len,
		      uint8_t state, struct rte_sft_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	uint32_t l1_flow;
	int ret;

	RTE_SET_USED(queue);
	if (!priv->config.sft_en)
		return rte_sft_error_set(error, ENOTSUP,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "no PMD support for SFT");
	if (!data || data_len > sizeof(int))
		return rte_sft_error_set(error, EINVAL,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "invalid data");
	l1_flow = entry->sft_l1_flow;
	if (!mlx5_sft_add_l1_rules(dev, entry, rte_cpu_to_be_32(*data),
				   state, error)) {
		mlx5_flow_list_destroy(dev, MLX5_FLOW_TYPE_SFT, l1_flow);
		ret = 0;
	} else {
		entry->sft_l1_flow = l1_flow;
		ret = rte_sft_error_set(error, rte_errno,
					RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					"failed to create modified flows");
	}

	return ret;
}

static void
mlx5_sft_dbg_fid_flow(const struct rte_eth_dev *dev,
		      struct rte_sft_entry *entry,
		      const struct rte_flow_action query_action[],
		      const char *direction)
{
	int ret;
	struct rte_flow_query_count count_data;
	struct rte_flow_error flow_error;

	printf("[%s] SFT FLOW %u L0: ", direction, entry->fid);
	memset(&count_data, 0, sizeof(count_data));
	ret = mlx5_flow_query(dev, entry->sft_l0_flow, MLX5_FLOW_TYPE_SFT,
			query_action, &count_data, &flow_error);
	if (!ret)
		printf("hits: %" PRIu64 "\n", count_data.hits);
	printf("[%s] SFT FLOW %u L1: ", direction, entry->fid);
	memset(&count_data, 0, sizeof(count_data));
	ret = mlx5_flow_query(dev, entry->sft_l1_flow, MLX5_FLOW_TYPE_SFT,
			query_action, &count_data, &flow_error);
	if (!ret)
		printf("hits: %" PRIu64 "\n", count_data.hits);
}

static void
mlx5_sft_debug(const struct rte_eth_dev *dev, struct rte_sft_entry *entry[2],
	       struct rte_sft_error *error)
{
	uint32_t i, ret;
	const struct mlx5_priv *priv = dev->data->dev_private;
	const struct rte_flow_action query_action[] = {
		[0] = { .type = RTE_FLOW_ACTION_TYPE_COUNT },
		[1] = { .type = RTE_FLOW_ACTION_TYPE_END },
	};
	uint32_t flow;
	const char *l0_flow_names[MLX5_SFT_L0_DFLT_FLOWS_NUM] = {
		"default miss",
		"ipv4 fragment",
		"ipv6 fragment"
	};
	struct rte_flow_query_count count_data;
	struct rte_flow_error flow_error;

	RTE_SET_USED(error);
	mlx5_sft_dbg_fid_flow(dev, entry[0], query_action, "I");
	mlx5_sft_dbg_fid_flow(dev, entry[1], query_action, "R");
	printf("SFT DEFAULT L0 flows:\n");
	for (i = 0; i < MLX5_SFT_L0_DFLT_FLOWS_NUM; i++) {
		flow = priv->sft_flows->l0_flows[i];
		if (!flow) {
			printf("  [%u]:%s: empty\n", i, l0_flow_names[i]);
			continue;
		}
		memset(&count_data, 0, sizeof(count_data));
		ret = mlx5_flow_query(dev, flow, MLX5_FLOW_TYPE_SFT,
				query_action, &count_data, &flow_error);
		if (!ret) {
			printf("  [%u]:%s:hits: %" PRIu64 "\n",
				i, l0_flow_names[i], count_data.hits);
		} else {
			printf("  [%u]:%s: failed to query err=%d %s\n",
			       i, l0_flow_names[i], rte_errno,
			       flow_error.message);
		}
	}
	printf("SFT DEFAULT L1 flows:\n");
	flow = priv->sft_flows->l1_flow;
	if (flow) {
		memset(&count_data, 0, sizeof(count_data));
		ret = mlx5_flow_query(dev, flow, MLX5_FLOW_TYPE_SFT,
				query_action, &count_data, &flow_error);
		if (!ret) {
			printf("  [%u]:%s: hits: %" PRIu64 "\n",
			       0, "default_miss", count_data.hits);
		} else {
			printf("  [%u]:%s: failed to query err=%d %s\n",
			       0, "default_miss", rte_errno,
			       flow_error.message);
		}
	} else {
		printf("  [%u]:%s: empty\n", 0, "default_miss");
	}
}

static int
mlx5_sft_query(const struct rte_eth_dev *dev, uint16_t queue,
	       struct rte_sft_entry *entry, struct rte_flow_query_count *data,
		   struct rte_sft_error *error)
{
	struct rte_flow_action query_action[] = {
		[0] = { .type = RTE_FLOW_ACTION_TYPE_COUNT },
		[1] = { .type = RTE_FLOW_ACTION_TYPE_END },
	};
	RTE_SET_USED(queue);
	RTE_SET_USED(error);

	return mlx5_flow_query(dev, entry->sft_l0_flow, MLX5_FLOW_TYPE_SFT,
			query_action, data, NULL);
}

static const struct rte_sft_ops mlx5_sft_ops = {
	.sft_start = mlx5_sft_start,
	.sft_stop = mlx5_sft_stop,
	.sft_create_entry = mlx5_sft_entry_create,
	.sft_entry_modify = mlx5_sft_entry_modify,
	.sft_entry_destroy = mlx5_sft_entry_destroy,
	.sft_entry_decode = mlx5_sft_entry_decode,
	.sft_query = mlx5_sft_query,
	.sft_debug = mlx5_sft_debug,
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

void
mlx5_sft_deactivate(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;

	if (priv->config.sft_en) {
		struct rte_sft_error err;
		mlx5_sft_stop(dev, &err);
	}
}
