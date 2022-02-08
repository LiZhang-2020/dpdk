#include <rte_flow.h>

#include <mlx5_malloc.h>

#include "mlx5_defs.h"
#include "mlx5_flow.h"
#include "mlx5_rx.h"
#include "mlx5_flow_os.h"

#include "mlx5dr_context.h"
#include "mlx5dr_send.h"

/* The maximum actions support in the flow. */
#define MLX5_HW_MAX_ACTS 16

/* NOP command required by DR action. */
#define MLX5_HW_NOP_MODI_HDR_ACT 2

#define MLX5_HW_INS_NOP_ACT(act_num) \
	((act_num) += MLX5_HW_NOP_MODI_HDR_ACT)

const struct mlx5_flow_driver_ops mlx5_flow_hw_drv_ops;

static uint32_t mlx5_hw_dr_ft_flag[2][MLX5DR_TABLE_TYPE_MAX] = {
	{
		MLX5DR_ACTION_FLAG_ROOT_RX,
		MLX5DR_ACTION_FLAG_ROOT_TX,
		MLX5DR_ACTION_FLAG_ROOT_FDB,
	},
	{
		MLX5DR_ACTION_FLAG_HWS_RX,
		MLX5DR_ACTION_FLAG_HWS_TX,
		MLX5DR_ACTION_FLAG_HWS_FDB,
	},
};

static int
flow_hw_q_drain(struct rte_eth_dev *dev, uint32_t queue,
		struct rte_flow_error *error);

/**
 * Generate the pattern item flags.
 * Will be used for shared RSS action.
 *
 * @param[in] items
 *   Pointer to the list of items.
 *
 * @return
 *   Item flags.
 */
static uint64_t
flow_hw_rss_item_flags_get(const struct rte_flow_item items[])
{
	uint64_t item_flags = 0;
	uint64_t last_item = 0;

	for (; items->type != RTE_FLOW_ITEM_TYPE_END; items++) {
		int tunnel = !!(item_flags & MLX5_FLOW_LAYER_TUNNEL);
		int item_type = items->type;

		switch (item_type) {
		case RTE_FLOW_ITEM_TYPE_IPV4:
			last_item = tunnel ? MLX5_FLOW_LAYER_INNER_L3_IPV4 :
					     MLX5_FLOW_LAYER_OUTER_L3_IPV4;
			break;
		case RTE_FLOW_ITEM_TYPE_IPV6:
			last_item = tunnel ? MLX5_FLOW_LAYER_INNER_L3_IPV6 :
					     MLX5_FLOW_LAYER_OUTER_L3_IPV6;
			break;
		case RTE_FLOW_ITEM_TYPE_TCP:
			last_item = tunnel ? MLX5_FLOW_LAYER_INNER_L4_TCP :
					     MLX5_FLOW_LAYER_OUTER_L4_TCP;
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			last_item = tunnel ? MLX5_FLOW_LAYER_INNER_L4_UDP :
					     MLX5_FLOW_LAYER_OUTER_L4_UDP;
			break;
		case RTE_FLOW_ITEM_TYPE_GRE:
			last_item = MLX5_FLOW_LAYER_GRE;
			break;
		case RTE_FLOW_ITEM_TYPE_NVGRE:
			last_item = MLX5_FLOW_LAYER_GRE;
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN:
			last_item = MLX5_FLOW_LAYER_VXLAN;
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN_GPE:
			last_item = MLX5_FLOW_LAYER_VXLAN_GPE;
			break;
		case RTE_FLOW_ITEM_TYPE_GENEVE:
			last_item = MLX5_FLOW_LAYER_GENEVE;
			break;
		case RTE_FLOW_ITEM_TYPE_MPLS:
			last_item = MLX5_FLOW_LAYER_MPLS;
			break;
		case RTE_FLOW_ITEM_TYPE_GTP:
			last_item = MLX5_FLOW_LAYER_GTP;
			break;
		default:
			break;
		}
		item_flags |= last_item;
	}
	return item_flags;
}

static void
flow_hw_release_jump(struct rte_eth_dev *dev, struct mlx5_hw_jump_action *jump)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_flow_group *grp;

	grp = container_of
		(jump, struct mlx5_flow_group, jump);
	mlx5_hlist_unregister(priv->sh->flow_tbls, &grp->entry);
}

static struct mlx5_hw_jump_action *
flow_hw_register_jump_action(struct rte_eth_dev *dev,
			     const struct rte_flow_attr *attr,
			     uint32_t dest_group,
			     struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_flow_attr jattr = *attr;
	struct mlx5_flow_group *grp;
	struct mlx5_flow_cb_ctx ctx = {
		.dev = dev,
		.error = error,
		.data = &jattr,
	};
	struct mlx5_list_entry *ge;

	jattr.group = dest_group;
	ge = mlx5_hlist_register(priv->sh->flow_tbls, dest_group, &ctx);
	if (!ge)
		return NULL;
	grp = container_of(ge, struct mlx5_flow_group, entry);
	return &grp->jump;
}

static void
flow_hw_rxq_flag_trim(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	unsigned int i;

	for (i = 0; i < priv->rxqs_n; ++i) {
		struct mlx5_rxq_ctrl *rxq_ctrl = mlx5_rxq_ctrl_get(dev, i);

		rxq_ctrl->flow_mark_n--;
		rxq_ctrl->rxq.mark = !!rxq_ctrl->flow_mark_n;
	}
}

static void
flow_hw_rxq_flag_set(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	unsigned int i;

	for (i = 0; i < priv->rxqs_n; ++i) {
		struct mlx5_rxq_ctrl *rxq_ctrl = mlx5_rxq_ctrl_get(dev, i);

		rxq_ctrl->rxq.mark = 1;
		rxq_ctrl->flow_mark_n++;
	}
}

static inline struct mlx5_hrxq*
flow_hw_register_tir_action(struct rte_eth_dev *dev,
			    uint32_t hws_flags,
			    const struct rte_flow_action *action)
{
	struct mlx5_flow_rss_desc rss_desc = {
		.hws_flags = hws_flags,
	};
	struct mlx5_hrxq *hrxq;

	if (action->type == RTE_FLOW_ACTION_TYPE_QUEUE) {
		const struct rte_flow_action_queue *queue = action->conf;

		rss_desc.const_q = &queue->index;
		rss_desc.queue_num = 1;
	} else {
		const struct rte_flow_action_rss *rss = action->conf;

		rss_desc.queue_num = rss->queue_num;
		rss_desc.const_q = rss->queue;
		memcpy(rss_desc.key,
		       !rss->key ? rss_hash_default_key : rss->key,
		       MLX5_RSS_HASH_KEY_LEN);
		rss_desc.key_len = MLX5_RSS_HASH_KEY_LEN;
		rss_desc.types = !rss->types ? ETH_RSS_IP : rss->types;
		flow_dv_hashfields_set(0, &rss_desc, &rss_desc.hash_fields);
		flow_dv_action_rss_l34_hash_adjust(rss->types,
						   &rss_desc.hash_fields);
		if (rss->level > 1) {
			rss_desc.hash_fields |= IBV_RX_HASH_INNER;
			rss_desc.tunnel = 1;
		}
	}
	hrxq = mlx5_hrxq_get(dev, &rss_desc);
	return hrxq;
}

static void
__flow_hw_action_template_destroy(struct rte_eth_dev *dev,
				 struct mlx5_hw_actions *acts)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_action_construct_data *data;

	while (!LIST_EMPTY(&acts->act_list)) {
		data = LIST_FIRST(&acts->act_list);
		LIST_REMOVE(data, next);
		mlx5_ipool_free(priv->acts_ipool, data->idx);
	}
	if (acts->jump) {
		flow_hw_release_jump(dev, acts->jump);
		acts->jump = NULL;
	}
	if (acts->tir) {
		mlx5_hrxq_release(dev, acts->tir->idx);
		acts->tir = NULL;
	}
	if (acts->encap_decap) {
		if (acts->encap_decap->action)
			mlx5dr_action_destroy(acts->encap_decap->action);
		mlx5_free(acts->encap_decap);
		acts->encap_decap = NULL;
	}
}

static __rte_always_inline struct mlx5_action_construct_data *
__flow_hw_alloc_act_data(struct mlx5_priv *priv,
			 enum rte_flow_action_type type,
			 uint16_t action_src,
			 uint16_t action_dst)
{
	struct mlx5_action_construct_data *act_data;
	uint32_t idx = 0;

	act_data = mlx5_ipool_zmalloc(priv->acts_ipool, &idx);
	if (!act_data)
		return NULL;
	act_data->idx = idx;
	act_data->type = type;
	act_data->action_src = action_src;
	act_data->action_dst = action_dst;
	return act_data;
}

static __rte_always_inline int
__flow_hw_append_act_data_tag(struct mlx5_priv *priv,
			      struct mlx5_hw_actions *acts,
			      enum rte_flow_action_type type,
			      uint16_t action_src,
			      uint16_t action_dst)
{	struct mlx5_action_construct_data *act_data;

	act_data = __flow_hw_alloc_act_data(priv, type, action_src, action_dst);
	if (!act_data)
		return -1;
	LIST_INSERT_HEAD(&acts->act_list, act_data, next);
	return 0;
}

static __rte_always_inline int
__flow_hw_append_act_data_encap(struct mlx5_priv *priv,
				struct mlx5_hw_actions *acts,
				enum rte_flow_action_type type,
				uint16_t action_src,
				uint16_t action_dst,
				uint16_t encap_src,
				uint16_t encap_dst,
				uint16_t len)
{	struct mlx5_action_construct_data *act_data;

	act_data = __flow_hw_alloc_act_data(priv, type, action_src, action_dst);
	if (!act_data)
		return -1;
	act_data->encap.src = encap_src;
	act_data->encap.dst = encap_dst;
	act_data->encap.len = len;
	LIST_INSERT_HEAD(&acts->act_list, act_data, next);
	return 0;
}

static __rte_always_inline int
__flow_hw_append_act_data_hdr_modify(struct mlx5_priv *priv,
				     struct mlx5_hw_actions *acts,
				     enum rte_flow_action_type type,
				     uint16_t action_src,
				     uint16_t action_dst,
				     uint16_t sub_action_dst)
{	struct mlx5_action_construct_data *act_data;

	act_data = __flow_hw_alloc_act_data(priv, type, action_src, action_dst);
	if (!act_data)
		return -1;
	act_data->modify_header.sub_action_dst = sub_action_dst;
	LIST_INSERT_HEAD(&acts->act_list, act_data, next);
	return 0;
}

static __rte_always_inline int
__flow_hw_append_act_data_general(struct mlx5_priv *priv,
				  struct mlx5_hw_actions *acts,
				  enum rte_flow_action_type type,
				  uint16_t action_src,
				  uint16_t action_dst)
{	struct mlx5_action_construct_data *act_data;

	act_data = __flow_hw_alloc_act_data(priv, type, action_src, action_dst);
	if (!act_data)
		return -1;
	LIST_INSERT_HEAD(&acts->act_list, act_data, next);
	return 0;
}

static __rte_always_inline int
__flow_hw_append_act_data_shared_rss(struct mlx5_priv *priv,
				     struct mlx5_hw_actions *acts,
				     enum rte_flow_action_type type,
				     uint16_t action_src,
				     uint16_t action_dst,
				     uint32_t idx,
				     struct mlx5_shared_action_rss *rss)
{	struct mlx5_action_construct_data *act_data;

	act_data = __flow_hw_alloc_act_data(priv, type, action_src, action_dst);
	if (!act_data)
		return -1;
	act_data->shared_rss.level = rss->origin.level;
	act_data->shared_rss.types = !rss->origin.types ? ETH_RSS_IP :
				     rss->origin.types;
	act_data->shared_rss.idx = idx;
	LIST_INSERT_HEAD(&acts->act_list, act_data, next);
	return 0;
}

static __rte_always_inline int
flow_hw_construct_encap_item(struct rte_eth_dev *dev,
			     struct mlx5_hw_actions *acts,
			     enum rte_flow_action_type type,
			     uint16_t action_src,
			     uint16_t action_dst,
			     const struct rte_flow_item *items,
			     const struct rte_flow_item *items_m)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	size_t len, total_len = 0;
	uint32_t i = 0;

	for (; items->type != RTE_FLOW_ITEM_TYPE_END; items++, items_m++, i++) {
		len = flow_get_item_hdr_len(items->type);
		if ((!items_m->spec ||
		    memcmp(items_m->spec, items->spec, len)) &&
		    __flow_hw_append_act_data_encap(priv, acts, type,
						    action_src, action_dst, i,
						    total_len, len))
			return -1;
		total_len += len;
	}
	return 0;
}

static __rte_always_inline int
flow_hw_shared_action_translate(struct rte_eth_dev *dev,
				const struct rte_flow_action *action,
				struct mlx5_hw_actions *acts,
				uint16_t action_src,
				uint16_t action_dst)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_shared_action_rss *shared_rss;
	uint32_t act_idx = (uint32_t)(uintptr_t)action->conf;
	uint32_t type = act_idx >> MLX5_INDIRECT_ACTION_TYPE_OFFSET;
	uint32_t idx = act_idx &
		       ((1u << MLX5_INDIRECT_ACTION_TYPE_OFFSET) - 1);

	switch (type) {
	case MLX5_INDIRECT_ACTION_TYPE_RSS:
		shared_rss = mlx5_ipool_get
		  (priv->sh->ipool[MLX5_IPOOL_RSS_SHARED_ACTIONS], idx);
		if (!shared_rss || __flow_hw_append_act_data_shared_rss
		    (priv, acts,
		    (enum rte_flow_action_type)MLX5_RTE_FLOW_ACTION_TYPE_RSS,
		    action_src, action_dst, idx, shared_rss))
			return -1;
		break;
	default:
		DRV_LOG(WARNING, "Unsupported shared action type:%d", type);
		break;
	}
	return 0;
}

static int
flow_hw_actions_translate(struct rte_eth_dev *dev,
			  const struct rte_flow_table_attr *table_attr,
			  struct mlx5_hw_actions *acts,
			  struct rte_flow_action_template *at,
			  struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	const struct rte_flow_attr *attr = &table_attr->flow_attr;
	struct rte_flow_action *actions = at->actions;
	struct rte_flow_action *masks = at->masks;
	struct rte_flow_action *action_start = actions;
	enum mlx5dr_action_reformat_type refmt_type;
	const struct rte_flow_action_raw_encap *raw_encap_data;
	const struct rte_flow_item *enc_item = NULL, *enc_item_m = NULL;
	uint8_t *encap_data = NULL;
	size_t data_size = 0;
	union {
		struct mlx5_flow_dv_modify_hdr_resource act;
		uint8_t len[sizeof(struct mlx5_flow_dv_modify_hdr_resource) +
			    sizeof(struct mlx5_modification_cmd) *
			    (MLX5_MAX_MODIFY_NUM * 2 + 1)];
	} mhdr_dummy;
	struct mlx5_flow_dv_modify_hdr_resource *mhdr_act =
						&mhdr_dummy.act;
	bool actions_end = false;
	uint32_t type, i;
	uint16_t reformat_pos = MLX5_HW_MAX_ACTS, reformat_src = 0;
	uint16_t mhdr_pos = UINT16_MAX;
	int err;

	if (attr->transfer)
		type = MLX5DR_TABLE_TYPE_FDB;
	else if (attr->egress)
		type = MLX5DR_TABLE_TYPE_NIC_TX;
	else
		type = MLX5DR_TABLE_TYPE_NIC_RX;
	memset(&mhdr_dummy, 0, sizeof(mhdr_dummy));
	for (i = 0; !actions_end; actions++, masks++) {
		uint32_t jump_group;
		const struct rte_flow_action_jump *jump_m;
		const struct rte_flow_action_queue *qm;

		switch (actions->type) {
		case RTE_FLOW_ACTION_TYPE_INDIRECT:
			if (!attr->group) {
				DRV_LOG(ERR, "Indirect action is not supported in root table.");
				goto err;
			}
			if (actions->conf && masks->conf) {
				if (flow_hw_shared_action_translate
				(dev, actions, acts, actions - action_start, i))
					goto err;
			} else if (__flow_hw_append_act_data_general
					(priv, acts, actions->type,
					 actions - action_start, i)){
				goto err;
			}
			i++;
			break;
		case RTE_FLOW_ACTION_TYPE_VOID:
			break;
		case RTE_FLOW_ACTION_TYPE_MARK:
			acts->mark = true;
			if (masks->conf)
				acts->rule_acts[i].tag.value =
					mlx5_flow_mark_set
					(((const struct rte_flow_action_mark *)
					(masks->conf))->id);
			else if (__flow_hw_append_act_data_tag(priv, acts,
				actions->type, actions - action_start, i))
				goto err;
			acts->rule_acts[i++].action =
				priv->hw_tag[!!attr->group][type];
			flow_hw_rxq_flag_set(dev);
			break;
		case RTE_FLOW_ACTION_TYPE_DROP:
			acts->rule_acts[i++].action =
				priv->hw_drop[!!attr->group][type];
			break;
		case RTE_FLOW_ACTION_TYPE_JUMP:
			jump_group = ((const struct rte_flow_action_jump *)
						actions->conf)->group;
			jump_m = masks->conf;
			if (jump_m) {
				acts->jump = flow_hw_register_jump_action
						(dev, attr, jump_group, error);
				if (!acts->jump)
					goto err;
				acts->rule_acts[i].action = (!!attr->group) ?
						acts->jump->hws_action :
						acts->jump->root_action;
			} else if (__flow_hw_append_act_data_general
					(priv, acts, actions->type,
					 actions - action_start, i)){
				goto err;
			}
			i++;
			break;
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			qm = masks->conf;
			if (qm) {
				acts->tir = flow_hw_register_tir_action
				(dev,
				 mlx5_hw_dr_ft_flag[!!attr->group][type],
				 actions);
				if (!acts->tir)
					goto err;
				acts->rule_acts[i].action =
					acts->tir->action;
			} else if (__flow_hw_append_act_data_general
					(priv, acts, actions->type,
					 actions - action_start, i)) {
				goto err;
			}
			i++;
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
			if (actions->conf && masks->conf) {
				acts->tir = flow_hw_register_tir_action
				(dev,
				 mlx5_hw_dr_ft_flag[!!attr->group][type],
				 actions);
				if (!acts->tir)
					goto err;
				acts->rule_acts[i].action =
					acts->tir->action;
			} else if (__flow_hw_append_act_data_general
					(priv, acts, actions->type,
					 actions - action_start, i)) {
				goto err;
			}
			i++;
			break;
		case RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP:
			MLX5_ASSERT(reformat_pos == MLX5_HW_MAX_ACTS);
			enc_item = ((const struct rte_flow_action_vxlan_encap *)
				   actions->conf)->definition;
			enc_item_m =
				((const struct rte_flow_action_vxlan_encap *)
				 masks->conf)->definition;
			reformat_pos = i++;
			reformat_src = actions - action_start;
			refmt_type = MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L2;
			break;
		case RTE_FLOW_ACTION_TYPE_NVGRE_ENCAP:
			MLX5_ASSERT(reformat_pos == MLX5_HW_MAX_ACTS);
			enc_item = ((const struct rte_flow_action_nvgre_encap *)
				   actions->conf)->definition;
			enc_item_m =
				((const struct rte_flow_action_nvgre_encap *)
				actions->conf)->definition;
			reformat_pos = i++;
			reformat_src = actions - action_start;
			refmt_type = MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L2;
			break;
		case RTE_FLOW_ACTION_TYPE_VXLAN_DECAP:
		case RTE_FLOW_ACTION_TYPE_NVGRE_DECAP:
			MLX5_ASSERT(reformat_pos == MLX5_HW_MAX_ACTS);
			reformat_pos = i++;
			refmt_type = MLX5DR_ACTION_REFORMAT_TYPE_TNL_L2_TO_L2;
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_ENCAP:
			raw_encap_data =
				(const struct rte_flow_action_raw_encap *)
				 actions->conf;
			encap_data = raw_encap_data->data;
			data_size = raw_encap_data->size;
			if (reformat_pos != MLX5_HW_MAX_ACTS) {
				refmt_type = data_size <
				MLX5_ENCAPSULATION_DECISION_SIZE ?
				MLX5DR_ACTION_REFORMAT_TYPE_TNL_L3_TO_L2 :
				MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L3;
			} else {
				reformat_pos = i++;
				refmt_type =
				MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L2;
			}
			reformat_src = actions - action_start;
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_DECAP:
			reformat_pos = i++;
			refmt_type = MLX5DR_ACTION_REFORMAT_TYPE_TNL_L2_TO_L2;
			break;
		case RTE_FLOW_ACTION_TYPE_SET_MAC_SRC:
			if (mhdr_pos == UINT16_MAX)
				mhdr_pos = i++;
			if (__flow_hw_append_act_data_hdr_modify
				(priv, acts, actions->type,
				 actions - action_start,
				 mhdr_pos, mhdr_act->actions_num) ||
			    flow_convert_action_modify_mac
				(mhdr_act, actions, error))
				goto err;
			MLX5_HW_INS_NOP_ACT(mhdr_act->actions_num);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_MAC_DST:
			if (mhdr_pos == UINT16_MAX)
				mhdr_pos = i++;
			if (__flow_hw_append_act_data_hdr_modify
				(priv, acts, actions->type,
				 actions - action_start,
				 mhdr_pos, mhdr_act->actions_num) ||
			    flow_convert_action_modify_mac
				(mhdr_act, actions, error))
				goto err;
			MLX5_HW_INS_NOP_ACT(mhdr_act->actions_num);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC:
			if (mhdr_pos == UINT16_MAX)
				mhdr_pos = i++;
			if (__flow_hw_append_act_data_hdr_modify
				(priv, acts, actions->type,
				 actions - action_start,
				 mhdr_pos, mhdr_act->actions_num) ||
			    flow_convert_action_modify_ipv4
				(mhdr_act, actions, error))
				goto err;
			MLX5_HW_INS_NOP_ACT(mhdr_act->actions_num);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV4_DST:
			if (mhdr_pos == UINT16_MAX)
				mhdr_pos = i++;
			if (__flow_hw_append_act_data_hdr_modify
				(priv, acts, actions->type,
				 actions - action_start,
				 mhdr_pos, mhdr_act->actions_num) ||
			    flow_convert_action_modify_ipv4
				(mhdr_act, actions, error))
				goto err;
			MLX5_HW_INS_NOP_ACT(mhdr_act->actions_num);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC:
			if (mhdr_pos == UINT16_MAX)
				mhdr_pos = i++;
			if (__flow_hw_append_act_data_hdr_modify
				(priv, acts, actions->type,
				 actions - action_start,
				 mhdr_pos, mhdr_act->actions_num) ||
			    flow_convert_action_modify_ipv6
				(mhdr_act, actions, error))
				goto err;
			MLX5_HW_INS_NOP_ACT(mhdr_act->actions_num);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV6_DST:
			if (mhdr_pos == UINT16_MAX)
				mhdr_pos = i++;
			if (__flow_hw_append_act_data_hdr_modify
				(priv, acts, actions->type,
				 actions - action_start,
				 mhdr_pos, mhdr_act->actions_num) ||
			    flow_convert_action_modify_ipv6
				(mhdr_act, actions, error))
				goto err;
			MLX5_HW_INS_NOP_ACT(mhdr_act->actions_num);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_UDP_TP_SRC:
			if (mhdr_pos == UINT16_MAX)
				mhdr_pos = i++;
			if (__flow_hw_append_act_data_hdr_modify
				(priv, acts, actions->type,
				 actions - action_start,
				 mhdr_pos, mhdr_act->actions_num) ||
			    flow_convert_action_modify_tp
				(mhdr_act, actions, true, true, error))
				goto err;
			MLX5_HW_INS_NOP_ACT(mhdr_act->actions_num);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_UDP_TP_DST:
			if (mhdr_pos == UINT16_MAX)
				mhdr_pos = i++;
			if (__flow_hw_append_act_data_hdr_modify
				(priv, acts, actions->type,
				 actions - action_start,
				 mhdr_pos, mhdr_act->actions_num) ||
			    flow_convert_action_modify_tp
				(mhdr_act, actions, true, false, error))
				goto err;
			MLX5_HW_INS_NOP_ACT(mhdr_act->actions_num);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_TCP_TP_SRC:
			if (mhdr_pos == UINT16_MAX)
				mhdr_pos = i++;
			if (__flow_hw_append_act_data_hdr_modify
				(priv, acts, actions->type,
				 actions - action_start,
				 mhdr_pos, mhdr_act->actions_num) ||
			    flow_convert_action_modify_tp
				(mhdr_act, actions, false, true, error))
				goto err;
			MLX5_HW_INS_NOP_ACT(mhdr_act->actions_num);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_TCP_TP_DST:
			if (mhdr_pos == UINT16_MAX)
				mhdr_pos = i++;
			if (__flow_hw_append_act_data_hdr_modify
				(priv, acts, actions->type,
				 actions - action_start,
				 mhdr_pos, mhdr_act->actions_num) ||
			    flow_convert_action_modify_tp
				(mhdr_act, actions, false, false, error))
				goto err;
			MLX5_HW_INS_NOP_ACT(mhdr_act->actions_num);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV4_TTL:
			if (mhdr_pos == UINT16_MAX)
				mhdr_pos = i++;
			if (__flow_hw_append_act_data_hdr_modify
				(priv, acts, actions->type,
				 actions - action_start,
				 mhdr_pos, mhdr_act->actions_num) ||
			    flow_convert_action_modify_ttl
				(mhdr_act, actions, true, error))
				goto err;
			MLX5_HW_INS_NOP_ACT(mhdr_act->actions_num);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV6_HOP:
			if (mhdr_pos == UINT16_MAX)
				mhdr_pos = i++;
			if (__flow_hw_append_act_data_hdr_modify
				(priv, acts, actions->type,
				 actions - action_start,
				 mhdr_pos, mhdr_act->actions_num) ||
			    flow_convert_action_modify_ttl
				(mhdr_act, actions, false, error))
				goto err;
			MLX5_HW_INS_NOP_ACT(mhdr_act->actions_num);
			break;
		case RTE_FLOW_ACTION_TYPE_DEC_IPV4_TTL:
			if (mhdr_pos == UINT16_MAX)
				mhdr_pos = i++;
			if (flow_convert_action_modify_ttl
				(mhdr_act, NULL, true, error))
				goto err;
			MLX5_HW_INS_NOP_ACT(mhdr_act->actions_num);
			break;
		case RTE_FLOW_ACTION_TYPE_DEC_IPV6_HOP:
			if (mhdr_pos == UINT16_MAX)
				mhdr_pos = i++;
			if (flow_convert_action_modify_ttl
				(mhdr_act, NULL, false, error))
				goto err;
			MLX5_HW_INS_NOP_ACT(mhdr_act->actions_num);
			break;
		case RTE_FLOW_ACTION_TYPE_INC_TCP_SEQ:
		case RTE_FLOW_ACTION_TYPE_DEC_TCP_SEQ:
			if (mhdr_pos == UINT16_MAX)
				mhdr_pos = i++;
			if (flow_convert_action_modify_tcp_seq
					(mhdr_act, actions, error))
				goto err;
			MLX5_HW_INS_NOP_ACT(mhdr_act->actions_num);
			break;
		case RTE_FLOW_ACTION_TYPE_INC_TCP_ACK:
		case RTE_FLOW_ACTION_TYPE_DEC_TCP_ACK:
			if (mhdr_pos == UINT16_MAX)
				mhdr_pos = i++;
			if (flow_convert_action_modify_tcp_ack
					(mhdr_act, actions, error))
				goto err;
			MLX5_HW_INS_NOP_ACT(mhdr_act->actions_num);
			break;
		case RTE_FLOW_ACTION_TYPE_MODIFY_FIELD:
			if (mhdr_pos == UINT16_MAX)
				mhdr_pos = i++;
			if (__flow_hw_append_act_data_hdr_modify
				(priv, acts, actions->type,
				 actions - action_start,
				 mhdr_pos, mhdr_act->actions_num) ||
			    flow_convert_action_modify_field
					(dev, mhdr_act,
					 actions, attr, error))
				goto err;
			MLX5_HW_INS_NOP_ACT(mhdr_act->actions_num);
			break;
		case RTE_FLOW_ACTION_TYPE_DEC_TTL:
		case RTE_FLOW_ACTION_TYPE_SET_TTL:
			/* Not supported now. */
			DRV_LOG(ERR, "Please use IPV4_TTL action.");
			goto err;
		case RTE_FLOW_ACTION_TYPE_END:
			actions_end = true;
			break;
		default:
			break;
		}
	}
	if (mhdr_act->actions_num) {
		size_t mhdr_len;

		/* Remove the tail NOP action. */
		mhdr_act->actions_num -= MLX5_HW_NOP_MODI_HDR_ACT;
		mhdr_len = mhdr_act->actions_num *
			   sizeof(struct mlx5_modification_cmd);
		mhdr_act->action = mlx5dr_action_create_modify_header
				(priv->dr_ctx, mhdr_len,
				 (__be64 *)mhdr_act->actions,
				 rte_log2_u32(table_attr->nb_flows),
				 mlx5_hw_dr_ft_flag[!!attr->group][type]);
		if (!mhdr_act->action)
			goto err;
		mhdr_len += sizeof(*acts->hdr_modify);
		acts->hdr_modify = mlx5_malloc(MLX5_MEM_ZERO, mhdr_len,
					       0, SOCKET_ID_ANY);
		if (!acts->hdr_modify)
			goto err;
		memcpy(acts->hdr_modify, mhdr_act, mhdr_len);
		acts->rule_acts[mhdr_pos].action = mhdr_act->action;
		acts->hdr_modify_pos = mhdr_pos;
	}
	if (reformat_pos != MLX5_HW_MAX_ACTS) {
		uint8_t buf[MLX5_ENCAP_MAX_LEN];

		if (enc_item) {
			MLX5_ASSERT(!encap_data);
			if (flow_convert_encap_data
				(enc_item, buf, &data_size, error) ||
			    flow_hw_construct_encap_item
				(dev, acts, (action_start + reformat_src)->type,
				 reformat_src, reformat_pos,
				 enc_item, enc_item_m))
				goto err;
			encap_data = buf;
		} else if (encap_data && __flow_hw_append_act_data_encap
				(priv, acts,
				 (action_start + reformat_src)->type,
				 reformat_src, reformat_pos, 0, 0, data_size)) {
			goto err;
		}
		acts->encap_decap = mlx5_malloc(MLX5_MEM_ZERO,
				    sizeof(*acts->encap_decap) + data_size,
				    0, SOCKET_ID_ANY);
		if (!acts->encap_decap)
			goto err;
		if (data_size) {
			acts->encap_decap->data_size = data_size;
			memcpy(acts->encap_decap->data, encap_data, data_size);
		}
		acts->encap_decap->action = mlx5dr_action_create_reformat
				(priv->dr_ctx, refmt_type,
				 data_size, encap_data,
				 rte_log2_u32(table_attr->nb_flows),
				 mlx5_hw_dr_ft_flag[!!attr->group][type]);
		if (!acts->encap_decap->action)
			goto err;
		acts->rule_acts[reformat_pos].action =
						acts->encap_decap->action;
		acts->encap_decap_pos = reformat_pos;
	}
	acts->acts_num = i;
	return 0;
err:
	err = rte_errno;
	__flow_hw_action_template_destroy(dev, acts);
	return rte_flow_error_set(error, err,
				  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				  "fail to create rte table");
}

static __rte_always_inline int
flow_hw_shared_action_get(struct rte_eth_dev *dev,
			  struct mlx5_action_construct_data *act_data,
			  const uint64_t item_flags,
			  struct mlx5dr_rule_action *rule_act)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_flow_rss_desc rss_desc = { 0 };
	uint64_t hash_fields = 0;
	uint32_t hrxq_idx = 0;
	struct mlx5_hrxq *hrxq = NULL;
	int act_type = act_data->type;

	switch (act_type) {
	case MLX5_RTE_FLOW_ACTION_TYPE_RSS:
		rss_desc.level = act_data->shared_rss.level;
		rss_desc.types = act_data->shared_rss.types;
		flow_dv_hashfields_set(item_flags, &rss_desc, &hash_fields);
		hrxq_idx = flow_dv_action_rss_hrxq_lookup
			(dev, act_data->shared_rss.idx, hash_fields);
		if (hrxq_idx)
			hrxq = mlx5_ipool_get(priv->sh->ipool[MLX5_IPOOL_HRXQ],
					      hrxq_idx);
		if (hrxq) {
			rule_act->action = hrxq->action;
			return 0;
		}
		break;
	default:
		DRV_LOG(WARNING, "Unsupported shared action type:%d",
			act_data->type);
		break;
	}
	return -1;
}

static __rte_always_inline int
flow_hw_shared_action_construct(struct rte_eth_dev *dev,
				const struct rte_flow_action *action,
				struct rte_flow_table *table,
				const uint8_t it_idx,
				struct mlx5dr_rule_action *rule_act)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_action_construct_data act_data;
	struct mlx5_shared_action_rss *shared_rss;
	uint32_t act_idx = (uint32_t)(uintptr_t)action->conf;
	uint32_t type = act_idx >> MLX5_INDIRECT_ACTION_TYPE_OFFSET;
	uint32_t idx = act_idx &
		       ((1u << MLX5_INDIRECT_ACTION_TYPE_OFFSET) - 1);
	uint64_t item_flags;

	memset(&act_data, 0, sizeof(act_data));
	switch (type) {
	case MLX5_INDIRECT_ACTION_TYPE_RSS:
		act_data.type = MLX5_RTE_FLOW_ACTION_TYPE_RSS;
		shared_rss = mlx5_ipool_get
			(priv->sh->ipool[MLX5_IPOOL_RSS_SHARED_ACTIONS], idx);
		if (!shared_rss)
			return -1;
		act_data.shared_rss.idx = idx;
		act_data.shared_rss.level = shared_rss->origin.level;
		act_data.shared_rss.types = !shared_rss->origin.types ?
					    ETH_RSS_IP :
					    shared_rss->origin.types;
		item_flags = table->its[it_idx]->item_flags;
		if (flow_hw_shared_action_get
				(dev, &act_data, item_flags, rule_act))
			return -1;
		break;
	default:
		DRV_LOG(WARNING, "Unsupported shared action type:%d", type);
		break;
	}
	return 0;
}

static __rte_always_inline int
flow_hw_actions_construct(struct rte_eth_dev *dev,
			  struct mlx5_hw_q_job *job,
			  const struct mlx5_hw_actions *hw_acts,
			  const uint8_t it_idx,
			  const struct rte_flow_action actions[],
			  struct mlx5dr_rule_action *rule_acts,
			  uint32_t *acts_num)
{
	struct rte_flow_table *table = job->flow->table;
	const struct rte_flow_action *action;
	const struct rte_flow_action_raw_encap *raw_encap_data;
	const struct rte_flow_item *enc_item = NULL;
	uint8_t *buf = job->encap_data;
	struct rte_flow_attr attr = {
		.ingress = 1,
	};
	uint32_t ft_flag;
	union {
		struct mlx5_flow_dv_modify_hdr_resource act;
		uint8_t len[sizeof(struct mlx5_flow_dv_modify_hdr_resource) +
			    sizeof(struct mlx5_modification_cmd) *
			    (MLX5_MAX_MODIFY_NUM * 2 + 1)];
	} mhdr_dummy;
	struct mlx5_flow_dv_modify_hdr_resource *mhdr_act =
						&mhdr_dummy.act;
	struct mlx5_action_construct_data *act_data;

	ft_flag = mlx5_hw_dr_ft_flag[!!table->grp->group_id][table->type];
	attr.group = table->grp->group_id;
	if (table->type == MLX5DR_TABLE_TYPE_FDB) {
		attr.transfer = 1;
		attr.ingress = 1;
	} else if (table->type == MLX5DR_TABLE_TYPE_NIC_TX) {
		attr.egress = 1;
		attr.ingress = 0;
	} else {
		attr.ingress = 1;
	}
	memcpy(rule_acts, hw_acts->rule_acts,
	       sizeof(*rule_acts) * hw_acts->acts_num);
	*acts_num = hw_acts->acts_num;
	if (hw_acts->hdr_modify)
		mhdr_act->actions_num = 0;
	if (hw_acts->encap_decap && hw_acts->encap_decap->data_size)
		memcpy(buf, hw_acts->encap_decap->data,
		       hw_acts->encap_decap->data_size);
	LIST_FOREACH(act_data, &hw_acts->act_list, next) {
		uint32_t tag;
		uint32_t jump_group;
		uint64_t item_flags;
		struct mlx5_hrxq *hrxq;
		struct mlx5_hw_jump_action *jump;

		action = &actions[act_data->action_src];
		MLX5_ASSERT(action->type == RTE_FLOW_ACTION_TYPE_INDIRECT ||
			    (int)action->type == act_data->type);
		switch (act_data->type) {
		case RTE_FLOW_ACTION_TYPE_INDIRECT:
			if (flow_hw_shared_action_construct
					(dev, action, table, it_idx,
					 &rule_acts[act_data->action_dst]))
				return -1;
			break;
		case RTE_FLOW_ACTION_TYPE_MARK:
			tag = mlx5_flow_mark_set
			      (((const struct rte_flow_action_mark *)
			      (action->conf))->id);
			rule_acts[act_data->action_dst].tag.value = tag;
			break;
		case RTE_FLOW_ACTION_TYPE_JUMP:
			jump_group = ((const struct rte_flow_action_jump *)
						action->conf)->group;
			jump = flow_hw_register_jump_action
				(dev, &attr, jump_group, NULL);
			if (!jump)
				return -1;
			rule_acts[act_data->action_dst].action =
			(!!attr.group) ? jump->hws_action : jump->root_action;
			job->flow->jump = jump;
			job->flow->fate_type = MLX5_FLOW_FATE_JUMP;
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			hrxq = flow_hw_register_tir_action(dev,
					ft_flag,
					action);
			if (!hrxq)
				return -1;
			rule_acts[act_data->action_dst].action = hrxq->action;
			job->flow->hrxq = hrxq;
			job->flow->fate_type = MLX5_FLOW_FATE_QUEUE;
			break;
		case MLX5_RTE_FLOW_ACTION_TYPE_RSS:
			item_flags = table->its[it_idx]->item_flags;
			if (flow_hw_shared_action_get
				(dev, act_data, item_flags,
				 &rule_acts[act_data->action_dst]))
				return -1;
			break;
		case RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP:
			enc_item = ((const struct rte_flow_action_vxlan_encap *)
				   action->conf)->definition;
			rte_memcpy((void *)&buf[act_data->encap.dst],
				   enc_item[act_data->encap.src].spec,
				   act_data->encap.len);
			break;
		case RTE_FLOW_ACTION_TYPE_NVGRE_ENCAP:
			enc_item = ((const struct rte_flow_action_nvgre_encap *)
				   action->conf)->definition;
			rte_memcpy((void *)&buf[act_data->encap.dst],
				   enc_item[act_data->encap.src].spec,
				   act_data->encap.len);
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_ENCAP:
			raw_encap_data =
				(const struct rte_flow_action_raw_encap *)
				 action->conf;
			rte_memcpy((void *)&buf[act_data->encap.dst],
				   raw_encap_data->data, act_data->encap.len);
			MLX5_ASSERT(raw_encap_data->size ==
				    act_data->encap.len);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_MAC_SRC:
			mhdr_act->actions_num =
				act_data->modify_header.sub_action_dst;
			flow_convert_action_modify_mac
				(mhdr_act, action, NULL);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_MAC_DST:
			mhdr_act->actions_num =
				act_data->modify_header.sub_action_dst;
			flow_convert_action_modify_mac
				(mhdr_act, action, NULL);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC:
			mhdr_act->actions_num =
				act_data->modify_header.sub_action_dst;
			flow_convert_action_modify_ipv4
				(mhdr_act, action, NULL);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV4_DST:
			mhdr_act->actions_num =
				act_data->modify_header.sub_action_dst;
			flow_convert_action_modify_ipv4
				(mhdr_act, action, NULL);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC:
			mhdr_act->actions_num =
				act_data->modify_header.sub_action_dst;
			flow_convert_action_modify_ipv6
				(mhdr_act, action, NULL);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV6_DST:
			mhdr_act->actions_num =
				act_data->modify_header.sub_action_dst;
			flow_convert_action_modify_ipv6
				(mhdr_act, action, NULL);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_UDP_TP_SRC:
			mhdr_act->actions_num =
				act_data->modify_header.sub_action_dst;
			flow_convert_action_modify_tp
				(mhdr_act, action, true, true, NULL);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_UDP_TP_DST:
			mhdr_act->actions_num =
				act_data->modify_header.sub_action_dst;
			flow_convert_action_modify_tp
				(mhdr_act, action, true, false, NULL);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_TCP_TP_SRC:
			mhdr_act->actions_num =
				act_data->modify_header.sub_action_dst;
			flow_convert_action_modify_tp
				(mhdr_act, action, false, true, NULL);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_TCP_TP_DST:
			mhdr_act->actions_num =
				act_data->modify_header.sub_action_dst;
			flow_convert_action_modify_tp
				(mhdr_act, action, false, false, NULL);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV4_TTL:
			mhdr_act->actions_num =
				act_data->modify_header.sub_action_dst;
			flow_convert_action_modify_ttl
				(mhdr_act, action, true, NULL);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_IPV6_HOP:
			mhdr_act->actions_num =
				act_data->modify_header.sub_action_dst;
			flow_convert_action_modify_ttl
				(mhdr_act, action, false, NULL);
			break;
		case RTE_FLOW_ACTION_TYPE_MODIFY_FIELD:
			mhdr_act->actions_num =
				act_data->modify_header.sub_action_dst;
			flow_convert_action_modify_field
					(dev, mhdr_act, action, &attr, NULL);
			break;
		default:
			break;
		}
	}
	if (hw_acts->hdr_modify) {
		rule_acts[hw_acts->hdr_modify_pos].modify_header.offset =
					job->flow->idx - 1;
		rule_acts[hw_acts->hdr_modify_pos].modify_header.data =
					(uint8_t *)job->mhdr_cmd;
		memcpy(job->mhdr_cmd, mhdr_act->actions,
		       sizeof(*job->mhdr_cmd) * mhdr_act->actions_num);
	}
	if (hw_acts->encap_decap) {
		rule_acts[hw_acts->encap_decap_pos].reformat.offset =
				job->flow->idx - 1;
		rule_acts[hw_acts->encap_decap_pos].reformat.data = buf;
	}
	return 0;
}

static struct rte_flow *
flow_hw_q_flow_create(struct rte_eth_dev *dev,
		      uint32_t queue,
		      const struct rte_flow_q_ops_attr *attr,
		      struct rte_flow_table *table,
		      const struct rte_flow_item items[],
		      uint8_t item_template_index,
		      const struct rte_flow_action actions[],
		      uint8_t action_template_index,
		      struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5dr_rule_attr rule_attr = {
		.queue_id = queue,
		.user_data = attr->user_data,
		.burst = !attr->drain,
	};
	struct mlx5dr_rule_action rule_acts[MLX5_HW_MAX_ACTS];
	struct mlx5_hw_actions *hw_acts;
	struct rte_flow_hw *flow;
	struct mlx5_hw_q_job *job;
	uint32_t acts_num, flow_idx;
	int ret;

	if (unlikely(!priv->hw_q[queue].job_idx)) {
		rte_errno = ENOMEM;
		goto error;
	}
	flow = mlx5_ipool_zmalloc(table->flow, &flow_idx);
	if (!flow)
		goto error;
	flow->table = table;
	flow->idx = flow_idx;
	job = priv->hw_q[queue].job[--priv->hw_q[queue].job_idx];
	job->type = MLX5_HW_Q_JOB_TYPE_CREATE;
	job->flow = flow;
	job->user_data = attr->user_data;
	hw_acts = &table->ats[action_template_index].acts;
	/* Construct the flow actions based on the input actions.*/
	if (flow_hw_actions_construct(dev, job, hw_acts, item_template_index,
				  actions, rule_acts, &acts_num)) {
		rte_errno = EINVAL;
		goto free;
	}
	rule_attr.user_data = job;
	ret = mlx5dr_rule_create(table->matcher,
				 item_template_index, items,
				 rule_acts, acts_num,
				 &rule_attr, &flow->rule);
	if (likely(!ret))
		return (struct rte_flow *)flow;
free:
	/* Flow created fail, return the descriptor and flow memory. */
	mlx5_ipool_free(table->flow, flow_idx);
	priv->hw_q[queue].job[priv->hw_q[queue].job_idx++] = job;
error:
	rte_flow_error_set(error, rte_errno,
			   RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			   "fail to create rte flow");
	return NULL;
}

static int
flow_hw_q_flow_destroy(struct rte_eth_dev *dev,
		       uint32_t queue,
		       const struct rte_flow_q_ops_attr *attr,
		       struct rte_flow *flow,
		       struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5dr_rule_attr rule_attr = {
		.queue_id = queue,
		.user_data = attr->user_data,
		.burst = !attr->drain,
	};
	struct rte_flow_hw *fh = (struct rte_flow_hw *)flow;
	struct mlx5_hw_q_job *job;
	int ret;

	if (unlikely(!priv->hw_q[queue].job_idx)) {
		rte_errno = ENOMEM;
		goto error;
	}
	job = priv->hw_q[queue].job[--priv->hw_q[queue].job_idx];
	job->type = MLX5_HW_Q_JOB_TYPE_DESTROY;
	job->user_data = attr->user_data;
	job->flow = fh;
	rule_attr.user_data = job;
	ret = mlx5dr_rule_destroy(&fh->rule, &rule_attr);
	if (ret)
		goto error;
	return 0;
error:
	return rte_flow_error_set(error, rte_errno,
			RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			"fail to create rte flow");
}

static int
flow_hw_q_dequeue(struct rte_eth_dev *dev,
		  uint32_t queue,
		  struct rte_flow_q_op_res res[],
		  uint16_t n_res,
		  struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_hw_q_job *job;
	int ret, i;

	ret = mlx5dr_send_queue_poll(priv->dr_ctx, queue, res, n_res);
	if (ret < 0)
		return rte_flow_error_set(error, rte_errno,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				"fail to query flow queue");
	for (i = 0; i <  ret; i++) {
		job = (struct mlx5_hw_q_job *)res[i].user_data;
		/* Restore user data. */
		res[i].user_data = job->user_data;
		if (job->type == MLX5_HW_Q_JOB_TYPE_DESTROY) {
			if (job->flow->fate_type == MLX5_FLOW_FATE_QUEUE)
				mlx5_hrxq_obj_release(dev, job->flow->hrxq);
			else if (job->flow->fate_type == MLX5_FLOW_FATE_JUMP)
				flow_hw_release_jump(dev, job->flow->jump);
			mlx5_ipool_free(job->flow->table->flow, job->flow->idx);
		}
		priv->hw_q[queue].job[priv->hw_q[queue].job_idx++] = job;
	}
	return ret;
}

static int
__flow_hw_drain_comp(struct rte_eth_dev *dev,
		     uint32_t queue,
		     uint32_t pending_rules,
		     struct rte_flow_error *error)
{
#define BURST_THR 32u
	struct rte_flow_q_op_res comp[BURST_THR];
	int ret, i, empty_loop = 0;

	flow_hw_q_drain(dev, queue, error);
	while (pending_rules) {
		ret = flow_hw_q_dequeue(dev, 0, comp, BURST_THR, error);
		if (ret < 0)
			return -1;
		if (!ret) {
			usleep(200);
			if (++empty_loop > 5) {
				DRV_LOG(WARNING, "No available dequeue, quit.");
				break;
			}
			continue;
		}
		for (i = 0; i < ret; i++) {
			if (comp[i].status == RTE_FLOW_Q_OP_ERROR)
				DRV_LOG(WARNING, "Flow flush get error CQE.");
		}
		if ((uint32_t)ret > pending_rules) {
			DRV_LOG(WARNING, "Flow flush get extra CQE.");
			return -1;
		}
		pending_rules -= ret;
		empty_loop = 0;
	}
	return 0;
}

int
flow_hw_q_flow_flush(struct rte_eth_dev *dev,
		     struct rte_flow_error *error)
{
#define DEFAULT_QUEUE 0
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_hw_q *hw_q;
	struct rte_flow_table *tbl;
	struct rte_flow_hw *flow;
	struct rte_flow_q_ops_attr attr = {
		.drain = 1,
	};
	uint32_t pending_rules = 0;
	uint32_t queue;
	uint32_t fidx;

	/*
	 * Ensure to drain and dequeue all the enqueued flows in case user
	 * forgot to dequeue. Or the enqueued created flows will be leaked.
	 * The forgot dequeue will also cause flow flush get extra CQEs as
	 * expected and pending_rules be minus value.
	 */
	for (queue = 0; queue < priv->nb_queues; queue++) {
		hw_q = &priv->hw_q[queue];
		if (__flow_hw_drain_comp(dev, queue, hw_q->size - hw_q->job_idx,
					 error))
			return -1;
	}
	/* Flush flow per-table from DEFAULT_QUEUE. */
	hw_q = &priv->hw_q[DEFAULT_QUEUE];
	LIST_FOREACH(tbl, &priv->flow_hw_tbl, next) {
		MLX5_IPOOL_FOREACH(tbl->flow, fidx, flow) {
			if (flow_hw_q_flow_destroy(dev, DEFAULT_QUEUE, &attr,
						   (struct rte_flow *)flow,
						   error))
				return -1;
			pending_rules++;
			/* Drain completion with queue size. */
			if (pending_rules >= hw_q->size) {
				if (__flow_hw_drain_comp(dev, DEFAULT_QUEUE,
							 pending_rules, error))
					return -1;
				pending_rules = 0;
			}
		}
	}
	/* Drain left completion. */
	if (pending_rules &&
	    __flow_hw_drain_comp(dev, DEFAULT_QUEUE, pending_rules,
				 error))
		return -1;
	return 0;
}

static int
flow_hw_q_drain(struct rte_eth_dev *dev,
		uint32_t queue,
		struct rte_flow_error *error __rte_unused)
{
	struct mlx5_priv *priv = dev->data->dev_private;

	return mlx5dr_send_queue_action(priv->dr_ctx, queue,
					MLX5DR_SEND_QUEUE_ACTION_DRAIN);
}

static struct rte_flow_table *
flow_hw_table_create(struct rte_eth_dev *dev,
		     const struct rte_flow_table_attr *attr,
		     struct rte_flow_item_template *item_templates[],
		     uint8_t nb_item_templates,
		     struct rte_flow_action_template *action_templates[],
		     uint8_t nb_action_templates,
		     struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5dr_matcher_attr matcher_attr = {0};
	struct rte_flow_table *tbl = NULL;
	struct mlx5_flow_group *grp;
	struct mlx5dr_match_template *mt[MLX5_HW_TBL_MAX_ITEM_TEMPLATE];
	struct rte_flow_attr flow_attr = attr->flow_attr;
	struct mlx5_flow_cb_ctx ctx = {
		.dev = dev,
		.error = error,
		.data = &flow_attr,
	};
	struct mlx5_indexed_pool_config cfg = {
		.size = sizeof(struct rte_flow_hw),
		.trunk_size = 1 << 12,
		.per_core_cache = 1 << 13,
		.need_lock = 1,
		.release_mem_en = !!priv->config.reclaim_mode,
		.malloc = mlx5_malloc,
		.free = mlx5_free,
		.type = "mlx5_hw_table_flow",
	};
	struct mlx5_list_entry *ge;
	uint32_t i, max_tpl = MLX5_HW_TBL_MAX_ITEM_TEMPLATE;
	uint32_t nb_flows = rte_align32pow2(attr->nb_flows);
	int err;

	if (!attr->flow_attr.group)
		max_tpl = 1;
	cfg.max_idx = nb_flows;
	if (nb_flows < cfg.trunk_size) {
		cfg.per_core_cache = nb_flows >> 2;
		cfg.trunk_size = nb_flows;
	}
	if (nb_item_templates > max_tpl ||
	    nb_action_templates > MLX5_HW_TBL_MAX_ACTION_TEMPLATE) {
		rte_errno = EINVAL;
		goto error;
	}
	/* Allocate the table memory. */
	tbl = mlx5_malloc(MLX5_MEM_ZERO, sizeof(*tbl), 0, SOCKET_ID_ANY);
	if (!tbl)
		goto error;
	/* Allocate flow indexed pool. */
	tbl->flow = mlx5_ipool_create(&cfg);
	if (!tbl->flow)
		goto error;
	/* Register the flow table. */
	ge = mlx5_hlist_register(priv->sh->groups, attr->flow_attr.group, &ctx);
	if (!ge)
		goto error;
	grp = container_of(ge, struct mlx5_flow_group, entry);
	tbl->grp = grp;
	/* Prepare matcher information. */
	matcher_attr.priority = attr->flow_attr.priority;
	matcher_attr.mode = MLX5DR_MATCHER_RESOURCE_MODE_RULE;
	matcher_attr.rule.num_log = rte_log2_u32(nb_flows);
	/* Build the item template. */
	for (i = 0; i < nb_item_templates; i++) {
		uint32_t ret;

		ret = __atomic_add_fetch(&item_templates[i]->refcnt, 1,
					 __ATOMIC_RELAXED);
		if (ret <= 1) {
			rte_errno = EINVAL;
			goto it_error;
		}
		mt[i] = item_templates[i]->mt;
		tbl->its[i] = item_templates[i];
	}
	tbl->matcher = mlx5dr_matcher_create
		(tbl->grp->tbl, mt, nb_item_templates, &matcher_attr);
	if (!tbl->matcher)
		goto it_error;
	tbl->nb_item_templates = nb_item_templates;
	/* Build the action template. */
	for (i = 0; i < nb_action_templates; i++) {
		uint32_t ret;

		ret = __atomic_add_fetch(&action_templates[i]->refcnt, 1,
					 __ATOMIC_RELAXED);
		if (ret <= 1) {
			rte_errno = EINVAL;
			goto at_error;
		}
		LIST_INIT(&tbl->ats[i].acts.act_list);
		err = flow_hw_actions_translate(dev, attr,
						&tbl->ats[i].acts,
						action_templates[i], error);
		if (err)
			goto at_error;
		tbl->ats[i].action_template = action_templates[i];
	}
	tbl->nb_action_templates = nb_action_templates;
	tbl->type = attr->flow_attr.transfer ? MLX5DR_TABLE_TYPE_FDB :
		    (attr->flow_attr.egress ? MLX5DR_TABLE_TYPE_NIC_TX :
		    MLX5DR_TABLE_TYPE_NIC_RX);
	LIST_INSERT_HEAD(&priv->flow_hw_tbl, tbl, next);
	return tbl;
at_error:
	while (i--) {
		__flow_hw_action_template_destroy(dev, &tbl->ats[i].acts);
		__atomic_sub_fetch(&action_templates[i]->refcnt,
				   1, __ATOMIC_RELAXED);
	}
	i = nb_item_templates;
it_error:
	while (i--)
		__atomic_sub_fetch(&item_templates[i]->refcnt,
				   1, __ATOMIC_RELAXED);
	if (tbl->matcher)
		mlx5dr_matcher_destroy(tbl->matcher);
error:
	err = rte_errno;
	if (tbl) {
		if (tbl->grp)
			mlx5_hlist_unregister(priv->sh->groups,
					      &tbl->grp->entry);
		if (tbl->flow)
			mlx5_ipool_destroy(tbl->flow);
		mlx5_free(tbl);
	}
	rte_flow_error_set(error, err,
			  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			  "fail to create rte table");
	return NULL;
}

static int
flow_hw_table_destroy(struct rte_eth_dev *dev,
		      struct rte_flow_table *table,
		      struct rte_flow_error *error __rte_unused)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	int i;

	if (table->refcnt)
		DRV_LOG(WARNING, "Table %p is still in use.", (void *)table);
	LIST_REMOVE(table, next);
	for (i = 0; i < table->nb_item_templates; i++)
		__atomic_sub_fetch(&table->its[i]->refcnt,
				   1, __ATOMIC_RELAXED);
	for (i = 0; i < table->nb_action_templates; i++) {
		if (table->ats[i].acts.mark)
			flow_hw_rxq_flag_trim(dev);
		__flow_hw_action_template_destroy(dev, &table->ats[i].acts);
		__atomic_sub_fetch(&table->ats[i].action_template->refcnt,
				   1, __ATOMIC_RELAXED);
	}
	mlx5dr_matcher_destroy(table->matcher);
	mlx5_hlist_unregister(priv->sh->groups, &table->grp->entry);
	mlx5_ipool_destroy(table->flow);
	mlx5_free(table);
	return 0;
}

static struct rte_flow_action_template *
flow_hw_action_template_create(struct rte_eth_dev *dev,
			       const struct rte_flow_action_template_attr *attr,
			       const struct rte_flow_action actions[],
			       const struct rte_flow_action masks[],
			       struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	int len, act_len, mask_len, i;
	struct rte_flow_action_template *at;

	act_len = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS,
				NULL, 0, actions, error);
	if (act_len <= 0)
		return NULL;
	len = RTE_ALIGN(act_len, 16);
	mask_len = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS,
				 NULL, 0, masks, error);
	if (mask_len <= 0)
		return NULL;

	len += RTE_ALIGN(mask_len, 16);
	at = mlx5_malloc(MLX5_MEM_ZERO | MLX5_MEM_SYS, len + sizeof(*at),
			 64, SOCKET_ID_ANY);
	if (!at) {
		rte_flow_error_set(error, ENOMEM,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "cannot allocate action template");
		return NULL;
	}
	at->attr = *attr;
	at->actions = (struct rte_flow_action *)(at + 1);
	act_len = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS, at->actions, len,
				actions, error);
	if (act_len <= 0)
		goto error;
	at->masks = (struct rte_flow_action *)
		    (((uint8_t *)at->actions) + act_len);
	mask_len = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS, at->masks,
				 len - act_len, masks, error);
	if (mask_len <= 0)
		goto error;
	for (i = 0; actions->type != RTE_FLOW_ACTION_TYPE_END;
	     actions++, masks++, i++) {
		if (actions->type == RTE_FLOW_ACTION_TYPE_INDIRECT) {
			at->actions[i].conf = actions->conf;
			at->masks[i].conf = masks->conf;
		}
	}
	__atomic_fetch_add(&at->refcnt, 1, __ATOMIC_RELAXED);
	LIST_INSERT_HEAD(&priv->flow_hw_at, at, next);
	return at;
error:
	mlx5_free(at);
	return NULL;
}

static int
flow_hw_action_template_destroy(struct rte_eth_dev *dev __rte_unused,
				struct rte_flow_action_template *template,
				struct rte_flow_error *error __rte_unused)
{
	if (__atomic_load_n(&template->refcnt, __ATOMIC_RELAXED) > 1)
		DRV_LOG(WARNING, "Acts template %p is still in use.",
			(void *)template);
	LIST_REMOVE(template, next);
	mlx5_free(template);
	return 0;
}

static struct rte_flow_item_template *
flow_hw_item_template_create(struct rte_eth_dev *dev,
			     const struct rte_flow_item_template_attr *attr,
			     const struct rte_flow_item items[],
			     struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_flow_item_template *it;

	it = mlx5_malloc(MLX5_MEM_ZERO, sizeof(*it), 0, SOCKET_ID_ANY);
	if (!it) {
		rte_flow_error_set(error, ENOMEM,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "cannot allocate item template");
		return NULL;
	}
	it->attr = *attr;
	it->mt = mlx5dr_match_template_create(items, attr->relaxed_matching);
	if (!it->mt) {
		mlx5_free(it);
		return NULL;
	}
	it->item_flags = flow_hw_rss_item_flags_get(items);
	__atomic_fetch_add(&it->refcnt, 1, __ATOMIC_RELAXED);
	LIST_INSERT_HEAD(&priv->flow_hw_itt, it, next);
	return it;
}

static int
flow_hw_item_template_destroy(struct rte_eth_dev *dev __rte_unused,
			      struct rte_flow_item_template *template,
			      struct rte_flow_error *error __rte_unused)
{
	if (__atomic_load_n(&template->refcnt, __ATOMIC_RELAXED) > 1)
		DRV_LOG(WARNING, "Item template %p is still in use.",
			(void *)template);
	LIST_REMOVE(template, next);
	mlx5dr_match_template_destroy(template->mt);
	mlx5_free(template);
	return 0;
}

struct mlx5_list_entry *
flow_hw_grp_create_cb(void *tool_ctx, void *cb_ctx)
{
	struct mlx5_dev_ctx_shared *sh = tool_ctx;
	struct mlx5_flow_cb_ctx *ctx = cb_ctx;
	struct rte_eth_dev *dev = ctx->dev;
	struct rte_flow_attr *attr = (struct rte_flow_attr *)ctx->data;
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5dr_table_attr dr_tbl_attr = {0};
	struct rte_flow_error *error = ctx->error;
	struct mlx5_flow_group *grp_data;
	struct mlx5dr_table *tbl = NULL;
	struct mlx5dr_action *jump;
	uint32_t idx = 0;

	grp_data = mlx5_ipool_zmalloc(sh->ipool[MLX5_IPOOL_HW_GRP], &idx);
	if (!grp_data) {
		rte_flow_error_set(error, ENOMEM,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "cannot allocate flow table data entry");
		return NULL;
	}
	dr_tbl_attr.level = attr->group;
	if (attr->transfer)
		dr_tbl_attr.type = MLX5DR_TABLE_TYPE_FDB;
	else if (attr->egress)
		dr_tbl_attr.type = MLX5DR_TABLE_TYPE_NIC_TX;
	else
		dr_tbl_attr.type = MLX5DR_TABLE_TYPE_NIC_RX;
	tbl = mlx5dr_table_create(priv->dr_ctx, &dr_tbl_attr);
	if (!tbl)
		goto error;
	grp_data->tbl = tbl;
	if (attr->group) {
		jump = mlx5dr_action_create_dest_table
			(priv->dr_ctx, tbl,
			 mlx5_hw_dr_ft_flag[!!attr->group][dr_tbl_attr.type]);
		if (!jump)
			goto error;
		grp_data->jump.hws_action = jump;
		jump = mlx5dr_action_create_dest_table
			(priv->dr_ctx, tbl,
			 mlx5_hw_dr_ft_flag[0][dr_tbl_attr.type]);
		if (!jump)
			goto error;
		grp_data->jump.root_action = jump;
	}
	grp_data->idx = idx;
	grp_data->group_id = attr->group;
	grp_data->type = dr_tbl_attr.type;
	return &grp_data->entry;
error:
	if (grp_data->jump.root_action)
		mlx5dr_action_destroy(grp_data->jump.root_action);
	if (grp_data->jump.hws_action)
		mlx5dr_action_destroy(grp_data->jump.hws_action);
	if (tbl)
		mlx5dr_table_destroy(tbl);
	if (idx)
		mlx5_ipool_free(sh->ipool[MLX5_IPOOL_HW_GRP], idx);
	rte_flow_error_set(error, ENOMEM,
			   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
			   NULL,
			   "cannot allocate flow dr table");
	return NULL;
}

void
flow_hw_grp_remove_cb(void *tool_ctx, struct mlx5_list_entry *entry)
{
	struct mlx5_dev_ctx_shared *sh = tool_ctx;
	struct mlx5_flow_group *grp_data =
		    container_of(entry, struct mlx5_flow_group, entry);

	MLX5_ASSERT(entry && sh);
	/* To use the wrapper glue functions instead. */
	if (grp_data->jump.hws_action)
		mlx5dr_action_destroy(grp_data->jump.hws_action);
	if (grp_data->jump.root_action)
		mlx5dr_action_destroy(grp_data->jump.root_action);
	mlx5dr_table_destroy(grp_data->tbl);
	mlx5_ipool_free(sh->ipool[MLX5_IPOOL_HW_GRP], grp_data->idx);
}

int
flow_hw_grp_match_cb(void *tool_ctx __rte_unused, struct mlx5_list_entry *entry,
		     void *cb_ctx)
{
	struct mlx5_flow_cb_ctx *ctx = cb_ctx;
	struct mlx5_flow_group *grp_data =
		container_of(entry, struct mlx5_flow_group, entry);
	struct rte_flow_attr *attr =
			(struct rte_flow_attr *)ctx->data;

	return (grp_data->group_id != attr->group) ||
		((grp_data->type != MLX5DR_TABLE_TYPE_FDB) &&
		attr->transfer) ||
		((grp_data->type != MLX5DR_TABLE_TYPE_NIC_TX) &&
		attr->egress) ||
		((grp_data->type != MLX5DR_TABLE_TYPE_NIC_RX) &&
		attr->ingress);
}

struct mlx5_list_entry *
flow_hw_grp_clone_cb(void *tool_ctx, struct mlx5_list_entry *oentry,
		     void *cb_ctx)
{
	struct mlx5_dev_ctx_shared *sh = tool_ctx;
	struct mlx5_flow_cb_ctx *ctx = cb_ctx;
	struct mlx5_flow_group *grp_data;
	struct rte_flow_error *error = ctx->error;
	uint32_t idx = 0;

	grp_data = mlx5_ipool_malloc(sh->ipool[MLX5_IPOOL_HW_GRP], &idx);
	if (!grp_data) {
		rte_flow_error_set(error, ENOMEM,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "cannot allocate flow table data entry");
		return NULL;
	}
	memcpy(grp_data, oentry, sizeof(*grp_data));
	grp_data->idx = idx;
	return &grp_data->entry;
}

void
flow_hw_grp_clone_free_cb(void *tool_ctx, struct mlx5_list_entry *entry)
{
	struct mlx5_dev_ctx_shared *sh = tool_ctx;
	struct mlx5_flow_group *grp_data =
		    container_of(entry, struct mlx5_flow_group, entry);

	mlx5_ipool_free(sh->ipool[MLX5_IPOOL_HW_GRP], grp_data->idx);
}

static int
flow_hw_configure(struct rte_eth_dev *dev,
		  const struct rte_flow_port_attr *port_attr,
		  const struct rte_flow_queue_attr *queue_attr[],
		  struct rte_flow_error *err)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5dr_context *dr_ctx = NULL;
	struct mlx5dr_context_attr dr_ctx_attr = {0};
	struct mlx5_hw_q_job *job = NULL;
	uint32_t mem_size, i, j;
	struct mlx5_indexed_pool_config cfg = {
		.size = sizeof(struct rte_flow_hw),
		.trunk_size = 4096,
		.need_lock = 1,
		.release_mem_en = !!priv->config.reclaim_mode,
		.malloc = mlx5_malloc,
		.free = mlx5_free,
		.type = "mlx5_hw_action_construct_data",
	};

	if (!port_attr || !port_attr->nb_queues || !queue_attr) {
		rte_errno = EINVAL;
		goto err;
	}
	dr_ctx_attr.pd = priv->sh->cdev->pd;
	dr_ctx_attr.queues = port_attr->nb_queues;
	/* TODO: Should configure the queue size individually.*/
	dr_ctx_attr.queue_size = queue_attr[0]->size;
	dr_ctx = mlx5dr_context_open(priv->sh->cdev->ctx, &dr_ctx_attr);
	if (!dr_ctx)
		goto err;
	priv->dr_ctx = dr_ctx;
	priv->acts_ipool = mlx5_ipool_create(&cfg);
	if (!priv->acts_ipool)
		goto err;
	/* Allocate the queue job descriptor LIFO. */
	mem_size = sizeof(priv->hw_q[0]) * port_attr->nb_queues;
	for (i = 0; i < port_attr->nb_queues; i++)
		mem_size += (sizeof(struct mlx5_hw_q_job *) +
			    sizeof(struct mlx5_hw_q_job) +
			    sizeof(uint8_t) * MLX5_ENCAP_MAX_LEN +
			    sizeof(struct mlx5_modification_cmd) *
			    MLX5_MHDR_MAX_CMD) *
			    queue_attr[0]->size;
	priv->hw_q = mlx5_malloc(MLX5_MEM_ZERO, mem_size,
				 64, SOCKET_ID_ANY);
	if (!priv->hw_q) {
		rte_errno = ENOMEM;
		goto err;
	}
	priv->nb_queues = port_attr->nb_queues;
	for (i = 0; i < port_attr->nb_queues; i++) {
		uint8_t *encap = NULL;
		struct mlx5_modification_cmd *mhdr_cmd = NULL;

		priv->hw_q[i].job_idx = queue_attr[i]->size;
		priv->hw_q[i].size = queue_attr[i]->size;
		LIST_INIT(&priv->hw_q[i].flow_list);
		if (i == 0)
			priv->hw_q[i].job = (struct mlx5_hw_q_job **)
					    &priv->hw_q[port_attr->nb_queues];
		else
			priv->hw_q[i].job = (struct mlx5_hw_q_job **)
				&job[queue_attr[i - 1]->size - 1].encap_data
				 [MLX5_ENCAP_MAX_LEN];
		job = (struct mlx5_hw_q_job *)
		      &priv->hw_q[i].job[queue_attr[i]->size];
		mhdr_cmd = (struct mlx5_modification_cmd *)
			   &job[queue_attr[i]->size];
		encap = (uint8_t *)
			 &mhdr_cmd[queue_attr[i]->size * MLX5_MHDR_MAX_CMD];
		for (j = 0; j < queue_attr[i]->size; j++) {
			job[j].mhdr_cmd = &mhdr_cmd[j * MLX5_MHDR_MAX_CMD];
			job[j].encap_data = &encap[j * MLX5_ENCAP_MAX_LEN];
			priv->hw_q[i].job[j] = &job[j];
		}
	}
	/* Add global actions. */
	for (i = 0; i < 2; i++) {
		for (j = 0; j < MLX5DR_TABLE_TYPE_MAX; j++) {
			priv->hw_drop[i][j] = mlx5dr_action_create_dest_drop
				(priv->dr_ctx, mlx5_hw_dr_ft_flag[i][j]);
			if (!priv->hw_drop[i][j])
				goto err;
			priv->hw_tag[i][j] = mlx5dr_action_create_tag
				(priv->dr_ctx, mlx5_hw_dr_ft_flag[i][j]);
		}
	}
	return 0;
err:
	for (i = 0; i < 2; i++) {
		for (j = 0; j < MLX5DR_TABLE_TYPE_MAX; j++) {
			if (priv->hw_drop[i][j])
				mlx5dr_action_destroy(priv->hw_drop[i][j]);
			if (priv->hw_tag[i][j])
				mlx5dr_action_destroy(priv->hw_tag[i][j]);
		}
	}
	if (priv->acts_ipool)
		mlx5_ipool_destroy(priv->acts_ipool);
	if (dr_ctx)
		claim_zero(mlx5dr_context_close(dr_ctx));
	return rte_flow_error_set(err, rte_errno,
				  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				  "fail to configure port");
}

void
flow_hw_resource_release(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_flow_table *tbl;
	struct rte_flow_item_template *it;
	struct rte_flow_action_template *at;

	if (!priv->dr_ctx)
		return;
	while (!LIST_EMPTY(&priv->flow_hw_tbl)) {
		tbl = LIST_FIRST(&priv->flow_hw_tbl);
		flow_hw_table_destroy(dev, tbl, NULL);
	}
	while (!LIST_EMPTY(&priv->flow_hw_itt)) {
		it = LIST_FIRST(&priv->flow_hw_itt);
		flow_hw_item_template_destroy(dev, it, NULL);
	}
	while (!LIST_EMPTY(&priv->flow_hw_at)) {
		at = LIST_FIRST(&priv->flow_hw_at);
		flow_hw_action_template_destroy(dev, at, NULL);
	}
	mlx5_ipool_destroy(priv->acts_ipool);
	mlx5_free(priv->hw_q);
	claim_zero(mlx5dr_context_close(priv->dr_ctx));
}

static struct rte_flow_action_handle *
flow_hw_action_handle_create(struct rte_eth_dev *dev, uint32_t queue,
			     const struct rte_flow_q_ops_attr *attr,
			     const struct rte_flow_indir_action_conf *conf,
			     const struct rte_flow_action *action,
			     struct rte_flow_error *error)
{
	RTE_SET_USED(queue);
	RTE_SET_USED(attr);
	return flow_dv_action_create(dev, conf, action, error);
}

static int
flow_hw_action_handle_update(struct rte_eth_dev *dev, uint32_t queue,
			     const struct rte_flow_q_ops_attr *attr,
			     struct rte_flow_action_handle *handle,
			     const void *update,
			     struct rte_flow_error *error)
{
	RTE_SET_USED(queue);
	RTE_SET_USED(attr);
	return flow_dv_action_update(dev, handle, update, error);
}

static int
flow_hw_action_handle_destroy(struct rte_eth_dev *dev, uint32_t queue,
			      const struct rte_flow_q_ops_attr *attr,
			      struct rte_flow_action_handle *handle,
			      struct rte_flow_error *error)
{
	RTE_SET_USED(queue);
	RTE_SET_USED(attr);
	return flow_dv_action_destroy(dev, handle, error);
}


const struct mlx5_flow_driver_ops mlx5_flow_hw_drv_ops = {
	.configure = flow_hw_configure,
	.item_template_create = flow_hw_item_template_create,
	.item_template_destroy = flow_hw_item_template_destroy,
	.action_template_create = flow_hw_action_template_create,
	.action_template_destroy = flow_hw_action_template_destroy,
	.table_create = flow_hw_table_create,
	.table_destroy = flow_hw_table_destroy,
	.q_flow_create = flow_hw_q_flow_create,
	.q_flow_destroy = flow_hw_q_flow_destroy,
	.q_dequeue = flow_hw_q_dequeue,
	.q_drain = flow_hw_q_drain,
	.q_action_create = flow_hw_action_handle_create,
	.q_action_destroy = flow_hw_action_handle_destroy,
	.q_action_update = flow_hw_action_handle_update,
	.action_validate = flow_dv_action_validate,
	.action_create = flow_dv_action_create,
	.action_destroy = flow_dv_action_destroy,
	.action_update = flow_dv_action_update,
	.action_query = flow_dv_action_query,
};
