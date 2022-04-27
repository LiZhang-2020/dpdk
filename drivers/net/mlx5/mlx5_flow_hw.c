#include <rte_flow.h>

#include <mlx5_malloc.h>

#include "mlx5_defs.h"
#include "mlx5_flow.h"
#include "mlx5_rx.h"
#include "mlx5_flow_os.h"

#include "mlx5dr_context.h"
#include "mlx5dr_send.h"
#include "mlx5_hws_cnt.h"

/* The maximum actions support in the flow. */
#define MLX5_HW_MAX_ACTS 16

/* NOP command required by DR action. */
#define MLX5_HW_NOP_MODI_HDR_ACT 2

#define MLX5_HW_INS_NOP_ACT(act_num) \
	((act_num) += MLX5_HW_NOP_MODI_HDR_ACT)

/*
 * The default table ipool threshold value indicates which per_core_cache
 * value to set.
 */
#define MLX5_HW_TABLE_SIZE_THRESHOLD (1 << 19)
/* The default min local cache size. */
#define MLX5_HW_TABLE_FLOW_CACHE_MIN (1 << 9)

/* Default push burst threshold. */
#define BURST_THR 32u

/* Default queue to flush the flows. */
#define MLX5_DEFAULT_FLUSH_QUEUE 0

/* Maximum number of rules in control flow tables. */
#define MLX5_HW_CTRL_FLOW_NB_RULES (4096)

/* Flow group for SQ miss default flows. */
#define MLX5_HW_SQ_MISS_GROUP (UINT32_MAX)

/* Maximum group index usable by user applications for transfer flows. */
#define MLX5_HW_MAX_TRANSFER_GROUP (MLX5_HW_SQ_MISS_GROUP - 2)

/* Lowest priority for HW root table. */
#define MLX5_HW_LOWEST_PRIO_ROOT 15

static int flow_hw_flush_all_ctrl_flows(struct rte_eth_dev *dev);
static int flow_hw_translate_group(struct rte_eth_dev *dev,
				   const struct mlx5_flow_template_table_cfg *cfg,
				   uint32_t group,
				   uint32_t *table_group,
				   struct rte_flow_error *error);

const struct mlx5_flow_driver_ops mlx5_flow_hw_drv_ops;

/* DR action flags with different table. */
static uint32_t mlx5_hw_act_flag[MLX5_HW_ACTION_FLAG_MAX]
				[MLX5DR_TABLE_TYPE_MAX] = {
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

/**
 * Set rxq flag.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] enable
 *   Flag to enable or not.
 */
static void
flow_hw_rxq_flag_set(struct rte_eth_dev *dev, bool enable)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	unsigned int i;

	if ((!priv->mark_enabled && !enable) ||
	    (priv->mark_enabled && enable))
		return;
	for (i = 0; i < priv->rxqs_n; ++i) {
		struct mlx5_rxq_ctrl *rxq_ctrl = mlx5_rxq_ctrl_get(dev, i);

		rxq_ctrl->rxq.mark = enable;
	}
	priv->mark_enabled = enable;
}

static int
flow_hw_create_tx_default_mreg_copy(struct rte_eth_dev *dev,
				    struct rte_flow_error *error);

static void
flow_hw_destroy_tx_default_mreg_copy(struct rte_eth_dev *dev,
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

static inline uint32_t
flow_hw_get_ctrl_queue(struct mlx5_priv *priv)
{
	MLX5_ASSERT(priv->nb_queue > 1);
	return priv->nb_queue - 1;
}

/**
 * Register destination table DR jump action.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] table_attr
 *   Pointer to the flow attributes.
 * @param[in] dest_group
 *   The destination group ID.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    Table on success, NULL otherwise and rte_errno is set.
 */
static struct mlx5_hw_jump_action *
flow_hw_jump_action_register(struct rte_eth_dev *dev,
			     const struct mlx5_flow_template_table_cfg *cfg,
			     uint32_t dest_group,
			     struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_flow_attr jattr = cfg->attr.flow_attr;
	struct mlx5_flow_group *grp;
	struct mlx5_flow_cb_ctx ctx = {
		.dev = dev,
		.error = error,
		.data = &jattr,
	};
	struct mlx5_list_entry *ge;
	uint32_t target_group;

	target_group = dest_group;
	if (flow_hw_translate_group(dev, cfg, dest_group, &target_group, error))
		return NULL;
	jattr.group = target_group;
	ge = mlx5_hlist_register(priv->sh->flow_tbls, target_group, &ctx);
	if (!ge)
		return NULL;
	grp = container_of(ge, struct mlx5_flow_group, entry);
	return &grp->jump;
}

/**
 * Release jump action.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] jump
 *   Pointer to the jump action.
 */
static void
flow_hw_jump_release(struct rte_eth_dev *dev, struct mlx5_hw_jump_action *jump)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_flow_group *grp;

	grp = container_of
		(jump, struct mlx5_flow_group, jump);
	mlx5_hlist_unregister(priv->sh->flow_tbls, &grp->entry);
}

/**
 * Register queue/RSS action.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] hws_flags
 *   DR action flags.
 * @param[in] action
 *   rte flow action.
 *
 * @return
 *    Table on success, NULL otherwise and rte_errno is set.
 */
static inline struct mlx5_hrxq*
flow_hw_tir_action_register(struct rte_eth_dev *dev,
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

/**
 * Destroy DR actions created by action template.
 *
 * For DR actions created during table creation's action translate.
 * Need to destroy the DR action when destroying the table.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] acts
 *   Pointer to the template HW steering DR actions.
 */
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
		flow_hw_jump_release(dev, acts->jump);
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
	if (acts->mhdr) {
		if (acts->mhdr->action)
			mlx5dr_action_destroy(acts->mhdr->action);
		mlx5_free(acts->mhdr);
	}
}

/**
 * Append dynamic action to the dynamic action list.
 *
 * @param[in] priv
 *   Pointer to the port private data structure.
 * @param[in] acts
 *   Pointer to the template HW steering DR actions.
 * @param[in] type
 *   Action type.
 * @param[in] action_src
 *   Offset of source rte flow action.
 * @param[in] action_dst
 *   Offset of destination DR action.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static __rte_always_inline struct mlx5_action_construct_data *
__flow_hw_act_data_alloc(struct mlx5_priv *priv,
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

/**
 * Append dynamic action to the dynamic action list.
 *
 * @param[in] priv
 *   Pointer to the port private data structure.
 * @param[in] acts
 *   Pointer to the template HW steering DR actions.
 * @param[in] type
 *   Action type.
 * @param[in] action_src
 *   Offset of source rte flow action.
 * @param[in] action_dst
 *   Offset of destination DR action.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static __rte_always_inline int
__flow_hw_act_data_general_append(struct mlx5_priv *priv,
				  struct mlx5_hw_actions *acts,
				  enum rte_flow_action_type type,
				  uint16_t action_src,
				  uint16_t action_dst)
{	struct mlx5_action_construct_data *act_data;

	act_data = __flow_hw_act_data_alloc(priv, type, action_src, action_dst);
	if (!act_data)
		return -1;
	LIST_INSERT_HEAD(&acts->act_list, act_data, next);
	return 0;
}

/**
 * Append dynamic encap action to the dynamic action list.
 *
 * @param[in] priv
 *   Pointer to the port private data structure.
 * @param[in] acts
 *   Pointer to the template HW steering DR actions.
 * @param[in] type
 *   Action type.
 * @param[in] action_src
 *   Offset of source rte flow action.
 * @param[in] action_dst
 *   Offset of destination DR action.
 * @param[in] len
 *   Length of the data to be updated.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static __rte_always_inline int
__flow_hw_act_data_encap_append(struct mlx5_priv *priv,
				struct mlx5_hw_actions *acts,
				enum rte_flow_action_type type,
				uint16_t action_src,
				uint16_t action_dst,
				uint16_t len)
{	struct mlx5_action_construct_data *act_data;

	act_data = __flow_hw_act_data_alloc(priv, type, action_src, action_dst);
	if (!act_data)
		return -1;
	act_data->encap.len = len;
	LIST_INSERT_HEAD(&acts->act_list, act_data, next);
	return 0;
}

static __rte_always_inline int
__flow_hw_act_data_hdr_modify_append(struct mlx5_priv *priv,
				     struct mlx5_hw_actions *acts,
				     enum rte_flow_action_type type,
				     uint16_t action_src,
				     uint16_t action_dst,
				     uint16_t mhdr_cmds_off,
				     uint16_t mhdr_cmds_end,
				     bool shared,
				     struct field_modify_info *field,
				     struct field_modify_info *dcopy,
				     uint32_t *mask)
{	struct mlx5_action_construct_data *act_data;

	act_data = __flow_hw_act_data_alloc(priv, type, action_src, action_dst);
	if (!act_data)
		return -1;
	act_data->modify_header.mhdr_cmds_off = mhdr_cmds_off;
	act_data->modify_header.mhdr_cmds_end = mhdr_cmds_end;
	act_data->modify_header.shared = shared;
	rte_memcpy(act_data->modify_header.field, field,
		   sizeof(*field) * MLX5_ACT_MAX_MOD_FIELDS);
	rte_memcpy(act_data->modify_header.dcopy, dcopy,
		   sizeof(*dcopy) * MLX5_ACT_MAX_MOD_FIELDS);
	rte_memcpy(act_data->modify_header.mask, mask,
		   sizeof(*mask) * MLX5_ACT_MAX_MOD_FIELDS);
	LIST_INSERT_HEAD(&acts->act_list, act_data, next);
	return 0;
}

/**
 * Append shared RSS action to the dynamic action list.
 *
 * @param[in] priv
 *   Pointer to the port private data structure.
 * @param[in] acts
 *   Pointer to the template HW steering DR actions.
 * @param[in] type
 *   Action type.
 * @param[in] action_src
 *   Offset of source rte flow action.
 * @param[in] action_dst
 *   Offset of destination DR action.
 * @param[in] idx
 *   Shared RSS index.
 * @param[in] rss
 *   Pointer to the shared RSS info.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static __rte_always_inline int
__flow_hw_act_data_shared_rss_append(struct mlx5_priv *priv,
				     struct mlx5_hw_actions *acts,
				     enum rte_flow_action_type type,
				     uint16_t action_src,
				     uint16_t action_dst,
				     uint32_t idx,
				     struct mlx5_shared_action_rss *rss)
{	struct mlx5_action_construct_data *act_data;

	act_data = __flow_hw_act_data_alloc(priv, type, action_src, action_dst);
	if (!act_data)
		return -1;
	act_data->shared_rss.level = rss->origin.level;
	act_data->shared_rss.types = !rss->origin.types ? ETH_RSS_IP :
				     rss->origin.types;
	act_data->shared_rss.idx = idx;
	LIST_INSERT_HEAD(&acts->act_list, act_data, next);
	return 0;
}

/**
 * Translate shared indirect action.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev data structure.
 * @param[in] action
 *   Pointer to the shared indirect rte_flow action.
 * @param[in] acts
 *   Pointer to the template HW steering DR actions.
 * @param[in] action_src
 *   Offset of source rte flow action.
 * @param[in] action_dst
 *   Offset of destination DR action.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
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
		if (!shared_rss || __flow_hw_act_data_shared_rss_append
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

static __rte_always_inline bool
flow_hw_action_modify_field_is_shared(const struct rte_flow_action *action,
				      const struct rte_flow_action *mask)
{
	const struct rte_flow_action_modify_field *v = action->conf;
	const struct rte_flow_action_modify_field *m = mask->conf;

	if (v->src.field == RTE_FLOW_FIELD_VALUE) {
		uint32_t j;

		if (m == NULL)
			return false;
		for (j = 0; j < RTE_DIM(m->src.value); ++j) {
			/*
			 * Immediate value is considered to be masked
			 * (and thus shared by all flow rules), if mask
			 * is non-zero. Partial mask over immediate value
			 * is not allowed.
			 */
			if (m->src.value[j])
				return true;
		}
		return false;
	}
	if (v->src.field == RTE_FLOW_FIELD_POINTER)
		return m->src.pvalue != NULL;
	/*
	 * Source field types other than VALUE and
	 * POINTER are always shared.
	 */
	return true;
}

static __rte_always_inline bool
flow_hw_should_insert_nop(const struct mlx5_hw_modify_header_action *mhdr,
			  const struct mlx5_flow_dv_modify_hdr_resource *resource)
{
	struct mlx5_modification_cmd last_cmd = { { 0 } };
	struct mlx5_modification_cmd new_cmd = { { 0 } };
	const uint32_t cmds_num = mhdr->mhdr_cmds_num;
	unsigned int last_type;
	bool should_insert = false;

	if (cmds_num == 0)
		return false;
	last_cmd = *(&mhdr->mhdr_cmds[cmds_num - 1]);
	last_cmd.data0 = rte_be_to_cpu_32(last_cmd.data0);
	last_cmd.data1 = rte_be_to_cpu_32(last_cmd.data1);
	last_type = last_cmd.action_type;
	MLX5_ASSERT(resource->actions_num >= 1);
	new_cmd = *(&resource->actions[0]);
	new_cmd.data0 = rte_be_to_cpu_32(new_cmd.data0);
	new_cmd.data1 = rte_be_to_cpu_32(new_cmd.data1);
	switch (new_cmd.action_type) {
	case MLX5_MODIFICATION_TYPE_SET:
	case MLX5_MODIFICATION_TYPE_ADD:
		if (last_type == MLX5_MODIFICATION_TYPE_SET ||
		    last_type == MLX5_MODIFICATION_TYPE_ADD)
			should_insert = new_cmd.field == last_cmd.field;
		else if (last_type == MLX5_MODIFICATION_TYPE_COPY)
			should_insert = new_cmd.field == last_cmd.dst_field;
		else
			MLX5_ASSERT(false); /* Other types are not supported. */
		break;
	case MLX5_MODIFICATION_TYPE_COPY:
		if (last_type == MLX5_MODIFICATION_TYPE_SET ||
		    last_type == MLX5_MODIFICATION_TYPE_ADD)
			should_insert = (new_cmd.field == last_cmd.field ||
					 new_cmd.dst_field == last_cmd.field);
		else if (last_type == MLX5_MODIFICATION_TYPE_COPY)
			should_insert = (new_cmd.field == last_cmd.dst_field ||
					 new_cmd.dst_field == last_cmd.dst_field);
		else
			MLX5_ASSERT(false); /* Other types are not supported. */
		break;
	default:
		/* Other action types should be rejected on AT validation. */
		MLX5_ASSERT(false);
		break;
	}
	return should_insert;
}

static __rte_always_inline int
flow_hw_mhdr_cmd_nop_append(struct mlx5_hw_modify_header_action *mhdr)
{
	struct mlx5_modification_cmd *nop;
	uint32_t num = mhdr->mhdr_cmds_num;

	if (num + 1 >= MLX5_MHDR_MAX_CMD)
		return -ENOMEM;
	nop = mhdr->mhdr_cmds + num;
	nop->data0 = 0;
	nop->action_type = MLX5_MODIFICATION_TYPE_NOP;
	nop->data0 = rte_cpu_to_be_32(nop->data0);
	nop->data1 = 0;
	mhdr->mhdr_cmds_num = num + 1;
	return 0;
}

static __rte_always_inline int
flow_hw_converted_mhdr_cmds_append(struct mlx5_hw_modify_header_action *mhdr,
				   struct mlx5_flow_dv_modify_hdr_resource *resource)
{
	uint32_t cmds_num = mhdr->mhdr_cmds_num;
	struct mlx5_modification_cmd *dst;
	struct mlx5_modification_cmd *src;
	size_t size;

	if (cmds_num + resource->actions_num >= MLX5_MHDR_MAX_CMD)
		return -ENOMEM;
	dst = mhdr->mhdr_cmds + cmds_num;
	src = &resource->actions[0];
	size = sizeof(resource->actions[0]) * resource->actions_num;
	rte_memcpy(dst, src, size);
	mhdr->mhdr_cmds_num = cmds_num + resource->actions_num;
	return 0;
}

static __rte_always_inline void
flow_hw_modify_field_init(struct mlx5_hw_modify_header_action *mhdr)
{
	memset(mhdr, 0, sizeof(*mhdr));
	/* Modify header action without any commands is shared by default. */
	mhdr->shared = true;
	mhdr->pos = UINT16_MAX;
}

static __rte_always_inline int
flow_hw_modify_field_compile(struct rte_eth_dev *dev,
			     const struct rte_flow_attr *attr,
			     const struct rte_flow_action *action_start, /* Start of AT actions. */
			     const struct rte_flow_action *action, /* Current action from AT. */
			     const struct rte_flow_action *action_mask, /* Current mask from AT. */
			     struct mlx5_hw_actions *acts,
			     struct mlx5_hw_modify_header_action *mhdr,
			     struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	const struct rte_flow_action_modify_field *conf = action->conf;
	union {
		struct mlx5_flow_dv_modify_hdr_resource resource;
		uint8_t data[sizeof(struct mlx5_flow_dv_modify_hdr_resource) +
			     sizeof(struct mlx5_modification_cmd) * MLX5_MHDR_MAX_CMD];
	} dummy;
	struct mlx5_flow_dv_modify_hdr_resource *resource;
	struct rte_flow_item item = {
		.spec = NULL,
		.mask = NULL
	};
	struct field_modify_info field[MLX5_ACT_MAX_MOD_FIELDS] = {
						{0, 0, MLX5_MODI_OUT_NONE} };
	struct field_modify_info dcopy[MLX5_ACT_MAX_MOD_FIELDS] = {
						{0, 0, MLX5_MODI_OUT_NONE} };
	uint32_t mask[MLX5_ACT_MAX_MOD_FIELDS] = { 0 };
	uint32_t type, meta = 0;
	uint16_t cmds_start, cmds_end;
	bool shared;
	int ret;

	/*
	 * Modify header action is shared if previous modify_field actions
	 * are shared and currently compiled action is shared.
	 */
	shared = flow_hw_action_modify_field_is_shared(action, action_mask);
	mhdr->shared &= shared;
	if (conf->src.field == RTE_FLOW_FIELD_POINTER ||
	    conf->src.field == RTE_FLOW_FIELD_VALUE) {
		type = conf->operation == RTE_FLOW_MODIFY_SET ? MLX5_MODIFICATION_TYPE_SET :
								MLX5_MODIFICATION_TYPE_ADD;
		/* For SET/ADD fill the destination field (field) first. */
		mlx5_flow_field_id_to_modify_info(&conf->dst, field, mask,
						  conf->width, dev,
						  attr, error);
		item.spec = conf->src.field == RTE_FLOW_FIELD_POINTER ?
				(void *)(uintptr_t)conf->src.pvalue :
				(void *)(uintptr_t)&conf->src.value;
		if (conf->dst.field == RTE_FLOW_FIELD_META) {
			meta = *(const unaligned_uint32_t *)item.spec;
			meta = rte_cpu_to_be_32(meta);
			item.spec = &meta;
		}
	} else {
		type = MLX5_MODIFICATION_TYPE_COPY;
		/* For COPY fill the destination field (dcopy) without mask. */
		mlx5_flow_field_id_to_modify_info(&conf->dst, dcopy, NULL,
						  conf->width, dev,
						  attr, error);
		/* Then construct the source field (field) with mask. */
		mlx5_flow_field_id_to_modify_info(&conf->src, field, mask,
						  conf->width, dev,
						  attr, error);
	}
	item.mask = &mask;
	memset(&dummy, 0, sizeof(dummy));
	resource = &dummy.resource;
	ret = flow_convert_modify_action(&item, field, dcopy, resource, type, error);
	if (ret)
		return ret;
	if (flow_hw_should_insert_nop(mhdr, resource)) {
		ret = flow_hw_mhdr_cmd_nop_append(mhdr);
		if (ret)
			return rte_flow_error_set(error, ret, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
						  NULL, "too many modify field operations specified");
	}
	cmds_start = mhdr->mhdr_cmds_num;
	ret = flow_hw_converted_mhdr_cmds_append(mhdr, resource);
	if (ret)
		return rte_flow_error_set(error, ret, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL, "too many modify field operations specified");

	cmds_end = mhdr->mhdr_cmds_num;
	if (shared)
		return 0;
	ret = __flow_hw_act_data_hdr_modify_append(priv, acts, RTE_FLOW_ACTION_TYPE_MODIFY_FIELD,
						   action - action_start, mhdr->pos,
						   cmds_start, cmds_end, shared,
						   field, dcopy, mask);
	if (ret)
		return rte_flow_error_set(error, ENOMEM, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL, "not enough memory to store modify field metadata");
	return 0;
}

static int
flow_hw_represented_port_compile(struct rte_eth_dev *dev,
				 const struct rte_flow_attr *attr,
				 const struct rte_flow_action *action_start,
				 const struct rte_flow_action *action,
				 const struct rte_flow_action *action_mask,
				 struct mlx5_hw_actions *acts,
				 uint16_t action_dst,
				 struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	const struct rte_flow_action_ethdev *v = action->conf;
	const struct rte_flow_action_ethdev *m = action_mask->conf;
	int ret;

	if (!attr->group)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ATTR, NULL,
					  "represented_port action cannot"
					  " be used on group 0");
	if (!attr->transfer)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ATTR_TRANSFER,
					  NULL,
					  "represented_port action requires"
					  " transfer attribute");
	if (attr->ingress || attr->egress)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ATTR, NULL,
					  "represented_port action cannot"
					  " be used with direction attributes");
	if (!priv->master)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
					  "represented_port acton must"
					  " be used on proxy port");
	if (m && !!m->port_id) {
		struct mlx5_priv *port_priv;

		port_priv = mlx5_port_to_eswitch_info(v->port_id, false);
		if (port_priv == NULL)
			return rte_flow_error_set
					(error, EINVAL,
					 RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
					 "port does not exist or unable to"
					 " obtain E-Switch info for port");
		MLX5_ASSERT(priv->hw_vport != NULL);
		if (priv->hw_vport[v->port_id]) {
			acts->rule_acts[action_dst].action =
					priv->hw_vport[v->port_id];
		} else {
			return rte_flow_error_set
					(error, EINVAL,
					 RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
					 "cannot use represented_port action"
					 " with this port");
		}
	} else {
		ret = __flow_hw_act_data_general_append
				(priv, acts, action->type,
				 action - action_start, action_dst);
		if (ret)
			return rte_flow_error_set
					(error, ENOMEM,
					 RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
					 "not enough memory to store"
					 " vport action");
	}
	return 0;
}

static __rte_always_inline int
flow_hw_meter_compile(struct rte_eth_dev *dev,
		      const struct mlx5_flow_template_table_cfg *cfg,
		      uint32_t  start_pos, const struct rte_flow_action *action,
		      struct mlx5_hw_actions *acts, uint32_t *end_pos,
		      struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_aso_mtr *aso_mtr;
	const struct rte_flow_action_meter *meter = action->conf;
	uint32_t pos = start_pos;
	uint32_t group = cfg->attr.flow_attr.group;

	aso_mtr = mlx5_aso_meter_by_idx(priv, meter->mtr_id);
	acts->rule_acts[pos].action = priv->mtr_bulk.action;
	acts->rule_acts[pos].aso_meter.offset = aso_mtr->offset;
	acts->jump = flow_hw_jump_action_register
		(dev, cfg, aso_mtr->fm.group, error);
	if (!acts->jump) {
		*end_pos = start_pos;
		return -ENOMEM;
	}
	acts->rule_acts[++pos].action = (!!group) ?
				    acts->jump->hws_action :
				    acts->jump->root_action;
	*end_pos = pos;
	if (mlx5_aso_mtr_wait(priv->sh, aso_mtr)) {
		*end_pos = start_pos;
		return -ENOMEM;
	}
	return 0;
}

/**
 * Translate rte_flow actions to DR action.
 *
 * As the action template has already indicated the actions. Translate
 * the rte_flow actions to DR action if possbile. So in flow create
 * stage we will save cycles from handing the actions' organizing.
 * For the actions with limited information, need to add these to a
 * list.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] cfg
 *   Pointer to the table configuration.
 * @param[in] item_templates
 *   Item template array to be binded to the table.
 * @param[in/out] acts
 *   Pointer to the template HW steering DR actions.
 * @param[in] at
 *   Action template.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    Table on success, NULL otherwise and rte_errno is set.
 */
static int
__flow_hw_actions_translate(struct rte_eth_dev *dev,
			    const struct mlx5_flow_template_table_cfg *cfg,
			    struct mlx5_hw_actions *acts,
			    struct rte_flow_actions_template *at,
			    struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	const struct rte_flow_template_table_attr *table_attr = &cfg->attr;
	const struct rte_flow_attr *attr = &table_attr->flow_attr;
	struct rte_flow_action *actions = at->actions;
	struct rte_flow_action *masks = at->masks;
	struct rte_flow_action *action_start = actions;
	/*
	 * Set to valid enum value to prevent "variable may be uinitialized"
	 * compilation errors triggering in this function, even though
	 * refmt_type is used if and only if it is initialized.
	 */
	enum mlx5dr_action_reformat_type refmt_type =
			MLX5DR_ACTION_REFORMAT_TYPE_TNL_L2_TO_L2;
	const struct rte_flow_action_raw_encap *raw_encap_data;
	const struct rte_flow_item *enc_item = NULL, *enc_item_m = NULL;
	uint8_t *encap_data = NULL, *encap_data_m = NULL;
	size_t data_size = 0;
	bool actions_end = false;
	uint32_t type, i;
	uint16_t reformat_pos = MLX5_HW_MAX_ACTS, reformat_src = 0;
	struct mlx5_hw_modify_header_action mhdr = { 0 };
	int ret;
	int err;

	flow_hw_modify_field_init(&mhdr);
	if (attr->transfer)
		type = MLX5DR_TABLE_TYPE_FDB;
	else if (attr->egress)
		type = MLX5DR_TABLE_TYPE_NIC_TX;
	else
		type = MLX5DR_TABLE_TYPE_NIC_RX;
	for (i = 0; !actions_end; actions++, masks++) {
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
			} else if (__flow_hw_act_data_general_append
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
			if (masks->conf &&
			    ((const struct rte_flow_action_mark *)
			     masks->conf)->id)
				acts->rule_acts[i].tag.value =
					mlx5_flow_mark_set
					(((const struct rte_flow_action_mark *)
					(actions->conf))->id);
			else if (__flow_hw_act_data_general_append(priv, acts,
				actions->type, actions - action_start, i))
				goto err;
			acts->rule_acts[i++].action =
				priv->hw_tag[!!attr->group];
			flow_hw_rxq_flag_set(dev, true);
			break;
		case RTE_FLOW_ACTION_TYPE_DROP:
			acts->rule_acts[i++].action =
				priv->hw_drop[!!attr->group];
			break;
		case RTE_FLOW_ACTION_TYPE_JUMP:
			if (masks->conf &&
			    ((const struct rte_flow_action_jump *)
			     masks->conf)->group) {
				uint32_t jump_group =
					((const struct rte_flow_action_jump *)
					actions->conf)->group;
				acts->jump = flow_hw_jump_action_register
						(dev, cfg, jump_group, error);
				if (!acts->jump)
					goto err;
				acts->rule_acts[i].action = (!!attr->group) ?
						acts->jump->hws_action :
						acts->jump->root_action;
			} else if (__flow_hw_act_data_general_append
					(priv, acts, actions->type,
					 actions - action_start, i)){
				goto err;
			}
			i++;
			break;
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			if (masks->conf &&
			    ((const struct rte_flow_action_queue *)
			     masks->conf)->index) {
				acts->tir = flow_hw_tir_action_register
				(dev,
				 mlx5_hw_act_flag[!!attr->group][type],
				 actions);
				if (!acts->tir)
					goto err;
				acts->rule_acts[i].action =
					acts->tir->action;
			} else if (__flow_hw_act_data_general_append
					(priv, acts, actions->type,
					 actions - action_start, i)) {
				goto err;
			}
			i++;
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
			if (actions->conf && masks->conf) {
				acts->tir = flow_hw_tir_action_register
				(dev,
				 mlx5_hw_act_flag[!!attr->group][type],
				 actions);
				if (!acts->tir)
					goto err;
				acts->rule_acts[i].action =
					acts->tir->action;
			} else if (__flow_hw_act_data_general_append
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
			if (masks->conf)
				enc_item_m = ((const struct rte_flow_action_vxlan_encap *)
					     masks->conf)->definition;
			reformat_pos = i++;
			reformat_src = actions - action_start;
			refmt_type = MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L2;
			break;
		case RTE_FLOW_ACTION_TYPE_NVGRE_ENCAP:
			MLX5_ASSERT(reformat_pos == MLX5_HW_MAX_ACTS);
			enc_item = ((const struct rte_flow_action_nvgre_encap *)
				   actions->conf)->definition;
			if (masks->conf)
				enc_item_m = ((const struct rte_flow_action_nvgre_encap *)
					     masks->conf)->definition;
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
				 masks->conf;
			if (raw_encap_data)
				encap_data_m = raw_encap_data->data;
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
		case RTE_FLOW_ACTION_TYPE_MODIFY_FIELD:
			if (mhdr.pos == UINT16_MAX)
				mhdr.pos = i++;
			ret = flow_hw_modify_field_compile(dev, attr, action_start,
							   actions, masks, acts, &mhdr,
							   error);
			if (ret)
				goto err;
			/*
			 * Adjust the action source position for the following.
			 * ... / MODIFY_FIELD: rx_cpy_pos / (QUEUE|RSS) / ...
			 * The next action will be Q/RSS, there will not be
			 * another adjustment and the real source position of
			 * the following actions will be decreased by 1.
			 * No change of the total actions in the new template.
			 */
			if ((actions - action_start) == at->rx_cpy_pos)
				action_start += 1;
			break;
		case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
			if (flow_hw_represented_port_compile
					(dev, attr, action_start, actions,
					 masks, acts, i, error))
				goto err;
			i++;
			break;
		case RTE_FLOW_ACTION_TYPE_METER:
			if (actions->conf && masks->conf &&
			    ((const struct rte_flow_action_meter *)
			     masks->conf)->mtr_id) {
				ret = flow_hw_meter_compile(dev, cfg,
						i, actions, acts, &i, error);
				if (ret)
					goto err;
			} else if (__flow_hw_act_data_general_append(priv, acts,
							actions->type,
							actions - action_start,
							i))
				goto err;
			i++;
			break;
		case RTE_FLOW_ACTION_TYPE_COUNT:
			if (__flow_hw_act_data_general_append
					(priv, acts, actions->type,
					 actions - action_start, i)) {
				goto err;
			}
			i++;
			break;
		case RTE_FLOW_ACTION_TYPE_END:
			actions_end = true;
			break;
		default:
			break;
		}
	}
	if (mhdr.pos != UINT16_MAX) {
		uint32_t flags;
		uint32_t bulk_size;
		size_t mhdr_len;

		acts->mhdr = mlx5_malloc(MLX5_MEM_ZERO, sizeof(*acts->mhdr),
					 0, SOCKET_ID_ANY);
		if (!acts->mhdr)
			goto err;
		rte_memcpy(acts->mhdr, &mhdr, sizeof(*acts->mhdr));
		mhdr_len = sizeof(struct mlx5_modification_cmd) * acts->mhdr->mhdr_cmds_num;
		flags = mlx5_hw_act_flag[!!attr->group][type];
		if (acts->mhdr->shared) {
			flags |= MLX5DR_ACTION_FLAG_SHARED;
			bulk_size = 0;
		} else {
			bulk_size = rte_log2_u32(table_attr->nb_flows);
		}
		acts->mhdr->action = mlx5dr_action_create_modify_header
				(priv->dr_ctx, mhdr_len, (__be64 *)acts->mhdr->mhdr_cmds,
				 bulk_size, flags);
		if (!acts->mhdr->action)
			goto err;
		acts->rule_acts[acts->mhdr->pos].action = acts->mhdr->action;
	}
	if (reformat_pos != MLX5_HW_MAX_ACTS) {
		uint8_t buf[MLX5_ENCAP_MAX_LEN];
		bool shared_rfmt = true;

		if (enc_item) {
			MLX5_ASSERT(!encap_data);
			if (flow_convert_encap_data(enc_item, buf, &data_size, error))
				goto err;
			encap_data = buf;
			if (!enc_item_m)
				shared_rfmt = false;
		} else if (encap_data && !encap_data_m) {
			shared_rfmt = false;
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
				 shared_rfmt ? 0 : rte_log2_u32(table_attr->nb_flows),
				 mlx5_hw_act_flag[!!attr->group][type] |
				 (shared_rfmt ? MLX5DR_ACTION_FLAG_SHARED : 0));
		if (!acts->encap_decap->action)
			goto err;
		acts->rule_acts[reformat_pos].action =
						acts->encap_decap->action;
		acts->rule_acts[reformat_pos].reformat.data =
						acts->encap_decap->data;
		if (shared_rfmt)
			acts->rule_acts[reformat_pos].reformat.offset = 0;
		else if (__flow_hw_act_data_encap_append(priv, acts,
				 (action_start + reformat_src)->type,
				 reformat_src, reformat_pos, data_size))
			goto err;
		acts->encap_decap->shared = shared_rfmt;
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

/**
 * Translate rte_flow actions to DR action.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] tbl
 *   Pointer to the flow template table.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static int
flow_hw_actions_translate(struct rte_eth_dev *dev,
			  struct rte_flow_template_table *tbl,
			  struct rte_flow_error *error)
{
	uint32_t i;

	for (i = 0; i < tbl->nb_action_templates; i++) {
		if (__flow_hw_actions_translate(dev, &tbl->cfg,
						&tbl->ats[i].acts,
						tbl->ats[i].action_template,
						error))
			goto err;
	}
	return 0;
err:
	while (i--)
		__flow_hw_action_template_destroy(dev, &tbl->ats[i].acts);
	return -1;
}

/**
 * Get shared indirect action.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev data structure.
 * @param[in] act_data
 *   Pointer to the recorded action construct data.
 * @param[in] item_flags
 *   The matcher itme_flags used for RSS lookup.
 * @param[in] rule_act
 *   Pointer to the shared action's destination rule DR action.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
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

/**
 * Construct shared indirect action.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev data structure.
 * @param[in] action
 *   Pointer to the shared indirect rte_flow action.
 * @param[in] table
 *   Pointer to the flow table.
 * @param[in] it_idx
 *   Item template index the action template refer to.
 * @param[in] rule_act
 *   Pointer to the shared action's destination rule DR action.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static __rte_always_inline int
flow_hw_shared_action_construct(struct rte_eth_dev *dev,
				const struct rte_flow_action *action,
				struct rte_flow_template_table *table,
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

/**
 * Construct flow action array.
 *
 * For action template contains dynamic actions, these actions need to
 * be updated according to the rte_flow action during flow creation.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] job
 *   Pointer to job descriptor.
 * @param[in] hw_acts
 *   Pointer to translated actions from template.
 * @param[in] it_idx
 *   Item template index the action template refer to.
 * @param[in] actions
 *   Array of rte_flow action need to be checked.
 * @param[in] rule_acts
 *   Array of DR rule actions to be used during flow creation..
 * @param[in] acts_num
 *   Pointer to the real acts_num flow has.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static __rte_always_inline int
flow_hw_modify_field_construct(struct mlx5_hw_q_job *job,
			       struct mlx5_action_construct_data *act_data,
			       const struct mlx5_hw_actions *hw_acts,
			       const struct rte_flow_action *action)
{
	const struct rte_flow_action_modify_field *mhdr_action = action->conf;
	uint8_t values[16] = { 0 };
	unaligned_uint32_t *meta_p;
	uint32_t i;
	struct field_modify_info *field;

	if (!hw_acts->mhdr)
		return -1;
	if (hw_acts->mhdr->shared || act_data->modify_header.shared)
		return 0;
	MLX5_ASSERT(mhdr_action->operation == RTE_FLOW_MODIFY_SET ||
		    mhdr_action->operation == RTE_FLOW_MODIFY_ADD);
	if (mhdr_action->src.field != RTE_FLOW_FIELD_VALUE &&
	    mhdr_action->src.field != RTE_FLOW_FIELD_POINTER)
		return 0;
	if (mhdr_action->src.field == RTE_FLOW_FIELD_VALUE)
		rte_memcpy(values, &mhdr_action->src.value, sizeof(values));
	else
		rte_memcpy(values, mhdr_action->src.pvalue, sizeof(values));
	if (mhdr_action->dst.field == RTE_FLOW_FIELD_META) {
		meta_p = (unaligned_uint32_t *)values;
		*meta_p = rte_cpu_to_be_32(*meta_p);
	}
	i = act_data->modify_header.mhdr_cmds_off;
	field = act_data->modify_header.field;
	do {
		uint32_t off_b;
		uint32_t mask;
		uint32_t data;
		const uint8_t *mask_src;

		if (i >= act_data->modify_header.mhdr_cmds_end)
			return -1;
		mask_src = (const uint8_t *)act_data->modify_header.mask;
		mask = flow_fetch_field(mask_src + field->offset, field->size);
		if (!mask) {
			++field;
			continue;
		}
		off_b = rte_bsf32(mask);
		data = flow_fetch_field(values + field->offset, field->size);
		data = (data & mask) >> off_b;
		job->mhdr_cmd[i++].data1 = rte_cpu_to_be_32(data);
		++field;
	} while (field->size);
	return 0;
}

static __rte_always_inline int
flow_hw_actions_construct(struct rte_eth_dev *dev,
			  struct mlx5_hw_q_job *job,
			  const struct mlx5_hw_actions *hw_acts,
			  const uint8_t it_idx,
			  const struct rte_flow_action actions[],
			  struct mlx5dr_rule_action *rule_acts,
			  uint32_t *acts_num,
			  uint32_t queue)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_flow_template_table *table = job->flow->table;
	const struct rte_flow_action *action;
	const struct rte_flow_action_raw_encap *raw_encap_data;
	const struct rte_flow_item *enc_item = NULL;
	const struct rte_flow_action_ethdev *port_action = NULL;
	const struct rte_flow_action_meter *meter = NULL;
	uint8_t *buf = job->encap_data;
	struct rte_flow_attr attr = {
		.ingress = 1,
	};
	uint32_t ft_flag;
	size_t encap_len = 0;
	struct mlx5_action_construct_data *act_data;
	struct mlx5_aso_mtr *mtr;
	uint32_t mtr_id;

	rte_memcpy(rule_acts, hw_acts->rule_acts, sizeof(*rule_acts) * hw_acts->acts_num);
	*acts_num = hw_acts->acts_num;
	attr.group = table->grp->group_id;
	ft_flag = mlx5_hw_act_flag[!!table->grp->group_id][table->type];
	if (table->type == MLX5DR_TABLE_TYPE_FDB) {
		attr.transfer = 1;
		attr.ingress = 1;
	} else if (table->type == MLX5DR_TABLE_TYPE_NIC_TX) {
		attr.egress = 1;
		attr.ingress = 0;
	} else {
		attr.ingress = 1;
	}
	rte_memcpy(rule_acts, hw_acts->rule_acts, sizeof(*rule_acts) * hw_acts->acts_num);
	*acts_num = hw_acts->acts_num;
	if (hw_acts->mhdr && hw_acts->mhdr->mhdr_cmds_num > 0) {
		uint16_t pos = hw_acts->mhdr->pos;

		if (!hw_acts->mhdr->shared) {
			rule_acts[pos].modify_header.offset =
						job->flow->idx - 1;
			rule_acts[pos].modify_header.data =
						(uint8_t *)job->mhdr_cmd;
			rte_memcpy(job->mhdr_cmd, hw_acts->mhdr->mhdr_cmds,
				   sizeof(*job->mhdr_cmd) * hw_acts->mhdr->mhdr_cmds_num);
		}
	}
	LIST_FOREACH(act_data, &hw_acts->act_list, next) {
		uint32_t tag;
		uint32_t jump_group;
		uint64_t item_flags;
		struct mlx5_hrxq *hrxq;
		struct mlx5_hw_jump_action *jump;
		int ret;
		cnt_id_t cnt_id;

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
			jump = flow_hw_jump_action_register
				(dev, &table->cfg, jump_group, NULL);
			if (!jump)
				return -1;
			rule_acts[act_data->action_dst].action =
			(!!attr.group) ? jump->hws_action : jump->root_action;
			job->flow->jump = jump;
			job->flow->fate_type = MLX5_FLOW_FATE_JUMP;
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			hrxq = flow_hw_tir_action_register(dev,
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
			if (flow_convert_encap_data(enc_item, buf, &encap_len, NULL))
				return -1;
			break;
		case RTE_FLOW_ACTION_TYPE_NVGRE_ENCAP:
			enc_item = ((const struct rte_flow_action_nvgre_encap *)
				   action->conf)->definition;
			if (flow_convert_encap_data(enc_item, buf, &encap_len, NULL))
				return -1;
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_ENCAP:
			raw_encap_data =
				(const struct rte_flow_action_raw_encap *)
				 action->conf;
			rte_memcpy((void *)buf, raw_encap_data->data, act_data->encap.len);
			MLX5_ASSERT(raw_encap_data->size ==
				    act_data->encap.len);
			break;
		case RTE_FLOW_ACTION_TYPE_MODIFY_FIELD:
			ret = flow_hw_modify_field_construct(job, act_data,
							     hw_acts, action);
			if (ret)
				return -1;
			break;
		case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
			port_action = action->conf;
			if (!priv->hw_vport[port_action->port_id])
				return -1;
			rule_acts[act_data->action_dst].action =
					priv->hw_vport[port_action->port_id];
			break;
		case RTE_FLOW_ACTION_TYPE_METER:
			meter = action->conf;
			mtr_id = meter->mtr_id;
			mtr = mlx5_aso_meter_by_idx(priv, mtr_id);
			rule_acts[act_data->action_dst].action =
				priv->mtr_bulk.action;
			rule_acts[act_data->action_dst].aso_meter.offset =
								mtr->offset;
			jump = flow_hw_jump_action_register
				(dev, &table->cfg, mtr->fm.group, NULL);
			if (!jump)
				return -1;
			MLX5_ASSERT
				(!rule_acts[act_data->action_dst + 1].action);
			rule_acts[act_data->action_dst + 1].action =
					(!!attr.group) ? jump->hws_action :
							 jump->root_action;
			job->flow->jump = jump;
			job->flow->fate_type = MLX5_FLOW_FATE_JUMP;
			(*acts_num)++;
			if (mlx5_aso_mtr_wait(priv->sh, mtr))
				return -1;
			break;
		case RTE_FLOW_ACTION_TYPE_COUNT:
			ret = mlx5_hws_cnt_pool_get(priv->hws_cpool, &queue,
					&cnt_id);
			if (ret != 0)
				return ret;
			ret = mlx5_hws_cnt_pool_get_action_offset
				(priv->hws_cpool,
				 cnt_id,
				 &rule_acts[act_data->action_dst].action,
				 &rule_acts[act_data->action_dst].counter.offset
				 );
			if (ret != 0)
				return ret;
			job->flow->cnt_id = cnt_id;
			break;
		default:
			break;
		}
	}
	if (hw_acts->encap_decap && !hw_acts->encap_decap->shared) {
		rule_acts[hw_acts->encap_decap_pos].reformat.offset =
				job->flow->idx - 1;
		rule_acts[hw_acts->encap_decap_pos].reformat.data = buf;
	}
	return 0;
}

static const struct rte_flow_item *
flow_hw_get_rule_items(struct rte_eth_dev *dev,
		       struct rte_flow_template_table *table,
		       const struct rte_flow_item items[],
		       uint8_t pattern_template_index,
		       struct mlx5_hw_q_job *job)
{
	if (table->its[pattern_template_index]->implicit_port) {
		const struct rte_flow_item *curr_item;
		unsigned int nb_items;
		bool found_end;
		unsigned int i;

		/* Count number of pattern items. */
		nb_items = 0;
		found_end = false;
		for (curr_item = items; !found_end; ++curr_item) {
			++nb_items;
			if (curr_item->type == RTE_FLOW_ITEM_TYPE_END)
				found_end = true;
		}
		/* Prepend represented port item. */
		job->port_spec = (struct rte_flow_item_ethdev){
			.port_id = dev->data->port_id,
		};
		job->items[0] = (struct rte_flow_item){
			.type = RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT,
			.spec = &job->port_spec,
		};
		found_end = false;
		for (i = 1; i < MLX5_HW_MAX_ITEMS && i - 1 < nb_items; ++i) {
			job->items[i] = items[i - 1];
			if (items[i - 1].type == RTE_FLOW_ITEM_TYPE_END) {
				found_end = true;
				break;
			}
		}
		if (i >= MLX5_HW_MAX_ITEMS && !found_end) {
			rte_errno = ENOMEM;
			return NULL;
		}
		return job->items;
	}
	return items;
}

/**
 * Enqueue HW steering flow creation.
 *
 * The flow will be applied to the HW only if the postpone bit is not set or
 * the extra push function is called.
 * The flow creation status should be checked from dequeue result.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] queue
 *   The queue to create the flow.
 * @param[in] attr
 *   Pointer to the flow operation attributes.
 * @param[in] items
 *   Items with flow spec value.
 * @param[in] pattern_template_index
 *   The item pattern flow follows from the table.
 * @param[in] actions
 *   Action with flow spec value.
 * @param[in] action_template_index
 *   The action pattern flow follows from the table.
 * @param[in] user_data
 *   Pointer to the user_data.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    Flow pointer on success, NULL otherwise and rte_errno is set.
 */
static struct rte_flow *
flow_hw_async_flow_create(struct rte_eth_dev *dev,
			  uint32_t queue,
			  const struct rte_flow_op_attr *attr,
			  struct rte_flow_template_table *table,
			  const struct rte_flow_item items[],
			  uint8_t pattern_template_index,
			  const struct rte_flow_action actions[],
			  uint8_t action_template_index,
			  void *user_data,
			  struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5dr_rule_attr rule_attr = {
		.queue_id = queue,
		.user_data = user_data,
		.burst = attr->postpone,
	};
	struct mlx5dr_rule_action rule_acts[MLX5_HW_MAX_ACTS];
	struct mlx5_hw_actions *hw_acts;
	struct rte_flow_hw *flow;
	struct mlx5_hw_q_job *job;
	const struct rte_flow_item *rule_items;
	uint32_t acts_num, flow_idx;
	int ret;

	if (unlikely((!dev->data->dev_started))) {
		rte_errno = EINVAL;
		goto error;
	}
	if (unlikely(!priv->hw_q[queue].job_idx)) {
		rte_errno = ENOMEM;
		goto error;
	}
	flow = mlx5_ipool_zmalloc(table->flow, &flow_idx);
	if (!flow)
		goto error;
	/*
	 * Set the table here in order to know the destination table
	 * when free the flow afterwards.
	 */
	flow->table = table;
	flow->idx = flow_idx;
	job = priv->hw_q[queue].job[--priv->hw_q[queue].job_idx];
	/*
	 * Set the job type here in order to know if the flow memory
	 * should be freed or not when get the result from dequeue.
	 */
	job->type = MLX5_HW_Q_JOB_TYPE_CREATE;
	job->flow = flow;
	job->user_data = user_data;
	rule_attr.user_data = job;
	hw_acts = &table->ats[action_template_index].acts;
	/*
	 * Construct the flow actions based on the input actions.
	 * The implicitly appended action is always fixed, like metadata
	 * copy action from FDB to NIC Rx.
	 * No need to copy and contrust a new "actions" list based on the
	 * user's input, in order to save the cost.
	 */
	if (flow_hw_actions_construct(dev, job, hw_acts, pattern_template_index,
				  actions, rule_acts, &acts_num, queue)) {
		rte_errno = EINVAL;
		goto free;
	}
	rule_items = flow_hw_get_rule_items(dev, table, items,
					    pattern_template_index, job);
	if (!rule_items)
		goto free;
	ret = mlx5dr_rule_create(table->matcher,
				 pattern_template_index, rule_items,
				 rule_acts, acts_num,
				 &rule_attr, &flow->rule);
	if (likely(!ret))
		return (struct rte_flow *)flow;
free:
	/* Flow created fail, return the descriptor and flow memory. */
	mlx5_ipool_free(table->flow, flow_idx);
	priv->hw_q[queue].job_idx++;
error:
	rte_flow_error_set(error, rte_errno,
			   RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			   "fail to create rte flow");
	return NULL;
}

/**
 * Enqueue HW steering flow destruction.
 *
 * The flow will be applied to the HW only if the postpone bit is not set or
 * the extra push function is called.
 * The flow destruction status should be checked from dequeue result.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] queue
 *   The queue to destroy the flow.
 * @param[in] attr
 *   Pointer to the flow operation attributes.
 * @param[in] flow
 *   Pointer to the flow to be destroyed.
 * @param[in] user_data
 *   Pointer to the user_data.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static int
flow_hw_async_flow_destroy(struct rte_eth_dev *dev,
			   uint32_t queue,
			   const struct rte_flow_op_attr *attr,
			   struct rte_flow *flow,
			   void *user_data,
			   struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5dr_rule_attr rule_attr = {
		.queue_id = queue,
		.user_data = user_data,
		.burst = attr->postpone,
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
	job->user_data = user_data;
	job->flow = fh;
	rule_attr.user_data = job;
	ret = mlx5dr_rule_destroy(&fh->rule, &rule_attr);
	if (likely(!ret))
		return 0;
	priv->hw_q[queue].job_idx++;
error:
	return rte_flow_error_set(error, rte_errno,
			RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			"fail to create rte flow");
}

/**
 * Pull the enqueued flows.
 *
 * For flows enqueued from creation/destruction, the status should be
 * checked from the dequeue result.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] queue
 *   The queue to pull the result.
 * @param[in/out] res
 *   Array to save the results.
 * @param[in] n_res
 *   Available result with the array.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    Result number on success, negative value otherwise and rte_errno is set.
 */
static int
flow_hw_pull(struct rte_eth_dev *dev,
	     uint32_t queue,
	     struct rte_flow_op_result res[],
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
				flow_hw_jump_release(dev, job->flow->jump);
			if (job->flow->cnt_id >= (uint32_t)
					(MLX5_INDIRECT_ACTION_TYPE_COUNT <<
					 MLX5_INDIRECT_ACTION_TYPE_OFFSET)) {
				mlx5_hws_cnt_pool_put(priv->hws_cpool, &queue,
						&job->flow->cnt_id);
				job->flow->cnt_id = 0;
			}
			mlx5_ipool_free(job->flow->table->flow, job->flow->idx);
		}
		priv->hw_q[queue].job[priv->hw_q[queue].job_idx++] = job;
	}
	return ret;
}

/**
 * Push the enqueued flows to HW.
 *
 * Force apply all the enqueued flows to the HW.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] queue
 *   The queue to push the flow.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static int
flow_hw_push(struct rte_eth_dev *dev,
	     uint32_t queue,
	     struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	int ret;

	ret = mlx5dr_send_queue_action(priv->dr_ctx, queue,
				       MLX5DR_SEND_QUEUE_ACTION_DRAIN);
	if (ret) {
		rte_flow_error_set(error, rte_errno,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				   "fail to push flows");
		return ret;
	}
	return 0;
}

/**
 * Drain the enqueued flows' completion.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] queue
 *   The queue to pull the flow.
 * @param[in] pending_rules
 *   The pending flow number.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static int
__flow_hw_pull_comp(struct rte_eth_dev *dev,
		    uint32_t queue,
		    uint32_t pending_rules,
		    struct rte_flow_error *error)
{
	struct rte_flow_op_result comp[BURST_THR];
	int ret, i, empty_loop = 0;

	ret = flow_hw_push(dev, queue, error);
	if (ret < 0)
		return ret;
	while (pending_rules) {
		ret = flow_hw_pull(dev, queue, comp, BURST_THR, error);
		if (ret < 0)
			return -1;
		if (!ret) {
			rte_delay_us_sleep(20000);
			if (++empty_loop > 5) {
				DRV_LOG(WARNING, "No available dequeue, quit.");
				break;
			}
			continue;
		}
		for (i = 0; i < ret; i++) {
			if (comp[i].status == RTE_FLOW_OP_ERROR)
				DRV_LOG(WARNING, "Flow flush get error CQE.");
		}
		if ((uint32_t)ret > pending_rules) {
			DRV_LOG(WARNING, "Flow flush get extra CQE.");
			return rte_flow_error_set(error, ERANGE,
					RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
					"get extra CQE");
		}
		pending_rules -= ret;
		empty_loop = 0;
	}
	return 0;
}

/**
 * Flush created flows.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
int
flow_hw_q_flow_flush(struct rte_eth_dev *dev,
		     struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_hw_q *hw_q;
	struct rte_flow_template_table *tbl;
	struct rte_flow_hw *flow;
	struct rte_flow_op_attr attr = {
		.postpone = 0,
	};
	uint32_t pending_rules = 0;
	uint32_t queue;
	uint32_t fidx;

	/*
	 * Ensure to push and dequeue all the enqueued flow
	 * creation/destruction jobs in case user forgot to
	 * dequeue. Or the enqueued created flows will be
	 * leaked. The forgotten dequeues would also cause
	 * flow flush get extra CQEs as expected and pending_rules
	 * be minus value.
	 */
	for (queue = 0; queue < priv->nb_queue; queue++) {
		hw_q = &priv->hw_q[queue];
		if (__flow_hw_pull_comp(dev, queue, hw_q->size - hw_q->job_idx,
					error))
			return -1;
	}
	/* Flush flow per-table from MLX5_DEFAULT_FLUSH_QUEUE. */
	hw_q = &priv->hw_q[MLX5_DEFAULT_FLUSH_QUEUE];
	LIST_FOREACH(tbl, &priv->flow_hw_tbl, next) {
		if (!tbl->cfg.external)
			continue;
		MLX5_IPOOL_FOREACH(tbl->flow, fidx, flow) {
			if (flow_hw_async_flow_destroy(dev,
						MLX5_DEFAULT_FLUSH_QUEUE,
						&attr,
						(struct rte_flow *)flow,
						NULL,
						error))
				return -1;
			pending_rules++;
			/* Drain completion with queue size. */
			if (pending_rules >= hw_q->size) {
				if (__flow_hw_pull_comp(dev,
						MLX5_DEFAULT_FLUSH_QUEUE,
						pending_rules, error))
					return -1;
				pending_rules = 0;
			}
		}
	}
	/* Drain left completion. */
	if (pending_rules &&
	    __flow_hw_pull_comp(dev, MLX5_DEFAULT_FLUSH_QUEUE, pending_rules,
				error))
		return -1;
	return 0;
}

/**
 * Create flow table.
 *
 * The input item and action templates will be binded to the table.
 * Flow memory will also be allocated. Matcher will be created based
 * on the item template. Action will be translated to the dedicated
 * DR action if possible.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] table_cfg
 *   Pointer to the table configuration.
 * @param[in] item_templates
 *   Item template array to be binded to the table.
 * @param[in] nb_item_templates
 *   Number of item template.
 * @param[in] action_templates
 *   Action template array to be binded to the table.
 * @param[in] nb_action_templates
 *   Number of action template.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    Table on success, NULL otherwise and rte_errno is set.
 */
static struct rte_flow_template_table *
flow_hw_table_create(struct rte_eth_dev *dev,
		     const struct mlx5_flow_template_table_cfg *table_cfg,
		     struct rte_flow_pattern_template *item_templates[],
		     uint8_t nb_item_templates,
		     struct rte_flow_actions_template *action_templates[],
		     uint8_t nb_action_templates,
		     struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5dr_matcher_attr matcher_attr = {0};
	struct rte_flow_template_table *tbl = NULL;
	struct mlx5_flow_group *grp;
	struct mlx5dr_match_template *mt[MLX5_HW_TBL_MAX_ITEM_TEMPLATE];
	const struct rte_flow_template_table_attr *attr = &table_cfg->attr;
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
		.release_mem_en = !!priv->sh->config.reclaim_mode,
		.malloc = mlx5_malloc,
		.free = mlx5_free,
		.type = "mlx5_hw_table_flow",
	};
	struct mlx5_list_entry *ge;
	uint32_t i, max_tpl = MLX5_HW_TBL_MAX_ITEM_TEMPLATE;
	uint32_t nb_flows = rte_align32pow2(attr->nb_flows);
	bool port_started = !!dev->data->dev_started;
	int err;

	/* HWS layer accepts only 1 item template with root table. */
	if (!attr->flow_attr.group)
		max_tpl = 1;
	cfg.max_idx = nb_flows;
	/*
	 * No need for local cache if flow number is a small number. Since
	 * flow insertion rate will be very limited in that case. Here let's
	 * set the number to less than default trunk size 4K.
	 */
	if (nb_flows <= cfg.trunk_size) {
		cfg.per_core_cache = 0;
		cfg.trunk_size = nb_flows;
	} else if (nb_flows <= MLX5_HW_TABLE_SIZE_THRESHOLD) {
		cfg.per_core_cache = MLX5_HW_TABLE_FLOW_CACHE_MIN;
	}
	/* Check if we requires too many templates. */
	if (nb_item_templates > max_tpl ||
	    nb_action_templates > MLX5_HW_TBL_MAX_ACTION_TEMPLATE) {
		rte_errno = EINVAL;
		goto error;
	}
	/* Allocate the table memory. */
	tbl = mlx5_malloc(MLX5_MEM_ZERO, sizeof(*tbl), 0, rte_socket_id());
	if (!tbl)
		goto error;
	tbl->cfg = *table_cfg;
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
		tbl->ats[i].action_template = action_templates[i];
		LIST_INIT(&tbl->ats[i].acts.act_list);
		if (!port_started)
			continue;
		err = __flow_hw_actions_translate(dev, &tbl->cfg,
						  &tbl->ats[i].acts,
						  action_templates[i], error);
		if (err) {
			i++;
			goto at_error;
		}
	}
	tbl->nb_action_templates = nb_action_templates;
	tbl->type = attr->flow_attr.transfer ? MLX5DR_TABLE_TYPE_FDB :
		    (attr->flow_attr.egress ? MLX5DR_TABLE_TYPE_NIC_TX :
		    MLX5DR_TABLE_TYPE_NIC_RX);
	if (port_started)
		LIST_INSERT_HEAD(&priv->flow_hw_tbl, tbl, next);
	else
		LIST_INSERT_HEAD(&priv->flow_hw_tbl_ongo, tbl, next);
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

/**
 * Update flow template table.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
int
flow_hw_table_update(struct rte_eth_dev *dev,
		     struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_flow_template_table *tbl;

	while ((tbl = LIST_FIRST(&priv->flow_hw_tbl_ongo)) != NULL) {
		if (flow_hw_actions_translate(dev, tbl, error))
			return -1;
		LIST_REMOVE(tbl, next);
		LIST_INSERT_HEAD(&priv->flow_hw_tbl, tbl, next);
	}
	return 0;
}

/**
 * Translates group index specified by the user in @p attr to internal
 * group index.
 *
 * Translation is done by incrementing group index, so group n becomes n + 1.
 *
 * @param[in] dev
 *   Pointer to Ethernet device.
 * @param[in] cfg
 *   Pointer to the template table configuration.
 * @param[in] group
 *   Currently used group index (table group or jump destination).
 * @param[out] table_group
 *   Pointer to output group index.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success. Otherwise, returns negative error code, rte_errno is set
 *   and error structure is filled.
 */
static int
flow_hw_translate_group(struct rte_eth_dev *dev,
			const struct mlx5_flow_template_table_cfg *cfg,
			uint32_t group,
			uint32_t *table_group,
			struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	const struct rte_flow_attr *flow_attr = &cfg->attr.flow_attr;

	if (priv->sh->config.dv_esw_en && cfg->external && flow_attr->transfer) {
		if (group > MLX5_HW_MAX_TRANSFER_GROUP)
			return rte_flow_error_set(error, EINVAL,
						  RTE_FLOW_ERROR_TYPE_ATTR_GROUP,
						  NULL,
						  "group index not supported");
		*table_group = group + 1;
	} else {
		*table_group = group;
	}
	return 0;
}

/**
 * Create flow table.
 *
 * This function is a wrapper over @ref flow_hw_table_create(), which translates parameters
 * provided by user to proper internal values.
 *
 * @param[in] dev
 *   Pointer to Ethernet device.
 * @param[in] attr
 *   Pointer to the table attributes.
 * @param[in] item_templates
 *   Item template array to be binded to the table.
 * @param[in] nb_item_templates
 *   Number of item templates.
 * @param[in] action_templates
 *   Action template array to be binded to the table.
 * @param[in] nb_action_templates
 *   Number of action templates.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   Table on success, Otherwise, returns negative error code, rte_errno is set
 *   and error structure is filled.
 */
static struct rte_flow_template_table *
flow_hw_template_table_create(struct rte_eth_dev *dev,
			      const struct rte_flow_template_table_attr *attr,
			      struct rte_flow_pattern_template *item_templates[],
			      uint8_t nb_item_templates,
			      struct rte_flow_actions_template *action_templates[],
			      uint8_t nb_action_templates,
			      struct rte_flow_error *error)
{
	struct mlx5_flow_template_table_cfg cfg = {
		.attr = *attr,
		.external = true,
	};
	uint32_t group = attr->flow_attr.group;

	if (flow_hw_translate_group(dev, &cfg, group, &cfg.attr.flow_attr.group, error))
		return NULL;
	return flow_hw_table_create(dev, &cfg, item_templates, nb_item_templates,
				    action_templates, nb_action_templates, error);
}

/**
 * Destroy flow table.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] table
 *   Pointer to the table to be destroyed.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_hw_table_destroy(struct rte_eth_dev *dev,
		      struct rte_flow_template_table *table,
		      struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	int i;
	uint32_t fidx = 1;

	/* Build ipool allocated object bitmap. */
	mlx5_ipool_flush_cache(table->flow);
	/* Check if ipool has allocated objects. */
	if (table->refcnt || mlx5_ipool_get_next(table->flow, &fidx)) {
		DRV_LOG(WARNING, "Table %p is still in using.", (void *)table);
		return rte_flow_error_set(error, EBUSY,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "table in using");
	}
	LIST_REMOVE(table, next);
	for (i = 0; i < table->nb_item_templates; i++)
		__atomic_sub_fetch(&table->its[i]->refcnt,
				   1, __ATOMIC_RELAXED);
	for (i = 0; i < table->nb_action_templates; i++) {
		if (table->ats[i].acts.mark)
			flow_hw_rxq_flag_set(dev, false);
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

static int
flow_hw_validate_action_modify_field(const struct rte_flow_action *action,
				     const struct rte_flow_action *mask,
				     struct rte_flow_error *error)
{
	const struct rte_flow_action_modify_field *action_conf =
		action->conf;
	const struct rte_flow_action_modify_field *mask_conf =
		mask->conf;

	if (action_conf->operation != mask_conf->operation)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, action,
				"modify_field operation mask and template are not equal");
	if (action_conf->dst.field != mask_conf->dst.field)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, action,
				"destination field mask and template are not equal");
	if (action_conf->dst.field == RTE_FLOW_FIELD_POINTER ||
	    action_conf->dst.field == RTE_FLOW_FIELD_VALUE)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, action,
				"immediate value and pointer cannot be used as destination");
	if (mask_conf->dst.level != UINT32_MAX)
		return rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_ACTION, action,
			"destination encapsulation level must be fully masked");
	if (mask_conf->dst.offset != UINT32_MAX)
		return rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_ACTION, action,
			"destination offset level must be fully masked");
	if (action_conf->src.field != mask_conf->src.field)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, action,
				"destination field mask and template are not equal");
	if (action_conf->src.field != RTE_FLOW_FIELD_POINTER &&
	    action_conf->src.field != RTE_FLOW_FIELD_VALUE) {
		if (mask_conf->src.level != UINT32_MAX)
			return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, action,
				"source encapsulation level must be fully masked");
		if (mask_conf->src.offset != UINT32_MAX)
			return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, action,
				"source offset level must be fully masked");
	}
	if (mask_conf->width != UINT32_MAX)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, action,
				"modify_field width field must be fully masked");
	return 0;
}

static int
flow_hw_validate_action_represented_port(struct rte_eth_dev *dev,
					 const struct rte_flow_action *action,
					 const struct rte_flow_action *mask,
					 struct rte_flow_error *error)
{
	const struct rte_flow_action_ethdev *action_conf = action->conf;
	const struct rte_flow_action_ethdev *mask_conf = mask->conf;
	struct mlx5_priv *priv = dev->data->dev_private;

	if (!priv->sh->config.dv_esw_en)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
					  "cannot use represented_port actions"
					  " without an E-Switch");
	if (mask_conf->port_id) {
		struct mlx5_priv *port_priv;
		struct mlx5_priv *dev_priv;

		port_priv = mlx5_port_to_eswitch_info(action_conf->port_id, false);
		if (!port_priv)
			return rte_flow_error_set(error, rte_errno,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  action,
						  "failed to obtain E-Switch"
						  " info for port");
		dev_priv = mlx5_dev_to_eswitch_info(dev);
		if (!dev_priv)
			return rte_flow_error_set(error, rte_errno,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  action,
						  "failed to obtain E-Switch"
						  " info for transfer proxy");
		if (port_priv->domain_id != dev_priv->domain_id)
			return rte_flow_error_set(error, rte_errno,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  action,
						  "cannot forward to port from"
						  " a different E-Switch");
	}
	return 0;
}

static inline int
flow_hw_action_meta_copy_insert(const struct rte_flow_action actions[],
				const struct rte_flow_action masks[],
				const struct rte_flow_action *ins_actions,
				const struct rte_flow_action *ins_masks,
				struct rte_flow_action *new_actions,
				struct rte_flow_action *new_masks,
				uint16_t *ins_pos)
{
	uint16_t idx, total = 0;
	bool ins = false;
	bool act_end = false;

	MLX5_ASSERT(actions && masks);
	MLX5_ASSERT(new_actions && new_masks);
	MLX5_ASSERT(ins_actions && ins_masks);
	for (idx = 0; !act_end; idx++) {
		if (idx >= MLX5_HW_MAX_ACTS)
			return -1;
		if (actions[idx].type == RTE_FLOW_ACTION_TYPE_RSS ||
		    actions[idx].type == RTE_FLOW_ACTION_TYPE_QUEUE) {
			ins = true;
			*ins_pos = idx;
		}
		if (actions[idx].type == RTE_FLOW_ACTION_TYPE_END)
			act_end = true;
	}
	if (!ins)
		return 0;
	else if (idx == MLX5_HW_MAX_ACTS)
		return -1; /* No more space. */
	total = idx;
	/* Before the position, no change for the actions. */
	for (idx = 0; idx < *ins_pos; idx++) {
		new_actions[idx] = actions[idx];
		new_masks[idx] = masks[idx];
	}
	/* Insert the new action and mask to the position. */
	new_actions[idx] = *ins_actions;
	new_masks[idx] = *ins_masks;
	/* Remaining content is right shifted by one position. */
	for (; idx < total; idx++) {
		new_actions[idx + 1] = actions[idx];
		new_masks[idx + 1] = masks[idx];
	}
	return 0;
}

static int
flow_hw_actions_validate(struct rte_eth_dev *dev,
			const struct rte_flow_actions_template_attr *attr,
			const struct rte_flow_action actions[],
			const struct rte_flow_action masks[],
			struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	uint16_t i;
	bool actions_end = false;
	int ret;

	/* FDB actions are only valid to proxy port. */
	if (attr->transfer && (!priv->sh->config.dv_esw_en || !priv->master))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL,
					  "transfer actions are only valid to proxy port");
	for (i = 0; !actions_end; ++i) {
		const struct rte_flow_action *action = &actions[i];
		const struct rte_flow_action *mask = &masks[i];

		MLX5_ASSERT(i < MLX5_HW_MAX_ACTS);
		if (action->type != mask->type)
			return rte_flow_error_set(error, ENOTSUP,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  action,
						  "mask type does not match action type");
		switch (action->type) {
		case RTE_FLOW_ACTION_TYPE_VOID:
			break;
		case RTE_FLOW_ACTION_TYPE_INDIRECT:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_MARK:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_DROP:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_JUMP:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_NVGRE_ENCAP:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_VXLAN_DECAP:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_NVGRE_DECAP:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_ENCAP:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_DECAP:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_METER:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_MODIFY_FIELD:
			ret = flow_hw_validate_action_modify_field(action,
									mask,
									error);
			if (ret < 0)
				return ret;
			break;
		case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
			ret = flow_hw_validate_action_represented_port
					(dev, action, mask, error);
			if (ret < 0)
				return ret;
			break;
		case RTE_FLOW_ACTION_TYPE_COUNT:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_END:
			actions_end = true;
			break;
		default:
			return rte_flow_error_set(error, ENOTSUP,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  action,
						  "action not supported in template API");
		}
	}
	return 0;
}

/**
 * Create flow action template.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] attr
 *   Pointer to the action template attributes.
 * @param[in] actions
 *   Associated actions (list terminated by the END action).
 * @param[in] masks
 *   List of actions that marks which of the action's member is constant.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   Action template pointer on success, NULL otherwise and rte_errno is set.
 */
static struct rte_flow_actions_template *
flow_hw_actions_template_create(struct rte_eth_dev *dev,
			const struct rte_flow_actions_template_attr *attr,
			const struct rte_flow_action actions[],
			const struct rte_flow_action masks[],
			struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	int len, act_len, mask_len, i;
	struct rte_flow_actions_template *at = NULL;
	uint16_t pos = MLX5_HW_MAX_ACTS;
	struct rte_flow_action tmp_action[MLX5_HW_MAX_ACTS];
	struct rte_flow_action tmp_mask[MLX5_HW_MAX_ACTS];
	const struct rte_flow_action *ra;
	const struct rte_flow_action *rm;
	const struct rte_flow_action_modify_field rx_mreg = {
		.operation = RTE_FLOW_MODIFY_SET,
		.dst = {
			.field = (enum rte_flow_field_id)MLX5_RTE_FLOW_FIELD_META_REG,
			.level = REG_B,
		},
		.src = {
			.field = (enum rte_flow_field_id)MLX5_RTE_FLOW_FIELD_META_REG,
			.level = REG_C_1,
		},
		.width = 32,
	};
	const struct rte_flow_action_modify_field rx_mreg_mask = {
		.operation = RTE_FLOW_MODIFY_SET,
		.dst = {
			.field = (enum rte_flow_field_id)MLX5_RTE_FLOW_FIELD_META_REG,
			.level = UINT32_MAX,
			.offset = UINT32_MAX,
		},
		.src = {
			.field = (enum rte_flow_field_id)MLX5_RTE_FLOW_FIELD_META_REG,
			.level = UINT32_MAX,
			.offset = UINT32_MAX,
		},
		.width = UINT32_MAX,
	};
	const struct rte_flow_action rx_cpy = {
		.type = RTE_FLOW_ACTION_TYPE_MODIFY_FIELD,
		.conf = &rx_mreg,
	};
	const struct rte_flow_action rx_cpy_mask = {
		.type = RTE_FLOW_ACTION_TYPE_MODIFY_FIELD,
		.conf = &rx_mreg_mask,
	};

	if (flow_hw_actions_validate(dev, attr, actions, masks, error))
		return NULL;
	if (priv->sh->config.dv_xmeta_en == MLX5_XMETA_MODE_META32_HWS &&
	    priv->sh->config.dv_esw_en) {
		if (flow_hw_action_meta_copy_insert(actions, masks, &rx_cpy, &rx_cpy_mask,
						    tmp_action, tmp_mask, &pos)) {
			rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_ACTION, NULL,
					   "Failed to concatenate new action/mask");
			return NULL;
		}
	}
	/* Application should make sure only one Q/RSS exist in one rule. */
	if (pos == MLX5_HW_MAX_ACTS) {
		ra = actions;
		rm = masks;
	} else {
		ra = tmp_action;
		rm = tmp_mask;
	}
	act_len = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS, NULL, 0, ra, error);
	if (act_len <= 0)
		return NULL;
	len = RTE_ALIGN(act_len, 16);
	mask_len = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS, NULL, 0, rm, error);
	if (mask_len <= 0)
		return NULL;
	len += RTE_ALIGN(mask_len, 16);
	at = mlx5_malloc(MLX5_MEM_ZERO, len + sizeof(*at),
			 RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (!at) {
		rte_flow_error_set(error, ENOMEM,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "cannot allocate action template");
		return NULL;
	}
	/* Actions part is in the first half. */
	at->attr = *attr;
	at->actions = (struct rte_flow_action *)(at + 1);
	act_len = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS, at->actions,
				len, ra, error);
	if (act_len <= 0)
		goto error;
	/* Masks part is in the second half. */
	at->masks = (struct rte_flow_action *)(((uint8_t *)at->actions) + act_len);
	mask_len = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS, at->masks,
				 len - act_len, rm, error);
	if (mask_len <= 0)
		goto error;
	at->rx_cpy_pos = pos;
	/*
	 * mlx5 PMD hacks indirect action index directly to the action conf.
	 * The rte_flow_conv() function copies the content from conf pointer.
	 * Need to restore the indirect action index from action conf here.
	 */
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
	if (at)
		mlx5_free(at);
	return NULL;
}

/**
 * Destroy flow action template.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] template
 *   Pointer to the action template to be destroyed.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_hw_actions_template_destroy(struct rte_eth_dev *dev __rte_unused,
				 struct rte_flow_actions_template *template,
				 struct rte_flow_error *error __rte_unused)
{
	if (__atomic_load_n(&template->refcnt, __ATOMIC_RELAXED) > 1) {
		DRV_LOG(WARNING, "Action template %p is still in use.",
			(void *)template);
		return rte_flow_error_set(error, EBUSY,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "action template in using");
	}
	LIST_REMOVE(template, next);
	mlx5_free(template);
	return 0;
}

static struct rte_flow_item *
flow_hw_copy_prepend_port_item(const struct rte_flow_item *items,
			       struct rte_flow_error *error)
{
	const struct rte_flow_item *curr_item;
	struct rte_flow_item *copied_items;
	bool found_end;
	unsigned int nb_items;
	unsigned int i;
	size_t size;

	/* Count number of pattern items. */
	nb_items = 0;
	found_end = false;
	for (curr_item = items; !found_end; ++curr_item) {
		++nb_items;
		if (curr_item->type == RTE_FLOW_ITEM_TYPE_END)
			found_end = true;
	}
	/* Allocate new array of items and prepend REPRESENTED_PORT item. */
	size = sizeof(*copied_items) * (nb_items + 1);
	copied_items = mlx5_malloc(MLX5_MEM_ZERO, size, 0, rte_socket_id());
	if (!copied_items) {
		rte_flow_error_set(error, ENOMEM,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "cannot allocate item template");
		return NULL;
	}
	copied_items[0] = (struct rte_flow_item){
		.type = RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT,
		.spec = NULL,
		.last = NULL,
		.mask = &rte_flow_item_ethdev_mask,
	};
	for (i = 1; i < nb_items + 1; ++i)
		copied_items[i] = items[i - 1];
	return copied_items;
}

static int
flow_hw_pattern_validate(struct rte_eth_dev *dev,
			 const struct rte_flow_pattern_template_attr *attr,
			 const struct rte_flow_item items[],
			 struct rte_flow_error *error)
{
	int i;
	bool items_end = false;
	RTE_SET_USED(dev);
	RTE_SET_USED(attr);

	for (i = 0; !items_end; i++) {
		int type = items[i].type;

		switch (type) {
		case RTE_FLOW_ITEM_TYPE_TAG:
		{
			int reg;
			const struct rte_flow_item_tag *tag =
				(const struct rte_flow_item_tag *)items[i].spec;

			reg = flow_hw_get_reg_id(RTE_FLOW_ITEM_TYPE_TAG, tag->index);
			if (reg == REG_NON)
				return rte_flow_error_set(error, EINVAL,
							  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
							  NULL,
							  "Unsupported tag index");
			break;
		}
		case MLX5_RTE_FLOW_ITEM_TYPE_TAG:
		{
			const struct rte_flow_item_tag *tag =
				(const struct rte_flow_item_tag *)items[i].spec;
			struct mlx5_priv *priv = dev->data->dev_private;
			uint8_t regcs = (uint8_t)priv->sh->cdev->config.hca_attr.set_reg_c;

			if (!((1 << (tag->index - REG_C_0)) & regcs))
				return rte_flow_error_set(error, EINVAL,
							  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
							  NULL,
							  "Unsupported internal tag index");
		}
		case RTE_FLOW_ITEM_TYPE_VOID:
		case RTE_FLOW_ITEM_TYPE_ETH:
		case RTE_FLOW_ITEM_TYPE_IPV4:
		case RTE_FLOW_ITEM_TYPE_IPV6:
		case RTE_FLOW_ITEM_TYPE_UDP:
		case RTE_FLOW_ITEM_TYPE_TCP:
		case RTE_FLOW_ITEM_TYPE_GTP:
		case RTE_FLOW_ITEM_TYPE_GTP_PSC:
		case RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT:
		case RTE_FLOW_ITEM_TYPE_VXLAN:
		case MLX5_RTE_FLOW_ITEM_TYPE_TX_QUEUE:
		case RTE_FLOW_ITEM_TYPE_META:
		case RTE_FLOW_ITEM_TYPE_GRE:
		case RTE_FLOW_ITEM_TYPE_GRE_KEY:
		case RTE_FLOW_ITEM_TYPE_GRE_OPTION:
			break;
		case RTE_FLOW_ITEM_TYPE_END:
			items_end = true;
			break;
		default:
			return rte_flow_error_set(error, EINVAL,
						  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
						  NULL,
						  "Unsupported item type");
		}
	}
	return 0;
}

/**
 * Create flow item template.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] attr
 *   Pointer to the item template attributes.
 * @param[in] items
 *   The template item pattern.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *  Item template pointer on success, NULL otherwise and rte_errno is set.
 */
static struct rte_flow_pattern_template *
flow_hw_pattern_template_create(struct rte_eth_dev *dev,
			     const struct rte_flow_pattern_template_attr *attr,
			     const struct rte_flow_item items[],
			     struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_flow_pattern_template *it;
	struct rte_flow_item *copied_items = NULL;
	const struct rte_flow_item *tmpl_items;

	if (flow_hw_pattern_validate(dev, attr, items, error))
		return NULL;
	if (priv->sh->config.dv_esw_en && attr->ingress) {
		/*
		 * Disallow pattern template with ingress and egress/transfer
		 * attributes in order to forbid implicit port matching
		 * on egress and transfer traffic.
		 */
		if (attr->egress || attr->transfer) {
			rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					   NULL,
					   "item template for ingress traffic"
					   " cannot be used for egress/transfer"
					   " traffic when E-Switch is enabled");
			return NULL;
		}
		copied_items = flow_hw_copy_prepend_port_item(items, error);
		if (!copied_items)
			return NULL;
		tmpl_items = copied_items;
	} else {
		tmpl_items = items;
	}
	it = mlx5_malloc(MLX5_MEM_ZERO, sizeof(*it), 0, rte_socket_id());
	if (!it) {
		if (copied_items)
			mlx5_free(copied_items);
		rte_flow_error_set(error, ENOMEM,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "cannot allocate item template");
		return NULL;
	}
	it->attr = *attr;
	it->mt = mlx5dr_match_template_create(tmpl_items, attr->relaxed_matching);
	if (!it->mt) {
		if (copied_items)
			mlx5_free(copied_items);
		mlx5_free(it);
		rte_flow_error_set(error, rte_errno,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "cannot create match template");
		return NULL;
	}
	it->item_flags = flow_hw_rss_item_flags_get(tmpl_items);
	it->implicit_port = !!copied_items;
	__atomic_fetch_add(&it->refcnt, 1, __ATOMIC_RELAXED);
	LIST_INSERT_HEAD(&priv->flow_hw_itt, it, next);
	if (copied_items)
		mlx5_free(copied_items);
	return it;
}

/**
 * Destroy flow item template.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] template
 *   Pointer to the item template to be destroyed.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_hw_pattern_template_destroy(struct rte_eth_dev *dev __rte_unused,
			      struct rte_flow_pattern_template *template,
			      struct rte_flow_error *error __rte_unused)
{
	if (__atomic_load_n(&template->refcnt, __ATOMIC_RELAXED) > 1) {
		DRV_LOG(WARNING, "Item template %p is still in use.",
			(void *)template);
		return rte_flow_error_set(error, EBUSY,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "item template in using");
	}
	LIST_REMOVE(template, next);
	claim_zero(mlx5dr_match_template_destroy(template->mt));
	mlx5_free(template);
	return 0;
}

/*
 * Get information about HWS pre-configurable resources.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[out] port_info
 *   Pointer to port information.
 * @param[out] queue_info
 *   Pointer to queue information.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_hw_info_get(struct rte_eth_dev *dev,
		 struct rte_flow_port_info *port_info,
		 struct rte_flow_queue_info *queue_info,
		 struct rte_flow_error *error __rte_unused)
{
	uint16_t port_id = dev->data->port_id;
	struct rte_mtr_capabilities mtr_cap;
	int ret;

	memset(port_info, 0, sizeof(*port_info));
	/* Queue size is unlimited from low-level. */
	port_info->max_nb_queues = UINT32_MAX;
	queue_info->max_size = UINT32_MAX;

	memset(&mtr_cap, 0, sizeof(struct rte_mtr_capabilities));
	ret = rte_mtr_capabilities_get(port_id, &mtr_cap, NULL);
	if (!ret) {
		port_info->max_nb_meters = mtr_cap.n_max;
		port_info->max_nb_meter_profiles = UINT32_MAX;
		port_info->max_nb_meter_policies = UINT32_MAX;
	}
	return 0;
}

/**
 * Create group callback.
 *
 * @param[in] tool_ctx
 *   Pointer to the hash list related context.
 * @param[in] cb_ctx
 *   Pointer to the group creation context.
 *
 * @return
 *   Group entry on success, NULL otherwise and rte_errno is set.
 */
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
		/* Jump action be used by non-root table. */
		jump = mlx5dr_action_create_dest_table
			(priv->dr_ctx, tbl,
			 mlx5_hw_act_flag[!!attr->group][dr_tbl_attr.type]);
		if (!jump)
			goto error;
		grp_data->jump.hws_action = jump;
		/* Jump action be used by root table.  */
		jump = mlx5dr_action_create_dest_table
			(priv->dr_ctx, tbl,
			 mlx5_hw_act_flag[MLX5_HW_ACTION_FLAG_ROOT]
					 [dr_tbl_attr.type]);
		if (!jump)
			goto error;
		grp_data->jump.root_action = jump;
	}
	grp_data->dev = dev;
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

/**
 * Remove group callback.
 *
 * @param[in] tool_ctx
 *   Pointer to the hash list related context.
 * @param[in] entry
 *   Pointer to the entry to be removed.
 */
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

/**
 * Match group callback.
 *
 * @param[in] tool_ctx
 *   Pointer to the hash list related context.
 * @param[in] entry
 *   Pointer to the group to be matched.
 * @param[in] cb_ctx
 *   Pointer to the group matching context.
 *
 * @return
 *   0 on matched, 1 on miss matched.
 */
int
flow_hw_grp_match_cb(void *tool_ctx __rte_unused, struct mlx5_list_entry *entry,
		     void *cb_ctx)
{
	struct mlx5_flow_cb_ctx *ctx = cb_ctx;
	struct mlx5_flow_group *grp_data =
		container_of(entry, struct mlx5_flow_group, entry);
	struct rte_flow_attr *attr =
			(struct rte_flow_attr *)ctx->data;

	return (grp_data->dev != ctx->dev) ||
		(grp_data->group_id != attr->group) ||
		((grp_data->type != MLX5DR_TABLE_TYPE_FDB) &&
		attr->transfer) ||
		((grp_data->type != MLX5DR_TABLE_TYPE_NIC_TX) &&
		attr->egress) ||
		((grp_data->type != MLX5DR_TABLE_TYPE_NIC_RX) &&
		attr->ingress);
}

/**
 * Clone group entry callback.
 *
 * @param[in] tool_ctx
 *   Pointer to the hash list related context.
 * @param[in] entry
 *   Pointer to the group to be matched.
 * @param[in] cb_ctx
 *   Pointer to the group matching context.
 *
 * @return
 *   0 on matched, 1 on miss matched.
 */
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

/**
 * Free cloned group entry callback.
 *
 * @param[in] tool_ctx
 *   Pointer to the hash list related context.
 * @param[in] entry
 *   Pointer to the group to be freed.
 */
void
flow_hw_grp_clone_free_cb(void *tool_ctx, struct mlx5_list_entry *entry)
{
	struct mlx5_dev_ctx_shared *sh = tool_ctx;
	struct mlx5_flow_group *grp_data =
		    container_of(entry, struct mlx5_flow_group, entry);

	mlx5_ipool_free(sh->ipool[MLX5_IPOOL_HW_GRP], grp_data->idx);
}

/**
 * Create and cache a vport action for given @p dev port. vport actions
 * cache is used in HWS with FDB flows.
 *
 * This function does not create any function if proxy port for @p dev port
 * was not configured for HW Steering.
 *
 * This function assumes that E-Switch is enabled and PMD is running with
 * HW Steering configured.
 *
 * @param dev
 *   Pointer to Ethernet device which will be the action destination.
 *
 * @return
 *   0 on success, positive value otherwise.
 */
int
flow_hw_create_vport_action(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_eth_dev *proxy_dev;
	struct mlx5_priv *proxy_priv;
	uint16_t port_id = dev->data->port_id;
	uint16_t proxy_port_id = port_id;
	int ret;

	ret = mlx5_flow_pick_transfer_proxy(dev, &proxy_port_id, NULL);
	if (ret)
		return ret;
	proxy_dev = &rte_eth_devices[proxy_port_id];
	proxy_priv = proxy_dev->data->dev_private;
	if (!proxy_priv->hw_vport)
		return 0;
	if (proxy_priv->hw_vport[port_id]) {
		DRV_LOG(ERR, "port %u HWS vport action already created",
			port_id);
		return -EINVAL;
	}
	proxy_priv->hw_vport[port_id] = mlx5dr_action_create_dest_vport
			(proxy_priv->dr_ctx, priv->dev_port,
			 MLX5DR_ACTION_FLAG_HWS_FDB);
	if (!proxy_priv->hw_vport[port_id]) {
		DRV_LOG(ERR, "port %u unable to create HWS vport action",
			port_id);
		return -EINVAL;
	}
	return 0;
}

/**
 * Destroys the vport action associated with @p dev device
 * from actions' cache.
 *
 * This function does not destroy any action if there is no action cached
 * for @p dev or proxy port was not configured for HW Steering.
 *
 * This function assumes that E-Switch is enabled and PMD is running with
 * HW Steering configured.
 *
 * @param dev
 *   Pointer to Ethernet device which will be the action destination.
 */
void
flow_hw_destroy_vport_action(struct rte_eth_dev *dev)
{
	struct rte_eth_dev *proxy_dev;
	struct mlx5_priv *proxy_priv;
	uint16_t port_id = dev->data->port_id;
	uint16_t proxy_port_id = port_id;

	if (mlx5_flow_pick_transfer_proxy(dev, &proxy_port_id, NULL))
		return;
	proxy_dev = &rte_eth_devices[proxy_port_id];
	proxy_priv = proxy_dev->data->dev_private;
	if (!proxy_priv->hw_vport || !proxy_priv->hw_vport[port_id])
		return;
	mlx5dr_action_destroy(proxy_priv->hw_vport[port_id]);
	proxy_priv->hw_vport[port_id] = NULL;
}

static int
flow_hw_create_vport_actions(struct mlx5_priv *priv)
{
	uint16_t port_id;

	MLX5_ASSERT(!priv->hw_vport);
	priv->hw_vport = mlx5_malloc(MLX5_MEM_ZERO,
				     sizeof(*priv->hw_vport) * RTE_MAX_ETHPORTS,
				     0, SOCKET_ID_ANY);
	if (!priv->hw_vport)
		return -ENOMEM;
	DRV_LOG(DEBUG, "port %u :: creating vport actions", priv->dev_data->port_id);
	DRV_LOG(DEBUG, "port %u ::    domain_id=%u", priv->dev_data->port_id, priv->domain_id);
	MLX5_ETH_FOREACH_DEV(port_id, NULL) {
		struct mlx5_priv *port_priv = rte_eth_devices[port_id].data->dev_private;

		if (!port_priv ||
		    port_priv->domain_id != priv->domain_id)
			continue;
		DRV_LOG(DEBUG, "port %u :: for port_id=%u, calling mlx5dr_action_create_dest_vport() with ibport=%u",
			priv->dev_data->port_id, port_id, port_priv->dev_port);
		priv->hw_vport[port_id] = mlx5dr_action_create_dest_vport
				(priv->dr_ctx, port_priv->dev_port,
				 MLX5DR_ACTION_FLAG_HWS_FDB);
		DRV_LOG(DEBUG, "port %u :: priv->hw_vport[%u]=%p",
			priv->dev_data->port_id, port_id, (void *)priv->hw_vport[port_id]);
		if (!priv->hw_vport[port_id])
			return -EINVAL;
	}
	return 0;
}

static void
flow_hw_free_vport_actions(struct mlx5_priv *priv)
{
	uint16_t port_id;

	if (!priv->hw_vport)
		return;
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; ++port_id)
		if (priv->hw_vport[port_id])
			mlx5dr_action_destroy(priv->hw_vport[port_id]);
	mlx5_free(priv->hw_vport);
	priv->hw_vport = NULL;
}

/**
 * Creates a flow pattern template used to match on E-Switch Manager.
 * This template is used to set up a table for SQ miss default flow.
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   Pointer to flow pattern template on success, NULL otherwise.
 */
static struct rte_flow_pattern_template *
flow_hw_create_ctrl_esw_mgr_pattern_template(struct rte_eth_dev *dev)
{
	struct rte_flow_pattern_template_attr attr = {
		.relaxed_matching = 0,
		.transfer = 1,
	};
	struct rte_flow_item_ethdev port_spec = {
		.port_id = MLX5_REPRESENTED_PORT_ESW_MGR,
	};
	struct rte_flow_item_ethdev port_mask = {
		.port_id = UINT16_MAX,
	};
	struct rte_flow_item items[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT,
			.spec = &port_spec,
			.mask = &port_mask,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};

	return flow_hw_pattern_template_create(dev, &attr, items, NULL);
}

/**
 * Creates a flow pattern template used to match on a TX queue.
 * This template is used to set up a table for SQ miss default flow.
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   Pointer to flow pattern template on success, NULL otherwise.
 */
static struct rte_flow_pattern_template *
flow_hw_create_ctrl_sq_pattern_template(struct rte_eth_dev *dev)
{
	struct rte_flow_pattern_template_attr attr = {
		.relaxed_matching = 0,
		.transfer = 1,
	};
	struct mlx5_rte_flow_item_tx_queue queue_mask = {
		.queue = UINT32_MAX,
	};
	struct rte_flow_item items[] = {
		{
			.type = (enum rte_flow_item_type)
				MLX5_RTE_FLOW_ITEM_TYPE_TX_QUEUE,
			.mask = &queue_mask,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};

	return flow_hw_pattern_template_create(dev, &attr, items, NULL);
}

/**
 * Creates a flow pattern template with unmasked represented port matching.
 * This template is used to set up a table for default transfer flows
 * directing packets to group 1.
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   Pointer to flow pattern template on success, NULL otherwise.
 */
static struct rte_flow_pattern_template *
flow_hw_create_ctrl_port_pattern_template(struct rte_eth_dev *dev)
{
	struct rte_flow_pattern_template_attr attr = {
		.relaxed_matching = 0,
		.transfer = 1,
	};
	struct rte_flow_item_ethdev port_mask = {
		.port_id = UINT16_MAX,
	};
	struct rte_flow_item items[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT,
			.mask = &port_mask,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};

	return flow_hw_pattern_template_create(dev, &attr, items, NULL);
}

/**
 * Creates a flow actions template with an unmasked JUMP action. Flows
 * based on this template will perform a jump to some group. This template
 * is used to set up tables for control flows.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param group
 *   Destination group for this action template.
 *
 * @return
 *   Pointer to flow actions template on success, NULL otherwise.
 */
static struct rte_flow_actions_template *
flow_hw_create_ctrl_jump_actions_template(struct rte_eth_dev *dev,
					  uint32_t group)
{
	struct rte_flow_actions_template_attr attr = {
		.transfer = 1,
	};
	struct rte_flow_action_jump jump_v = {
		.group = group,
	};
	struct rte_flow_action_jump jump_m = {
		.group = UINT32_MAX,
	};
	struct rte_flow_action actions_v[] = {
		{
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &jump_v,
		},
		{
			.type = RTE_FLOW_ACTION_TYPE_END,
		}
	};
	struct rte_flow_action actions_m[] = {
		{
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &jump_m,
		},
		{
			.type = RTE_FLOW_ACTION_TYPE_END,
		}
	};

	return flow_hw_actions_template_create(dev, &attr, actions_v, actions_m,
					       NULL);
}

/**
 * Creates a flow action template with a unmasked REPRESENTED_PORT action.
 * It is used to create control flow tables.
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   Pointer to flow action template on success, NULL otherwise.
 */
static struct rte_flow_actions_template *
flow_hw_create_ctrl_port_actions_template(struct rte_eth_dev *dev)
{
	struct rte_flow_actions_template_attr attr = {
		.transfer = 1,
	};
	struct rte_flow_action_ethdev port_v = {
		.port_id = 0,
	};
	struct rte_flow_action actions_v[] = {
		{
			.type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT,
			.conf = &port_v,
		},
		{
			.type = RTE_FLOW_ACTION_TYPE_END,
		}
	};
	struct rte_flow_action_ethdev port_m = {
		.port_id = 0,
	};
	struct rte_flow_action actions_m[] = {
		{
			.type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT,
			.conf = &port_m,
		},
		{
			.type = RTE_FLOW_ACTION_TYPE_END,
		}
	};

	return flow_hw_actions_template_create(dev, &attr, actions_v, actions_m,
					       NULL);
}

/**
 * Creates a control flow table used to transfer traffic from E-Switch Manager
 * and TX queues from group 0 to group 1.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param it
 *   Pointer to flow pattern template.
 * @param at
 *   Pointer to flow actions template.
 *
 * @return
 *   Pointer to flow table on success, NULL otherwise.
 */
static struct rte_flow_template_table*
flow_hw_create_ctrl_sq_miss_root_table(struct rte_eth_dev *dev,
				       struct rte_flow_pattern_template *it,
				       struct rte_flow_actions_template *at)
{
	struct rte_flow_template_table_attr attr = {
		.flow_attr = {
			.group = 0,
			.priority = 0,
			.ingress = 0,
			.egress = 0,
			.transfer = 1,
			.hint_num_of_rules_log = 0,
		},
		.nb_flows = MLX5_HW_CTRL_FLOW_NB_RULES,
	};
	struct mlx5_flow_template_table_cfg cfg = {
		.attr = attr,
		.external = false,
	};

	return flow_hw_table_create(dev, &cfg, &it, 1, &at, 1, NULL);
}


/**
 * Creates a control flow table used to transfer traffic from E-Switch Manager
 * and TX queues from group 0 to group 1.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param it
 *   Pointer to flow pattern template.
 * @param at
 *   Pointer to flow actions template.
 *
 * @return
 *   Pointer to flow table on success, NULL otherwise.
 */
static struct rte_flow_template_table*
flow_hw_create_ctrl_sq_miss_table(struct rte_eth_dev *dev,
				  struct rte_flow_pattern_template *it,
				  struct rte_flow_actions_template *at)
{
	struct rte_flow_template_table_attr attr = {
		.flow_attr = {
			.group = MLX5_HW_SQ_MISS_GROUP,
			.priority = 0,
			.ingress = 0,
			.egress = 0,
			.transfer = 1,
			.hint_num_of_rules_log = 0,
		},
		.nb_flows = MLX5_HW_CTRL_FLOW_NB_RULES,
	};
	struct mlx5_flow_template_table_cfg cfg = {
		.attr = attr,
		.external = false,
	};

	return flow_hw_table_create(dev, &cfg, &it, 1, &at, 1, NULL);
}

/**
 * Creates a control flow table used to transfer traffic
 * from group 0 to group 1.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param it
 *   Pointer to flow pattern template.
 * @param at
 *   Pointer to flow actions template.
 *
 * @return
 *   Pointer to flow table on success, NULL otherwise.
 */
static struct rte_flow_template_table *
flow_hw_create_ctrl_jump_table(struct rte_eth_dev *dev,
			       struct rte_flow_pattern_template *it,
			       struct rte_flow_actions_template *at)
{
	struct rte_flow_template_table_attr attr = {
		.flow_attr = {
			.group = 0,
			.priority = MLX5_HW_LOWEST_PRIO_ROOT,
			.ingress = 0,
			.egress = 0,
			.transfer = 1,
			.hint_num_of_rules_log = 0,
		},
		.nb_flows = MLX5_HW_CTRL_FLOW_NB_RULES,
	};
	struct mlx5_flow_template_table_cfg cfg = {
		.attr = attr,
		.external = false,
	};

	return flow_hw_table_create(dev, &cfg, &it, 1, &at, 1, NULL);
}

/**
 * Creates a set of flow tables used to create control flows used
 * when E-Switch is engaged.
 *
 * @param dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   0 on success, EINVAL otherwise
 */
static __rte_unused int
flow_hw_create_ctrl_tables(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_flow_pattern_template *esw_mgr_items_tmpl = NULL;
	struct rte_flow_pattern_template *sq_items_tmpl = NULL;
	struct rte_flow_pattern_template *port_items_tmpl = NULL;
	struct rte_flow_actions_template *jump_sq_actions_tmpl = NULL;
	struct rte_flow_actions_template *port_actions_tmpl = NULL;
	struct rte_flow_actions_template *jump_one_actions_tmpl = NULL;

	/* Item templates */
	esw_mgr_items_tmpl = flow_hw_create_ctrl_esw_mgr_pattern_template(dev);
	if (!esw_mgr_items_tmpl) {
		DRV_LOG(ERR, "port %u failed to create E-Switch Manager item"
			" template for control flows", dev->data->port_id);
		goto error;
	}
	sq_items_tmpl = flow_hw_create_ctrl_sq_pattern_template(dev);
	if (!sq_items_tmpl) {
		DRV_LOG(ERR, "port %u failed to create SQ item template for"
			" control flows", dev->data->port_id);
		goto error;
	}
	port_items_tmpl = flow_hw_create_ctrl_port_pattern_template(dev);
	if (!port_items_tmpl) {
		DRV_LOG(ERR, "port %u failed to create SQ item template for"
			" control flows", dev->data->port_id);
		goto error;
	}
	/* Action templates */
	jump_sq_actions_tmpl = flow_hw_create_ctrl_jump_actions_template(dev,
									 MLX5_HW_SQ_MISS_GROUP);
	if (!jump_sq_actions_tmpl) {
		DRV_LOG(ERR, "port %u failed to create jump action template"
			" for control flows", dev->data->port_id);
		goto error;
	}
	port_actions_tmpl = flow_hw_create_ctrl_port_actions_template(dev);
	if (!port_actions_tmpl) {
		DRV_LOG(ERR, "port %u failed to create port action template"
			" for control flows", dev->data->port_id);
		goto error;
	}
	jump_one_actions_tmpl = flow_hw_create_ctrl_jump_actions_template(dev, 1);
	if (!jump_one_actions_tmpl) {
		DRV_LOG(ERR, "port %u failed to create jump action template"
			" for control flows", dev->data->port_id);
		goto error;
	}
	/* Tables */
	MLX5_ASSERT(priv->hw_esw_sq_miss_root_tbl == NULL);
	priv->hw_esw_sq_miss_root_tbl = flow_hw_create_ctrl_sq_miss_root_table
			(dev, esw_mgr_items_tmpl, jump_sq_actions_tmpl);
	if (!priv->hw_esw_sq_miss_root_tbl) {
		DRV_LOG(ERR, "port %u failed to create table for default sq miss (root table)"
			" for control flows", dev->data->port_id);
		goto error;
	}
	MLX5_ASSERT(priv->hw_esw_sq_miss_tbl == NULL);
	priv->hw_esw_sq_miss_tbl = flow_hw_create_ctrl_sq_miss_table(dev, sq_items_tmpl,
								     port_actions_tmpl);
	if (!priv->hw_esw_sq_miss_tbl) {
		DRV_LOG(ERR, "port %u failed to create table for default sq miss (non-root table)"
			" for control flows", dev->data->port_id);
		goto error;
	}
	MLX5_ASSERT(priv->hw_esw_zero_tbl == NULL);
	priv->hw_esw_zero_tbl = flow_hw_create_ctrl_jump_table(dev, port_items_tmpl,
							       jump_one_actions_tmpl);
	if (!priv->hw_esw_zero_tbl) {
		DRV_LOG(ERR, "port %u failed to create table for default jump to group 1"
			" for control flows", dev->data->port_id);
		goto error;
	}
	return 0;
error:
	if (priv->hw_esw_zero_tbl) {
		flow_hw_table_destroy(dev, priv->hw_esw_zero_tbl, NULL);
		priv->hw_esw_zero_tbl = NULL;
	}
	if (priv->hw_esw_sq_miss_tbl) {
		flow_hw_table_destroy(dev, priv->hw_esw_sq_miss_tbl, NULL);
		priv->hw_esw_sq_miss_tbl = NULL;
	}
	if (priv->hw_esw_sq_miss_root_tbl) {
		flow_hw_table_destroy(dev, priv->hw_esw_sq_miss_root_tbl, NULL);
		priv->hw_esw_sq_miss_root_tbl = NULL;
	}
	if (jump_one_actions_tmpl)
		flow_hw_actions_template_destroy(dev, jump_one_actions_tmpl, NULL);
	if (port_actions_tmpl)
		flow_hw_actions_template_destroy(dev, port_actions_tmpl, NULL);
	if (jump_sq_actions_tmpl)
		flow_hw_actions_template_destroy(dev, jump_sq_actions_tmpl, NULL);
	if (port_items_tmpl)
		flow_hw_pattern_template_destroy(dev, port_items_tmpl, NULL);
	if (sq_items_tmpl)
		flow_hw_pattern_template_destroy(dev, sq_items_tmpl, NULL);
	if (esw_mgr_items_tmpl)
		flow_hw_pattern_template_destroy(dev, esw_mgr_items_tmpl, NULL);
	return -EINVAL;
}

/**
 * Configure port HWS resources.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] port_attr
 *   Port configuration attributes.
 * @param[in] nb_queue
 *   Number of queue.
 * @param[in] queue_attr
 *   Array that holds attributes for each flow queue.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_hw_configure(struct rte_eth_dev *dev,
		  const struct rte_flow_port_attr *port_attr,
		  uint16_t nb_queue,
		  const struct rte_flow_queue_attr *queue_attr[],
		  struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5dr_context *dr_ctx = NULL;
	struct mlx5dr_context_attr dr_ctx_attr = {0};
	struct mlx5_hw_q *hw_q;
	struct mlx5_hw_q_job *job = NULL;
	uint32_t mem_size, i, j;
	struct mlx5_indexed_pool_config cfg = {
		.size = sizeof(struct rte_flow_hw),
		.trunk_size = 4096,
		.need_lock = 1,
		.release_mem_en = !!priv->sh->config.reclaim_mode,
		.malloc = mlx5_malloc,
		.free = mlx5_free,
		.type = "mlx5_hw_action_construct_data",
	};
	/* Adds one queue to be used by PMD.
	 * The last queue will be used by the PMD.
	 */
	uint16_t nb_q_updated;
	struct rte_flow_queue_attr **_queue_attr = NULL;
	struct rte_flow_queue_attr ctrl_queue_attr = {0};
	bool is_proxy = !!(priv->sh->config.dv_esw_en && priv->master);
	int ret = 0;

	if (!port_attr || !nb_queue || !queue_attr) {
		rte_errno = EINVAL;
		goto err;
	}
	/* In case re-configuring, release existing context at first. */
	if (priv->dr_ctx) {
		/* */
		for (i = 0; i < priv->nb_queue; i++) {
			hw_q = &priv->hw_q[i];
			/* Make sure all queues are empty. */
			if (hw_q->size != hw_q->job_idx) {
				rte_errno = EBUSY;
				goto err;
			}
		}
		flow_hw_resource_release(dev);
	}
	ctrl_queue_attr.size = queue_attr[0]->size;
	nb_q_updated = nb_queue + 1;
	_queue_attr = mlx5_malloc(MLX5_MEM_ZERO,
				  nb_q_updated *
				  sizeof(struct rte_flow_queue_attr *),
				  64, SOCKET_ID_ANY);
	if (!_queue_attr) {
		rte_errno = ENOMEM;
		goto err;
	}

	memcpy(_queue_attr, queue_attr,
	       sizeof(void *) * nb_queue);
	_queue_attr[nb_queue] = &ctrl_queue_attr;
	priv->acts_ipool = mlx5_ipool_create(&cfg);
	if (!priv->acts_ipool)
		goto err;
	/* Allocate the queue job descriptor LIFO. */
	mem_size = sizeof(priv->hw_q[0]) * nb_q_updated;
	for (i = 0; i < nb_q_updated; i++) {
		/*
		 * Check if the queues' size are all the same as the
		 * limitation from HWS layer.
		 */
		if (_queue_attr[i]->size != _queue_attr[0]->size) {
			rte_errno = EINVAL;
			goto err;
		}
		mem_size += (sizeof(struct mlx5_hw_q_job *) +
			    sizeof(struct mlx5_hw_q_job) +
			    sizeof(uint8_t) * MLX5_ENCAP_MAX_LEN +
			    sizeof(struct mlx5_modification_cmd) *
			    MLX5_MHDR_MAX_CMD +
			    sizeof(struct rte_flow_item) *
			    MLX5_HW_MAX_ITEMS) *
			    _queue_attr[i]->size;
	}
	priv->hw_q = mlx5_malloc(MLX5_MEM_ZERO, mem_size,
				 64, SOCKET_ID_ANY);
	if (!priv->hw_q) {
		rte_errno = ENOMEM;
		goto err;
	}
	for (i = 0; i < nb_q_updated; i++) {
		uint8_t *encap = NULL;
		struct mlx5_modification_cmd *mhdr_cmd = NULL;
		struct rte_flow_item *items = NULL;

		priv->hw_q[i].job_idx = _queue_attr[i]->size;
		priv->hw_q[i].size = _queue_attr[i]->size;
		if (i == 0)
			priv->hw_q[i].job = (struct mlx5_hw_q_job **)
					    &priv->hw_q[nb_q_updated];
		else
			priv->hw_q[i].job = (struct mlx5_hw_q_job **)
				&job[_queue_attr[i - 1]->size - 1].encap_data
				 [MLX5_ENCAP_MAX_LEN];
		job = (struct mlx5_hw_q_job *)
		      &priv->hw_q[i].job[_queue_attr[i]->size];
		mhdr_cmd = (struct mlx5_modification_cmd *)
			   &job[_queue_attr[i]->size];
		encap = (uint8_t *)
			 &mhdr_cmd[_queue_attr[i]->size * MLX5_MHDR_MAX_CMD];
		items = (struct rte_flow_item *)
			 &encap[_queue_attr[i]->size * MLX5_ENCAP_MAX_LEN];
		for (j = 0; j < _queue_attr[i]->size; j++) {
			job[j].mhdr_cmd = &mhdr_cmd[j * MLX5_MHDR_MAX_CMD];
			job[j].encap_data = &encap[j * MLX5_ENCAP_MAX_LEN];
			job[j].items = &items[j * MLX5_HW_MAX_ITEMS];
			priv->hw_q[i].job[j] = &job[j];
		}
	}
	dr_ctx_attr.pd = priv->sh->cdev->pd;
	dr_ctx_attr.queues = nb_q_updated;
	/* Queue size should all be the same. Take the first one. */
	dr_ctx_attr.queue_size = _queue_attr[0]->size;
	dr_ctx = mlx5dr_context_open(priv->sh->cdev->ctx, &dr_ctx_attr);
	/* rte_errno has been updated by HWS layer. */
	if (!dr_ctx)
		goto err;
	priv->dr_ctx = dr_ctx;
	priv->nb_queue = nb_q_updated;
	rte_spinlock_init(&priv->hw_ctrl_lock);
	LIST_INIT(&priv->hw_ctrl_flows);
	/* Initialize meter library*/
	if (port_attr->nb_meters)
		if (mlx5_flow_meter_init(dev,
					port_attr->nb_meters,
					port_attr->nb_meter_profiles,
					port_attr->nb_meter_policies))
			goto err;
	/* Add global actions. */
	for (i = 0; i < MLX5_HW_ACTION_FLAG_MAX; i++) {
		uint32_t act_flags = 0;

		act_flags = mlx5_hw_act_flag[i][0] | mlx5_hw_act_flag[i][1];
		if (is_proxy)
			act_flags |= mlx5_hw_act_flag[i][2];
		priv->hw_drop[i] = mlx5dr_action_create_dest_drop(priv->dr_ctx, act_flags);
		if (!priv->hw_drop[i])
			goto err;
		priv->hw_tag[i] = mlx5dr_action_create_tag
			(priv->dr_ctx, mlx5_hw_act_flag[i][0]);
		if (!priv->hw_tag[i])
			goto err;
	}
	if (is_proxy) {
		ret = flow_hw_create_vport_actions(priv);
		if (ret) {
			rte_errno = -ret;
			goto err;
		}
		ret = flow_hw_create_ctrl_tables(dev);
		if (ret) {
			rte_errno = -ret;
			goto err;
		}
	}
	/*
	 * The default flow to copy Tx metadata will only be created
	 * in the switchdev mode.
	 * "dv_flow_en" is checked in the previous code.
	 */
	if (priv->sh->config.dv_esw_en &&
	    priv->sh->config.dv_xmeta_en == MLX5_XMETA_MODE_META32_HWS) {
		ret = flow_hw_create_tx_default_mreg_copy(dev, error);
		if (ret)
			goto err;
	}
	if (_queue_attr)
		mlx5_free(_queue_attr);
	if (port_attr->nb_counters) {
		priv->hws_cpool = mlx5_hws_cnt_pool_create(dev, port_attr,
				nb_queue);
		if (priv->hws_cpool == NULL)
			goto err;
	}
	return 0;
err:
	flow_hw_free_vport_actions(priv);
	for (i = 0; i < MLX5_HW_ACTION_FLAG_MAX; i++) {
		if (priv->hw_drop[i])
			mlx5dr_action_destroy(priv->hw_drop[i]);
		if (priv->hw_tag[i])
			mlx5dr_action_destroy(priv->hw_tag[i]);
	}
	if (dr_ctx)
		claim_zero(mlx5dr_context_close(dr_ctx));
	mlx5_free(priv->hw_q);
	priv->hw_q = NULL;
	if (priv->acts_ipool) {
		mlx5_ipool_destroy(priv->acts_ipool);
		priv->acts_ipool = NULL;
	}
	if (_queue_attr)
		mlx5_free(_queue_attr);
	/* Do not overwrite the internal errno information. */
	if (ret)
		return ret;
	return rte_flow_error_set(error, rte_errno,
				  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				  "fail to configure port");
}

/**
 * Release HWS resources.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 */
void
flow_hw_resource_release(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_flow_template_table *tbl;
	struct rte_flow_pattern_template *it;
	struct rte_flow_actions_template *at;
	int i;

	if (!priv->dr_ctx)
		return;
	flow_hw_flush_all_ctrl_flows(dev);
	if (priv->sh->config.dv_esw_en &&
	    priv->sh->config.dv_xmeta_en == MLX5_XMETA_MODE_META32_HWS) {
		flow_hw_destroy_tx_default_mreg_copy(dev, NULL);
	}
	while (!LIST_EMPTY(&priv->flow_hw_tbl_ongo)) {
		tbl = LIST_FIRST(&priv->flow_hw_tbl_ongo);
		flow_hw_table_destroy(dev, tbl, NULL);
	}
	while (!LIST_EMPTY(&priv->flow_hw_tbl)) {
		tbl = LIST_FIRST(&priv->flow_hw_tbl);
		flow_hw_table_destroy(dev, tbl, NULL);
	}
	while (!LIST_EMPTY(&priv->flow_hw_itt)) {
		it = LIST_FIRST(&priv->flow_hw_itt);
		flow_hw_pattern_template_destroy(dev, it, NULL);
	}
	while (!LIST_EMPTY(&priv->flow_hw_at)) {
		at = LIST_FIRST(&priv->flow_hw_at);
		flow_hw_actions_template_destroy(dev, at, NULL);
	}
	for (i = 0; i < MLX5_HW_ACTION_FLAG_MAX; i++) {
		if (priv->hw_drop[i])
			mlx5dr_action_destroy(priv->hw_drop[i]);
		if (priv->hw_tag[i])
			mlx5dr_action_destroy(priv->hw_tag[i]);
	}
	flow_hw_free_vport_actions(priv);
	if (priv->acts_ipool) {
		mlx5_ipool_destroy(priv->acts_ipool);
		priv->acts_ipool = NULL;
	}
	if (priv->hws_cpool)
		mlx5_hws_cnt_pool_destroy(priv->sh, priv->hws_cpool);
	mlx5_free(priv->hw_q);
	priv->hw_q = NULL;
	claim_zero(mlx5dr_context_close(priv->dr_ctx));
	priv->dr_ctx = NULL;
	priv->nb_queue = 0;
}

/* Sets vport tag and mask, for given port, used in HWS rules. */
void
flow_hw_set_port_info(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	uint16_t port_id = dev->data->port_id;
	struct flow_hw_port_info *info;

	MLX5_ASSERT(port_id < RTE_MAX_ETHPORTS);
	info = &mlx5_flow_hw_port_infos[port_id];
	info->regc_mask = priv->vport_meta_mask;
	info->regc_value = priv->vport_meta_tag;
	info->is_wire = priv->master;
}

/* Clears vport tag and mask used for HWS rules. */
void
flow_hw_clear_port_info(struct rte_eth_dev *dev)
{
	uint16_t port_id = dev->data->port_id;
	struct flow_hw_port_info *info;

	MLX5_ASSERT(port_id < RTE_MAX_ETHPORTS);
	info = &mlx5_flow_hw_port_infos[port_id];
	info->regc_mask = 0;
	info->regc_value = 0;
	info->is_wire = 0;
}

/*
 * Initialize the information of available tag registers and an intersection
 * of all the probed devices' REG_C_Xs.
 * PS. No port concept in steering part, right now it cannot be per port level.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 */
void flow_hw_init_tags_set(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	uint32_t meta_mode = priv->sh->config.dv_xmeta_en;
	uint8_t masks = (uint8_t)priv->sh->cdev->config.hca_attr.set_reg_c;
	uint32_t i, j;
	enum modify_reg copy[MLX5_FLOW_HW_TAGS_MAX] = {REG_NON};
	uint8_t unset = 0;
	uint8_t copy_masks = 0;

	/*
	 * The CAPA is global for common device but only used in net.
	 * It is shared per eswitch domain.
	 */
	if (!!priv->sh->hws_tags)
		return;
	unset |= 1 << (priv->mtr_color_reg - REG_C_0);
	unset |= 1 << (REG_C_6 - REG_C_0);
	if (meta_mode == MLX5_XMETA_MODE_META32_HWS) {
		unset |= 1 << (REG_C_1 - REG_C_0);
		unset |= 1 << (REG_C_0 - REG_C_0);
	}
	masks &= ~unset;
	if (mlx5_flow_hw_avl_tags_init_cnt) {
		for (i = 0; i < MLX5_FLOW_HW_TAGS_MAX; i++) {
			if (mlx5_flow_hw_avl_tags[i] != REG_NON && !!((1 << i) & masks)) {
				copy[mlx5_flow_hw_avl_tags[i] - REG_C_0] =
						mlx5_flow_hw_avl_tags[i];
				copy_masks |= (1 << i);
			}
		}
		if (copy_masks != masks) {
			j = 0;
			for (i = 0; i < MLX5_FLOW_HW_TAGS_MAX; i++)
				if (!!((1 << i) & copy_masks))
					mlx5_flow_hw_avl_tags[j++] = copy[i];
		}
	} else {
		j = 0;
		for (i = 0; i < MLX5_FLOW_HW_TAGS_MAX; i++) {
			if (!!((1 << i) & masks))
				mlx5_flow_hw_avl_tags[j++] =
					(enum modify_reg)(i + (uint32_t)REG_C_0);
		}
	}
	priv->sh->hws_tags = 1;
	mlx5_flow_hw_avl_tags_init_cnt++;
}

/*
 * Reset the available tag registers information to NONE.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 */
void flow_hw_clear_tags_set(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;

	if (!priv->sh->hws_tags)
		return;
	priv->sh->hws_tags = 0;
	mlx5_flow_hw_avl_tags_init_cnt--;
	if (!mlx5_flow_hw_avl_tags_init_cnt)
		memset(mlx5_flow_hw_avl_tags, REG_NON,
		       sizeof(enum modify_reg) * MLX5_FLOW_HW_TAGS_MAX);
}

/**
 * Create shared action.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] queue
 *   Which queue to be used..
 * @param[in] attr
 *   Operation attribute.
 * @param[in] conf
 *   Indirect action configuration.
 * @param[in] action
 *   rte_flow action detail.
 * @param[in] user_data
 *   Pointer to the user_data.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   Action handle on success, NULL otherwise and rte_errno is set.
 */
static struct rte_flow_action_handle *
flow_hw_action_handle_create(struct rte_eth_dev *dev, uint32_t queue,
			     const struct rte_flow_op_attr *attr,
			     const struct rte_flow_indir_action_conf *conf,
			     const struct rte_flow_action *action,
			     void *user_data,
			     struct rte_flow_error *error)
{
	RTE_SET_USED(queue);
	RTE_SET_USED(attr);
	RTE_SET_USED(user_data);
	return flow_dv_action_create(dev, conf, action, error);
}

/**
 * Update shared action.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] queue
 *   Which queue to be used..
 * @param[in] attr
 *   Operation attribute.
 * @param[in] handle
 *   Action handle to be updated.
 * @param[in] update
 *   Update value.
 * @param[in] user_data
 *   Pointer to the user_data.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, negative value otherwise and rte_errno is set.
 */
static int
flow_hw_action_handle_update(struct rte_eth_dev *dev, uint32_t queue,
			     const struct rte_flow_op_attr *attr,
			     struct rte_flow_action_handle *handle,
			     const void *update,
			     void *user_data,
			     struct rte_flow_error *error)
{
	RTE_SET_USED(queue);
	RTE_SET_USED(attr);
	RTE_SET_USED(user_data);
	return flow_dv_action_update(dev, handle, update, error);
}

/**
 * Destroy shared action.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] queue
 *   Which queue to be used..
 * @param[in] attr
 *   Operation attribute.
 * @param[in] handle
 *   Action handle to be destroyed.
 * @param[in] user_data
 *   Pointer to the user_data.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, negative value otherwise and rte_errno is set.
 */
static int
flow_hw_action_handle_destroy(struct rte_eth_dev *dev, uint32_t queue,
			      const struct rte_flow_op_attr *attr,
			      struct rte_flow_action_handle *handle,
			      void *user_data,
			      struct rte_flow_error *error)
{
	RTE_SET_USED(queue);
	RTE_SET_USED(attr);
	RTE_SET_USED(user_data);
	return flow_dv_action_destroy(dev, handle, error);
}

static int
flow_hw_create_tx_default_mreg_copy(struct rte_eth_dev *dev,
				    struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_hw_meta_tx_cpy_info *tx_info =
		(struct mlx5_hw_meta_tx_cpy_info *)priv->sh->hws_tx;
	struct rte_flow_pattern_template_attr tx_pa_attr = {
		.relaxed_matching = 0,
		.egress = 1,
	};
	struct rte_flow_actions_template_attr tx_act_attr = {
		.egress = 1,
	};
	struct rte_flow_item_eth promisc = {
		.dst.addr_bytes = "\x00\x00\x00\x00\x00\x00",
		.src.addr_bytes = "\x00\x00\x00\x00\x00\x00",
		.type = 0,
	};
	struct rte_flow_item eth_all[] = {
		[0] = {
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = &promisc,
			.mask = &promisc,
		},
		[1] = {
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};
	struct rte_flow_pattern_template *pt;
	const struct rte_flow_action_modify_field mreg_action = {
		.operation = RTE_FLOW_MODIFY_SET,
		.dst = {
			.field = (enum rte_flow_field_id)MLX5_RTE_FLOW_FIELD_META_REG,
			.level = REG_C_1,
		},
		.src = {
			.field = (enum rte_flow_field_id)MLX5_RTE_FLOW_FIELD_META_REG,
			.level = REG_A,
		},
		.width = 32,
	};
	const struct rte_flow_action_modify_field mreg_mask = {
		.operation = RTE_FLOW_MODIFY_SET,
		.dst = {
			.field = (enum rte_flow_field_id)MLX5_RTE_FLOW_FIELD_META_REG,
			.level = UINT32_MAX,
			.offset = UINT32_MAX,
		},
		.src = {
			.field = (enum rte_flow_field_id)MLX5_RTE_FLOW_FIELD_META_REG,
			.level = UINT32_MAX,
			.offset = UINT32_MAX,
		},
		.width = UINT32_MAX,
	};
	const struct rte_flow_action copy_reg_action[] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_MODIFY_FIELD,
			.conf = &mreg_action,
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	const struct rte_flow_action copy_reg_mask[] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_MODIFY_FIELD,
			.conf = &mreg_mask,
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_flow_actions_template *at = NULL;
	struct rte_flow_template_table_attr tx_tbl_attr = {
		.flow_attr = {
			.group = 0,
			.priority = MLX5_HW_LOWEST_PRIO_ROOT,
			.egress = 1,
		},
		.nb_flows = 1,
	};
	struct mlx5_flow_template_table_cfg tx_tbl_cfg = {
		.attr = tx_tbl_attr,
		.external = false,
	};
	struct rte_flow_template_table *tx_tbl = NULL;
	struct rte_flow_op_attr q_ops = {
		.postpone = 1,
	};
	struct rte_flow *tx_cpy_flow = NULL;
	uint32_t ctrl_q = flow_hw_get_ctrl_queue(priv);

	/* All representors share the same NIC Tx rule. */
	if (tx_info) {
		tx_info->cnt++;
		return 0;
	}
	tx_info = mlx5_malloc(MLX5_MEM_ZERO,
			      sizeof(struct mlx5_hw_meta_tx_cpy_info),
			      RTE_CACHE_LINE_SIZE, SOCKET_ID_ANY);
	if (!tx_info)
		return rte_flow_error_set(error, ENOMEM,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL,
					  "cannot allocate tx copy info");
	pt = flow_hw_pattern_template_create(dev, &tx_pa_attr, eth_all, error);
	if (!pt)
		goto err_exit;
	at = flow_hw_actions_template_create(dev, &tx_act_attr, copy_reg_action,
					     copy_reg_mask, error);
	if (!at)
		goto err_exit;
	tx_tbl = flow_hw_table_create(dev, &tx_tbl_cfg, &pt, 1, &at, 1, error);
	if (!tx_tbl)
		goto err_exit;
	tx_cpy_flow = flow_hw_async_flow_create(dev, ctrl_q, &q_ops,
						tx_tbl, eth_all, 0, copy_reg_action,
						0, NULL, error);
	if (!tx_cpy_flow)
		goto err_exit;
	if (__flow_hw_pull_comp(dev, ctrl_q, 1, error))
		goto err_exit;
	tx_info->pt = pt;
	tx_info->at = at;
	tx_info->tbl = tx_tbl;
	tx_info->rule = tx_cpy_flow;
	tx_info->cnt = 1;
	priv->sh->hws_tx = tx_info;
	return 0;
err_exit:
	if (tx_cpy_flow) {
		struct rte_flow_error drop_error;
		int ret;

		ret = flow_hw_async_flow_destroy(dev, ctrl_q, &q_ops, tx_cpy_flow,
						 NULL, &drop_error);
		MLX5_ASSERT(!ret);
		if (!ret)
			(void)__flow_hw_pull_comp(dev, ctrl_q, 1, &drop_error);
	}
	if (tx_tbl)
		claim_zero(flow_hw_table_destroy(dev, tx_tbl, error));
	if (at)
		claim_zero(flow_hw_actions_template_destroy(dev, at, error));
	if (pt)
		claim_zero(flow_hw_pattern_template_destroy(dev, pt, error));
	if (tx_info)
		mlx5_free(tx_info);
	return -rte_errno;
}

static void
flow_hw_destroy_tx_default_mreg_copy(struct rte_eth_dev *dev,
				     struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_hw_meta_tx_cpy_info *tx_info =
		(struct mlx5_hw_meta_tx_cpy_info *)priv->sh->hws_tx;
	struct rte_flow_op_attr q_ops = {
		.postpone = 1,
	};
	uint32_t ctrl_q = flow_hw_get_ctrl_queue(priv);

	if (!tx_info || --tx_info->cnt)
		return;
	if (!flow_hw_async_flow_destroy(dev, ctrl_q, &q_ops,
					tx_info->rule, NULL, error))
		(void)__flow_hw_pull_comp(dev, ctrl_q, 1, error);
	claim_zero(flow_hw_table_destroy(dev, tx_info->tbl, error));
	claim_zero(flow_hw_actions_template_destroy(dev, tx_info->at, error));
	claim_zero(flow_hw_pattern_template_destroy(dev, tx_info->pt, error));
	mlx5_free(tx_info);
	priv->sh->hws_tx = NULL;
}

static int
flow_hw_query_counter(const struct rte_eth_dev *dev, uint32_t counter,
		      void *data, struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_hws_cnt *cnt;
	struct rte_flow_query_count *qc = data;
	uint32_t iidx = counter & ((1 << MLX5_INDIRECT_ACTION_TYPE_OFFSET) - 1);
	uint64_t pkts, bytes;

	if ((counter >> MLX5_INDIRECT_ACTION_TYPE_OFFSET) !=
	    MLX5_INDIRECT_ACTION_TYPE_COUNT)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				"counter are not available");
	cnt = &priv->hws_cpool->pool[iidx];
	__hws_cnt_query_raw(priv->hws_cpool, counter, &pkts, &bytes);
	qc->hits_set = 1;
	qc->bytes_set = 1;
	qc->hits = pkts - cnt->reset.hits;
	qc->bytes = bytes - cnt->reset.bytes;
	if (qc->reset) {
		cnt->reset.bytes = bytes;
		cnt->reset.hits = pkts;
	}
	return 0;
}

static int
flow_hw_query(const struct rte_eth_dev *dev,
	      struct rte_flow *flow __rte_unused,
	      const struct rte_flow_action *actions __rte_unused,
	      void *data __rte_unused,
	      struct rte_flow_error *error __rte_unused)
{
	int ret = -EINVAL;
	struct rte_flow_hw *hw_flow = (struct rte_flow_hw *)flow;

	for (; actions->type != RTE_FLOW_ACTION_TYPE_END; actions++) {
		switch (actions->type) {
		case RTE_FLOW_ACTION_TYPE_VOID:
			break;
		case RTE_FLOW_ACTION_TYPE_COUNT:
			ret = flow_hw_query_counter(dev, hw_flow->cnt_id, data,
						  error);
			break;
		default:
			return rte_flow_error_set(error, ENOTSUP,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  actions,
						  "action not supported");
		}
	}
	return ret;
}

const struct mlx5_flow_driver_ops mlx5_flow_hw_drv_ops = {
	.info_get = flow_hw_info_get,
	.configure = flow_hw_configure,
	.pattern_validate = flow_hw_pattern_validate,
	.pattern_template_create = flow_hw_pattern_template_create,
	.pattern_template_destroy = flow_hw_pattern_template_destroy,
	.actions_validate = flow_hw_actions_validate,
	.actions_template_create = flow_hw_actions_template_create,
	.actions_template_destroy = flow_hw_actions_template_destroy,
	.template_table_create = flow_hw_template_table_create,
	.template_table_destroy = flow_hw_table_destroy,
	.async_flow_create = flow_hw_async_flow_create,
	.async_flow_destroy = flow_hw_async_flow_destroy,
	.pull = flow_hw_pull,
	.push = flow_hw_push,
	.async_action_create = flow_hw_action_handle_create,
	.async_action_destroy = flow_hw_action_handle_destroy,
	.async_action_update = flow_hw_action_handle_update,
	.action_validate = flow_dv_action_validate,
	.action_create = flow_dv_action_create,
	.action_destroy = flow_dv_action_destroy,
	.action_update = flow_dv_action_update,
	.action_query = flow_dv_action_query,
	.query = flow_hw_query,
};

/**
 * Creates a control flow using flow template API on @p proxy_dev device,
 * on behalf of @p owner_dev device.
 *
 * This function uses locks internally to synchronize access to the
 * flow queue.
 *
 * Created flow is stored in private list associated with @p proxy_dev device.
 *
 * @param owner_dev
 *   Pointer to Ethernet device on behalf of which flow is created.
 * @param proxy_dev
 *   Pointer to Ethernet device on which flow is created.
 * @param table
 *   Pointer to flow table.
 * @param items
 *   Pointer to flow rule items.
 * @param item_template_idx
 *   Index of an item template associated with @p table.
 * @param actions
 *   Pointer to flow rule actions.
 * @param action_template_idx
 *   Index of an action template associated with @p table.
 *
 * @return
 *   0 on success, negative errno value otherwise and rte_errno set.
 */
static __rte_unused int
flow_hw_create_ctrl_flow(struct rte_eth_dev *owner_dev,
			 struct rte_eth_dev *proxy_dev,
			 struct rte_flow_template_table *table,
			 struct rte_flow_item items[],
			 uint8_t item_template_idx,
			 struct rte_flow_action actions[],
			 uint8_t action_template_idx)
{
	struct mlx5_priv *priv = proxy_dev->data->dev_private;
	uint32_t queue = CTRL_QUEUE_ID(priv);
	struct rte_flow_op_attr op_attr = {
		.postpone = 0,
	};
	struct rte_flow *flow = NULL;
	struct mlx5_hw_ctrl_flow *entry = NULL;
	int ret;

	rte_spinlock_lock(&priv->hw_ctrl_lock);
	entry = mlx5_malloc(MLX5_MEM_ZERO | MLX5_MEM_SYS, sizeof(*entry),
			    0, SOCKET_ID_ANY);
	if (!entry) {
		DRV_LOG(ERR, "port %u not enough memory to create control flows",
			proxy_dev->data->port_id);
		rte_errno = ENOMEM;
		ret = -rte_errno;
		goto error;
	}
	flow = flow_hw_async_flow_create(proxy_dev, queue, &op_attr, table,
					 items, item_template_idx,
					 actions, action_template_idx,
					 NULL, NULL);
	if (!flow) {
		DRV_LOG(ERR, "port %u failed to enqueue create control"
			" flow operation", proxy_dev->data->port_id);
		ret = -rte_errno;
		goto error;
	}
	ret = flow_hw_push(proxy_dev, queue, NULL);
	if (ret) {
		DRV_LOG(ERR, "port %u failed to drain control flow queue",
			proxy_dev->data->port_id);
		goto error;
	}
	ret = __flow_hw_pull_comp(proxy_dev, queue, 1, NULL);
	if (ret) {
		DRV_LOG(ERR, "port %u failed to insert control flow",
			proxy_dev->data->port_id);
		rte_errno = EINVAL;
		ret = -rte_errno;
		goto error;
	}
	entry->owner_dev = owner_dev;
	entry->flow = flow;
	LIST_INSERT_HEAD(&priv->hw_ctrl_flows, entry, next);
	rte_spinlock_unlock(&priv->hw_ctrl_lock);
	return 0;
error:
	if (entry)
		mlx5_free(entry);
	rte_spinlock_unlock(&priv->hw_ctrl_lock);
	return ret;
}

/**
 * Destroys a control flow @p flow using flow template API on @p dev device.
 *
 * This function uses locks internally to synchronize access to the
 * flow queue.
 *
 * If the @p flow is stored on any private list/pool, then caller must free up
 * the relevant resources.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param flow
 *   Pointer to flow rule.
 *
 * @return
 *   0 on success, non-zero value otherwise.
 */
static int
flow_hw_destroy_ctrl_flow(struct rte_eth_dev *dev, struct rte_flow *flow)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	uint32_t queue = CTRL_QUEUE_ID(priv);
	struct rte_flow_op_attr op_attr = {
		.postpone = 0,
	};
	int ret;

	rte_spinlock_lock(&priv->hw_ctrl_lock);
	ret = flow_hw_async_flow_destroy(dev, queue, &op_attr, flow, NULL, NULL);
	if (ret) {
		DRV_LOG(ERR, "port %u failed to enqueue destroy control"
			" flow operation", dev->data->port_id);
		goto exit;
	}
	ret = flow_hw_push(dev, queue, NULL);
	if (ret) {
		DRV_LOG(ERR, "port %u failed to drain control flow queue",
			dev->data->port_id);
		goto exit;
	}
	ret = __flow_hw_pull_comp(dev, queue, 1, NULL);
	if (ret) {
		DRV_LOG(ERR, "port %u failed to destroy control flow",
			dev->data->port_id);
		rte_errno = EINVAL;
		ret = -rte_errno;
		goto exit;
	}
exit:
	rte_spinlock_unlock(&priv->hw_ctrl_lock);
	return ret;
}

/**
 * Destroys control flows created on behalf of @p owner_dev device.
 *
 * @param owner_dev
 *   Pointer to Ethernet device owning control flows.
 *
 * @return
 *   0 on success, otherwise negative error code is returned and
 *   rte_errno is set.
 */
int
mlx5_flow_hw_flush_ctrl_flows(struct rte_eth_dev *owner_dev)
{
	struct mlx5_priv *owner_priv = owner_dev->data->dev_private;
	struct rte_eth_dev *proxy_dev;
	struct mlx5_priv *proxy_priv;
	struct mlx5_hw_ctrl_flow *cf;
	struct mlx5_hw_ctrl_flow *cf_next;
	uint16_t owner_port_id = owner_dev->data->port_id;
	uint16_t proxy_port_id = owner_dev->data->port_id;
	int ret;

	if (owner_priv->sh->config.dv_esw_en) {
		if (rte_flow_pick_transfer_proxy(owner_port_id, &proxy_port_id, NULL)) {
			DRV_LOG(ERR, "Unable to find proxy port for port %u",
				owner_port_id);
			rte_errno = EINVAL;
			return -rte_errno;
		}
		proxy_dev = &rte_eth_devices[proxy_port_id];
		proxy_priv = proxy_dev->data->dev_private;
	} else {
		proxy_dev = owner_dev;
		proxy_priv = owner_priv;
	}
	cf = LIST_FIRST(&proxy_priv->hw_ctrl_flows);
	while (cf != NULL) {
		cf_next = LIST_NEXT(cf, next);
		if (cf->owner_dev == owner_dev) {
			ret = flow_hw_destroy_ctrl_flow(proxy_dev, cf->flow);
			if (ret) {
				rte_errno = ret;
				return -ret;
			}
			LIST_REMOVE(cf, next);
			mlx5_free(cf);
		}
		cf = cf_next;
	}
	return 0;
}

/**
 * Destroys all control flows created on @p dev device.
 *
 * @param owner_dev
 *   Pointer to Ethernet device.
 *
 * @return
 *   0 on success, otherwise negative error code is returned and
 *   rte_errno is set.
 */
static int
flow_hw_flush_all_ctrl_flows(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_hw_ctrl_flow *cf;
	struct mlx5_hw_ctrl_flow *cf_next;
	int ret;

	cf = LIST_FIRST(&priv->hw_ctrl_flows);
	while (cf != NULL) {
		cf_next = LIST_NEXT(cf, next);
		ret = flow_hw_destroy_ctrl_flow(dev, cf->flow);
		if (ret) {
			rte_errno = ret;
			return -ret;
		}
		LIST_REMOVE(cf, next);
		mlx5_free(cf);
		cf = cf_next;
	}
	return 0;
}

int
mlx5_flow_hw_esw_create_mgr_sq_miss_flow(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_flow_item_ethdev port_spec = {
		.port_id = MLX5_REPRESENTED_PORT_ESW_MGR,
	};
	struct rte_flow_item_ethdev port_mask = {
		.port_id = MLX5_REPRESENTED_PORT_ESW_MGR,
	};
	struct rte_flow_item items[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT,
			.spec = &port_spec,
			.mask = &port_mask,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};
	struct rte_flow_action_jump jump = {
		.group = MLX5_HW_SQ_MISS_GROUP,
	};
	struct rte_flow_action actions[] = {
		{
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &jump,
		},
		{
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};

	MLX5_ASSERT(priv->master);
	if (!priv->dr_ctx ||
	    !priv->hw_esw_sq_miss_root_tbl)
		return 0;
	return flow_hw_create_ctrl_flow(dev, dev,
					priv->hw_esw_sq_miss_root_tbl,
					items, 0, actions, 0);
}

int
mlx5_flow_hw_esw_create_sq_miss_flow(struct rte_eth_dev *dev, uint32_t txq)
{
	uint16_t port_id = dev->data->port_id;
	struct mlx5_rte_flow_item_tx_queue queue_spec = {
		.queue = txq,
	};
	struct mlx5_rte_flow_item_tx_queue queue_mask = {
		.queue = UINT32_MAX,
	};
	struct rte_flow_item items[] = {
		{
			.type = (enum rte_flow_item_type)
				MLX5_RTE_FLOW_ITEM_TYPE_TX_QUEUE,
			.spec = &queue_spec,
			.mask = &queue_mask,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};
	struct rte_flow_action_ethdev port = {
		.port_id = port_id,
	};
	struct rte_flow_action actions[] = {
		{
			.type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT,
			.conf = &port,
		},
		{
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	struct rte_eth_dev *proxy_dev;
	struct mlx5_priv *proxy_priv;
	uint16_t proxy_port_id = dev->data->port_id;
	int ret;

	RTE_SET_USED(txq);
	ret = rte_flow_pick_transfer_proxy(port_id, &proxy_port_id, NULL);
	if (ret) {
		DRV_LOG(ERR, "Unable to pick proxy port for port %u", port_id);
		return ret;
	}
	proxy_dev = &rte_eth_devices[proxy_port_id];
	proxy_priv = proxy_dev->data->dev_private;
	if (!proxy_priv->dr_ctx)
		return 0;
	if (!proxy_priv->hw_esw_sq_miss_root_tbl ||
	    !proxy_priv->hw_esw_sq_miss_tbl) {
		DRV_LOG(ERR, "port %u proxy port %u was configured but default"
			" flow tables are not created",
			port_id, proxy_port_id);
		rte_errno = ENOMEM;
		return -rte_errno;
	}
	return flow_hw_create_ctrl_flow(dev, proxy_dev,
					proxy_priv->hw_esw_sq_miss_tbl,
					items, 0, actions, 0);
}

int
mlx5_flow_hw_esw_create_default_jump_flow(struct rte_eth_dev *dev)
{
	uint16_t port_id = dev->data->port_id;
	struct rte_flow_item_ethdev port_spec = {
		.port_id = port_id,
	};
	struct rte_flow_item items[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT,
			.spec = &port_spec,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};
	struct rte_flow_action_jump jump = {
		.group = 1,
	};
	struct rte_flow_action actions[] = {
		{
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &jump,
		},
		{
			.type = RTE_FLOW_ACTION_TYPE_END,
		}
	};
	struct rte_eth_dev *proxy_dev;
	struct mlx5_priv *proxy_priv;
	uint16_t proxy_port_id = dev->data->port_id;
	int ret;

	ret = rte_flow_pick_transfer_proxy(port_id, &proxy_port_id, NULL);
	if (ret) {
		DRV_LOG(ERR, "Unable to pick proxy port for port %u", port_id);
		return ret;
	}
	proxy_dev = &rte_eth_devices[proxy_port_id];
	proxy_priv = proxy_dev->data->dev_private;
	if (!proxy_priv->dr_ctx)
		return 0;
	if (!proxy_priv->hw_esw_zero_tbl) {
		DRV_LOG(ERR, "port %u proxy port %u was configured but default"
			" flow tables are not created",
			port_id, proxy_port_id);
		rte_errno = EINVAL;
		return -rte_errno;
	}
	return flow_hw_create_ctrl_flow(dev, proxy_dev,
					proxy_priv->hw_esw_zero_tbl,
					items, 0, actions, 0);
}
