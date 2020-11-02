/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <time.h>

#include <rte_byteorder.h>
#include <rte_lhash.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_malloc.h>
#include <rte_rwlock.h>

#include "rte_sft.h"
#include "rte_sft_driver.h"
#include "sft_utils.h"

extern int sft_logtype;
#define RTE_SFT_LOG(level, ...) \
	rte_log(RTE_LOG_ ## level, sft_logtype, "" __VA_ARGS__)

#define VOID_PTR(x) ((void *)(uintptr_t)(x))
#define CONST_VOID_PTR(x) ((const void *)(uintptr_t)(x))

/**
 * fid_hash   - locate flow SFT contex by FID
 * stpl_hash  - locate flow SFT context by 6-tuple
 * rstpl_hash - locate flow SFT context by reversed 6-tuple
 */
struct sft_hash {
	struct rte_lhash *fid_hash;
	struct rte_lhash *stpl_hash;
	struct rte_lhash *rstpl_hash;
};

/**
 * sft_priv
 * singleton that concentrates SFT library internal variables
 */
static struct {
	struct sft_hash *hq;
	struct sft_id_pool *fid_ids_pool;
	rte_rwlock_t fid_rwlock; // TODO: lockless queue
	struct rte_sft_conf conf;
} *sft_priv = NULL;

#define SFT_DATA_LEN (sft_priv->conf.app_data_len * sizeof(int))

struct net_hdr {
	void *ptr;
	uint16_t protocol; // host_order
};

struct client_obj {
	LIST_ENTRY(client_obj) chain;
	const void *obj;
	uint8_t id;
};

struct sft_lib_entry {
	uint32_t fid;
	/* entry zone is required to find out if mbuf was sent from
	 * initiator or target connection side */
	uint32_t zone;
	uint16_t queue;
	uint8_t app_state; // application defined flow state
	uint8_t proto_state; // protocol state
	uint8_t proto;
	uint8_t event_dev_id;
	uint8_t event_port_id;
	uint8_t proto_enable;
	uint32_t *data; // TODO: shoud it be __be32 ?
	uint64_t ns_rx_timestamp;
	/* initiator 7tuple determines direction of active mbuf.buf_addr
	 * alternative is to extract it live from mbuf and run a hash search */
	struct rte_sft_7tuple stpl[2];
	struct rte_sft_entry *sft_entry[2];
	struct rte_sft_actions_specs action_specs;
	/* this is per queue list - no lock required */
	LIST_HEAD(, client_obj) client_objects_head;
	time_t last_activity_ts; // number of seconds since the Epoch
	bool offload;
};

static __rte_always_inline bool
sft_track_conn(const struct sft_lib_entry *entry)
{
	bool verdict;

	if (!entry)
		verdict = true;
	else
		verdict = !!entry->proto_enable;

	return verdict;
}

static const struct rte_sft_ops *
sft_ops_get(struct rte_eth_dev *dev)
{
	const struct rte_sft_ops *ops = NULL;

	if (!dev || !dev->dev_ops || !dev->dev_ops->sft_ops_get)
		ops = NULL;
	else if (dev->dev_ops->sft_ops_get(dev, &ops))
		ops = NULL;

	return ops;
}

static __rte_always_inline void
sft_get_dev_ops(struct rte_eth_dev *dev[2], struct sft_lib_entry *entry,
		const struct rte_sft_ops *ops[2])
{
	ops[0] = sft_ops_get(dev[0]);
	if (entry->stpl[0].port_id != entry->stpl[1].port_id) {
		ops[1] = sft_ops_get(dev[1]);
	} else {
		ops[1] = ops[0];
	}
}

static __rte_always_inline bool
ipv6_is_zero_addr(const void *ipv6_addr)
{
	const uint64_t *ddw = ipv6_addr;
	return ddw[0] == 0 && ddw[1] == 0;
}

static __rte_always_inline void
ipv6_set_addr(void *dst, const void *src)
{
	memcpy(dst, src, 16);
}

static __rte_always_inline int
sft_fid_release(uint32_t fid)
{
	int ret;
	
	rte_rwlock_write_lock(&sft_priv->fid_rwlock);
	ret = sft_id_release(sft_priv->fid_ids_pool, fid);
	rte_rwlock_write_unlock(&sft_priv->fid_rwlock);

	return ret;
}


static __rte_always_inline int
sft_fid_generate(uint32_t *fid)
{
	int ret;

	rte_rwlock_write_lock(&sft_priv->fid_rwlock);
	ret = sft_id_get(sft_priv->fid_ids_pool, fid);
	rte_rwlock_write_unlock(&sft_priv->fid_rwlock);

	return ret;
}

static inline const struct rte_lhash *
fid_hash(uint16_t queue)
{
	struct sft_hash *hq = sft_priv->hq + queue;
	return hq ? hq->fid_hash : NULL;
}

static inline const struct rte_lhash *
stpl_hash(uint16_t queue)
{
	struct sft_hash *hq = sft_priv->hq + queue;
	return hq ? hq->stpl_hash : NULL;
}

static inline const struct rte_lhash *
rstpl_hash(uint16_t queue)
{
	struct sft_hash *hq = sft_priv->hq + queue;
	return hq ? hq->rstpl_hash : NULL;
}

/* Initialize sft error structure. */
int
rte_sft_error_set(struct rte_sft_error *error,
		  int code,
		  enum rte_sft_error_type type,
		  const void *cause,
		  const char *message)
{
	if (error) {
		*error = (struct rte_sft_error){
			.type = type,
			.cause = cause,
			.message = message,
		};
	}
	rte_errno = code;
	return -code;
}

static inline size_t
ipv6_ext_hdr_len(const struct rte_ipv6_hdr *ipv6_hdr, uint16_t *next_proto)
{
	size_t ext_len = 0, dx;
	int proto = ipv6_hdr->proto;

	const uint8_t *p = (const uint8_t *)ipv6_hdr + sizeof(*ipv6_hdr);
	while ((proto = rte_ipv6_get_next_ext(p, proto, &dx)) != -EINVAL) {
		ext_len += dx;
		p += dx;
	}

	*next_proto = !ext_len ? ipv6_hdr->proto : p[1];

	return sizeof(*ipv6_hdr) + ext_len;
}

static void
stp_mbuf_l4_hdr(const struct net_hdr *l3_hdr,
			    struct net_hdr *l4_hdr)
{
	switch (l3_hdr->protocol) {
	case RTE_ETHER_TYPE_IPV4:
		l4_hdr->ptr = (char *)l3_hdr->ptr +
			      rte_ipv4_hdr_len(l3_hdr->ptr);
		l4_hdr->protocol =
		((const struct rte_ipv4_hdr *)l3_hdr->ptr)->next_proto_id;
		break;
	case RTE_ETHER_TYPE_IPV6:
		l4_hdr->ptr = (char *)l3_hdr->ptr +
			      ipv6_ext_hdr_len(l3_hdr->ptr, &l4_hdr->protocol);
		break;
	default:
		l4_hdr->protocol = 0;
		l4_hdr->ptr = NULL;
	}
}

static void
stp_mbuf_l3_hdr(const struct rte_mbuf *mbuf, struct net_hdr *nh) // use mif !!!
{
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, typeof(eth_hdr));
	size_t l2_len = RTE_ETHER_HDR_LEN;
	uint16_t type;

	type = rte_be_to_cpu_16(eth_hdr->ether_type);
	while (type == RTE_ETHER_TYPE_VLAN ||
	       type == RTE_ETHER_TYPE_QINQ) {
		const struct rte_vlan_hdr *vlan_hdr;
		vlan_hdr = (typeof(vlan_hdr))((const char *)eth_hdr + l2_len);
		l2_len += sizeof(*vlan_hdr);
		type = rte_be_to_cpu_16(vlan_hdr->eth_proto);
	}
	nh->ptr = (char *)eth_hdr + l2_len;
	nh->protocol = type;
}

static int
stp_parse_ipv6(struct sft_mbuf_info *mif, struct rte_sft_error *error)
{
	RTE_SET_USED(mif);
	return rte_sft_error_set(error, ENOTSUP, RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				 NULL, "ipv6 not supported");
}

static int
stp_parse_ipv4(struct sft_mbuf_info *mif, struct rte_sft_error *error)
{
	mif->l4_hdr = (const uint8_t *)mif->ip4 + rte_ipv4_hdr_len(mif->ip4);
	switch (mif->ip4->next_proto_id) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		break;
	default:
		return rte_sft_error_set(error, ENOTSUP,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
					 NULL, "unsupported l4 protocol");
	}

	return 0;
}

static int
stp_parse_ethernet(struct sft_mbuf_info *mif, struct rte_sft_error *error)
{
	size_t l2_len = RTE_ETHER_HDR_LEN;
	int ret = 0;

	mif->eth_type = rte_be_to_cpu_16(mif->eth_hdr->ether_type);
	while (mif->eth_type == RTE_ETHER_TYPE_VLAN ||
	       mif->eth_type == RTE_ETHER_TYPE_QINQ) {
		const struct rte_vlan_hdr *vlan_hdr;
		vlan_hdr = (typeof(vlan_hdr))((const char *)mif->eth_hdr + l2_len);
		l2_len += sizeof(*vlan_hdr);
		mif->eth_type = rte_be_to_cpu_16(vlan_hdr->eth_proto);
	}
	mif->l3_hdr = (const uint8_t *)mif->eth_hdr + l2_len;
	switch (mif->eth_type) {
	case RTE_ETHER_TYPE_IPV4:
		ret = stp_parse_ipv4(mif, error);
		break;
	case RTE_ETHER_TYPE_IPV6:
		ret = stp_parse_ipv6(mif, error);
		break;
	default:
		ret = rte_sft_error_set(error, ENOTSUP, RTE_SFT_ERROR_TYPE_UNSPECIFIED,
					NULL, "unsupported L3 protocol");
	}

	return ret;
}

int
sft_parse_mbuf(struct sft_mbuf_info *mif, struct rte_sft_error *error)
{
	if (mif->m->l2_type != RTE_PTYPE_L2_ETHER)
		return rte_sft_error_set(error, ENOTSUP,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
					 NULL, "no support for  "
					 "non Ethernet packet");
	mif->eth_hdr = rte_pktmbuf_mtod(mif->m, typeof(mif->eth_hdr));
	return stp_parse_ethernet(mif, error);
}

void
rte_sft_mbuf_stpl(struct sft_mbuf_info *mif, uint32_t zone,
	      struct rte_sft_7tuple *stpl, struct rte_sft_error *error)
{
	RTE_SET_USED(error);
	memset(stpl, 0, sizeof(*stpl));
	stpl->port_id = mif->m->port;
	stpl->zone = zone;
	switch(mif->eth_type) {
	case RTE_ETHER_TYPE_IPV4:
		stpl->flow_5tuple.is_ipv6 = false;
		stpl->flow_5tuple.ipv4.src_addr = mif->ip4->src_addr;
		stpl->flow_5tuple.ipv4.dst_addr = mif->ip4->dst_addr;
		stpl->flow_5tuple.proto = mif->ip4->next_proto_id; 
		break;
	case RTE_ETHER_TYPE_IPV6:
		stpl->flow_5tuple.is_ipv6 = true;
		break;	
	}
	switch(stpl->flow_5tuple.proto) {
	case IPPROTO_TCP:
		stpl->flow_5tuple.src_port = mif->tcp->src_port;
		stpl->flow_5tuple.dst_port = mif->tcp->dst_port;
		break;
	case IPPROTO_UDP:
		stpl->flow_5tuple.src_port = mif->udp->src_port;
		stpl->flow_5tuple.dst_port = mif->udp->dst_port;
		break;
	}	
}

static int
sft_mbuf_decode(uint16_t queue, struct rte_mbuf *mbuf,
		struct rte_sft_decode_info *info, struct rte_sft_error *error)
{
	int ret;
	struct rte_eth_dev *dev = &rte_eth_devices[mbuf->port];
	const struct rte_sft_ops *sft_ops = sft_ops_get(dev);

	if (!sft_ops) {
		info->state = 0;
		return 0;
	}
	ret = sft_ops->sft_entry_decode(dev, queue, mbuf, info, error);
	if (ret)
		return ret;
	else if (info->state && (info->state & ~RTE_SFT_STATE_ALL))
		return rte_sft_error_set(error, EINVAL,
				 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				 NULL, "mbuf with invalid decode state");
	return 0;
}

static int
sft_pmd_stop(struct rte_sft_error *error)
{
	int ret = 0;
	uint16_t port;

	RTE_ETH_FOREACH_DEV(port) {
		struct rte_eth_dev *dev = &rte_eth_devices[port];
		const struct rte_sft_ops *sft_ops = sft_ops_get(dev);
		if (!sft_ops)
			continue;
		ret = sft_ops->sft_stop(dev, error);
		if (ret)
			break;
	}

	return ret;
}

static int
sft_pmd_start(struct rte_sft_error *error)
{
	int ret = 0;
	uint16_t port;
	uint16_t data_len = sft_priv->conf.app_data_len;
	uint16_t nb_queues = sft_priv->conf.nb_queues;

	RTE_ETH_FOREACH_DEV(port) {
		struct rte_eth_dev *dev = &rte_eth_devices[port];
		const struct rte_sft_ops *sft_ops = sft_ops_get(dev);

		if (!sft_ops)
			continue;
		ret = sft_ops->sft_start(dev, nb_queues, data_len, error);
		if (ret)
			break;
	}

	if (ret) {
		struct rte_sft_error stop_error;
		sft_pmd_stop(&stop_error);
	}

	return 0;
}

union sft_action_ctx {
	struct rte_flow_action_set_ipv4 ipv4_spec;
	struct rte_flow_action_set_ipv6 ipv6_spec;
	struct rte_flow_action_set_tp tp_spec;
	struct rte_flow_action_age age; 
};

static int
sft_action_nat(struct rte_flow_action *action,
	       const struct rte_sft_5tuple *orig,
	       const struct rte_sft_5tuple *nat,
	       union sft_action_ctx *ctx)
{
	int i = 0;
	RTE_VERIFY(orig->is_ipv6 == nat->is_ipv6);
	if (!orig->is_ipv6) {
		if (nat->ipv4.src_addr) {
			ctx[i].ipv4_spec.ipv4_addr = nat->ipv4.src_addr;
			action[i].type = RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC;
			action[i].conf = ctx + i;
			i++;
		}
		if (nat->ipv4.dst_addr) {
			ctx[i].ipv4_spec.ipv4_addr = nat->ipv4.src_addr;
			action[i].type = RTE_FLOW_ACTION_TYPE_SET_IPV4_DST;
			action[i].conf = ctx + i;
			i++;
		}
	} else {
		if (!ipv6_is_zero_addr(nat->ipv6.src_addr)) {
			ipv6_set_addr(ctx[i].ipv6_spec.ipv6_addr, nat->ipv6.src_addr);
			action[i].type = RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC;
			action[i].conf = ctx + i;
			i++;
		}
		if (!ipv6_is_zero_addr(nat->ipv6.dst_addr)) {
			ipv6_set_addr(ctx[i].ipv6_spec.ipv6_addr, nat->ipv6.dst_addr);
			action[i].type = RTE_FLOW_ACTION_TYPE_SET_IPV6_DST;
			action[i].conf = ctx + i;
			i++;
		}
	}
	if (nat->src_port) {
		ctx[i].tp_spec.port = nat->src_port;
		action[i].type = RTE_FLOW_ACTION_TYPE_SET_TP_SRC;
		action[i].conf = ctx + i;
		i++;
	}
	if (nat->dst_port) {
		action[i].type = RTE_FLOW_ACTION_TYPE_SET_TP_DST;
		ctx[i].tp_spec.port = nat->dst_port;
		action[i].conf = ctx + i;
		i++;
	}

	return i;	
}

#define SFT_PATTERNS_NUM 4
#define SFT_ACTIONS_NUM 8

__extension__
struct sft_pattern_ctx {
	union {
		struct rte_flow_item_ipv4 ipv4_spec;
		struct rte_flow_item_ipv6 ipv6_spec;
		uint8_t l3_spec;
	};
	union {
		struct rte_flow_item_ipv4 ipv4_mask;
		struct rte_flow_item_ipv6 ipv6_mask;
		uint8_t l3_mask;		
	};
	union {
		struct rte_flow_item_tcp tcp_spec;
		struct rte_flow_item_udp udp_spec;
		uint8_t l4_spec;
	};
	union {
		struct rte_flow_item_tcp tcp_mask;
		struct rte_flow_item_udp udp_mask;
		uint8_t l4_mask;
	};
};

static void
sft_l3_pattern(struct rte_flow_item *p, const struct rte_sft_5tuple *ftpl,
		struct sft_pattern_ctx *ctx)
{
	if (!ftpl->is_ipv6) {
		p->type = RTE_FLOW_ITEM_TYPE_IPV4;
		if (ftpl->ipv4.src_addr) {
			ctx->ipv4_spec.hdr.src_addr = ftpl->ipv4.src_addr;
			ctx->ipv4_mask.hdr.src_addr = RTE_BE32(0xffffffff);
		}
		if (ftpl->ipv4.dst_addr) {
			ctx->ipv4_spec.hdr.dst_addr = ftpl->ipv4.dst_addr;
			ctx->ipv4_mask.hdr.dst_addr = RTE_BE32(0xffffffff);
		}
	} else {
		p->type = RTE_FLOW_ITEM_TYPE_IPV6;
		if (!ipv6_is_zero_addr(ftpl->ipv6.src_addr)) {
			memcpy(ctx->ipv6_spec.hdr.src_addr,
			       ftpl->ipv6.src_addr, sizeof(ftpl->ipv6.src_addr));
			memset(ctx->ipv6_mask.hdr.src_addr, 0xff,
			       sizeof(ctx->ipv6_mask.hdr.src_addr));
		}
		if (!ipv6_is_zero_addr(ftpl->ipv6.dst_addr)) {
			memcpy(ctx->ipv6_spec.hdr.dst_addr,
			       ftpl->ipv6.dst_addr, sizeof(ftpl->ipv6.dst_addr));
			memset(ctx->ipv6_mask.hdr.dst_addr, 0xff,
			       sizeof(ctx->ipv6_mask.hdr.dst_addr));
		}
	}
	p->spec = &ctx->l3_spec;
	p->mask = &ctx->l3_mask;
}

static void
sft_l4_pattern(struct rte_flow_item *p, const struct rte_sft_5tuple *ftpl,
		struct sft_pattern_ctx *ctx)
{
	switch (ftpl->proto) {
	case IPPROTO_TCP: 
		p->type = RTE_FLOW_ITEM_TYPE_TCP;
		if (ftpl->src_port) {
			ctx->tcp_spec.hdr.src_port = ftpl->src_port;
			ctx->tcp_mask.hdr.src_port = RTE_BE16(0xffff);
		}
		if (ftpl->dst_port) {
			ctx->tcp_spec.hdr.dst_port = ftpl->dst_port;
			ctx->tcp_mask.hdr.dst_port = RTE_BE16(0xffff);
		}
		break;
	case IPPROTO_UDP:
		p->type = RTE_FLOW_ITEM_TYPE_UDP;
		if (ftpl->src_port) {
			ctx->udp_spec.hdr.src_port = ftpl->src_port;
			ctx->udp_mask.hdr.src_port = RTE_BE16(0xffff);
		}
		if (ftpl->dst_port) {
			ctx->udp_spec.hdr.dst_port = ftpl->dst_port;
			ctx->udp_mask.hdr.dst_port = RTE_BE16(0xffff);
		}
		break;
	default:
		RTE_VERIFY(false);
		
	}
	p->spec = &ctx->l4_spec;
	p->mask = &ctx->l4_mask;
}

static void
sft_hit_pattern(const struct sft_lib_entry *entry,
		struct rte_flow_item patterns[2][SFT_PATTERNS_NUM],
		struct sft_pattern_ctx ctx[2][SFT_PATTERNS_NUM])
{
	patterns[0][0].type = RTE_FLOW_ITEM_TYPE_ETH;
	sft_l3_pattern(&patterns[0][1], &entry->stpl[0].flow_5tuple, &ctx[0][1]);
	sft_l4_pattern(&patterns[0][2], &entry->stpl[0].flow_5tuple, &ctx[0][2]);
	patterns[0][3].type = RTE_FLOW_ITEM_TYPE_END;
	patterns[1][0].type = RTE_FLOW_ITEM_TYPE_ETH;
	sft_l3_pattern(&patterns[1][1], &entry->stpl[1].flow_5tuple, &ctx[1][1]);
	sft_l4_pattern(&patterns[1][2], &entry->stpl[1].flow_5tuple, &ctx[1][2]); 
	patterns[1][3].type = RTE_FLOW_ITEM_TYPE_END;
}

static void
sft_hit_actions(const struct sft_lib_entry *entry,
		struct rte_flow_action actions[2][SFT_ACTIONS_NUM],
		union sft_action_ctx ctx[2][SFT_ACTIONS_NUM])
{
	int fx = 0; /* forward traffic actions index */
	int rx = 0; /* reversed traffic actions index */

	if (entry->action_specs.actions & RTE_SFT_ACTION_INITIATOR_NAT)
		fx += sft_action_nat(&actions[0][fx], &entry->stpl[0].flow_5tuple,
				     entry->action_specs.initiator_nat,
				     &ctx[0][fx]);
	if (entry->action_specs.actions & RTE_SFT_ACTION_REVERSE_NAT)
		rx += sft_action_nat(&actions[1][rx], &entry->stpl[1].flow_5tuple,
				     entry->action_specs.reverse_nat,
				     &ctx[1][rx]);
	if (entry->action_specs.actions & RTE_SFT_ACTION_COUNT) {
		actions[0][fx].type = RTE_FLOW_ACTION_TYPE_COUNT;
		actions[0][fx].conf = &ctx[0][fx];
		actions[1][rx].type = RTE_FLOW_ACTION_TYPE_COUNT;
		actions[1][rx].conf = &ctx[1][rx];
		fx++;
		rx++;
	}
	if (entry->action_specs.actions & RTE_SFT_ACTION_AGE) {
		actions[0][fx].type = RTE_FLOW_ACTION_TYPE_AGE;
		actions[0][fx].conf = &ctx[0][fx];
		actions[1][rx].type = RTE_FLOW_ACTION_TYPE_AGE;
		actions[1][rx].conf = &ctx[1][rx];
		ctx[0][fx++].age.timeout = entry->action_specs.aging;
		ctx[1][rx++].age.timeout = entry->action_specs.aging;
	}
	RTE_VERIFY(fx < SFT_ACTIONS_NUM);
	RTE_VERIFY(rx < SFT_ACTIONS_NUM);	
	actions[0][fx].type = RTE_FLOW_ACTION_TYPE_END;
	actions[1][rx].type = RTE_FLOW_ACTION_TYPE_END;
}

static void
sft_miss_actions(const struct sft_lib_entry *entry,
		 struct rte_flow_action actions[2][SFT_ACTIONS_NUM],
		 union sft_action_ctx ctx[2][SFT_ACTIONS_NUM])
{
	int fx = 0; /* forward traffic actions index */
	int rx = 0; /* reversed traffic actions index */

	if (entry->action_specs.actions & RTE_SFT_ACTION_INITIATOR_NAT)
		fx += sft_action_nat(&actions[0][fx], &entry->stpl[0].flow_5tuple,
				     entry->action_specs.initiator_nat,
				     &ctx[0][fx]);
	if (entry->action_specs.actions & RTE_SFT_ACTION_REVERSE_NAT)
		rx += sft_action_nat(&actions[1][rx], &entry->stpl[1].flow_5tuple,
				     entry->action_specs.reverse_nat,
				     &ctx[1][rx]);
	if (entry->action_specs.actions & RTE_SFT_ACTION_COUNT) {
		actions[0][fx].type = RTE_FLOW_ACTION_TYPE_COUNT;
		actions[0][fx].conf = &ctx[0][fx];
		actions[1][rx].type = RTE_FLOW_ACTION_TYPE_COUNT;
		actions[1][rx].conf = &ctx[1][rx];
		fx++;
		rx++;
	}
	RTE_VERIFY(fx < SFT_ACTIONS_NUM);
	RTE_VERIFY(rx < SFT_ACTIONS_NUM);	
	actions[0][fx].type = RTE_FLOW_ACTION_TYPE_END;
	actions[1][rx].type = RTE_FLOW_ACTION_TYPE_END;
}

static uint64_t
sft_miss_conditions(const struct sft_lib_entry *entry)
{
	int miss_conditions;

	switch(entry->stpl[0].flow_5tuple.proto) {
	case IPPROTO_TCP:
		miss_conditions = RTE_SFT_MISS_TCP_FLAGS;
		break;
	case IPPROTO_UDP:
	default:
		miss_conditions = 0;
		break;
	}

	return miss_conditions;
}

static int
sft_flow_deactivate(struct sft_lib_entry *entry, struct rte_sft_error *error)
{
	struct rte_eth_dev *dev[2];
	const struct rte_sft_ops *ops[2];

	dev[0] = &rte_eth_devices[entry->stpl[0].port_id];
	dev[1] = &rte_eth_devices[entry->stpl[1].port_id];
	sft_get_dev_ops(dev, entry, ops);
	if (ops[0] && entry->sft_entry[0])
		ops[0]->sft_entry_destroy(dev[0], entry->sft_entry[0], entry->queue,
					  error);
	if (ops[1] && entry->sft_entry[1])
		ops[1]->sft_entry_destroy(dev[1], entry->sft_entry[1], entry->queue,
					  error);

	return 0;		
}

static int
sft_flow_activate(struct sft_lib_entry *entry,
		  struct rte_sft_error *error)
{
	struct rte_eth_dev *dev[2];
	const struct rte_sft_ops *ops[2];
	struct rte_flow_item hit_pattern[2][SFT_PATTERNS_NUM];
	struct sft_pattern_ctx hit_pattern_ctx[2][SFT_PATTERNS_NUM]; 
	struct rte_flow_action hit_actions[2][SFT_ACTIONS_NUM];
	union sft_action_ctx hit_actions_ctx[2][SFT_ACTIONS_NUM];
	struct rte_flow_action miss_actions[2][SFT_ACTIONS_NUM];
	union sft_action_ctx miss_actions_ctx[2][SFT_ACTIONS_NUM];
	uint64_t miss_conditions;

	dev[0] = &rte_eth_devices[entry->stpl[0].port_id];
	dev[1] = &rte_eth_devices[entry->stpl[1].port_id];
	sft_get_dev_ops(dev, entry, ops);
	memset(hit_pattern, 0, sizeof(hit_pattern));
	memset(hit_pattern_ctx, 0, sizeof(hit_pattern_ctx));
	memset(hit_actions_ctx, 0, sizeof(hit_actions_ctx));
	memset(hit_actions, 0, sizeof(hit_actions));
	memset(miss_actions, 0, sizeof(miss_actions));
	memset(miss_actions_ctx, 0, sizeof(miss_actions_ctx));
	sft_hit_pattern(entry, hit_pattern, hit_pattern_ctx);
	if (entry->action_specs.actions) {
		sft_hit_actions(entry, hit_actions, hit_actions_ctx);
		sft_miss_actions(entry, miss_actions, miss_actions_ctx);
	}
	miss_conditions = sft_miss_conditions(entry);

	if (ops[0]) {
		entry->sft_entry[0] =
		ops[0]->sft_create_entry(dev[0], entry->fid, entry->queue, hit_pattern[0],
					  miss_conditions, hit_actions[0], miss_actions[0],
					  entry->data, sft_priv->conf.app_data_len,
					  entry->app_state, error);
		if (!entry->sft_entry[0])
			return -rte_errno;
	}
	if (ops[1]) {
		entry->sft_entry[1] =
		ops[1]->sft_create_entry(dev[1], entry->fid, entry->queue, hit_pattern[1],
					  miss_conditions, hit_actions[1], miss_actions[1],
					  entry->data, sft_priv->conf.app_data_len,
					  entry->app_state, error);
		if (!entry->sft_entry[1] && ops[0]) {
			int err = -rte_errno;
			ops[0]->sft_entry_destroy(dev[0], entry->sft_entry[0],
						  entry->queue, error);
			return err;
		}
	}
	return 0;
}

static inline void
sft_search_hash(const struct rte_lhash *h, const void *key, void **data)
{
	int ret = rte_lhash_lookup(h, key, (uint64_t *)data);

	if (ret == -ENOENT) {
		*data = NULL;
		ret = 0;
	}
}

static void
sft_fid_locate_entry(uint16_t queue, uint32_t fid, struct sft_lib_entry **entry)
{
	sft_search_hash(fid_hash(queue), (const void *)(uintptr_t)fid,
		      (void **)entry);
}

static void
sft_stpl_locate_entry(uint16_t queue, const struct rte_sft_7tuple *stpl,
		      struct sft_lib_entry **entry)
{
	sft_search_hash(stpl_hash(queue), (const void *)stpl, (void **)entry);
}

__rte_unused static void
sft_rstpl_locate_entry(uint16_t queue, const struct rte_sft_7tuple *stpl,
		      struct sft_lib_entry **entry)
{
	sft_search_hash(rstpl_hash(queue), (const void *)stpl, (void **)entry);
}

static void
sft_mbuf_apply_nat(struct rte_mbuf *mbuf, const struct rte_sft_5tuple *nat)
{
	struct net_hdr l3_hdr, l4_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_udp_hdr *udp_hdr;

	stp_mbuf_l3_hdr(mbuf, &l3_hdr); // use mif
	stp_mbuf_l4_hdr(&l3_hdr, &l4_hdr); // use mif
	if (!nat->is_ipv6) {
		struct rte_ipv4_hdr *ipv4_hdr = l3_hdr.ptr;

		RTE_VERIFY(l3_hdr.protocol == RTE_ETHER_TYPE_IPV4);
		if (nat->ipv4.src_addr)
			ipv4_hdr->src_addr = nat->ipv4.src_addr;
		if (nat->ipv4.dst_addr)
		ipv4_hdr->dst_addr = nat->ipv4.dst_addr;
	} else {
		struct rte_ipv6_hdr *ipv6_hdr = l3_hdr.ptr;

		RTE_VERIFY(l3_hdr.protocol == RTE_ETHER_TYPE_IPV6);
		
		if (!ipv6_is_zero_addr(nat->ipv6.src_addr))
			memcpy(ipv6_hdr->src_addr, nat->ipv6.src_addr,
			       sizeof(ipv6_hdr->src_addr));
		if (!ipv6_is_zero_addr(nat->ipv6.dst_addr))
			memcpy(ipv6_hdr->dst_addr, nat->ipv6.dst_addr,
			       sizeof(ipv6_hdr->dst_addr));
	}
	switch (l4_hdr.protocol) {
	case IPPROTO_UDP:
		udp_hdr = l4_hdr.ptr;
		if (nat->src_port)
			udp_hdr->src_port = nat->src_port;
		if (nat->dst_port)
		udp_hdr->dst_port = nat->dst_port;
		break;
	case IPPROTO_TCP:
		tcp_hdr = l4_hdr.ptr;
		if (nat->src_port)
			tcp_hdr->src_port = nat->src_port;
		if (nat->dst_port)
		tcp_hdr->dst_port = nat->dst_port;
		break;
	default:
		break;
	}

}

static void
sft_apply_mbuf_actions(struct rte_mbuf *mbuf,
		       const struct rte_sft_actions_specs *action_specs,
		       bool is_initiator)
{
	if (is_initiator && (action_specs->actions & RTE_SFT_ACTION_INITIATOR_NAT))
		sft_mbuf_apply_nat(mbuf, action_specs->initiator_nat);
	if(!is_initiator && (action_specs->actions & RTE_SFT_ACTION_REVERSE_NAT))
		sft_mbuf_apply_nat(mbuf, action_specs->reverse_nat);
	if (action_specs->actions & RTE_SFT_ACTION_COUNT)
		RTE_VERIFY(false);
	if (action_specs->actions & RTE_SFT_ACTION_AGE)
		RTE_VERIFY(false);
}

static void
sft_destroy_context(void)
{
	if (sft_priv->fid_ids_pool)
		sft_id_pool_release(sft_priv->fid_ids_pool);
	if (sft_priv->hq)
		rte_free(sft_priv->hq);
	if (sft_priv) {
		rte_free(sft_priv);
		sft_priv = NULL;
	}
}

static int
sft_init_context(const struct rte_sft_conf *conf, struct rte_sft_error *error)
{
	sft_priv = rte_zmalloc("sft context", sizeof(*sft_priv), 0);
	if (!sft_priv)
		goto error;
	sft_priv->hq = rte_zmalloc("sft hash queues",
				      conf->nb_queues *
				      sizeof(sft_priv->hq[0]), 0);
	if (!sft_priv->hq)
		goto error;
	memcpy(&sft_priv->conf, conf, sizeof(sft_priv->conf));
	if (!sft_priv->conf.nb_queues)
		sft_priv->conf.nb_queues = 1;
	sft_priv->fid_ids_pool = sft_id_pool_alloc(conf->nb_max_entries);
	if (!sft_priv->fid_ids_pool)
		goto error;
	rte_rwlock_init(&sft_priv->fid_rwlock);

	return 0;

error:
	sft_destroy_context();
	return rte_sft_error_set(error, ENOMEM,
			 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
			 NULL, "no memory for sft context");
}


static inline void
__destroy_hash(struct rte_lhash *h)
{
	rte_lhash_flush(h);
	rte_lhash_free(h);
}

static void
sft_destroy_hash(void)
{
	uint16_t i;

	for (i = 0; i < sft_priv->conf.nb_queues; i++) {
		struct sft_hash *hq = sft_priv->hq + i;

		if (hq->fid_hash)
			__destroy_hash(hq->fid_hash);
		if (hq->stpl_hash)
			__destroy_hash(hq->stpl_hash);
		if (hq->rstpl_hash)
			__destroy_hash(hq->rstpl_hash);
	}
}

static int
sft_create_hash(struct rte_sft_error *error)
{
	uint16_t i;
	int err_code;
	char err_msg[2 * RTE_HASH_NAMESIZE];
	char hash_name[RTE_HASH_NAMESIZE];
	const struct rte_lhash_parameters stpl_hash_params = {
		.name = hash_name,
		.buckets_num = 64,
		.key_size = sizeof(struct rte_sft_7tuple),
	};
	const struct rte_lhash_parameters rstpl_hash_params = {
		.name = hash_name,
		.buckets_num = 64,
		.key_size = sizeof(struct rte_sft_7tuple),
	};
	const struct rte_lhash_parameters fid_hash_params = {
		.name = hash_name,
		.buckets_num = 64,
		.key_size = sizeof(uint32_t),
	};

	for (i = 0; i < sft_priv->conf.nb_queues; i++) {
		struct sft_hash *hq = sft_priv->hq + i;

		/* hash create memcopy parameter name */
		snprintf(hash_name, sizeof(hash_name) , "fid_hash:q%u", i);
		hq->fid_hash = rte_lhash_create(&fid_hash_params);
		if (!hq->fid_hash) {
			err_code = -rte_errno;
			snprintf(err_msg, sizeof(err_msg),
				 "cannot create %s", hash_name);
			goto err;
		}
		snprintf(hash_name, sizeof(hash_name), "stpl_hash:q%u", i);
		hq->stpl_hash = rte_lhash_create(&stpl_hash_params);
		if (!hq->stpl_hash) {
			err_code = -rte_errno;
			snprintf(err_msg, sizeof(err_msg),
				 "cannot create %s", hash_name);
			goto err;
		}
		snprintf(hash_name, sizeof(hash_name), "rstpl_hash:q%u",i);
		hq->rstpl_hash = rte_lhash_create(&rstpl_hash_params);
		if (!hq->rstpl_hash) {
			err_code = -rte_errno;
			snprintf(err_msg, sizeof(err_msg),
				 "cannot create %s", hash_name);
			goto err;
		}
	}

	return 0;

err:
	sft_destroy_hash();
	return rte_sft_error_set(error, err_code,
				 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL, err_msg);
}

static struct client_obj *
sft_get_client_obj(uint16_t queue, const uint32_t fid, uint8_t id,
		   struct sft_lib_entry **entry)
{
	struct client_obj *cobj = NULL;

	sft_fid_locate_entry(queue, fid, entry);
	if (*entry)
		LIST_FOREACH(cobj, &(*entry)->client_objects_head, chain) {
			if (cobj->id == id)
				break;
		}

	return cobj;
}

enum {
	SFT_CT_STATE_UNKNOWN = 0,
	SFT_CT_STATE_CONNECTING = 1,
	SFT_CT_STATE_ACTIVE = 2,
	SFT_CT_STATE_TERMINATING = 3,
	SFT_CT_STATE_INVALID = 0xFF
/* last state */
};

// TODO: massive WIP !!!
static uint8_t
sft_get_tcp_state(const struct sft_mbuf_info *mif)
{
	uint8_t flags = mif->tcp->tcp_flags;

	if (flags == 0xFF)
		return SFT_CT_STATE_INVALID;
	else if (flags & RTE_TCP_SYN_FLAG)
		return SFT_CT_STATE_CONNECTING;
	else if (flags & (RTE_TCP_RST_FLAG | RTE_TCP_FIN_FLAG))
		return SFT_CT_STATE_TERMINATING;

	return SFT_CT_STATE_UNKNOWN;
}

static uint8_t
sft_get_conn_state(const struct sft_mbuf_info *mif)
{
	uint8_t proto_state;

	switch (mif->m->l4_type << 8) {
	default:
		proto_state = 0;
		break;
	case RTE_PTYPE_L4_TCP:
		proto_state = sft_get_tcp_state(mif);
		break;
	}

	return proto_state;
}

static int
sft_set_data(struct sft_lib_entry *entry, const uint32_t *data,
	     struct rte_sft_error *error)
{
	if (SFT_DATA_LEN == 0) {
		entry->data = NULL;
		return 0;
	}
	entry->data = rte_malloc("uint32_t",
				 sft_priv->conf.app_data_len, 0);
	if (!entry->data)
		return rte_sft_error_set(error, ENOMEM,
					 RTE_SFT_ERROR_TYPE_HASH_ERROR,
					 NULL, "failed allocate user data");
	if (data)
		memcpy(entry->data, data, SFT_DATA_LEN);
	else
		memset(entry->data, 0, SFT_DATA_LEN);

	return 0;
}

/*
* 7-tuple structure has memory regions that are not accessible by application
* content of that memory can fail memory compare operations
*/
static void
sft_init_rstpl(struct rte_sft_7tuple *local, const struct rte_sft_7tuple *app)
{
	memset(local, 0, sizeof(*local));
	if (!app->flow_5tuple.is_ipv6)
		local->flow_5tuple.ipv4 = app->flow_5tuple.ipv4;
	else
		local->flow_5tuple.ipv6 = app->flow_5tuple.ipv6;
	local->flow_5tuple.src_port = app->flow_5tuple.src_port;
	local->flow_5tuple.dst_port = app->flow_5tuple.dst_port;
	local->flow_5tuple.proto = app->flow_5tuple.proto;
	local->flow_5tuple.is_ipv6 = app->flow_5tuple.is_ipv6;
	local->zone = app->zone;
	local->port_id = app->port_id;	
}

int
rte_sft_flow_destroy(uint16_t queue, uint32_t fid, struct rte_sft_error *error)
{
	int ret;
	struct sft_lib_entry *entry = NULL;

	ret = rte_lhash_del_key(fid_hash(queue), CONST_VOID_PTR(fid),
				(uint64_t *)&entry);
	if (ret == -ENOENT)
		return rte_sft_error_set(error, ENOENT,
				  	 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "invalid fid value");		
	rte_lhash_del_key(stpl_hash(queue),
			  (const void *)&entry->stpl[0], 0);
	rte_lhash_del_key(rstpl_hash(queue),
			  (const void *)&entry->stpl[1], 0);
	sft_flow_deactivate(entry, error);
	if (entry->data)
		rte_free(entry->data);
	while (!LIST_EMPTY(&entry->client_objects_head))
		LIST_REMOVE(LIST_FIRST(&entry->client_objects_head), chain);
	sft_fid_release(entry->fid);
	rte_free(entry);

	return 0;
}

int
rte_sft_flow_get_status(const uint16_t queue, const uint32_t fid,
			struct rte_sft_flow_status *status,
			struct rte_sft_error *error)
{
	struct sft_lib_entry *entry = NULL;

	sft_fid_locate_entry(queue, fid, &entry);
	if(!entry)
		return rte_sft_error_set(error, ENOENT,
				  	 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "invalid fid value");

	status->fid = entry->fid;
	status->zone = entry->zone;
	status->state = entry->app_state;
	status->proto_state = entry->proto_state;
	status->proto = entry->proto;
	if (entry->data)
		memcpy(status->data, entry->data, SFT_DATA_LEN);

	return 0;
}

int
rte_sft_flow_query(uint16_t queue, uint32_t fid,
		   struct rte_sft_query_data *data,
		   struct rte_sft_error *error)
{
	RTE_SET_USED(queue);
	RTE_SET_USED(fid);
	RTE_SET_USED(data);
	
	return rte_sft_error_set(error, ENOENT, RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				 NULL, "not supported");
}

int
rte_sft_flow_set_aging(uint16_t queue, uint32_t fid, uint32_t aging,
		       struct rte_sft_error *error)
{
	RTE_SET_USED(queue);
	RTE_SET_USED(fid);
	RTE_SET_USED(aging);

	return rte_sft_error_set(error, ENOENT, RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				 NULL, "not supported");
}

/**
 * TODO: how to notify that all / some flow ports
 * cannot be offloaded due to non-existing hardware / PMD capabilities
 */
int
rte_sft_flow_set_offload(uint16_t queue, uint32_t fid, bool offload,
			 struct rte_sft_error *error)
{
	struct sft_lib_entry *entry = NULL;
	int (*f_op)(struct sft_lib_entry *, struct rte_sft_error *);

	sft_fid_locate_entry(queue, fid, &entry);
	if(!entry)
		return rte_sft_error_set(error, ENOENT,
				  	 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "invalid fid value");
	if (entry->offload && !offload)
		f_op = sft_flow_deactivate;
	else if (!entry->offload && offload)
		f_op = sft_flow_activate;
	else
		f_op = NULL;

	return f_op ? f_op(entry, error) : 0;
}

int
rte_sft_flow_set_state(uint16_t queue, uint32_t fid, const uint8_t state,
		       struct rte_sft_error *error)
{
	struct sft_lib_entry *entry = NULL;

	sft_fid_locate_entry(queue, fid, &entry);
	if(!entry)
		return rte_sft_error_set(error, ENOENT,
				  	 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "invalid fid value");
	entry->app_state = state;

	return 0;
}

int
rte_sft_flow_touch(uint16_t queue, uint32_t fid, struct rte_sft_error *error)
{
	struct sft_lib_entry *entry = NULL;

	sft_fid_locate_entry(queue, fid, &entry);
	if(!entry)
		return rte_sft_error_set(error, ENOENT,
				  	 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "invalid fid value");
	entry->last_activity_ts = time(NULL);

	return 0;
}

int
rte_sft_flow_set_data(uint16_t queue, uint32_t fid, const uint32_t *data,
		      struct rte_sft_error *error)
{
	struct sft_lib_entry *entry = NULL;

	sft_fid_locate_entry(queue, fid, &entry);
	if(!entry)
		return rte_sft_error_set(error, ENOENT,
				  	 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "invalid fid value");
	return sft_set_data(entry, data, error);

}

void *
rte_sft_flow_get_client_obj(uint16_t queue, const uint32_t fid,
			    uint8_t id, struct rte_sft_error *error)
{
	struct client_obj *cobj;
	struct sft_lib_entry *entry;

	cobj = sft_get_client_obj(queue, fid, id, &entry);
	if (!cobj) {
		rte_sft_error_set(error, ENOENT,
				  RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
				  entry ? "cannot locate client object" :
					  "invalid fid value");
		return NULL;
	}
	return (void *)(uintptr_t)cobj->obj;
}

int
rte_sft_flow_set_client_obj(uint16_t queue, uint32_t fid, uint8_t id,
			    const void *obj, struct rte_sft_error *error)
{
	struct sft_lib_entry *entry;
	struct client_obj *cobj;

	cobj = sft_get_client_obj(queue, fid, id, &entry);
	if (!cobj) {
		if (!entry)
			return rte_sft_error_set(error, ENOENT,
						 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
						 NULL, "invalid fid value");
		cobj = rte_malloc("sft_client_obj", sizeof(*cobj), 0);
		if (!cobj)
			return rte_sft_error_set(error, ENOMEM,
						 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
						 NULL,
						 "cannot allocate client object");
		cobj->id = id;
		cobj->obj = obj;
		LIST_INSERT_HEAD(&entry->client_objects_head, cobj, chain);
	} else {
		cobj->obj = obj;
	}

	return 0;
}

int
rte_sft_flow_activate(uint16_t queue, uint32_t zone, struct rte_mbuf *mbuf_in,
		      const struct rte_sft_7tuple *rev_stpl,
		      uint8_t state, uint32_t *data, uint8_t proto_enable,
		      const struct rte_sft_actions_specs *action_specs,
		      uint8_t dev_id, uint8_t port_id,
		      struct rte_mbuf **mbuf_out,
		      struct rte_sft_flow_status *status,
		      struct rte_sft_error *error)
{
	int ret;
	struct sft_lib_entry *entry;
	struct rte_sft_7tuple stpl, rstpl;
	struct sft_mbuf_info mif;

	*mbuf_out = mbuf_in;
	mif.m = mbuf_in;
	ret = sft_parse_mbuf(&mif, error);
	if (ret)
		return ret;
	rte_sft_mbuf_stpl(&mif, zone, &stpl, error);
	sft_init_rstpl(&rstpl, rev_stpl);
	if (stpl.flow_5tuple.is_ipv6 != rstpl.flow_5tuple.is_ipv6)
		return rte_sft_error_set(error, EINVAL,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "L3 protocols not match");
	if (stpl.flow_5tuple.proto != rstpl.flow_5tuple.proto)
		return rte_sft_error_set(error, EINVAL,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "L4 protocols not match");
	sft_stpl_locate_entry(queue, &stpl, &entry);
	if (entry)
		goto end;
	sft_stpl_locate_entry(queue, &rstpl, &entry);
	if (entry)
		goto end;
	entry = rte_zmalloc("sft entry", sizeof(*entry), 0);
	if (!entry)
		return rte_sft_error_set(error, ENOMEM,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "failed to allocate sft entry");
	LIST_INIT(&entry->client_objects_head);
	ret = sft_fid_generate(&entry->fid);
	if (ret < 0) {
		ret = rte_sft_error_set(error, ENOMEM,
					RTE_SFT_ERROR_TYPE_HASH_ERROR, NULL,
					"failed to generate fid");
		goto err1;
	}
	entry->queue = queue;
	entry->zone = zone;
	entry->app_state = state;
	entry->proto = stpl.flow_5tuple.proto;
	entry->proto_enable = !!proto_enable;
	entry->event_dev_id = dev_id;
	entry->event_port_id = port_id;
	entry->stpl[0] = stpl;
	entry->stpl[1] = rstpl;
	entry->offload = true;
	if (data && SFT_DATA_LEN != 0) {
		ret = sft_set_data(entry, data, error);
		if (ret)
			goto err2;
	}
	if (action_specs) {
		entry->action_specs = *action_specs;
		if (action_specs->actions)
			sft_apply_mbuf_actions(mbuf_in, action_specs, true);
	} else {
		memset(&entry->action_specs, 0, sizeof(entry->action_specs));
	}
	ret = rte_lhash_add_key_data(fid_hash(queue),
				     CONST_VOID_PTR(entry->fid),
				     (uint64_t)entry);
	if (ret) {
		ret = rte_sft_error_set(error, -ret,
					RTE_SFT_ERROR_TYPE_HASH_ERROR,
					NULL, "failed to add fid entry");
		goto err2;
	}
	ret = rte_lhash_add_key_data(stpl_hash(queue), (const void *)&stpl,
				    (uint64_t)entry);
	if (ret) {
		ret = rte_sft_error_set(error, -ret,
					RTE_SFT_ERROR_TYPE_HASH_ERROR,
					NULL, "failed to add client tuple");
		goto err3;
	}
	ret = rte_lhash_add_key_data(rstpl_hash(queue),
				    (const void *)&rstpl, (uint64_t)entry);
	if (ret) {
		ret = rte_sft_error_set(error, -ret,
					RTE_SFT_ERROR_TYPE_HASH_ERROR,
					NULL, "failed to add reverse tuple");
		goto err4;
	}
	sft_flow_activate(entry, error);

end:
	status->fid = entry->fid;
	status->activated = 1;

	return 0;

err4:
	rte_lhash_del_key(stpl_hash(queue), (const void *)&stpl, NULL);
err3:
	rte_lhash_del_key(fid_hash(queue), (const void *)&stpl, NULL);
err2:
	sft_fid_release(entry->fid);
err1:
	rte_free(entry);
	return ret;
}

int
rte_sft_process_mbuf_with_zone(uint16_t queue, struct rte_mbuf *mbuf_in,
			       uint32_t zone, struct rte_mbuf **mbuf_out,
			       struct rte_sft_flow_status *status,
			       struct rte_sft_error *error)
{
	int ret;
	struct sft_lib_entry *entry = NULL;
	struct rte_sft_decode_info decode_info;
	struct sft_mbuf_info mif;

	*mbuf_out = mbuf_in;
	mif.m = mbuf_in;
	ret = sft_parse_mbuf(&mif, error);
	if (ret)
		return ret;
	ret = sft_mbuf_decode(queue, mbuf_in, &decode_info, error);
	if (ret)
		return ret;
	if (decode_info.state & RTE_SFT_STATE_FLAG_FID_VALID) {
		sft_fid_locate_entry(queue, decode_info.fid, &entry);
		if (entry) {
			status->fid = entry->fid;
			if (entry->zone != zone)
				return rte_sft_error_set(error, EINVAL,
				 	RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				 	NULL, "zones not match");
		}
	} else if (decode_info.state & RTE_SFT_STATE_FLAG_ZONE_VALID) {
		if (decode_info.zone != zone)
			return rte_sft_error_set(error, EINVAL,
				 		 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				 		 NULL, "zones not match");
	}
	if (!entry) {
		struct rte_sft_7tuple stpl;
		rte_sft_mbuf_stpl(&mif, zone, &stpl, error);
		status->proto = stpl.flow_5tuple.proto;		
		sft_stpl_locate_entry(queue, &stpl, &entry);
		if (entry) {
			status->initiator = 1;
		} else {
			sft_rstpl_locate_entry(queue, &stpl, &entry);
			if (entry)
				status->initiator = 0;
		}
	}
	if (entry) {
		if (entry->zone != zone)
			return rte_sft_error_set(error, EINVAL,
				 	RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				 	NULL, "zones not match");
		status->fid = entry->fid;
		status->state = entry->app_state;
		status->activated = 1;
		status->offloaded = 1;
		if (entry->data)
			memcpy(status->data, entry->data, SFT_DATA_LEN);
		if (entry->action_specs.actions)
			sft_apply_mbuf_actions(mbuf_in, &entry->action_specs,
					       status->initiator);
	}
	status->zone_valid = 1;
	status->zone = zone;

	return 0;
}

int
rte_sft_process_mbuf(uint16_t queue, struct rte_mbuf *mbuf_in,
		     struct rte_mbuf **mbuf_out,
		     struct rte_sft_flow_status *status,
		     struct rte_sft_error *error)
{
	int ret;
	struct rte_sft_decode_info decode_info;
	struct sft_lib_entry *entry = NULL;
	struct sft_mbuf_info mif;

	*mbuf_out = mbuf_in;
	mif.m = mbuf_in;
	ret = sft_parse_mbuf(&mif, error);
	if (ret)
		return ret;
	ret = sft_mbuf_decode(queue, mbuf_in, &decode_info, error);
	if (ret)
		return ret;
	if (decode_info.state & RTE_SFT_STATE_FLAG_FID_VALID) {
		sft_fid_locate_entry(queue, decode_info.fid, &entry);
	} else if (decode_info.state & RTE_SFT_STATE_FLAG_ZONE_VALID) {
		struct rte_sft_7tuple stpl;

		status->zone = decode_info.zone;
		status->zone_valid = 1; 
		rte_sft_mbuf_stpl(&mif, decode_info.zone, &stpl, error);
		status->proto = stpl.flow_5tuple.proto;	
		sft_stpl_locate_entry(queue, &stpl, &entry);
		if (entry) {
			status->initiator = 1;
		} else {
			sft_rstpl_locate_entry(queue, &stpl, &entry);
			if (entry)
				status->initiator = 0;
		}
	}
	if (entry) {
		status->fid = entry->fid;
		status->state = entry->app_state;

		status->proto = entry->proto;
		status->offloaded = 1;
		if (entry->data)
			memcpy(status->data, entry->data, SFT_DATA_LEN);
		if (entry->action_specs.actions)
			sft_apply_mbuf_actions(mbuf_in, &entry->action_specs,
					       status->initiator);
	}
	if (sft_track_conn(entry)) {
		status->proto_state  = sft_get_conn_state(&mif);
		if (entry)
			entry->proto_state = status->proto_state;
	}
	
	return 0;
}

int
rte_sft_init(const struct rte_sft_conf *conf, struct rte_sft_error *error)
{
	int ret;

	RTE_SFT_LOG(DEBUG, "==== SFT DEBUG\n");

	ret = sft_init_context(conf, error);
	if (ret)
		return ret;
	ret = sft_create_hash(error);
	if (ret)
		goto err1;
	ret = sft_pmd_start(error);
	if (ret)
		goto err2;

	return 0;

err2:
	sft_destroy_hash();
err1:
	sft_destroy_context();
	return ret;
}

int
rte_sft_fini(struct rte_sft_error *error)
{
	sft_pmd_stop(error);
	sft_destroy_hash();
	sft_destroy_context();
	return 0;
}

RTE_LOG_REGISTER(sft_logtype, lib.sft, NOTICE);
