/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <time.h>

#include <rte_alarm.h>
#include <rte_byteorder.h>
#include <rte_lhash.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_malloc.h>
#include <rte_rwlock.h>
#include <rte_ip_frag.h>
#include <rte_cycles.h>

#include "rte_sft.h"
#include "rte_sft_driver.h"
#include "sft_utils.h"

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

struct ipfrag_ctx {
	struct rte_ip_frag_tbl *table;
	struct rte_ip_frag_death_row dr;
};

struct sft_age {
	rte_spinlock_t entries_sl;
	struct sft_lib_entries armed_entries;
	struct sft_lib_entries aged_entries;
	bool event_triggered;
};

/**
 * sft_priv
 * singleton that concentrates SFT library internal variables
 */
static struct {
	struct sft_hash *hq; /**< per-queue hashes */
	struct sft_id_pool *fid_ids_pool; /**< per-queue id pools */
	struct ipfrag_ctx *ipfrag; /**< per-queue ipfrag contexts */
	rte_rwlock_t fid_rwlock;
	struct rte_sft_conf conf;
	struct sft_age *age; /**<per-queue age lists */
} *sft_priv = NULL;

#define SFT_DATA_LEN (sft_priv->conf.app_data_len * sizeof(int))
#define SFT_IPFRAG_BUCKETS_NUM 128

#define SFT_OFFLOAD_QUERY_REPL_ERROR (1ul << 0)
#define SFT_OFFLOAD_QUERY_INIT_ERROR (1ul << 1)
/*
 * The default IP fragments timeout in Linux is 30 sec
 */
#define SFT_DEFAULT_IPFRAG_TIMEOUT 30

static __rte_always_inline bool
is_first_ipv4_frag(const struct rte_ipv4_hdr *h)
{
	uint16_t frag = rte_be_to_cpu_16(h->fragment_offset);
	return (frag & RTE_IPV4_HDR_MF_FLAG) &&
	       ((frag & RTE_IPV4_HDR_OFFSET_MASK) == 0);
}

static inline uint64_t
sft_calc_max_ipfrag_cycles(void)
{
	uint64_t one_sec_cycles = rte_get_tsc_hz();
	uint64_t ipfrag_timeout = sft_priv->conf.ipfrag_timeout ?
				  sft_priv->conf.ipfrag_timeout :
				  SFT_DEFAULT_IPFRAG_TIMEOUT;
	return one_sec_cycles * ipfrag_timeout;
}

static void
sft_destroy_ipfrag(void)
{
	uint16_t q;

	if (!sft_priv->ipfrag)
		return;
	for (q = 0; q < sft_priv->conf.nb_queues; q++) {
		struct ipfrag_ctx *ctx = &sft_priv->ipfrag[q];
		if (ctx->table)
			rte_ip_frag_table_destroy(ctx->table);
	}
	rte_free(sft_priv->ipfrag);
	sft_priv->ipfrag = NULL;
}

static int
sft_init_ipfrag_ctx(struct rte_sft_error *error)
{
	uint16_t q;
	uint16_t max_queue_ipfrags = sft_priv->conf.nb_max_ipfrag;
	uint32_t bucket_entries;
	uint64_t max_cycles = sft_calc_max_ipfrag_cycles();
	const char *err_msg;

	bucket_entries = sft_priv->conf.nb_max_ipfrag / SFT_IPFRAG_BUCKETS_NUM;
	bucket_entries /= 2; /* check rte_ip_frag_table_create() */
	sft_priv->ipfrag = rte_calloc("sft ipfrag ctx",
				      sft_priv->conf.nb_queues,
				      sizeof(struct ipfrag_ctx), 0);
	if (!sft_priv->ipfrag)
		return rte_sft_error_set(error, ENOMEM,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
					 NULL, "no ipfrag context");
	for (q = 0; q < sft_priv->conf.nb_queues; q++) {
		struct ipfrag_ctx *ctx = &sft_priv->ipfrag[q];
		ctx->table = rte_ip_frag_table_create(SFT_IPFRAG_BUCKETS_NUM,
						      bucket_entries,
						      max_queue_ipfrags,
						      max_cycles,
						      SOCKET_ID_ANY);
		if (!ctx->table) {
			err_msg = "cannot allocate ipfrag table";
			goto err;
		}
	}
	return 0;

err:
	sft_destroy_ipfrag();
	return rte_sft_error_set(error, ENOMEM, RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				 NULL, err_msg);

}

static void
sft_process_ipfrag(uint16_t queue, struct sft_mbuf *smb,
		   struct rte_sft_mbuf_info *mif,
		   struct rte_sft_flow_status *status,
		   struct rte_sft_error *error)
{
	struct ipfrag_ctx *ctx = &sft_priv->ipfrag[queue];
	struct ip_frag_pkt *fp;
	bool dr_full;
	uint32_t pkt_len = smb->m_in->pkt_len;

	RTE_SET_USED(error);
retry:
	dr_full = false;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	fp = !mif->is_ipv6 ?
	     rte_ipv4_frag_process(ctx->table, &ctx->dr,
				   (struct rte_mbuf *)smb->m_in,
				   rte_rdtsc(),
				   (struct rte_ipv4_hdr *)mif->ip4) :
	     rte_ipv6_frag_process(ctx->table, &ctx->dr,
				   (struct rte_mbuf *)smb->m_in,
				   rte_rdtsc(), (struct rte_ipv6_hdr *)mif->ip6,
				   (struct rte_ipv6_fragment_ext *)
					   mif->ip6_frag);
	if (pkt_len > smb->m_in->pkt_len)
		rte_pktmbuf_append((struct rte_mbuf *)smb->m_in,
				   pkt_len - smb->m_in->pkt_len);
#pragma GCC diagnostic pop
	dr_full = rte_ip_frag_dr_full(&ctx->dr);
	if (ctx->dr.cnt)
		rte_ip_frag_free_death_row(&ctx->dr, 0); /* clear all DR */
	if (dr_full)
		goto retry;
	status->fragmented = !!(fp == NULL);
	status->ipfrag_ctx = (uintptr_t)fp;
	if (fp) {
		/* first fragment is returned in m_out */
		status->nb_ip_fragments = fp->last_idx - 1;
		smb->m_out = fp->frags[IP_FIRST_FRAG_IDX].mb;
		smb->m_in = smb->m_out;
	} else {
		status->nb_ip_fragments = 0;
		smb->m_out = NULL;
	}
}

static void
sft_update_stat(struct sft_mbuf *smb, struct sft_lib_entry *entry, uint32_t dir)
{
	if (entry->action_specs.actions & RTE_SFT_ACTION_COUNT) {
		if (!entry->sft_entry[dir]) {
			/* update only if not counted in hardware already */
			entry->nb_bytes_sw[dir] += smb->m_in->pkt_len;
			entry->nb_packets_sw[dir]++;
		}
	}
	if (entry->action_specs.actions & RTE_SFT_ACTION_AGE) {
		rte_spinlock_lock(&(sft_priv->age[entry->queue].entries_sl));
		entry->last_activity_ts = time(NULL);
		rte_spinlock_unlock(&(sft_priv->age[entry->queue].entries_sl));
	}
}

static void
sft_track_conn(struct sft_mbuf *smb, struct rte_sft_mbuf_info *mif,
	       const struct sft_lib_entry *entry,
	       struct rte_sft_flow_status *status, struct rte_sft_error *error)
{
	if (entry->offload) {
		status->proto_state = SFT_CT_STATE_OFFLOADED;
		return;
	}
	switch (smb->m_in->l4_type << 8) {
	case RTE_PTYPE_L4_TCP:
		sft_tcp_track_conn(smb, mif, entry, status, error);
		break;
	case RTE_PTYPE_L4_UDP:
		status->proto_state = SFT_CT_STATE_TRACKING;
		break;
	default:
		status->protocol_error = 1;
		status->ct_info = SFT_CT_ERROR_UNSUPPORTED;
	}
}

static int
sft_start_conn_track(struct sft_lib_entry *entry, struct rte_sft_error *error)
{
	switch (entry->proto) {
	case IPPROTO_TCP:
		return sft_tcp_start_track(entry, error);
	default:
		break;
	}

	return 0;
}

static const struct rte_sft_ops *
sft_ops_get(struct rte_eth_dev *dev)
{
	const struct rte_sft_ops *ops = NULL;

	if (dev && dev->dev_ops && dev->dev_ops->sft_ops_get)
		dev->dev_ops->sft_ops_get(dev, &ops);

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
ipv6_ext_hdr_len(const struct rte_ipv6_hdr *ipv6_hdr, uint8_t *next_proto)
{
	size_t ext_len = 0, dx;
	int proto = ipv6_hdr->proto;
	const uint8_t *p = (typeof(p))(ipv6_hdr + 1);

	while ((proto = rte_ipv6_get_next_ext(p, proto, &dx)) != -EINVAL) {
		ext_len += dx;
		p += dx;
	}
	*next_proto = !ext_len ? ipv6_hdr->proto : p[1];

	return ext_len;
}

static int
stp_parse_ipv6(struct rte_sft_mbuf_info *mif, struct rte_sft_error *error)
{
	mif->is_ipv6 = 1;
	mif->is_fragment = !!(mif->ip6->proto == IPPROTO_FRAGMENT);
	if (!mif->is_fragment) {
		uint8_t l4_protocol;
		size_t ext_len = ipv6_ext_hdr_len(mif->ip6, &l4_protocol);

		/* rfc2460:
		 * "any extension headers [section 4] present are considered
		 *  part of the payload, i.e., included in the length count"
		 */
		mif->l4_hdr = (const char *)mif->l3_hdr + sizeof(*mif->ip6)
			      + ext_len;
		mif->l4_protocol = l4_protocol;
		switch (l4_protocol) {
		case IPPROTO_TCP:
			mif->data_len =
				rte_be_to_cpu_16(mif->ip6->payload_len) -
				ext_len - rte_tcp_hdr_len(mif->tcp);
			break;
		case IPPROTO_UDP:
			mif->data_len =
				rte_be_to_cpu_16(mif->ip6->payload_len) -
				ext_len - sizeof(struct rte_udp_hdr);
			break;
		default:
			return rte_sft_error_set(error, ENOTSUP,
						 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
						 NULL,
						 "unsupported l4 protocol");
		}

	}

	return 0;
}

static int
stp_parse_ipv4(struct rte_sft_mbuf_info *mif, struct rte_sft_error *error)
{
	mif->is_fragment = !!(mif->ip4->fragment_offset &
			      rte_cpu_to_be_16(RTE_IPV4_HDR_FRAGMENT_MASK));
	if (!mif->is_fragment || is_first_ipv4_frag(mif->ip4)) {
		mif->l4_hdr =
			(const uint8_t *)mif->ip4 + rte_ipv4_hdr_len(mif->ip4);
		mif->l4_protocol = mif->ip4->next_proto_id;
		switch (mif->ip4->next_proto_id) {
		case IPPROTO_UDP:
			mif->data_len = rte_be_to_cpu_16(mif->ip4->total_length)
					- rte_ipv4_hdr_len(mif->ip4)
					- sizeof(struct rte_udp_hdr);
			break;
		case IPPROTO_TCP:
			mif->data_len = rte_be_to_cpu_16(mif->ip4->total_length)
					- rte_ipv4_hdr_len(mif->ip4)
					- rte_tcp_hdr_len(mif->tcp);
			break;
		default:
			return rte_sft_error_set(error, ENOTSUP,
						 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
						 NULL,
						 "unsupported l4 protocol");
		}
	} else {
		mif->l4_hdr = NULL;
		mif->data_len = rte_be_to_cpu_16(mif->ip4->total_length)
				- rte_ipv4_hdr_len(mif->ip4);
	}
	return 0;
}

static int
stp_parse_ethernet(struct rte_sft_mbuf_info *mif, const void *entry,
		   struct rte_sft_error *error)
{
	size_t l2_len = RTE_ETHER_HDR_LEN;
	int ret = 0;

	RTE_SET_USED(entry);
	mif->eth_type = rte_be_to_cpu_16(mif->eth_hdr->ether_type);
	while (mif->eth_type == RTE_ETHER_TYPE_VLAN ||
	       mif->eth_type == RTE_ETHER_TYPE_QINQ) {
		const struct rte_vlan_hdr *vlan_hdr;
		vlan_hdr =
			(typeof(vlan_hdr))((const char *)mif->eth_hdr + l2_len);
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
		ret = rte_sft_error_set(error, ENOTSUP,
					RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					"unsupported L3 protocol");
	}
	return ret;
}

int
rte_sft_parse_mbuf(const struct rte_mbuf *m, struct rte_sft_mbuf_info *mif,
		   const void *entry, struct rte_sft_error *error)
{
	mif->eth_hdr = rte_pktmbuf_mtod(m, typeof(mif->eth_hdr));
	return stp_parse_ethernet(mif, entry, error);
}

void
rte_sft_mbuf_stpl(const struct rte_mbuf *m, struct rte_sft_mbuf_info *mif,
		  uint32_t zone, struct rte_sft_7tuple *stpl,
		  struct rte_sft_error *error)
{
	RTE_SET_USED(error);
	memset(stpl, 0, sizeof(*stpl));
	stpl->port_id = m->port;
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
		rte_memcpy(stpl->flow_5tuple.ipv6.src_addr, mif->ip6->src_addr,
			   sizeof(stpl->flow_5tuple.ipv6.src_addr));
		rte_memcpy(stpl->flow_5tuple.ipv6.dst_addr, mif->ip6->dst_addr,
			   sizeof(stpl->flow_5tuple.ipv6.dst_addr));
		stpl->flow_5tuple.proto = mif->ip6->proto;
		break;
	}
	if (!mif->is_fragment || is_first_ipv4_frag(mif->ip4)) {
		switch (stpl->flow_5tuple.proto) {
		case IPPROTO_TCP:
			stpl->flow_5tuple.src_port = mif->tcp->src_port;
			stpl->flow_5tuple.dst_port = mif->tcp->dst_port;
			break;
		case IPPROTO_UDP:
			stpl->flow_5tuple.src_port = mif->udp->src_port;
			stpl->flow_5tuple.dst_port = mif->udp->dst_port;
			break;
		}
	} else {
		stpl->flow_5tuple.src_port = 0xffff;
		stpl->flow_5tuple.dst_port = 0xffff;
	}
}

static int
sft_mbuf_decode(uint16_t queue, const struct rte_mbuf *mbuf,
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
	else if (info->state && (info->state & ~RTE_SFT_STATE_MASK))
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
		switch (ret) {
		case 0:
			RTE_SFT_LOG(DEBUG, "port-%u: SFT stopped\n", port);
			break;
		case -ENOTSUP:
			RTE_SFT_LOG(INFO, "port-%u: no SFT support\n", port);
			ret = 0;
			break;
		default:
			RTE_SFT_LOG(NOTICE, "port-%u: SFT stop failed err=%d\n",
				    port, ret);
		}
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
		switch (ret) {
		case 0:
			RTE_SFT_LOG(DEBUG, "port-%u: SFT started\n", port);
			break;
		case -ENOTSUP:
			RTE_SFT_LOG(INFO, "port-%u: no SFT support\n", port);
			ret = 0;
			break;
		default:
			RTE_SFT_LOG(NOTICE, "port-%u: SFT init failed err=%d\n",
				    port, ret);
			goto out;
		}
	}

out:
	if (ret) {
		struct rte_sft_error stop_error;
		sft_pmd_stop(&stop_error);
	}

	return ret;
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
	int i;
	patterns[0][0].type = RTE_FLOW_ITEM_TYPE_ETH;
	sft_l3_pattern(&patterns[0][1], &entry->stpl[0].flow_5tuple,
		       &ctx[0][1]);
	sft_l4_pattern(&patterns[0][2], &entry->stpl[0].flow_5tuple,
		       &ctx[0][2]);
	patterns[1][0].type = RTE_FLOW_ITEM_TYPE_ETH;
	sft_l3_pattern(&patterns[1][1], &entry->stpl[1].flow_5tuple,
		       &ctx[1][1]);
	sft_l4_pattern(&patterns[1][2], &entry->stpl[1].flow_5tuple,
		       &ctx[1][2]);
	for (i = 3; i < SFT_PATTERNS_NUM - 1; i++)
		patterns[0][i].type = patterns[1][i].type =
			RTE_FLOW_ITEM_TYPE_VOID;
	patterns[0][i].type = patterns[1][i].type =
		RTE_FLOW_ITEM_TYPE_END;
}

static void
sft_hit_actions(const struct sft_lib_entry *entry,
		struct rte_flow_action actions[2][SFT_ACTIONS_NUM],
		union sft_action_ctx ctx[2][SFT_ACTIONS_NUM])
{
	int fx = 0; /* forward traffic actions index */
	int rx = 0; /* reversed traffic actions index */

	if (entry->action_specs.actions & RTE_SFT_ACTION_INITIATOR_NAT)
		fx += sft_action_nat(&actions[0][fx],
				     &entry->stpl[0].flow_5tuple,
				     entry->action_specs.initiator_nat,
				     &ctx[0][fx]);
	if (entry->action_specs.actions & RTE_SFT_ACTION_REVERSE_NAT)
		rx += sft_action_nat(&actions[1][rx],
				     &entry->stpl[1].flow_5tuple,
				     entry->action_specs.reverse_nat,
				     &ctx[1][rx]);
	if (entry->action_specs.actions & RTE_SFT_ACTION_COUNT ||
	    entry->action_specs.actions & RTE_SFT_ACTION_AGE) {
		actions[0][fx].type = RTE_FLOW_ACTION_TYPE_COUNT;
		actions[0][fx].conf = &ctx[0][fx];
		actions[1][rx].type = RTE_FLOW_ACTION_TYPE_COUNT;
		actions[1][rx].conf = &ctx[1][rx];
		fx++;
		rx++;
	}
	RTE_VERIFY(fx < SFT_ACTIONS_NUM);
	RTE_VERIFY(rx < SFT_ACTIONS_NUM);
	for (; fx < SFT_ACTIONS_NUM - 1; fx++)
		actions[0][fx].type = RTE_FLOW_ACTION_TYPE_VOID;
	for (; rx < SFT_ACTIONS_NUM - 1; rx++)
		actions[1][rx].type = RTE_FLOW_ACTION_TYPE_VOID;
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
		fx += sft_action_nat(&actions[0][fx],
				     &entry->stpl[0].flow_5tuple,
				     entry->action_specs.initiator_nat,
				     &ctx[0][fx]);
	if (entry->action_specs.actions & RTE_SFT_ACTION_REVERSE_NAT)
		rx += sft_action_nat(&actions[1][rx],
				     &entry->stpl[1].flow_5tuple,
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
	for (; fx < SFT_ACTIONS_NUM - 1; fx++)
		actions[0][fx].type = RTE_FLOW_ACTION_TYPE_VOID;
	for (; rx < SFT_ACTIONS_NUM - 1; rx++)
		actions[1][rx].type = RTE_FLOW_ACTION_TYPE_VOID;
	actions[0][fx].type = RTE_FLOW_ACTION_TYPE_END;
	actions[1][rx].type = RTE_FLOW_ACTION_TYPE_END;
}

static uint64_t
sft_miss_conditions(const struct sft_lib_entry *entry)
{
	int miss_conditions;

	switch(entry->stpl[0].flow_5tuple.proto) {
	case IPPROTO_TCP:
		miss_conditions = entry->ct_enable ? RTE_SFT_MISS_TCP_FLAGS : 0;
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
		ops[0]->sft_entry_destroy(dev[0], entry->sft_entry[0],
					  entry->queue, error);
	if (ops[1] && entry->sft_entry[1])
		ops[1]->sft_entry_destroy(dev[1], entry->sft_entry[1],
					  entry->queue, error);

	return 0;
}

static int
sft_flow_modify(struct sft_lib_entry *entry, struct rte_sft_error *error)
{
	int ret;
	struct rte_eth_dev *dev[2];
	const struct rte_sft_ops *ops[2];

	dev[0] = &rte_eth_devices[entry->stpl[0].port_id];
	dev[1] = &rte_eth_devices[entry->stpl[1].port_id];
	sft_get_dev_ops(dev, entry, ops);
	if (ops[0] && ops[0]->sft_entry_modify) {
		ret = ops[0]->sft_entry_modify(dev[0], entry->queue,
					       entry->sft_entry[0], entry->data,
					       SFT_DATA_LEN, entry->app_state,
					       error);
		if (ret)
			return ret;
	}
	if (ops[1] && ops[1]->sft_entry_modify) {
		ret = ops[1]->sft_entry_modify(dev[1], entry->queue,
					       entry->sft_entry[1], entry->data,
					       SFT_DATA_LEN, entry->app_state,
					       error);
		if (ret)
			return ret;
	}

	return 0;
}

static __rte_always_inline int
sft_create_entry(struct rte_eth_dev *dev[2], const struct rte_sft_ops *ops[2],
		 struct sft_lib_entry *entry,
		 struct rte_flow_item hit_pattern[2][SFT_PATTERNS_NUM],
		 struct rte_flow_action hit_actions[2][SFT_PATTERNS_NUM],
		 struct rte_flow_action miss_actions[2][SFT_PATTERNS_NUM],
		 uint64_t miss_conditions, uint8_t dir,
		 struct rte_sft_error *error)
{
	int ret;
	struct rte_sft_entry *se;
	sft_entry_create_t create_entry = ops[dir]->sft_create_entry;
	bool initiator = !dir;

	se = create_entry(dev[dir], entry->fid, entry->zone, entry->queue,
			  hit_pattern[dir], miss_conditions, hit_actions[dir],
			  miss_actions[dir], entry->data, SFT_DATA_LEN,
			  entry->app_state, initiator, error);
	entry->sft_entry[dir] = se;
	if (entry->sft_entry[dir]) {
		ret = 0;
	} else {
		switch (rte_errno) {
		default:
			ret = -rte_errno;
			RTE_SFT_LOG(NOTICE, "port-%u: "
				    "failed to activate flow %u err=%d\n",
				    dev[dir]->data->port_id, entry->fid, ret);
			break;
		case ENOTSUP:
			ret = 0;
			break;
		}
	}

	return ret;
}

static int
sft_flow_activate(struct sft_lib_entry *entry,
		  struct rte_sft_error *error)
{
	int ret;
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
		ret = sft_create_entry(dev, ops, entry, hit_pattern,
				       hit_actions, miss_actions,
				       miss_conditions, 0, error);
		if (ret)
			return ret;
	}
	if (ops[1]) {
		ret = sft_create_entry(dev, ops, entry, hit_pattern,
				       hit_actions, miss_actions,
				       miss_conditions, 1, error);
		if (ret && entry->sft_entry[0]) {
			ops[0]->sft_entry_destroy(dev[0], entry->sft_entry[0],
						  entry->queue, error);
			return ret;
		}
	}
	return 0;
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
sft_mbuf_apply_nat(struct rte_sft_mbuf_info *mif,
		   const struct rte_sft_5tuple *nat)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	struct rte_ipv6_hdr *ip6 = (typeof(ip6))mif->ip6;
	struct rte_ipv4_hdr *ip4 = (typeof(ip4))mif->ip4;
	struct rte_tcp_hdr  *tcp = (typeof(tcp))mif->tcp;
	struct rte_udp_hdr  *udp = (typeof(udp))mif->udp;
#pragma GCC diagnostic pop

	if (!nat->is_ipv6) {

		if (nat->ipv4.src_addr)
			ip4->src_addr = nat->ipv4.src_addr;
		if (nat->ipv4.dst_addr)
			ip4->dst_addr = nat->ipv4.dst_addr;
	} else {

		if (!ipv6_is_zero_addr(nat->ipv6.src_addr))
			memcpy(ip6->src_addr, nat->ipv6.src_addr,
			       sizeof(ip6->src_addr));
		if (!ipv6_is_zero_addr(nat->ipv6.dst_addr))
			memcpy(ip6->dst_addr, nat->ipv6.dst_addr,
			       sizeof(ip6->dst_addr));
	}
	switch (mif->l4_protocol) {
	case IPPROTO_UDP:
		if (nat->src_port)
			udp->src_port = nat->src_port;
		if (nat->dst_port)
			udp->dst_port = nat->dst_port;
		break;
	case IPPROTO_TCP:
		if (nat->src_port)
			tcp->src_port = nat->src_port;
		if (nat->dst_port)
			tcp->dst_port = nat->dst_port;
		break;
	default:
		break;
	}
}

static void
sft_apply_mbuf_actions(struct rte_sft_mbuf_info *mif,
		       const struct rte_sft_actions_specs *action_specs,
		       bool is_initiator)
{
	if (is_initiator &&
	    (action_specs->actions & RTE_SFT_ACTION_INITIATOR_NAT))
		sft_mbuf_apply_nat(mif, action_specs->initiator_nat);
	if (!is_initiator &&
	    (action_specs->actions & RTE_SFT_ACTION_REVERSE_NAT))
		sft_mbuf_apply_nat(mif, action_specs->reverse_nat);
}

static void
sft_destroy_context(void)
{
	if (sft_priv->age)
		rte_free(sft_priv->age);
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
	uint16_t i;

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
	if (!sft_priv->conf.ipfrag_timeout)
		sft_priv->conf.ipfrag_timeout = SFT_IPFRAG_TIMEOUT;
	sft_priv->fid_ids_pool = sft_id_pool_alloc(conf->nb_max_entries);
	if (!sft_priv->fid_ids_pool)
		goto error;
	rte_rwlock_init(&sft_priv->fid_rwlock);

	sft_priv->age = rte_zmalloc("sft age lists",
				      conf->nb_queues *
				      sizeof(sft_priv->age[0]), 0);
	for (i = 0; i < sft_priv->conf.nb_queues; i++) {
		rte_spinlock_init(&(sft_priv->age[i].entries_sl));
		TAILQ_INIT(&(sft_priv->age[i].armed_entries));
		TAILQ_INIT(&(sft_priv->age[i].aged_entries));
	}

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

static int
sft_set_data(struct sft_lib_entry *entry, const uint32_t *data,
	     struct rte_sft_error *error)
{
	if (SFT_DATA_LEN == 0)
		return 0;
	else if (!entry->data) {
		entry->data = rte_malloc("uint32_t", SFT_DATA_LEN, 0);
		if (!entry->data)
			return rte_sft_error_set(error, ENOMEM,
						 RTE_SFT_ERROR_TYPE_HASH_ERROR,
						 NULL,
						 "failed allocate user data");
	}
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
	if (entry->action_specs.actions & RTE_SFT_ACTION_AGE) {
		rte_spinlock_lock(&(sft_priv->age[queue].entries_sl));
		if (entry->aged)
			TAILQ_REMOVE(&(sft_priv->age[queue].aged_entries),
					entry, next);
		else
			TAILQ_REMOVE(&(sft_priv->age[queue].armed_entries),
					entry, next);
		rte_spinlock_unlock(&(sft_priv->age[queue].entries_sl));
	}
	sft_flow_deactivate(entry, error);
	if (entry->data)
		rte_free(entry->data);
	while (!LIST_EMPTY(&entry->client_objects_head)) {
		struct client_obj *head;

		head = LIST_FIRST(&entry->client_objects_head);
		LIST_REMOVE(head, chain);
		rte_free(head);
	}
	sft_fid_release(entry->fid);
	if (entry->ct_enable && entry->proto == IPPROTO_TCP)
		sft_tcp_stop_conn_track(entry, error);
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
	status->proto_state = (typeof(status->proto_state))entry->proto_state;
	status->proto = entry->proto;
	if (entry->data)
		memcpy(status->data, entry->data, SFT_DATA_LEN);

	return 0;
}

static int
sft_flow_query(struct sft_lib_entry *entry,
	       struct rte_flow_query_count *reply_data,
		   struct rte_flow_query_count *init_data,
	       struct rte_sft_error *error)
{
	int ret = 0, reply_ret = 0, init_ret = 0;
	struct rte_eth_dev *dev[2];
	const struct rte_sft_ops *ops[2];

	dev[0] = &rte_eth_devices[entry->stpl[0].port_id];
	dev[1] = &rte_eth_devices[entry->stpl[1].port_id];
	sft_get_dev_ops(dev, entry, ops);
	if (ops[0] && entry->sft_entry[0]) {
		reply_ret = ops[0]->sft_query(dev[0], entry->queue,
					      entry->sft_entry[0],
					      reply_data, error);
		if (reply_ret)
			ret |= SFT_OFFLOAD_QUERY_REPL_ERROR;
	}
	if (ops[1] && entry->sft_entry[1]) {
		init_ret = ops[1]->sft_query(dev[1], entry->queue,
					     entry->sft_entry[1],
					     init_data, error);
		if (init_ret)
			ret |= SFT_OFFLOAD_QUERY_INIT_ERROR;
	}
	return ret;
}

int
rte_sft_flow_query(uint16_t queue, uint32_t fid,
		   struct rte_sft_query_data *data,
		   struct rte_sft_error *error)
{
	struct sft_lib_entry *entry = NULL;
	struct rte_flow_query_count repl_cnt, init_cnt;
	int ret = 0;

	sft_fid_locate_entry(queue, fid, &entry);
	if (!entry)
		return rte_sft_error_set(error, ENOENT,
					 RTE_SFT_ERROR_TYPE_FLOW_NOT_DEFINED,
					 NULL, "invalid fid value");
	if (!(entry->action_specs.actions & RTE_SFT_ACTION_COUNT) &&
	    !(entry->action_specs.actions & RTE_SFT_ACTION_AGE))
		return rte_sft_error_set(error, ENOENT,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
					 NULL, "action not configured");
	memset(&repl_cnt, 0, sizeof(repl_cnt));
	memset(&init_cnt, 0, sizeof(init_cnt));
	ret = sft_flow_query(entry, &repl_cnt, &init_cnt, error);
	if (entry->action_specs.actions & RTE_SFT_ACTION_COUNT) {
		if (!(ret & SFT_OFFLOAD_QUERY_REPL_ERROR)) {
			entry->nb_bytes_hw[0] = repl_cnt.bytes;
			entry->nb_packets_hw[0] = repl_cnt.hits;
		}
		data->nb_bytes[0] =
			entry->nb_bytes_sw[0] + entry->nb_bytes_hw[0];
		data->nb_packets[0] =
			entry->nb_packets_sw[0] + entry->nb_packets_hw[0];
		if (!(ret & SFT_OFFLOAD_QUERY_INIT_ERROR)) {
			entry->nb_bytes_hw[1] += init_cnt.bytes;
			entry->nb_packets_hw[1] = init_cnt.hits;
		}
		data->nb_bytes[1] =
			entry->nb_bytes_sw[1] + entry->nb_bytes_hw[1];
		data->nb_bytes_valid = 1;
		data->nb_packets[1] =
			entry->nb_packets_sw[1] + entry->nb_packets_hw[1];
		data->nb_packets_valid = 1;
	}
	if (entry->action_specs.actions & RTE_SFT_ACTION_AGE) {
		data->age = RTE_MIN((uint32_t)difftime(time(NULL),
						       entry->last_activity_ts),
				    entry->action_specs.aging);
		data->nb_age_valid = 1;
		data->aging = entry->action_specs.aging;
		data->nb_aging_valid = 1;
	}
	return 0;
}

int
rte_sft_flow_get_aged_flows(uint16_t queue, uint32_t *fids,
		    uint32_t nb_fids, struct rte_sft_error *error)
{
	struct sft_lib_entry *entry = NULL;
	int nb_flows = 0;

	if (nb_fids && !fids)
		return rte_sft_error_set(error, ENOENT,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "empty fids array");
	rte_spinlock_lock(&(sft_priv->age[queue].entries_sl));
	TAILQ_FOREACH(entry, &(sft_priv->age[queue].aged_entries), next) {
		nb_flows++;
		if (nb_fids) {
			fids[nb_flows - 1] = entry->fid;
			if (!(--nb_fids))
				break;
			if (sft_priv->age[queue].event_triggered)
				sft_priv->age[queue].event_triggered = false;
		}
	}
	rte_spinlock_unlock(&(sft_priv->age[queue].entries_sl));
	return nb_flows;
}

int
rte_sft_flow_set_aging(uint16_t queue, uint32_t fid, uint32_t aging,
		       struct rte_sft_error *error)
{
	struct sft_lib_entry *entry = NULL;

	sft_fid_locate_entry(queue, fid, &entry);
	if (!entry)
		return rte_sft_error_set(error, ENOENT,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "invalid fid value");
	rte_spinlock_lock(&(sft_priv->age[queue].entries_sl));
	entry->action_specs.aging = aging;
	if (!(entry->action_specs.actions & RTE_SFT_ACTION_AGE)) {
		entry->action_specs.actions &= RTE_SFT_ACTION_AGE;
		TAILQ_INSERT_TAIL(&(sft_priv->age[queue].armed_entries),
				  entry, next);
	}
	rte_spinlock_unlock(&(sft_priv->age[queue].entries_sl));
	RTE_SFT_LOG(DEBUG, "Set aging for SFT %u to %u\n", fid, aging);
	return 0;
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
	if (entry->offload && !offload) {
		f_op = sft_flow_deactivate;
		if (entry->ct_enable) {
			sft_tcp_stop_conn_track(entry, error);
			entry->ct_enable = 0;
			entry->ct_obj = NULL;
		}
	} else if (!entry->offload && offload) {
		f_op = sft_flow_activate;
	} else {
		f_op = NULL;
	}

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

	return sft_flow_modify(entry, error);
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
	rte_spinlock_lock(&(sft_priv->age[queue].entries_sl));
	entry->last_activity_ts = time(NULL);
	if (entry->aged) {
		TAILQ_REMOVE(&(sft_priv->age[queue].aged_entries), entry, next);
		TAILQ_INSERT_TAIL(&(sft_priv->age[queue].armed_entries),
						  entry, next);
		entry->aged = false;
	}
	rte_spinlock_unlock(&(sft_priv->age[queue].entries_sl));
	return 0;
}

int
rte_sft_flow_set_data(uint16_t queue, uint32_t fid, const uint32_t *data,
		      struct rte_sft_error *error)
{
	int ret;
	struct sft_lib_entry *entry = NULL;

	sft_fid_locate_entry(queue, fid, &entry);
	if(!entry)
		return rte_sft_error_set(error, ENOENT,
				  	 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "invalid fid value");
	ret = sft_set_data(entry, data, error);
	if (ret)
		return ret;
	return sft_flow_modify(entry, error);

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
						 NULL, "cannot allocate "
						       "client object");
		cobj->id = id;
		cobj->obj = obj;
		LIST_INSERT_HEAD(&entry->client_objects_head, cobj, chain);
	} else {
		cobj->obj = obj;
	}

	return 0;
}

void
sft_query_alarm(void *param)
{
	struct sft_lib_entry *entry;
	struct rte_flow_query_count repl_cnt, init_cnt;
	time_t now = time(NULL);
	bool trigger_event = false;
	uint16_t port_id = 0;
	int ret = 0;
	uint16_t i;

	RTE_SET_USED(param);

	if (sft_priv == NULL) {
		RTE_SFT_LOG(ERR, "Query alarm called after SFT was destroyed");
		return;
	}

	for (i = 0; i < sft_priv->conf.nb_queues; i++) {
		rte_spinlock_lock(&(sft_priv->age[i].entries_sl));
		trigger_event = false;
		if (TAILQ_EMPTY(&(sft_priv->age[i].aged_entries)))
			sft_priv->age[i].event_triggered = false;
		TAILQ_FOREACH(entry, &(sft_priv->age[i].armed_entries), next) {
			memset(&repl_cnt, 0, sizeof(repl_cnt));
			memset(&init_cnt, 0, sizeof(init_cnt));
			ret = sft_flow_query(entry, &repl_cnt, &init_cnt, NULL);
			if (!(ret & SFT_OFFLOAD_QUERY_REPL_ERROR) &&
			    entry->nb_packets_hw[0] != repl_cnt.hits) {
				entry->last_activity_ts = now;
				entry->nb_bytes_hw[0] = repl_cnt.bytes;
				entry->nb_packets_hw[0] = repl_cnt.hits;
			}
			if (!(ret & SFT_OFFLOAD_QUERY_INIT_ERROR) &&
			    entry->nb_packets_hw[1] != init_cnt.hits) {
				entry->last_activity_ts = now;
				entry->nb_bytes_hw[1] = init_cnt.bytes;
				entry->nb_packets_hw[1] = init_cnt.hits;
			}
			if (difftime(now, entry->last_activity_ts) >=
			    entry->action_specs.aging) {
				TAILQ_REMOVE(&(sft_priv->age[i].armed_entries),
					     entry, next);
				TAILQ_INSERT_TAIL(
					&(sft_priv->age[i].aged_entries),
					entry, next);
				entry->aged = true;
				RTE_SFT_LOG(DEBUG,
					    "%" PRIu64 ": SFT entry %u aged out"
					    " on queue %u since %" PRIu64,
					    (uint64_t)now, entry->fid, i,
					    (uint64_t)entry->last_activity_ts);
				trigger_event = true;
				port_id = entry->stpl[0].port_id;
			}
		}
		rte_spinlock_unlock(&(sft_priv->age[i].entries_sl));
		if (trigger_event && !sft_priv->age[i].event_triggered) {
			sft_priv->age[i].event_triggered = true;
			rte_eth_dev_callback_process(&rte_eth_devices[port_id],
						RTE_ETH_EVENT_SFT_AGED, &i);
		}
	}
	sft_set_alarm();
}

int
sft_set_alarm(void)
{
	if (rte_eal_alarm_set(RTE_SFT_QUERY_FREQ_US, sft_query_alarm, NULL)) {
		RTE_SFT_LOG(ERR, "Cannot reinitialize query alarm");
		return -1;
	}
	return 0;
}

int
sft_cancel_alarm(void)
{
	if (rte_eal_alarm_cancel(sft_query_alarm, NULL) < 0) {
		RTE_SFT_LOG(ERR, "Cannot cancel query alarm");
		return -1;
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
	struct sft_mbuf smb = { .m_in = mbuf_in, .m_out = mbuf_in };
	struct rte_sft_mbuf_info mif = { NULL, };

	ret = rte_sft_parse_mbuf(mbuf_in, &mif, NULL, error);
	if (ret)
		return ret;
	rte_sft_mbuf_stpl(mbuf_in, &mif, zone, &stpl, error);
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
	entry->ct_enable = sft_priv->conf.tcp_ct_enable && proto_enable;
	entry->event_dev_id = dev_id;
	entry->event_port_id = port_id;
	entry->stpl[0] = stpl;
	entry->stpl[1] = rstpl;
	entry->offload = false;
	entry->l2_len = (uintptr_t)mif.l3_hdr - (uintptr_t)mif.eth_hdr;
	entry->direction_key =
		*(const typeof(entry->direction_key) *)mif.eth_hdr;
	status->initiator = 1;
	if (data && SFT_DATA_LEN != 0) {
		ret = sft_set_data(entry, data, error);
		if (ret)
			goto err2;
	}
	if (action_specs) {
		entry->action_specs = *action_specs;
		if (action_specs->actions)
			sft_apply_mbuf_actions(&mif, action_specs,
					       true);
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
	if (entry->ct_enable) {
		ret = sft_start_conn_track(entry, error);
		if (ret)
			goto err5;
		sft_track_conn(&smb, &mif, entry, status, error);
	}
	sft_flow_activate(entry, error);
	if (action_specs && action_specs->actions & RTE_SFT_ACTION_AGE) {
		if (!action_specs->aging) {
			switch (smb.m_in->l4_type << 8) {
			case RTE_PTYPE_L4_TCP:
				if (sft_priv->conf.tcp_aging)
					entry->action_specs.aging =
						sft_priv->conf.tcp_aging;
				else
					entry->action_specs.aging =
						sft_priv->conf.default_aging;
				break;
			case RTE_PTYPE_L4_UDP:
				if (sft_priv->conf.udp_aging)
					entry->action_specs.aging =
						sft_priv->conf.udp_aging;
				else
					entry->action_specs.aging =
						sft_priv->conf.default_aging;
				break;
			default:
				entry->action_specs.aging =
					sft_priv->conf.default_aging;
			}
		}
		rte_spinlock_lock(&(sft_priv->age[queue].entries_sl));
		entry->last_activity_ts = time(NULL);
		entry->aged = false;
		TAILQ_INSERT_TAIL(&(sft_priv->age[queue].armed_entries),
				  entry, next);
		rte_spinlock_unlock(&(sft_priv->age[queue].entries_sl));
		RTE_SFT_LOG(DEBUG, "Add SFT entry %u to list %" PRIu64 "\n",
			    entry->fid, (uint64_t)entry->last_activity_ts);
	}

end:
	status->fid = entry->fid;
	status->activated = 1;
	*mbuf_out = smb.m_out;

	return 0;

err5:
	rte_lhash_del_key(rstpl_hash(queue), (const void *)&rstpl, NULL);
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

static int
sft_process_mbuf(uint16_t queue, struct sft_mbuf *smb,
		 struct rte_sft_mbuf_info *mif,
		 struct rte_sft_decode_info *decode_info,
		 struct sft_lib_entry **entry,
		 struct rte_sft_flow_status *status,
		 struct rte_sft_error *error)
{
	int ret;
	uint64_t rx_ol_flags = smb->m_in->ol_flags;

	if ((rx_ol_flags & PKT_RX_IP_CKSUM_MASK) == PKT_RX_IP_CKSUM_BAD)
		return rte_sft_error_set(error, EINVAL,
					 RTE_SFT_ERROR_CHECKSUM, NULL,
					 "bad L3 checksum");
	if ((rx_ol_flags & PKT_RX_L4_CKSUM_MASK) == PKT_RX_L4_CKSUM_BAD)
		return rte_sft_error_set(error, EINVAL,
					 RTE_SFT_ERROR_CHECKSUM, NULL,
					 "bad L4 checksum");
	ret = sft_mbuf_decode(queue, smb->m_in, decode_info, error);
	if (ret)
		return ret;
	if (decode_info->fid_valid) {
		status->initiator = decode_info->direction;
		mif->direction_located = 1;
		sft_fid_locate_entry(queue, decode_info->fid, entry);
	}
	ret = rte_sft_parse_mbuf(smb->m_in, mif, NULL, error);
	if (ret)
		return ret;
	if (mif->is_fragment) {
		if (!sft_priv->conf.ipfrag_enable)
			return rte_sft_error_set(error, ENOTSUP,
						 RTE_SFT_ERROR_IPFRAG,
						 NULL,
						 "IP fragments not supported");
		sft_process_ipfrag(queue, smb, mif, status, error);
	}

	return 0;
}

static struct sft_lib_entry *
sft_stpl_to_entry(uint16_t queue, struct sft_mbuf *smb,
		  struct rte_sft_mbuf_info *mif, uint32_t zone,
		  struct rte_sft_flow_status *status,
		  struct rte_sft_error *error)
{
	struct rte_sft_7tuple stpl;
	struct sft_lib_entry *entry;

	status->zone = zone;
	status->zone_valid = 1;
	rte_sft_mbuf_stpl(smb->m_in, mif, zone, &stpl, error);
	status->proto = stpl.flow_5tuple.proto;
	sft_stpl_locate_entry(queue, &stpl, &entry);
	if (entry) {
		status->initiator = 1;
	} else {
		status->initiator = 0;
		sft_rstpl_locate_entry(queue, &stpl, &entry);
	}
	mif->direction_located = 1;

	return entry;
}

static void
sft_process_entry(struct sft_mbuf *smb, struct rte_sft_mbuf_info *mif,
		  struct rte_sft_decode_info *decode_info,
		  struct sft_lib_entry *entry,
		  struct rte_sft_flow_status *status,
		  struct rte_sft_error *error)
{
	status->fid = entry->fid;
	status->activated = 1;
	status->state = entry->app_state;
	status->proto = entry->proto;
	status->offloaded = entry->offload;

	if (!mif->direction_located)
		status->initiator = sft_match_directions(entry, smb->m_in);
	if (entry->data)
		memcpy(status->data, entry->data, SFT_DATA_LEN);
	if (entry->action_specs.actions && !decode_info->fid_valid) {
		sft_apply_mbuf_actions(mif, &entry->action_specs,
				       status->initiator);
	}
	if (entry->ct_enable)
		sft_track_conn(smb, mif, entry, status, error);
	sft_update_stat(smb, entry, status->initiator);
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
	struct sft_mbuf smb = { .m_in = mbuf_in, .m_out = mbuf_in };
	struct rte_sft_mbuf_info mif = { NULL, };

	ret = sft_process_mbuf(queue, &smb, &mif, &decode_info, &entry, status,
			       error);
	if (ret || status->fragmented)
		return ret;
	if (decode_info.zone_valid) {
		if (decode_info.zone != zone)
			return rte_sft_error_set(error, EINVAL,
				 		 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				 		 NULL, "zones not match");
	}
	if (!entry)
		entry = sft_stpl_to_entry(queue, &smb, &mif, zone, status,
					  error);
	if (entry) {
		if (entry->zone != zone)
			return rte_sft_error_set(error, EINVAL,
				 	RTE_SFT_ERROR_TYPE_UNSPECIFIED,
				 	NULL, "zones not match");
		sft_process_entry(&smb, &mif, &decode_info, entry, status,
				  error);
	} else {
		status->proto_state = SFT_CT_STATE_NEW;
	}
	*mbuf_out = smb.m_out;

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
	struct sft_mbuf smb = { .m_in = mbuf_in, .m_out = mbuf_in };
	struct rte_sft_mbuf_info mif = { NULL, };

	ret = sft_process_mbuf(queue, &smb, &mif, &decode_info, &entry,
			       status, error);
	if (ret || status->fragmented)
		return ret;
	if (decode_info.zone_valid)
		entry = sft_stpl_to_entry(queue, &smb, &mif, decode_info.zone,
					  status, error);
	if (entry)
		sft_process_entry(&smb, &mif, &decode_info, entry, status,
				  error);
	else
		status->proto_state = SFT_CT_STATE_NEW;
	*mbuf_out = smb.m_out;

	return 0;
}

int
rte_sft_drain_mbuf(uint16_t queue, uint32_t fid,
		   struct rte_mbuf **mbuf_out, uint16_t nb_out,
		   bool initiator, struct rte_sft_flow_status *status,
		   struct rte_sft_error *error)
{
	int ret;
	struct sft_lib_entry *entry;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	const struct rte_mbuf **m_out = (typeof(m_out))mbuf_out;
#pragma GCC diagnostic pop

	sft_fid_locate_entry(queue, fid, &entry);
	if (!entry)
		return rte_sft_error_set(error, EINVAL,
					 RTE_SFT_ERROR_TYPE_FLOW_NOT_DEFINED,
					 NULL, "invalid fid value");
	status->fid = fid;
	status->initiator = !!initiator;
	ret = sft_tcp_drain_mbuf(entry, m_out, nb_out, status);
	if (ret < 0)
		ret = rte_sft_error_set(error, EINVAL,
					RTE_SFT_ERROR_TYPE_UNSPECIFIED,
					NULL, "failed to drain TCP");
	return ret;
}

static void
sft_ipfrag_release_key(uint16_t queue, uintptr_t frag_ctx)
{
	struct ip_frag_pkt *fp = (typeof(fp))frag_ctx;
	fp->key.key_len = 0; /* invalidate key */
	rte_ip_frag_release_collected(fp, &sft_priv->ipfrag[queue].dr);
}

static void
sft_ipfrag_flush(uint16_t queue, uintptr_t frag_ctx)
{
	struct ip_frag_pkt *fp = (typeof(fp))frag_ctx;
	uint32_t fx;

	for (fx = 0; fx < IP_MAX_FRAG_NUM; fx++) {
		if (fp->frags[fx].mb) {
			rte_pktmbuf_free(fp->frags[fx].mb);
			fp->frags[fx].mb = NULL;
		}
	}
	fp->last_idx = 0;
	sft_ipfrag_release_key(queue, frag_ctx);
}

int
rte_sft_drain_fragment_mbuf(uint16_t queue, uint32_t zone, uintptr_t frag_ctx,
			    uint16_t num_to_drain, struct rte_mbuf **mbuf_out,
			    struct rte_sft_flow_status *status,
			    struct rte_sft_error *error)
{
	struct ip_frag_pkt *fp = (typeof(fp))frag_ctx;
	struct rte_sft_decode_info decode_info = {{ 0 }, };
	struct rte_sft_mbuf_info mif = { NULL, };
	struct sft_mbuf smb;
	struct sft_lib_entry *entry;
	uint32_t fx, i, frag_num;
	int ret = 0;
	RTE_SET_USED(queue);
	RTE_SET_USED(error);
	if (!fp || !fp->key.locked)
		return rte_sft_error_set(error, EINVAL,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED, NULL,
					 "invalid IP fragments context");
	if (fp->frags[IP_FIRST_FRAG_IDX].mb) {
		smb.m_in = smb.m_out = fp->frags[IP_FIRST_FRAG_IDX].mb;
		fp->frags[IP_FIRST_FRAG_IDX].mb = NULL;
		ret = rte_sft_parse_mbuf(smb.m_in, &mif, NULL, error);
		if (ret) {
			sft_ipfrag_flush(queue, frag_ctx);
			return rte_sft_error_set(error, EINVAL,
						 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
						 NULL, "cannot parse mbuf");
		}
		entry = sft_stpl_to_entry(queue, &smb, &mif, zone, status,
					  error);
		if (!entry) {
			sft_ipfrag_flush(queue, frag_ctx);
			return rte_sft_error_set(error, EINVAL,
						 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
						 NULL, "no active flow");
		} else if (entry->zone != zone) {
			sft_ipfrag_flush(queue, frag_ctx);
			return rte_sft_error_set(error, EINVAL,
						 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
						 NULL, "zones not match");
		}
		for (fx = IP_FIRST_FRAG_IDX + 1;
		     fx != IP_FIRST_FRAG_IDX;
		     fx = (fx + 1) % IP_MAX_FRAG_NUM) {
			struct rte_sft_mbuf_info fif = { NULL, };
			if (!fp->frags[fx].mb)
				continue;
			ret = rte_sft_parse_mbuf(fp->frags[fx].mb, &fif, NULL,
						 error);
			if (ret) {
				sft_ipfrag_flush(queue, frag_ctx);
				return rte_sft_error_set
					(error, EINVAL,
					 RTE_SFT_ERROR_TYPE_UNSPECIFIED,
					 NULL, "cannot parse fragment mbuf");
			}
			mif.data_len += fif.data_len;
		}
		sft_process_entry(&smb, &mif, &decode_info, entry, status,
				  error);
	}
	for (fx = IP_FIRST_FRAG_IDX + 1, i = 0;
	     fx != IP_FIRST_FRAG_IDX && i < num_to_drain;
	     fx = (fx + 1) % IP_MAX_FRAG_NUM) {
		if (!fp->frags[fx].mb)
			continue;
		mbuf_out[i++] = fp->frags[fx].mb;
		fp->frags[fx].mb = NULL;
	}
	status->nb_ip_fragments = i;
	for (fx = 0, frag_num = 0; fx < IP_FIRST_FRAG_IDX; fx++) {
		if (fp->frags[fx].mb)
			frag_num++;
	}
	if (!frag_num) {
		fp->last_idx = 0;
		sft_ipfrag_release_key(queue, frag_ctx);
	}
	return 0;
}

void
rte_sft_debug(uint16_t port_id, uint16_t queue, uint32_t fid,
	      struct rte_sft_error *error)
{
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	const struct rte_sft_ops *sft_ops = sft_ops_get(dev);
	struct sft_lib_entry *entry = NULL;

	if (!sft_ops || !sft_ops->sft_debug)
		return;
	sft_fid_locate_entry(queue, fid, &entry);
	if (!entry)
		return;
	sft_ops->sft_debug(dev, entry->sft_entry, error);
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
	if (conf->ipfrag_enable) {
		ret = sft_init_ipfrag_ctx(error);
		if (ret)
			goto err2;
	}
	ret = sft_pmd_start(error);
	if (ret)
		goto err3;
	ret = sft_set_alarm();
	if (ret)
		goto err4;

	return 0;

err4:
	sft_pmd_stop(error);
err3:
	sft_destroy_ipfrag();
err2:
	sft_destroy_hash();
err1:
	sft_destroy_context();
	return ret;
}

int
rte_sft_fini(struct rte_sft_error *error)
{
	sft_cancel_alarm();
	sft_pmd_stop(error);
	sft_destroy_hash();
	sft_destroy_context();
	return 0;
}

/*
 * enable SFT debug logs with EAL parameter:
 *  --log-level=lib.sft:debug
 */
RTE_LOG_REGISTER(sft_logtype, lib.sft, NOTICE);
