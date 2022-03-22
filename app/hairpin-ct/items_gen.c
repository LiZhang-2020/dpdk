/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Nvidia Inc. All rights reserved.
 *
 * This file contain the implementations of the items
 * related methods. Each Item have a method to prepare
 * the item and add it into items array in given index.
 */

#include <stdint.h>
#include <rte_flow.h>

#include "items_gen.h"
#include "flow_gen.h"
#include "config.h"

/* Storage for additional parameters for items */
struct additional_para {
	rte_be32_t src_ip;
	uint8_t core_idx;
	bool cross_port;
	bool reply_dir;
	uint8_t time_to_live;
	bool set_ipv4_addrs;
	bool no_frag;
	bool set_ports;
	uint16_t l3_type;
	bool set_ihl;
	uint64_t ports_per_ip;
};

static void
add_ether(struct rte_flow_item *items,
	uint8_t items_counter,
	__rte_unused struct additional_para para)
{
	static struct rte_flow_item_eth eth_spec[RTE_MAX_LCORE] __rte_cache_aligned;
	static struct rte_flow_item_eth eth_mask[RTE_MAX_LCORE] __rte_cache_aligned;

	if (para.l3_type != (uint16_t)-1) {
		eth_spec[para.core_idx].type = RTE_BE16(para.l3_type);
		eth_mask[para.core_idx].type = RTE_BE16(0xffff);
	} else {
		eth_mask[para.core_idx].type = RTE_BE16(0x0000);
	}

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_ETH;
	items[items_counter].spec = &eth_spec;
	items[items_counter].mask = &eth_mask;
}

static void
add_vlan(struct rte_flow_item *items,
	uint8_t items_counter,
	__rte_unused struct additional_para para)
{
	static struct rte_flow_item_vlan vlan_spec = {
		.tci = RTE_BE16(VLAN_VALUE),
	};
	static struct rte_flow_item_vlan vlan_mask = {
		.tci = RTE_BE16(0xffff),
	};

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_VLAN;
	items[items_counter].spec = &vlan_spec;
	items[items_counter].mask = &vlan_mask;
}

static void
add_ipv4(struct rte_flow_item *items,
	uint8_t items_counter, struct additional_para para)
{
	static struct rte_flow_item_ipv4 ipv4_specs[RTE_MAX_LCORE] __rte_cache_aligned;
	static struct rte_flow_item_ipv4 ipv4_masks[RTE_MAX_LCORE] __rte_cache_aligned;
	uint8_t ti = para.core_idx;
	uint8_t time_to_live = para.time_to_live;
	uint32_t src_ip = (para.src_ip / para.ports_per_ip) + 1;

	if (para.set_ipv4_addrs) {
		if (!para.reply_dir) {
			ipv4_specs[ti].hdr.src_addr = RTE_BE32(src_ip);
			ipv4_specs[ti].hdr.dst_addr = RTE_BE32(src_ip << 1);
		} else {
			ipv4_specs[ti].hdr.dst_addr = RTE_BE32(src_ip);
			ipv4_specs[ti].hdr.src_addr = RTE_BE32(src_ip << 1);
		}

		ipv4_masks[ti].hdr.src_addr = RTE_BE32(0xffffffff);
		ipv4_masks[ti].hdr.dst_addr = RTE_BE32(0xffffffff);
	} else {
		ipv4_masks[ti].hdr.src_addr = RTE_BE32(0x00000000);
		ipv4_masks[ti].hdr.dst_addr = RTE_BE32(0x00000000);
	}

	if (time_to_live != (uint8_t)-1) {
		ipv4_specs[ti].hdr.time_to_live = time_to_live;
		ipv4_masks[ti].hdr.time_to_live = 0xff;
	} else {
		ipv4_masks[ti].hdr.time_to_live = 0x00;
	}

	if (para.no_frag) {
		/* ipv4.flags = 010 (DF - Don't Fragment)*/
		ipv4_specs[ti].hdr.fragment_offset = RTE_BE16(0x0000);
		ipv4_masks[ti].hdr.fragment_offset = RTE_BE16(0x3fff);
	} else {
		ipv4_masks[ti].hdr.fragment_offset = RTE_BE16(0x0000);
	}

	if (para.set_ihl) {
		ipv4_specs[ti].hdr.version = 4;
		ipv4_specs[ti].hdr.ihl = 5;
		ipv4_masks[ti].hdr.version_ihl = 0xff;
	} else {
		ipv4_masks[ti].hdr.version_ihl = 0x00;
	}

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_IPV4;
	items[items_counter].spec = &ipv4_specs[ti];
	items[items_counter].mask = &ipv4_masks[ti];
}


static void
add_ipv6(struct rte_flow_item *items,
	uint8_t items_counter, struct additional_para para)
{
	static struct rte_flow_item_ipv6 ipv6_specs[RTE_MAX_LCORE] __rte_cache_aligned;
	static struct rte_flow_item_ipv6 ipv6_masks[RTE_MAX_LCORE] __rte_cache_aligned;
	uint8_t ti = para.core_idx;
	uint8_t i;

	/** Set ipv6 src **/
	for (i = 0; i < 16; i++) {
		/* Currently src_ip is limited to 32 bit */
		if (i < 4)
			ipv6_specs[ti].hdr.src_addr[15 - i] = para.src_ip >> (i * 8);
		ipv6_masks[ti].hdr.src_addr[15 - i] = 0xff;
	}

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_IPV6;
	items[items_counter].spec = &ipv6_specs[ti];
	items[items_counter].mask = &ipv6_masks[ti];
}

static void
add_tcp(struct rte_flow_item *items,
	uint8_t items_counter,
	struct additional_para para)
{
	static struct rte_flow_item_tcp tcp_spec[RTE_MAX_LCORE] __rte_cache_aligned;
	static const struct rte_flow_item_tcp tcp_mask = {
		.hdr = {
			.src_port = RTE_BE16(0xffff),
			.dst_port = RTE_BE16(0xffff),
		},
	};
	static const struct rte_flow_item_tcp tcp_mask_any = {
		.hdr = {
			.src_port = RTE_BE16(0x0000),
			.dst_port = RTE_BE16(0x0000),
		},
	};
	uint8_t ti = para.core_idx;
	uint16_t src_port = para.src_ip % para.ports_per_ip;

	items[items_counter].mask = &tcp_mask_any;

	if (para.set_ports) {
		tcp_spec[ti].hdr.src_port = RTE_BE16(src_port);
		tcp_spec[ti].hdr.dst_port = RTE_BE16(FIXED_DST_PORT);
		items[items_counter].mask = &tcp_mask;
	}

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_TCP;
	items[items_counter].spec = &tcp_spec[ti];
}

static void
add_udp(struct rte_flow_item *items,
	uint8_t items_counter,
	struct additional_para para)
{
	static struct rte_flow_item_udp udp_spec[RTE_MAX_LCORE] __rte_cache_aligned;
	static const struct rte_flow_item_udp udp_mask_any;
	static const struct rte_flow_item_udp udp_mask = {
		.hdr = {
			.src_port = RTE_BE16(0xffff),
			.dst_port = RTE_BE16(0xffff),
		},
	};
	uint8_t ti = para.core_idx;
	uint16_t src_port = para.src_ip % para.ports_per_ip;

	items[items_counter].mask = &udp_mask_any;

	if (para.set_ports) {
		udp_spec[ti].hdr.src_port = RTE_BE16(src_port);
		udp_spec[ti].hdr.dst_port = RTE_BE16(FIXED_DST_PORT);
		items[items_counter].mask = &udp_mask;
	}

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_UDP;
	items[items_counter].spec = &udp_spec;
}

static void
add_vxlan(struct rte_flow_item *items,
	uint8_t items_counter,
	struct additional_para para)
{
	static struct rte_flow_item_vxlan vxlan_specs[RTE_MAX_LCORE] __rte_cache_aligned;
	static struct rte_flow_item_vxlan vxlan_masks[RTE_MAX_LCORE] __rte_cache_aligned;
	uint8_t ti = para.core_idx;

	/* Standard vxlan flags */
	vxlan_specs[ti].flags = 0x8;

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_VXLAN;
	items[items_counter].spec = &vxlan_specs[ti];
	items[items_counter].mask = &vxlan_masks[ti];
}

static void
add_vxlan_gpe(struct rte_flow_item *items,
	uint8_t items_counter,
	__rte_unused struct additional_para para)
{
	static struct rte_flow_item_vxlan_gpe vxlan_gpe_specs[RTE_MAX_LCORE] __rte_cache_aligned;
	static struct rte_flow_item_vxlan_gpe vxlan_gpe_masks[RTE_MAX_LCORE] __rte_cache_aligned;
	uint8_t ti = para.core_idx;
	uint32_t vni_value;
	uint8_t i;

	vni_value = VNI_VALUE;

	/* Set vxlan-gpe vni */
	for (i = 0; i < 3; i++) {
		vxlan_gpe_specs[ti].vni[2 - i] = vni_value >> (i * 8);
		vxlan_gpe_masks[ti].vni[2 - i] = 0xff;
	}

	/* vxlan-gpe flags */
	vxlan_gpe_specs[ti].flags = 0x0c;

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_VXLAN_GPE;
	items[items_counter].spec = &vxlan_gpe_specs[ti];
	items[items_counter].mask = &vxlan_gpe_masks[ti];
}

static void
add_gre(struct rte_flow_item *items,
	uint8_t items_counter,
	__rte_unused struct additional_para para)
{
	static struct rte_flow_item_gre gre_spec = {
		.protocol = RTE_BE16(RTE_ETHER_TYPE_TEB),
	};
	static struct rte_flow_item_gre gre_mask = {
		.protocol = RTE_BE16(0xffff),
	};

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_GRE;
	items[items_counter].spec = &gre_spec;
	items[items_counter].mask = &gre_mask;
}

static void
add_geneve(struct rte_flow_item *items,
	uint8_t items_counter,
	__rte_unused struct additional_para para)
{
	static struct rte_flow_item_geneve geneve_specs[RTE_MAX_LCORE] __rte_cache_aligned;
	static struct rte_flow_item_geneve geneve_masks[RTE_MAX_LCORE] __rte_cache_aligned;
	uint8_t ti = para.core_idx;
	uint32_t vni_value;
	uint8_t i;

	vni_value = VNI_VALUE;

	for (i = 0; i < 3; i++) {
		geneve_specs[ti].vni[2 - i] = vni_value >> (i * 8);
		geneve_masks[ti].vni[2 - i] = 0xff;
	}

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_GENEVE;
	items[items_counter].spec = &geneve_specs[ti];
	items[items_counter].mask = &geneve_masks[ti];
}

static void
add_gtp(struct rte_flow_item *items,
	uint8_t items_counter,
	__rte_unused struct additional_para para)
{
	static struct rte_flow_item_gtp gtp_spec = {
		.teid = RTE_BE32(TEID_VALUE),
	};
	static struct rte_flow_item_gtp gtp_mask = {
		.teid = RTE_BE32(0xffffffff),
	};

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_GTP;
	items[items_counter].spec = &gtp_spec;
	items[items_counter].mask = &gtp_mask;
}

static void
add_meta_data(struct rte_flow_item *items,
	uint8_t items_counter,
	__rte_unused struct additional_para para)
{
	static struct rte_flow_item_meta meta_spec = {
		.data = RTE_BE32(META_DATA),
	};
	static struct rte_flow_item_meta meta_mask = {
		.data = RTE_BE32(0xffffffff),
	};

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_META;
	items[items_counter].spec = &meta_spec;
	items[items_counter].mask = &meta_mask;
}


static void
add_meta_tag(struct rte_flow_item *items,
	uint8_t items_counter,
	__rte_unused struct additional_para para)
{
	static struct rte_flow_item_tag tag_spec = {
		.data = RTE_BE32(META_DATA),
		.index = TAG_INDEX,
	};
	static struct rte_flow_item_tag tag_mask = {
		.data = RTE_BE32(0xffffffff),
		.index = 0xff,
	};

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_TAG;
	items[items_counter].spec = &tag_spec;
	items[items_counter].mask = &tag_mask;
}

static void
add_ct_meta_tag(struct rte_flow_item *items,
	uint8_t items_counter,
	struct additional_para para)
{
	uint32_t tag = META_DATA + para.src_ip; /* src_ip is the counter. */
	static const struct rte_flow_item_tag tag_mask = {
		.data = RTE_BE32(0xffffffff),
		.index = 0xff,
	};
	static struct rte_flow_item_tag tag_spec[RTE_MAX_LCORE] = {
		[0 ... (RTE_MAX_LCORE - 1)] = {
			.data = RTE_BE32(META_DATA),
			.index = TAG_INDEX,
		},
	};

	tag_spec[para.core_idx].index = TAG_INDEX;
	tag_spec[para.core_idx].data = RTE_BE32(tag);

	if (!para.cross_port && para.reply_dir)
		tag_spec[para.core_idx].index = TAG_INDEX_REPLY;

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_TAG;
	items[items_counter].spec = &tag_spec[para.core_idx];
	items[items_counter].mask = &tag_mask;
}

static void
add_ct_item(struct rte_flow_item *items,
	uint8_t items_counter,
	__rte_unused struct additional_para para)
{
	static const struct rte_flow_item_conntrack ct_item = {
		.flags = CT_ITEM_RESULT,
	};
	items[items_counter].type = RTE_FLOW_ITEM_TYPE_CONNTRACK;
	items[items_counter].spec = &ct_item;
}

static void
add_icmpv4(struct rte_flow_item *items,
	uint8_t items_counter,
	__rte_unused struct additional_para para)
{
	static struct rte_flow_item_icmp icmpv4_spec;
	static struct rte_flow_item_icmp icmpv4_mask;

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_ICMP;
	items[items_counter].spec = &icmpv4_spec;
	items[items_counter].mask = &icmpv4_mask;
}

static void
add_icmpv6(struct rte_flow_item *items,
	uint8_t items_counter,
	__rte_unused struct additional_para para)
{
	static struct rte_flow_item_icmp6 icmpv6_spec;
	static struct rte_flow_item_icmp6 icmpv6_mask;

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_ICMP6;
	items[items_counter].spec = &icmpv6_spec;
	items[items_counter].mask = &icmpv6_mask;
}

static void
add_sanity_checks(struct rte_flow_item *items,
	uint8_t items_counter,
	__rte_unused struct additional_para para)
{
	static const struct rte_flow_item_integrity sanity_spec = {
		.l3_ok = 1,
		.l4_ok = 1,
		.ipv4_csum_ok = 1,
		.l4_csum_ok = 1,
	};
	items[items_counter].type = RTE_FLOW_ITEM_TYPE_INTEGRITY;
	items[items_counter].spec = &sanity_spec;
	items[items_counter].mask = &sanity_spec;
}

void
fill_items(struct rte_flow_item *items,
	uint64_t *flow_items, uint32_t outer_ip_src,
	uint8_t core_idx, bool cross_port, bool reply_dir, uint8_t  time_to_live,
	bool set_ipv4_addrs, bool no_frag, bool set_ports, uint16_t l3_type,
	bool set_ihl, uint64_t ports_per_ip)
{
	uint8_t items_counter = 0;
	uint8_t i, j;
	struct additional_para additional_para_data = {
		.src_ip = outer_ip_src,
		.core_idx = core_idx,
		.cross_port = cross_port,
		.reply_dir = reply_dir,
		.time_to_live = time_to_live,
		.set_ipv4_addrs = set_ipv4_addrs,
		.no_frag = no_frag,
		.set_ports = set_ports,
		.l3_type = l3_type,
		.set_ihl = set_ihl,
		.ports_per_ip = ports_per_ip,
	};

	/* Support outer items up to tunnel layer only. */
	static const struct items_dict {
		uint64_t mask;
		void (*funct)(
			struct rte_flow_item *items,
			uint8_t items_counter,
			struct additional_para para
			);
	} items_list[] = {
		{
			.mask = RTE_FLOW_ITEM_TYPE_META,
			.funct = add_meta_data,
		},
		{
			.mask = RTE_FLOW_ITEM_TYPE_TAG,
			.funct = add_meta_tag,
		},
		{
			.mask = RTE_FLOW_ITEM_TYPE_ETH,
			.funct = add_ether,
		},
		{
			.mask = RTE_FLOW_ITEM_TYPE_VLAN,
			.funct = add_vlan,
		},
		{
			.mask = RTE_FLOW_ITEM_TYPE_IPV4,
			.funct = add_ipv4,
		},
		{
			.mask = RTE_FLOW_ITEM_TYPE_IPV6,
			.funct = add_ipv6,
		},
		{
			.mask = RTE_FLOW_ITEM_TYPE_TCP,
			.funct = add_tcp,
		},
		{
			.mask = RTE_FLOW_ITEM_TYPE_UDP,
			.funct = add_udp,
		},
		{
			.mask = RTE_FLOW_ITEM_TYPE_VXLAN,
			.funct = add_vxlan,
		},
		{
			.mask = RTE_FLOW_ITEM_TYPE_VXLAN_GPE,
			.funct = add_vxlan_gpe,
		},
		{
			.mask = RTE_FLOW_ITEM_TYPE_GRE,
			.funct = add_gre,
		},
		{
			.mask = RTE_FLOW_ITEM_TYPE_GENEVE,
			.funct = add_geneve,
		},
		{
			.mask = RTE_FLOW_ITEM_TYPE_GTP,
			.funct = add_gtp,
		},
		{
			.mask = RTE_FLOW_ITEM_TYPE_ICMP,
			.funct = add_icmpv4,
		},
		{
			.mask = RTE_FLOW_ITEM_TYPE_ICMP6,
			.funct = add_icmpv6,
		},
		{
			.mask = RTE_FLOW_ITEM_TYPE_INTEGRITY,
			.funct = add_sanity_checks,
		},
		{
			.mask = CT_TAG_ITEM,
			.funct = add_ct_meta_tag,
		},
		{
			.mask = RTE_FLOW_ITEM_TYPE_CONNTRACK,
			.funct = add_ct_item,
		},
	};

	for (j = 0; j < MAX_ITEMS_NUM; j++) {
		if (flow_items[j] == 0)
			break;
		for (i = 0; i < RTE_DIM(items_list); i++) {
			if ((flow_items[j] &
				FLOW_ITEM_MASK(items_list[i].mask)) == 0)
				continue;
			items_list[i].funct(
				items, items_counter++,
				additional_para_data
			);
			break;
		}
	}

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_END;
}
