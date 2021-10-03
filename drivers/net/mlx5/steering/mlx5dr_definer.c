/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_internal.h"

#define BITS_IN_BYTE	8
#define STE_IPV4	0x1
#define STE_IPV6	0x2
#define STE_TCP		0x1
#define STE_UDP		0x2
#define GTP_PDU_SC	0x85

/* Selectors based on match TAG */
#define DW_SELECTORS	6
#define BYTE_SELECTORS	8

#define DR_CALC_FNAME(field, inner) \
	((inner) ? MLX5DR_DEFINER_FNAME_##field##_I : \
		   MLX5DR_DEFINER_FNAME_##field##_O)

/* Setter function based on bit offset and mask */
#define DR_SET(p, v, byte_off, bit_off, mask) \
	do { \
		u32 _v = v; \
		*((rte_be32_t *)(p) + (byte_off / 4)) = \
		rte_cpu_to_be_32((rte_be_to_cpu_32(*((u32 *)(p) + \
				  (byte_off / 4))) & \
				  (~(mask << bit_off))) | \
				 (((_v) & mask) << \
				  bit_off)); \
	} while (0)

/* Helper to calculate data used by DR_SET */
#define DR_CALC_SET(fc, hdr, field, is_inner) \
	do { \
		if (is_inner) { \
			fc->bit_mask = __mlx5_mask(definer_hl, hdr##_inner.field); \
			fc->bit_off = __mlx5_dw_bit_off(definer_hl, hdr##_inner.field); \
			fc->byte_off = MLX5_BYTE_OFF(definer_hl, hdr##_inner.field); \
		} else { \
			fc->bit_mask = __mlx5_mask(definer_hl, hdr##_outer.field); \
			fc->bit_off = __mlx5_dw_bit_off(definer_hl, hdr##_outer.field); \
			fc->byte_off = MLX5_BYTE_OFF(definer_hl, hdr##_outer.field); \
		} \
	} while (0)


enum mlx5dr_definer_fname {
	MLX5DR_DEFINER_FNAME_ETH_SMAC_48_16_O,
	MLX5DR_DEFINER_FNAME_ETH_SMAC_48_16_I,
	MLX5DR_DEFINER_FNAME_ETH_SMAC_15_0_O,
	MLX5DR_DEFINER_FNAME_ETH_SMAC_15_0_I,
	MLX5DR_DEFINER_FNAME_ETH_DMAC_48_16_O,
	MLX5DR_DEFINER_FNAME_ETH_DMAC_48_16_I,
	MLX5DR_DEFINER_FNAME_ETH_DMAC_15_0_O,
	MLX5DR_DEFINER_FNAME_ETH_DMAC_15_0_I,
	MLX5DR_DEFINER_FNAME_ETH_TYPE_O,
	MLX5DR_DEFINER_FNAME_ETH_TYPE_I,
	MLX5DR_DEFINER_FNAME_IPV4_IHL_O,
	MLX5DR_DEFINER_FNAME_IPV4_IHL_I,
	MLX5DR_DEFINER_FNAME_IPV4_TTL_O,
	MLX5DR_DEFINER_FNAME_IPV4_TTL_I,
	MLX5DR_DEFINER_FNAME_IPV4_DST_O,
	MLX5DR_DEFINER_FNAME_IPV4_DST_I,
	MLX5DR_DEFINER_FNAME_IPV4_SRC_O,
	MLX5DR_DEFINER_FNAME_IPV4_SRC_I,
	MLX5DR_DEFINER_FNAME_IPV4_VERSION_O,
	MLX5DR_DEFINER_FNAME_IPV4_VERSION_I,
	MLX5DR_DEFINER_FNAME_IP_PROTOCOL_O,
	MLX5DR_DEFINER_FNAME_IP_PROTOCOL_I,
	MLX5DR_DEFINER_FNAME_L4_SPORT_O,
	MLX5DR_DEFINER_FNAME_L4_SPORT_I,
	MLX5DR_DEFINER_FNAME_L4_DPORT_O,
	MLX5DR_DEFINER_FNAME_L4_DPORT_I,
	MLX5DR_DEFINER_FNAME_GTP_TEID,
	MLX5DR_DEFINER_FNAME_GTP_MSG_TYPE,
	MLX5DR_DEFINER_FNAME_GTP_EXT_FLAG,
	MLX5DR_DEFINER_FNAME_GTP_NEXT_EXT_HDR,
	MLX5DR_DEFINER_FNAME_GTP_EXT_HDR_PDU,
	MLX5DR_DEFINER_FNAME_GTP_EXT_HDR_QFI,
	MLX5DR_DEFINER_FNAME_FLEX_PARSER_0,
	MLX5DR_DEFINER_FNAME_FLEX_PARSER_1,
	MLX5DR_DEFINER_FNAME_FLEX_PARSER_2,
	MLX5DR_DEFINER_FNAME_FLEX_PARSER_3,
	MLX5DR_DEFINER_FNAME_FLEX_PARSER_4,
	MLX5DR_DEFINER_FNAME_FLEX_PARSER_5,
	MLX5DR_DEFINER_FNAME_FLEX_PARSER_6,
	MLX5DR_DEFINER_FNAME_FLEX_PARSER_7,
	MLX5DR_DEFINER_FNAME_MAX,
};

struct mlx5dr_definer {
	uint8_t dw_selector[DW_SELECTORS];
	uint8_t byte_selector[BYTE_SELECTORS];
	uint8_t mask_tag[MLX5DR_MATCH_TAG_SZ];
	struct mlx5dr_devx_obj *obj;
};

struct mlx5dr_definer_fc {
	uint8_t item_idx;
	uint32_t byte_off;
	uint32_t bit_off;
	uint32_t bit_mask;
	void (*tag_set)(struct mlx5dr_definer_fc *fc,
			const void *item_spec,
			uint8_t *tag);
	void (*tag_mask_set)(struct mlx5dr_definer_fc *fc,
			     const void *item_spec,
			     uint8_t *tag);
};

struct mlx5dr_definer_conv_data {
	struct mlx5dr_cmd_query_caps *caps;
	struct mlx5dr_definer_fc *fc;
	uint8_t tunnel;
	uint8_t *hl;
};

/* Xmacro used to create generic item setter from items */
#define LIST_OF_FIELDS_INFO \
	X(eth_type,		v->type,			rte_flow_item_eth) \
	X(ipv4_ihl,		v->ihl,				rte_ipv4_hdr) \
	X(ipv4_time_to_live,	v->time_to_live,		rte_ipv4_hdr) \
	X(ipv4_dst_addr,	v->dst_addr,			rte_ipv4_hdr) \
	X(ipv4_src_addr,	v->src_addr,			rte_ipv4_hdr) \
	X(ipv4_next_proto,	v->next_proto_id,		rte_ipv4_hdr) \
	X(ipv4_version,		STE_IPV4,			rte_ipv4_hdr) \
	X(udp_protocol,		STE_UDP,			rte_flow_item_udp) \
	X(udp_src_port,		v->hdr.src_port,		rte_flow_item_udp) \
	X(udp_dst_port,		v->hdr.dst_port,		rte_flow_item_udp) \
	X(tcp_protocol,		STE_TCP,			rte_flow_item_tcp) \
	X(tcp_src_port,		v->hdr.src_port,		rte_flow_item_tcp) \
	X(tcp_dst_port,		v->hdr.dst_port,		rte_flow_item_tcp) \
	X(gtp_udp_port,		RTE_GTPU_UDP_PORT,		rte_flow_item_gtp) \
	X(gtp_teid,		rte_be_to_cpu_32(v->teid),	rte_flow_item_gtp) \
	X(gtp_msg_type,		v->msg_type,			rte_flow_item_gtp) \
	X(gtp_ext_flag,		!!v->v_pt_rsv_flags,		rte_flow_item_gtp) \
	X(gtp_next_ext_hdr,	GTP_PDU_SC,			rte_flow_item_gtp_psc) \
	X(gtp_ext_hdr_pdu,	v->pdu_type,			rte_flow_item_gtp_psc) \
	X(gtp_ext_hdr_qfi,	v->qfi,				rte_flow_item_gtp_psc)

/* Item set function format */
#define X(func_name, value, itme_type) \
static void mlx5dr_definer_##func_name##_set( \
	struct mlx5dr_definer_fc *fc, \
	const void *item_spec, \
	uint8_t *tag) \
{ \
	__rte_unused const struct itme_type *v = item_spec; \
	DR_SET(tag, value, fc->byte_off, fc->bit_off, fc->bit_mask); \
}
LIST_OF_FIELDS_INFO
#undef X

static void
mlx5dr_definer_ones_set(struct mlx5dr_definer_fc *fc,
			__rte_unused const void *item_spec,
			__rte_unused uint8_t *tag)
{
	DR_SET(tag, -1, fc->byte_off, fc->bit_off, fc->bit_mask);
}

static void
mlx5dr_definer_eth_smac_47_16_set(struct mlx5dr_definer_fc *fc,
				  const void *item_spec,
				  uint8_t *tag)
{
	const struct rte_flow_item_eth *v = item_spec;

	memcpy(tag + fc->byte_off, v->src.addr_bytes, 4);
}

static void
mlx5dr_definer_eth_smac_15_0_set(struct mlx5dr_definer_fc *fc,
				  const void *item_spec,
				  uint8_t *tag)
{
	const struct rte_flow_item_eth *v = item_spec;

	memcpy(tag + fc->byte_off, v->src.addr_bytes + 4, 2);
}

static void
mlx5dr_definer_eth_dmac_47_16_set(struct mlx5dr_definer_fc *fc,
				  const void *item_spec,
				  uint8_t *tag)
{
	const struct rte_flow_item_eth *v = item_spec;

	memcpy(tag + fc->byte_off, v->dst.addr_bytes, 4);
}

static void
mlx5dr_definer_eth_dmac_15_0_set(struct mlx5dr_definer_fc *fc,
				  const void *item_spec,
				  uint8_t *tag)
{
	const struct rte_flow_item_eth *v = item_spec;

	memcpy(tag + fc->byte_off, v->dst.addr_bytes + 4, 2);
}

static uint32_t mlx5dr_definer_get_flex_parser_off(uint8_t flex_parser_id)
{
	uint32_t byte_off;

	/* Get the last flex parser */
	byte_off = MLX5_BYTE_OFF(definer_hl, flex_parser.flex_parser_0);
	/* Jump back based on needed flex parser id */
	byte_off -= DW_SIZE * flex_parser_id;

	return byte_off;
}

static int
mlx5dr_definer_conv_item_eth(struct mlx5dr_definer_conv_data *cd,
			     struct rte_flow_item *item,
			     int item_idx)
{
	const struct rte_flow_item_eth *m = item->mask;
	uint8_t empty_mac[RTE_ETHER_ADDR_LEN] = {0};
	struct mlx5dr_definer_fc *fc;
	bool inner = cd->tunnel;

	if (m->has_vlan || m->reserved) {
		rte_errno = ENOTSUP;
		return rte_errno;
	}

	if (m->type) {
		fc = &cd->fc[DR_CALC_FNAME(ETH_TYPE, inner)];
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_eth_type_set;
		DR_CALC_SET(fc, eth_l2, l3_ethertype, inner);
	}

	/* Check SMAC 47_16 */
	if (memcmp(m->src.addr_bytes, empty_mac, 4)) {
		fc = &cd->fc[DR_CALC_FNAME(ETH_SMAC_48_16, inner)];
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_eth_smac_47_16_set;
		DR_CALC_SET(fc, eth_l2_src, smac_47_16, inner);
	}

	/* Check SMAC 15_0 */
	if (memcmp(m->src.addr_bytes + 4, empty_mac + 4, 2)) {
		fc = &cd->fc[DR_CALC_FNAME(ETH_SMAC_15_0, inner)];
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_eth_smac_15_0_set;
		DR_CALC_SET(fc, eth_l2_src, smac_15_0, inner);
	}

	/* Check DMAC 47_16 */
	if (memcmp(m->dst.addr_bytes, empty_mac, 4)) {
		fc = &cd->fc[DR_CALC_FNAME(ETH_DMAC_48_16, inner)];
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_eth_dmac_47_16_set;
		DR_CALC_SET(fc, eth_l2, dmac_47_16, inner);
	}

	/* Check DMAC 15_0 */
	if (memcmp(m->dst.addr_bytes + 4, empty_mac + 4, 2)) {
		fc = &cd->fc[DR_CALC_FNAME(ETH_DMAC_15_0, inner)];
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_eth_dmac_15_0_set;
		DR_CALC_SET(fc, eth_l2, dmac_15_0, inner);
	}

	return 0;
}

static int
mlx5dr_definer_conv_item_ipv4(struct mlx5dr_definer_conv_data *cd,
			      struct rte_flow_item *item,
			      int item_idx)
{
	const struct rte_ipv4_hdr *m = item->mask;
	struct mlx5dr_definer_fc *fc;
	bool inner = cd->tunnel;

	if (m->type_of_service || m->total_length || m->packet_id ||
	    m->fragment_offset || m->hdr_checksum) {
		rte_errno = ENOTSUP;
		return rte_errno;
	}

	fc = &cd->fc[DR_CALC_FNAME(IPV4_VERSION, inner)];
	fc->item_idx = item_idx;
	fc->tag_set = &mlx5dr_definer_ipv4_version_set;
	fc->tag_mask_set = &mlx5dr_definer_ones_set;
	// TODO: l3_type is present in multiple headers, this value is correct
	// for definer 22 but not for definer 28.  (eth_l2 -> eth_l2_src)
	DR_CALC_SET(fc, eth_l2, l3_type, inner);

	/* Unset ethertype if present */
	memset(&cd->fc[DR_CALC_FNAME(ETH_TYPE, inner)], 0, sizeof(*fc));

	if (m->next_proto_id) {
		fc = &cd->fc[DR_CALC_FNAME(IP_PROTOCOL, inner)];
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_ipv4_next_proto_set;
		DR_CALC_SET(fc, eth_l3, protocol_next_header, inner);
	}

	if (m->dst_addr) {
		fc = &cd->fc[DR_CALC_FNAME(IPV4_DST, inner)];
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_ipv4_dst_addr_set;
		DR_CALC_SET(fc, ipv4_src_dest, destination_address, inner);
	}

	if (m->src_addr) {
		fc = &cd->fc[DR_CALC_FNAME(IPV4_SRC, inner)];
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_ipv4_src_addr_set;
		DR_CALC_SET(fc, ipv4_src_dest, source_address, inner);
	}

	if (m->ihl) {
		fc = &cd->fc[DR_CALC_FNAME(IPV4_IHL, inner)];
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_ipv4_ihl_set;
		DR_CALC_SET(fc, eth_l3, ihl, inner);
	}

	if (m->time_to_live) {
		fc = &cd->fc[DR_CALC_FNAME(IPV4_TTL, inner)];
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_ipv4_time_to_live_set;
		DR_CALC_SET(fc, eth_l3, time_to_live_hop_limit, inner);
	}

	return 0;
}

static int
mlx5dr_definer_conv_item_udp(struct mlx5dr_definer_conv_data *cd,
			     struct rte_flow_item *item,
			     int item_idx)
{
	const struct rte_flow_item_udp *m = item->mask;
	struct mlx5dr_definer_fc *fc;
	bool inner = cd->tunnel;

	if (m->hdr.dgram_cksum || m->hdr.dgram_len) {
		rte_errno = ENOTSUP;
		return rte_errno;
	}

	/* Set match on L4 type UDP */
	fc = &cd->fc[DR_CALC_FNAME(IP_PROTOCOL, inner)];
	fc->item_idx = item_idx;
	fc->tag_set = &mlx5dr_definer_udp_protocol_set;
	fc->tag_mask_set = &mlx5dr_definer_ones_set;
	// TODO: l4_type is present in multiple headers, this value is correct
	// for definer 22 but not for definer 28. (eth_l2 -> eth_l2_src)
	DR_CALC_SET(fc, eth_l2, l4_type_bwc, inner);

	if (m->hdr.src_port) {
		fc = &cd->fc[DR_CALC_FNAME(L4_SPORT, inner)];
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_udp_src_port_set;
		DR_CALC_SET(fc, eth_l4, source_port, inner);
	}

	if (m->hdr.dst_port) {
		fc = &cd->fc[DR_CALC_FNAME(L4_DPORT, inner)];
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_udp_dst_port_set;
		DR_CALC_SET(fc, eth_l4, destination_port, inner);
	}

	return 0;
}

static int
mlx5dr_definer_conv_item_tcp(struct mlx5dr_definer_conv_data *cd,
			     struct rte_flow_item *item,
			     int item_idx)
{
	const struct rte_flow_item_tcp *m = item->mask;
	struct mlx5dr_definer_fc *fc;
	bool inner = cd->tunnel;

	if (m->hdr.ack || m->hdr.fin || m->hdr.syn || m->hdr.rst ||
	    m->hdr.psh || m->hdr.ack || m->hdr.urg || m->hdr.ecne ||
	    m->hdr.cwr) {
		rte_errno = ENOTSUP;
		return rte_errno;
	}

	/* Overwrite match on L4 type TCP */
	fc = &cd->fc[DR_CALC_FNAME(IP_PROTOCOL, inner)];
	fc->item_idx = item_idx;
	fc->tag_set = &mlx5dr_definer_tcp_protocol_set;
	fc->tag_mask_set = &mlx5dr_definer_ones_set;
	// TODO: l4_type is present in multiple headers, this value is correct
	// for definer 22 but not for definer 28.  (eth_l2 -> eth_l2_src)
	DR_CALC_SET(fc, eth_l2, l4_type_bwc, inner);

	if (m->hdr.src_port) {
		fc = &cd->fc[DR_CALC_FNAME(L4_SPORT, inner)];
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_tcp_src_port_set;
		DR_CALC_SET(fc, eth_l4, source_port, inner);
	}

	if (m->hdr.dst_port) {
		fc = &cd->fc[DR_CALC_FNAME(L4_DPORT, inner)];
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_tcp_dst_port_set;
		DR_CALC_SET(fc, eth_l4, destination_port, inner);
	}

	return 0;
}

static int
mlx5dr_definer_conv_item_gtp(struct mlx5dr_definer_conv_data *cd,
			     struct rte_flow_item *item,
			     int item_idx)
{
	const struct rte_flow_item_gtp *m = item->mask;
	struct mlx5dr_definer_fc *fc;
	uint8_t flex_idx;

	if (m->msg_len || m->v_pt_rsv_flags & ~MLX5DR_DEFINER_GTP_EXT_HDR_BIT) {
		rte_errno = ENOTSUP;
		return rte_errno;
	}

	/* Overwrite GTPU dest port if not present */
	fc = &cd->fc[DR_CALC_FNAME(L4_DPORT, false)];
	if (!fc->tag_set) {
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_gtp_udp_port_set;
		fc->tag_mask_set = &mlx5dr_definer_ones_set;
		DR_CALC_SET(fc, eth_l4, destination_port, false);
	}

	if (m->teid) {
		if (cd->caps->flex_protocols & MLX5_HCA_FLEX_GTPU_TEID_ENABLED) {
			rte_errno = ENOTSUP;
			return rte_errno;
		}
		flex_idx = cd->caps->flex_parser_id_gtpu_teid;
		fc = &cd->fc[MLX5DR_DEFINER_FNAME_GTP_TEID];
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_gtp_teid_set;
		fc->bit_mask = __mlx5_mask(header_gtp, teid);
		fc->byte_off = mlx5dr_definer_get_flex_parser_off(flex_idx);
	}

	if (m->v_pt_rsv_flags) {
		if (cd->caps->flex_protocols & MLX5_HCA_FLEX_GTPU_DW_0_ENABLED) {
			rte_errno = ENOTSUP;
			return rte_errno;
		}
		flex_idx = cd->caps->flex_parser_id_gtpu_dw_0;
		fc = &cd->fc[MLX5DR_DEFINER_FNAME_GTP_EXT_FLAG];
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_gtp_ext_flag_set;
		fc->bit_mask = __mlx5_mask(header_gtp, ext_hdr_flag);
		fc->bit_off = __mlx5_dw_bit_off(header_gtp, ext_hdr_flag);
		fc->byte_off = mlx5dr_definer_get_flex_parser_off(flex_idx);
	}

	if (m->msg_type) {
		if (cd->caps->flex_protocols & MLX5_HCA_FLEX_GTPU_DW_0_ENABLED) {
			rte_errno = ENOTSUP;
			return rte_errno;
		}
		flex_idx = cd->caps->flex_parser_id_gtpu_dw_0;
		fc = &cd->fc[MLX5DR_DEFINER_FNAME_GTP_MSG_TYPE];
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_gtp_msg_type_set;
		fc->bit_mask = __mlx5_mask(header_gtp, msg_type);
		fc->bit_off = __mlx5_dw_bit_off(header_gtp, msg_type);
		fc->byte_off = mlx5dr_definer_get_flex_parser_off(flex_idx);
	}

	return 0;
}

static int
mlx5dr_definer_conv_item_gtp_psc(struct mlx5dr_definer_conv_data *cd,
				 struct rte_flow_item *item,
				 int item_idx)
{
	const struct rte_flow_item_gtp_psc *m = item->mask;
	struct mlx5dr_definer_fc *fc;
	uint8_t flex_idx;

	/* Overwrite GTP extension flag to be 1 */
	if (cd->caps->flex_protocols & MLX5_HCA_FLEX_GTPU_DW_0_ENABLED) {
		rte_errno = ENOTSUP;
		return rte_errno;
	}
	flex_idx = cd->caps->flex_parser_id_gtpu_dw_0;
	fc = &cd->fc[MLX5DR_DEFINER_FNAME_GTP_EXT_FLAG];
	fc->item_idx = item_idx;
	fc->tag_set = &mlx5dr_definer_ones_set;
	fc->bit_mask = __mlx5_mask(header_gtp, ext_hdr_flag);
	fc->bit_off = __mlx5_dw_bit_off(header_gtp, ext_hdr_flag);
	fc->byte_off = mlx5dr_definer_get_flex_parser_off(flex_idx);

	/* Overwrite next extension header type */
	if (cd->caps->flex_protocols & MLX5_HCA_FLEX_GTPU_DW_2_ENABLED) {
		rte_errno = ENOTSUP;
		return rte_errno;
	}
	flex_idx = cd->caps->flex_parser_id_gtpu_dw_2;
	fc = &cd->fc[MLX5DR_DEFINER_FNAME_GTP_NEXT_EXT_HDR];
	fc->item_idx = item_idx;
	fc->tag_set = &mlx5dr_definer_gtp_next_ext_hdr_set;
	fc->tag_mask_set = &mlx5dr_definer_ones_set;
	fc->bit_mask = __mlx5_mask(header_opt_gtp, next_ext_hdr_type);
	fc->bit_off = __mlx5_dw_bit_off(header_opt_gtp, next_ext_hdr_type);
	fc->byte_off = mlx5dr_definer_get_flex_parser_off(flex_idx);

	if (m->pdu_type) {
		flex_idx = cd->caps->flex_parser_id_gtpu_first_ext_dw_0;
		if (cd->caps->flex_protocols & MLX5_HCA_FLEX_GTPU_FIRST_EXT_DW_0_ENABLED) {
			rte_errno = ENOTSUP;
			return rte_errno;
		}
		fc = &cd->fc[MLX5DR_DEFINER_FNAME_GTP_EXT_HDR_PDU];
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_gtp_ext_hdr_pdu_set;
		fc->bit_mask = __mlx5_mask(header_gtp_psc, pdu_type);
		fc->bit_off = __mlx5_dw_bit_off(header_gtp_psc, pdu_type);
		fc->byte_off = mlx5dr_definer_get_flex_parser_off(flex_idx);
	}

	if (m->qfi) {
		flex_idx = cd->caps->flex_parser_id_gtpu_first_ext_dw_0;
		if (cd->caps->flex_protocols & MLX5_HCA_FLEX_GTPU_FIRST_EXT_DW_0_ENABLED) {
			rte_errno = ENOTSUP;
			return rte_errno;
		}
		fc = &cd->fc[MLX5DR_DEFINER_FNAME_GTP_EXT_HDR_QFI];
		fc->item_idx = item_idx;
		fc->tag_set = &mlx5dr_definer_gtp_ext_hdr_qfi_set;
		fc->bit_mask = __mlx5_mask(header_gtp_psc, qfi);
		fc->bit_off = __mlx5_dw_bit_off(header_gtp_psc, qfi);
		fc->byte_off = mlx5dr_definer_get_flex_parser_off(flex_idx);
	}

	return 0;
}

static int
mlx5dr_definer_conv_items_to_hl(struct mlx5dr_context *ctx,
				struct mlx5dr_match_template *mt,
				uint8_t *hl)
{
	struct mlx5dr_definer_fc fc[MLX5DR_DEFINER_FNAME_MAX] = {{0}};
	struct mlx5dr_definer_conv_data cd = {0};
	struct rte_flow_item *items = mt->items;
	uint64_t item_flags = 0;
	uint32_t total = 0;
	int i, j;
	int ret;

	cd.fc = fc;
	cd.hl = hl;
	cd.caps = ctx->caps;

	/* Collect all RTE fields to the field array and set header layout */
	for (i = 0; items->type != RTE_FLOW_ITEM_TYPE_END; i++, items++) {
		cd.tunnel = !!(item_flags & MLX5_FLOW_LAYER_TUNNEL);

		switch (items->type) {
		case RTE_FLOW_ITEM_TYPE_ETH:
			ret = mlx5dr_definer_conv_item_eth(&cd, items, i);
			item_flags |= cd.tunnel ? MLX5_FLOW_LAYER_INNER_L2 :
						  MLX5_FLOW_LAYER_OUTER_L2;
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
			ret = mlx5dr_definer_conv_item_ipv4(&cd, items, i);
			item_flags |= cd.tunnel ? MLX5_FLOW_LAYER_INNER_L3_IPV4 :
						  MLX5_FLOW_LAYER_OUTER_L3_IPV4;
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			ret = mlx5dr_definer_conv_item_udp(&cd, items, i);
			item_flags |= cd.tunnel ? MLX5_FLOW_LAYER_INNER_L4_UDP :
						  MLX5_FLOW_LAYER_OUTER_L4_UDP;
			break;
		case RTE_FLOW_ITEM_TYPE_TCP:
			ret = mlx5dr_definer_conv_item_tcp(&cd, items, i);
			item_flags |= cd.tunnel ? MLX5_FLOW_LAYER_INNER_L4_TCP :
						  MLX5_FLOW_LAYER_OUTER_L4_TCP;
			break;
		case RTE_FLOW_ITEM_TYPE_GTP:
			ret = mlx5dr_definer_conv_item_gtp(&cd, items, i);
			item_flags |= MLX5_FLOW_LAYER_GTP;
			break;
		case RTE_FLOW_ITEM_TYPE_GTP_PSC:
			ret = mlx5dr_definer_conv_item_gtp_psc(&cd, items, i);
			item_flags |= MLX5_FLOW_LAYER_GTP_PSC;
			break;
		default:
			rte_errno = ENOTSUP;
			return rte_errno;
		}

		if (ret) {
			DRV_LOG(ERR, "Failed processing item type: %d", items->type);
			return ret;
		}
	}

	/* Fill in headers layout and calculate total number of fields  */
	for (i = 0; i < MLX5DR_DEFINER_FNAME_MAX; i++) {
		if (fc[i].tag_set) {
			total++;
			DR_SET(hl, -1, fc[i].byte_off, fc[i].bit_off, fc[i].bit_mask);
		}
	}

	mt->fc_sz = total;
	mt->fc = simple_calloc(total, sizeof(*mt->fc));
	if (!mt->fc) {
		DRV_LOG(ERR, "Failed to allocate field copy array");
                rte_errno = ENOMEM;
                return rte_errno;
	}

	j = 0;
	for (i = 0; i < MLX5DR_DEFINER_FNAME_MAX; i++) {
		if (fc[i].tag_set) {
			memcpy(&mt->fc[j], &fc[i], sizeof(*mt->fc));
			j++;
		}
	}

	return 0;
}

static int
mlx5dr_definer_find_byte_in_tag(struct mlx5dr_definer *definer,
				uint32_t hl_byte_off,
				uint32_t *tag_byte_off)
{
	uint8_t byte_offset;;
	int i;

	/* Add offset to skip DWs in definer */
	byte_offset = DW_SIZE * DW_SELECTORS;
	for (i = 0; i < BYTE_SELECTORS; i++) {
		if (definer->byte_selector[i] == hl_byte_off) {
			*tag_byte_off = byte_offset + (BYTE_SELECTORS - i - 1);
			return 0;
		}
	}

	/* Add offset since each DW covers multiple BYTEs */
	byte_offset = hl_byte_off % DW_SIZE;
	for (i = 0; i < DW_SELECTORS; i++) {
		if (definer->dw_selector[i] == hl_byte_off / DW_SIZE) {
			*tag_byte_off = byte_offset + DW_SIZE * (DW_SELECTORS - i - 1);
			return 0;
		}
	}

	/* The hl byte offset must be part of the definer */
	DRV_LOG(ERR, "Failed to map to definer - Field not supported");
	rte_errno = EINVAL;
	return rte_errno;
}

static int
mlx5dr_definer_fc_bind(struct mlx5dr_definer *definer,
		       struct mlx5dr_definer_fc *fc,
		       uint32_t fc_sz)
{
	uint32_t tag_offset;
	int ret, byte_diff;
	uint32_t i;

	for (i = 0; i < fc_sz; i++) {
		/* Map header layout byte offset to byte offset in tag */
		ret = mlx5dr_definer_find_byte_in_tag(definer, fc->byte_off, &tag_offset);
		if (ret)
			return ret;

		/* Move setter based on the location in the definer */
		byte_diff = tag_offset % DW_SIZE - fc->byte_off % DW_SIZE;
		fc->bit_off = fc->bit_off + byte_diff * BITS_IN_BYTE;

		/* Update offset in headers layout to offset in tag */
		fc->byte_off = tag_offset;
		fc++;
	}

	return 0;
}

static int
mlx5dr_definer_find_best_hl_fit(struct mlx5dr_definer *definer,
				uint16_t *format_id)
{
	definer->dw_selector[5] = 64;
	definer->dw_selector[4] = 65;
	definer->dw_selector[3] = 24;
	definer->dw_selector[2] = 2;
	definer->dw_selector[1] = 138;
	definer->dw_selector[0] = 0;
	definer->byte_selector[7] = 32;
	definer->byte_selector[6] = 33;
	definer->byte_selector[5] = 34;
	definer->byte_selector[4] = 35;
	definer->byte_selector[3] = 36;
	definer->byte_selector[2] = 37;
	definer->byte_selector[1] = 4;
	definer->byte_selector[0] = 5;
	*format_id = 22;

//	TODO Once FW will support def28, please check other TODO`s before enabling
//	definer->dw_selector[5] = 26;
//	definer->dw_selector[4] = MLX5_BYTE_OFF(definer_hl, flex_parser.flex_parser_0) / DW_SIZE;
//	definer->dw_selector[4] -= caps->flex_parser_id_gtpu_teid;
//	definer->dw_selector[3] = 66;
//	definer->dw_selector[2] = 67;
//	definer->dw_selector[1] = 64;
//	definer->dw_selector[0] = 65;
//	definer->byte_selector[7] = 96;
//	definer->byte_selector[6] = 97;
//	definer->byte_selector[5] = 98;
//	definer->byte_selector[4] = 99;
//	definer->byte_selector[3] = 79;
//	definer->byte_selector[2] = 47;
//	definer->byte_selector[1] = 59;
//	definer->byte_selector[0] = 39;
//	*format_id = 28;

	return 0;
}

static void
mlx5dr_definer_create_tag_mask(struct rte_flow_item *items,
			       struct mlx5dr_definer_fc *fc,
			       uint32_t fc_sz,
			       uint8_t *tag)
{
	uint32_t i;

	for (i = 0; i < fc_sz; i++) {
		if (fc->tag_mask_set)
			fc->tag_mask_set(fc, items[fc->item_idx].mask, tag);
		else
			fc->tag_set(fc, items[fc->item_idx].mask, tag);
		fc++;
	}
}

void mlx5dr_definer_create_tag(struct rte_flow_item *items,
			       struct mlx5dr_definer_fc *fc,
			       uint32_t fc_sz,
			       uint8_t *tag)
{
	uint32_t i;

	for (i = 0; i < fc_sz; i++) {
		fc->tag_set(fc, items[fc->item_idx].spec, tag);
		fc++;
	}
}

int mlx5dr_definer_get_id(struct mlx5dr_definer *definer)
{
	return definer->obj->id;
}

int mlx5dr_definer_compare(struct mlx5dr_definer *definer_a,
			   struct mlx5dr_definer *definer_b)
{
	int i;

	for (i = 0; i < BYTE_SELECTORS; i++)
		if (definer_a->byte_selector[i] != definer_b->byte_selector[i])
			return 1;

	for (i = 0; i < DW_SELECTORS; i++)
		if (definer_a->dw_selector[i] != definer_b->dw_selector[i])
			return 1;

	for (i = 0; i < MLX5DR_MATCH_TAG_SZ; i++)
		if (definer_a->mask_tag[i] != definer_b->mask_tag[i])
			return 1;

	return 0;
}

int mlx5dr_definer_get(struct mlx5dr_context *ctx,
		       struct mlx5dr_match_template *mt)
{
	struct mlx5dr_cmd_definer_create_attr def_attr = {0};
	struct ibv_context *ibv_ctx = ctx->ibv_ctx;
	uint16_t format_id;
	uint8_t *hl;
	int ret;

	if (mt->refcount++)
		return 0;

	mt->definer = simple_calloc(1, sizeof(*mt->definer));
	if (!mt->definer) {
		DRV_LOG(ERR, "Failed to allocate memory for definer");
		rte_errno = ENOMEM;
		goto dec_refcount;
	}

	/* Header layout (hl) holds full bit mask per field */
	hl = simple_calloc(1, MLX5_ST_SZ_BYTES(definer_hl));
	if (!hl) {
		DRV_LOG(ERR, "Failed to allocate memory for header layout");
                rte_errno = ENOMEM;
                goto free_definer;
	}

	/* Convert items to hl and allocate the field copy array (fc) */
	ret = mlx5dr_definer_conv_items_to_hl(ctx, mt, hl);
	if (ret) {
		DRV_LOG(ERR, "Failed to convert items to hl");
		goto free_hl;
	}

	/* Find the definer for given header layout */
	ret = mlx5dr_definer_find_best_hl_fit(mt->definer, &format_id);
	if (ret) {
		DRV_LOG(ERR, "Failed to create definer from header layout");
		goto free_field_copy;
	}

	/* Align field copy array based on the new definer */
	ret = mlx5dr_definer_fc_bind(mt->definer,
				     mt->fc,
				     mt->fc_sz);
	if (ret) {
		DRV_LOG(ERR, "Failed to bind field copy to definer");
		goto free_field_copy;
	}

	/* Create the tag mask used for definer creation */
	mlx5dr_definer_create_tag_mask(mt->items,
				       mt->fc,
				       mt->fc_sz,
				       mt->definer->mask_tag);

	/* Create definer based on the bitmask tag */
	def_attr.match_mask = mt->definer->mask_tag;
	def_attr.format_id = format_id;
	mt->definer->obj = mlx5dr_cmd_definer_create(ibv_ctx, &def_attr);
	if (!mt->definer->obj)
		goto free_field_copy;

	simple_free(hl);

	return 0;

free_field_copy:
	simple_free(mt->fc);
free_hl:
	simple_free(hl);
free_definer:
	simple_free(mt->definer);
dec_refcount:
	mt->refcount--;

	return rte_errno;
}

void mlx5dr_definer_put(struct mlx5dr_match_template *mt)
{
	if (--mt->refcount)
		return;

	simple_free(mt->fc);
	mlx5dr_cmd_destroy_obj(mt->definer->obj);
	simple_free(mt->definer);
}
