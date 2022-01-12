/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_DEFINER_H_
#define MLX5DR_DEFINER_H_

/* Selectors based on match TAG */
#define DW_SELECTORS    6
#define BYTE_SELECTORS  8

struct mlx5_ifc_definer_hl_eth_l2_bits {
	u8 dmac_47_16[0x20];
	u8 dmac_15_0[0x10];
	u8 l3_ethertype[0x10];
	u8 reserved_at_40[0x1];
	u8 sx_sniffer[0x1];
	u8 functional_lb[0x1];
	u8 ip_fragmented[0x1];
	u8 qp_type[0x2];
	u8 encap_type[0x2];
	u8 port_number[0x2];
	u8 l3_type[0x2];
	u8 l4_type_bwc[0x2];
	u8 first_vlan_qualifier[0x2];
	u8 first_priority[0x3];
	u8 first_cfi[0x1];
	u8 first_vlan_id[0xc];
	u8 l4_type[0x4];
	u8 reserved_at_64[0x2];
	u8 ipsec_layer[0x2];
	u8 l2_type[0x2];
	u8 force_lb[0x1];
	u8 l2_ok[0x1];
	u8 l3_ok[0x1];
	u8 l4_ok[0x1];
	u8 second_vlan_qualifier[0x2];
	u8 second_priority[0x3];
	u8 second_cfi[0x1];
	u8 second_vlan_id[0xc];
};

struct mlx5_ifc_definer_hl_eth_l2_src_bits {
	u8 smac_47_16[0x20];
	u8 smac_15_0[0x10];
	u8 loopback_syndrome[0x8];
	u8 l3_type[0x2];
	u8 l4_type_bwc[0x2];
	u8 first_vlan_qualifier[0x2];
	u8 ip_fragmented[0x1];
	u8 functional_lb[0x1];
};

struct mlx5_ifc_definer_hl_ib_l2_bits {
	u8 sx_sniffer[0x1];
	u8 force_lb[0x1];
	u8 functional_lb[0x1];
	u8 reserved_at_3[0x3];
	u8 port_number[0x2];
	u8 sl[0x4];
	u8 qp_type[0x2];
	u8 lnh[0x2];
	u8 dlid[0x10];
	u8 vl[0x4];
	u8 lrh_packet_length[0xc];
	u8 slid[0x10];
};

struct mlx5_ifc_definer_hl_eth_l3_bits {
	u8 ip_version[0x4];
	u8 ihl[0x4];
	u8 dscp[0x6];
	u8 ecn[0x2];
	u8 time_to_live_hop_limit[0x8];
	u8 protocol_next_header[0x8];
	u8 identification[0x10];
	u8 flags[0x3];
	u8 fragment_offset[0xd];
	u8 ipv4_total_length[0x10];
	u8 checksum[0x10];
	u8 reserved_at_60[0xc];
	u8 flow_label[0x14];
	u8 packet_length[0x10];
	u8 ipv6_payload_length[0x10];
};

struct mlx5_ifc_definer_hl_eth_l4_bits {
	u8 source_port[0x10];
	u8 destination_port[0x10];
	u8 data_offset[0x4];
	u8 l4_ok[0x1];
	u8 l3_ok[0x1];
	u8 ip_fragmented[0x1];
	u8 tcp_ns[0x1];
	u8 tcp_cwr[0x1];
	u8 tcp_ece[0x1];
	u8 tcp_urg[0x1];
	u8 tcp_ack[0x1];
	u8 tcp_psh[0x1];
	u8 tcp_rst[0x1];
	u8 tcp_syn[0x1];
	u8 tcp_fin[0x1];
	u8 first_fragment[0x1];
	u8 reserved_at_31[0xf];
};

struct mlx5_ifc_definer_hl_src_qp_gvmi_bits {
	u8 loopback_syndrome[0x8];
	u8 l3_type[0x2];
	u8 l4_type_bwc[0x2];
	u8 first_vlan_qualifier[0x2];
	u8 reserved_at_e[0x1];
	u8 functional_lb[0x1];
	u8 source_gvmi[0x10];
	u8 force_lb[0x1];
	u8 ip_fragmented[0x1];
	u8 source_is_requestor[0x1];
	u8 reserved_at_23[0x5];
	u8 source_qp[0x18];
};

struct mlx5_ifc_definer_hl_ib_l4_bits {
	u8 opcode[0x8];
	u8 qp[0x18];
	u8 se[0x1];
	u8 migreq[0x1];
	u8 ackreq[0x1];
	u8 fecn[0x1];
	u8 becn[0x1];
	u8 bth[0x1];
	u8 deth[0x1];
	u8 dcceth[0x1];
	u8 reserved_at_28[0x2];
	u8 pad_count[0x2];
	u8 tver[0x4];
	u8 p_key[0x10];
	u8 reserved_at_40[0x8];
	u8 deth_source_qp[0x18];
};

struct mlx5_ifc_definer_hl_oks1_bits {
	u8 second_ipv4_checksum_ok[0x1];
	u8 second_l4_checksum_ok[0x1];
	u8 first_ipv4_checksum_ok[0x1];
	u8 first_l4_checksum_ok[0x1];
	u8 second_l3_ok[0x1];
	u8 second_l4_ok[0x1];
	u8 first_l3_ok[0x1];
	u8 first_l4_ok[0x1];
	u8 flex_parser7_steering_ok[0x1];
	u8 flex_parser6_steering_ok[0x1];
	u8 flex_parser5_steering_ok[0x1];
	u8 flex_parser4_steering_ok[0x1];
	u8 flex_parser3_steering_ok[0x1];
	u8 flex_parser2_steering_ok[0x1];
	u8 flex_parser1_steering_ok[0x1];
	u8 flex_parser0_steering_ok[0x1];
	u8 second_ipv6_extension_header_vld[0x1];
	u8 first_ipv6_extension_header_vld[0x1];
	u8 l3_tunneling_ok[0x1];
	u8 l2_tunneling_ok[0x1];
	u8 second_tcp_ok[0x1];
	u8 second_udp_ok[0x1];
	u8 second_ipv4_ok[0x1];
	u8 second_ipv6_ok[0x1];
	u8 second_l2_ok[0x1];
	u8 vxlan_ok[0x1];
	u8 gre_ok[0x1];
	u8 first_tcp_ok[0x1];
	u8 first_udp_ok[0x1];
	u8 first_ipv4_ok[0x1];
	u8 first_ipv6_ok[0x1];
	u8 first_l2_ok[0x1];
};

struct mlx5_ifc_definer_hl_oks2_bits {
	u8 reserved_at_0[0xa];
	u8 second_mpls_ok[0x1];
	u8 second_mpls4_s_bit[0x1];
	u8 second_mpls4_qualifier[0x1];
	u8 second_mpls3_s_bit[0x1];
	u8 second_mpls3_qualifier[0x1];
	u8 second_mpls2_s_bit[0x1];
	u8 second_mpls2_qualifier[0x1];
	u8 second_mpls1_s_bit[0x1];
	u8 second_mpls1_qualifier[0x1];
	u8 second_mpls0_s_bit[0x1];
	u8 second_mpls0_qualifier[0x1];
	u8 first_mpls_ok[0x1];
	u8 first_mpls4_s_bit[0x1];
	u8 first_mpls4_qualifier[0x1];
	u8 first_mpls3_s_bit[0x1];
	u8 first_mpls3_qualifier[0x1];
	u8 first_mpls2_s_bit[0x1];
	u8 first_mpls2_qualifier[0x1];
	u8 first_mpls1_s_bit[0x1];
	u8 first_mpls1_qualifier[0x1];
	u8 first_mpls0_s_bit[0x1];
	u8 first_mpls0_qualifier[0x1];
};

struct mlx5_ifc_definer_hl_voq_bits {
	u8 reserved_at_0[0x18];
	u8 ecn_ok[0x1];
	u8 congestion[0x1];
	u8 profile[0x2];
	u8 internal_prio[0x4];
};

struct mlx5_ifc_definer_hl_ipv4_src_dst_bits {
	u8 source_address[0x20];
	u8 destination_address[0x20];
};

struct mlx5_ifc_definer_hl_ipv6_addr_bits {
	u8 ipv6_address_127_96[0x20];
	u8 ipv6_address_95_64[0x20];
	u8 ipv6_address_63_32[0x20];
	u8 ipv6_address_31_0[0x20];
};

struct mlx5_ifc_definer_hl_flex_parser_bits {
	u8 flex_parser_7[0x20];
	u8 flex_parser_6[0x20];
	u8 flex_parser_5[0x20];
	u8 flex_parser_4[0x20];
	u8 flex_parser_3[0x20];
	u8 flex_parser_2[0x20];
	u8 flex_parser_1[0x20];
	u8 flex_parser_0[0x20];
};

struct mlx5_ifc_definer_hl_bits {
	struct mlx5_ifc_definer_hl_eth_l2_bits eth_l2_outer;
	struct mlx5_ifc_definer_hl_eth_l2_bits eth_l2_inner;
	struct mlx5_ifc_definer_hl_eth_l2_src_bits eth_l2_src_outer;
	struct mlx5_ifc_definer_hl_eth_l2_src_bits eth_l2_src_inner;
	struct mlx5_ifc_definer_hl_ib_l2_bits ib_l2;
	struct mlx5_ifc_definer_hl_eth_l3_bits eth_l3_outer;
	struct mlx5_ifc_definer_hl_eth_l3_bits eth_l3_inner;
	struct mlx5_ifc_definer_hl_eth_l4_bits eth_l4_outer;
	struct mlx5_ifc_definer_hl_eth_l4_bits eth_l4_inner;
	struct mlx5_ifc_definer_hl_src_qp_gvmi_bits source_qp_gvmi;
	struct mlx5_ifc_definer_hl_ib_l4_bits ib_l4;
	struct mlx5_ifc_definer_hl_oks1_bits oks1;
	struct mlx5_ifc_definer_hl_oks2_bits oks2;
	struct mlx5_ifc_definer_hl_voq_bits voq;
	u8 reserved_at_480[0x380];
	struct mlx5_ifc_definer_hl_ipv4_src_dst_bits ipv4_src_dest_outer;
	struct mlx5_ifc_definer_hl_ipv4_src_dst_bits ipv4_src_dest_inner;
	struct mlx5_ifc_definer_hl_ipv6_addr_bits ipv6_dest_outer;
	struct mlx5_ifc_definer_hl_ipv6_addr_bits ipv6_dest_inner;
	struct mlx5_ifc_definer_hl_ipv6_addr_bits ipv6_src_outer;
	struct mlx5_ifc_definer_hl_ipv6_addr_bits ipv6_src_inner;
	u8 unsupported_dest_ib_l3[0x80];
	u8 unsupported_source_ib_l3[0x80];
	u8 reserved_at_b80[0x4c0];
	//	struct x udp_misc_outer;
	//	struct x udp_misc_inner;
	//	struct x tcp_misc;
	//	struct x tunnel_header;
	//	struct x mpls_outer;
	//	struct x mpls_inner;
	//	struct x config_headers_outer;
	//	struct x config_headers_inner;
	//	struct x random_number;
	//	struct x ipsec;
	//	struct x metadata_to_cqe;
	//	struct x general_purpose_lookup_field;
	//	struct x accumulated_hash;
	//	struct x utc_timestamp;
	//	struct x free_running_timestamp;
	struct mlx5_ifc_definer_hl_flex_parser_bits flex_parser;
	//	struct x registers;
	//	struct x ib_l3_extended;
	//	struct x rwh;
	//	struct x dcceth;
	//	struct x dceth;
	//	/.autodirect/swgwork/maayang/repo_1/golan_fw/include/
	//	tamar_g_cr_no_aligned_expose__descsteering_headers_layout_desc_adb.h
};

enum mlx5dr_definer_gtp {
	MLX5DR_DEFINER_GTP_EXT_HDR_BIT = 0x04,
};

struct mlx5_ifc_header_gtp_bits {
	u8 version[0x3];
	u8 proto_type[0x1];
	u8 reserved1[0x1];
	u8 ext_hdr_flag[0x1];
	u8 seq_num_flag[0x1];
	u8 pdu_flag[0x1];
	u8 msg_type[0x8];
	u8 msg_len[0x8];
	u8 teid[0x20];
};

struct mlx5_ifc_header_opt_gtp_bits {
	u8 seq_num[0x10];
	u8 pdu_num[0x8];
	u8 next_ext_hdr_type[0x8];
};

struct mlx5_ifc_header_gtp_psc_bits {
	u8 len[0x8];
	u8 pdu_type[0x4];
	u8 flags[0x4];
	u8 qfi[0x8];
	u8 reserved2[0x8];
};

struct mlx5dr_definer {
	uint8_t dw_selector[DW_SELECTORS];
	uint8_t byte_selector[BYTE_SELECTORS];
	uint8_t mask_tag[MLX5DR_MATCH_TAG_SZ];
	struct mlx5dr_devx_obj *obj;
};

void mlx5dr_definer_create_tag(const struct rte_flow_item *items,
			       struct mlx5dr_definer_fc *fc,
			       uint32_t fc_sz,
			       uint8_t *tag);

int mlx5dr_definer_compare(struct mlx5dr_definer *definer_a,
			   struct mlx5dr_definer *definer_b);

int mlx5dr_definer_get_id(struct mlx5dr_definer *definer);

int mlx5dr_definer_get(struct mlx5dr_context *ctx,
		       struct mlx5dr_match_template *mt);

void mlx5dr_definer_put(struct mlx5dr_match_template *mt);

#endif