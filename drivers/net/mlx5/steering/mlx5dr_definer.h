/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_DEFINER_H_
#define MLX5DR_DEFINER_H_

struct mlx5_ifc_definer_hl_eth_l2_bits {
	uint8_t dmac_47_16[0x20];
	uint8_t dmac_15_0[0x10];
	uint8_t l3_ethertype[0x10];
	uint8_t reserved_at_40[0x1];
	uint8_t sx_sniffer[0x1];
	uint8_t functional_lb[0x1];
	uint8_t ip_fragmented[0x1];
	uint8_t qp_type[0x2];
	uint8_t encap_type[0x2];
	uint8_t port_number[0x2];
	uint8_t l3_type[0x2];
	uint8_t l4_type_bwc[0x2];
	uint8_t first_vlan_qualifier[0x2];
	uint8_t first_priority[0x3];
	uint8_t first_cfi[0x1];
	uint8_t first_vlan_id[0xc];
	uint8_t l4_type[0x4];
	uint8_t reserved_at_64[0x2];
	uint8_t ipsec_layer[0x2];
	uint8_t l2_type[0x2];
	uint8_t force_lb[0x1];
	uint8_t l2_ok[0x1];
	uint8_t l3_ok[0x1];
	uint8_t l4_ok[0x1];
	uint8_t second_vlan_qualifier[0x2];
	uint8_t second_priority[0x3];
	uint8_t second_cfi[0x1];
	uint8_t second_vlan_id[0xc];
};

struct mlx5_ifc_definer_hl_eth_l2_src_bits {
	uint8_t smac_47_16[0x20];
	uint8_t smac_15_0[0x10];
	uint8_t loopback_syndrome[0x8];
	uint8_t l3_type[0x2];
	uint8_t l4_type_bwc[0x2];
	uint8_t first_vlan_qualifier[0x2];
	uint8_t ip_fragmented[0x1];
	uint8_t functional_lb[0x1];
};

struct mlx5_ifc_definer_hl_ib_l2_bits {
	uint8_t sx_sniffer[0x1];
	uint8_t force_lb[0x1];
	uint8_t functional_lb[0x1];
	uint8_t reserved_at_3[0x3];
	uint8_t port_number[0x2];
	uint8_t sl[0x4];
	uint8_t qp_type[0x2];
	uint8_t lnh[0x2];
	uint8_t dlid[0x10];
	uint8_t vl[0x4];
	uint8_t lrh_packet_length[0xc];
	uint8_t slid[0x10];
};

struct mlx5_ifc_definer_hl_eth_l3_bits {
	uint8_t ip_version[0x4];
	uint8_t ihl[0x4];
	uint8_t dscp[0x6];
	uint8_t ecn[0x2];
	uint8_t time_to_live_hop_limit[0x8];
	uint8_t protocol_next_header[0x8];
	uint8_t identification[0x10];
	uint8_t flags[0x3];
	uint8_t fragment_offset[0xd];
	uint8_t ipv4_total_length[0x10];
	uint8_t checksum[0x10];
	uint8_t reserved_at_60[0xc];
	uint8_t flow_label[0x14];
	uint8_t packet_length[0x10];
	uint8_t ipv6_payload_length[0x10];
};

struct mlx5_ifc_definer_hl_eth_l4_bits {
	uint8_t source_port[0x10];
	uint8_t destination_port[0x10];
	uint8_t data_offset[0x4];
	uint8_t l4_ok[0x1];
	uint8_t l3_ok[0x1];
	uint8_t ip_fragmented[0x1];
	uint8_t tcp_ns[0x1];
	uint8_t tcp_cwr[0x1];
	uint8_t tcp_ece[0x1];
	uint8_t tcp_urg[0x1];
	uint8_t tcp_ack[0x1];
	uint8_t tcp_psh[0x1];
	uint8_t tcp_rst[0x1];
	uint8_t tcp_syn[0x1];
	uint8_t tcp_fin[0x1];
	uint8_t first_fragment[0x1];
	uint8_t reserved_at_31[0xf];
};

struct mlx5_ifc_definer_hl_src_qp_gvmi_bits {
	uint8_t loopback_syndrome[0x8];
	uint8_t l3_type[0x2];
	uint8_t l4_type_bwc[0x2];
	uint8_t first_vlan_qualifier[0x2];
	uint8_t reserved_at_e[0x1];
	uint8_t functional_lb[0x1];
	uint8_t source_gvmi[0x10];
	uint8_t force_lb[0x1];
	uint8_t ip_fragmented[0x1];
	uint8_t source_is_requestor[0x1];
	uint8_t reserved_at_23[0x5];
	uint8_t source_qp[0x18];
};

struct mlx5_ifc_definer_hl_ib_l4_bits {
	uint8_t opcode[0x8];
	uint8_t qp[0x18];
	uint8_t se[0x1];
	uint8_t migreq[0x1];
	uint8_t ackreq[0x1];
	uint8_t fecn[0x1];
	uint8_t becn[0x1];
	uint8_t bth[0x1];
	uint8_t deth[0x1];
	uint8_t dcceth[0x1];
	uint8_t reserved_at_28[0x2];
	uint8_t pad_count[0x2];
	uint8_t tver[0x4];
	uint8_t p_key[0x10];
	uint8_t reserved_at_40[0x8];
	uint8_t deth_source_qp[0x18];
};

struct mlx5_ifc_definer_hl_oks1_bits {
	uint8_t second_ipv4_checksum_ok[0x1];
	uint8_t second_l4_checksum_ok[0x1];
	uint8_t first_ipv4_checksum_ok[0x1];
	uint8_t first_l4_checksum_ok[0x1];
	uint8_t second_l3_ok[0x1];
	uint8_t second_l4_ok[0x1];
	uint8_t first_l3_ok[0x1];
	uint8_t first_l4_ok[0x1];
	uint8_t flex_parser7_steering_ok[0x1];
	uint8_t flex_parser6_steering_ok[0x1];
	uint8_t flex_parser5_steering_ok[0x1];
	uint8_t flex_parser4_steering_ok[0x1];
	uint8_t flex_parser3_steering_ok[0x1];
	uint8_t flex_parser2_steering_ok[0x1];
	uint8_t flex_parser1_steering_ok[0x1];
	uint8_t flex_parser0_steering_ok[0x1];
	uint8_t second_ipv6_extension_header_vld[0x1];
	uint8_t first_ipv6_extension_header_vld[0x1];
	uint8_t l3_tunneling_ok[0x1];
	uint8_t l2_tunneling_ok[0x1];
	uint8_t second_tcp_ok[0x1];
	uint8_t second_udp_ok[0x1];
	uint8_t second_ipv4_ok[0x1];
	uint8_t second_ipv6_ok[0x1];
	uint8_t second_l2_ok[0x1];
	uint8_t vxlan_ok[0x1];
	uint8_t gre_ok[0x1];
	uint8_t first_tcp_ok[0x1];
	uint8_t first_udp_ok[0x1];
	uint8_t first_ipv4_ok[0x1];
	uint8_t first_ipv6_ok[0x1];
	uint8_t first_l2_ok[0x1];
};

struct mlx5_ifc_definer_hl_oks2_bits {
	uint8_t reserved_at_0[0xa];
	uint8_t second_mpls_ok[0x1];
	uint8_t second_mpls4_s_bit[0x1];
	uint8_t second_mpls4_qualifier[0x1];
	uint8_t second_mpls3_s_bit[0x1];
	uint8_t second_mpls3_qualifier[0x1];
	uint8_t second_mpls2_s_bit[0x1];
	uint8_t second_mpls2_qualifier[0x1];
	uint8_t second_mpls1_s_bit[0x1];
	uint8_t second_mpls1_qualifier[0x1];
	uint8_t second_mpls0_s_bit[0x1];
	uint8_t second_mpls0_qualifier[0x1];
	uint8_t first_mpls_ok[0x1];
	uint8_t first_mpls4_s_bit[0x1];
	uint8_t first_mpls4_qualifier[0x1];
	uint8_t first_mpls3_s_bit[0x1];
	uint8_t first_mpls3_qualifier[0x1];
	uint8_t first_mpls2_s_bit[0x1];
	uint8_t first_mpls2_qualifier[0x1];
	uint8_t first_mpls1_s_bit[0x1];
	uint8_t first_mpls1_qualifier[0x1];
	uint8_t first_mpls0_s_bit[0x1];
	uint8_t first_mpls0_qualifier[0x1];
};

struct mlx5_ifc_definer_hl_voq_bits {
	uint8_t reserved_at_0[0x18];
	uint8_t ecn_ok[0x1];
	uint8_t congestion[0x1];
	uint8_t profile[0x2];
	uint8_t internal_prio[0x4];
};

struct mlx5_ifc_definer_hl_ipv4_src_dst_bits {
	uint8_t source_address[0x20];
	uint8_t destination_address[0x20];
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
	uint8_t reserved_at_480[0x380];
	struct mlx5_ifc_definer_hl_ipv4_src_dst_bits ipv4_src_dest_outer;
	struct mlx5_ifc_definer_hl_ipv4_src_dst_bits ipv4_src_dest_inner;

//	TODO
//	struct x ipv6_dest_outer;
//	struct x ipv6_dest_inner;
//	struct x ipv6_source_outer;
//	struct x ipv6_source_inner;
//	struct x dest_ib_l3;
//	struct x source_ib_l3;
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
//	struct x flex_parser;
//	struct x registers;
//	struct x ib_l3_extended;
//	struct x rwh;
//	struct x dcceth;
//	struct x dceth;
//	/.autodirect/swgwork/maayang/repo_1/golan_fw/include/
//	tamar_g_cr_no_aligned_expose__descsteering_headers_layout_desc_adb.h
};

void mlx5dr_definer_create_tag(struct rte_flow_item *items,
			       struct mlx5dr_definer_fc *fc,
			       uint32_t fc_sz,
			       uint8_t *tag);

int mlx5dr_definer_create(struct mlx5dr_matcher *matcher,
			  struct rte_flow_item *items);

void mlx5dr_definer_destroy(struct mlx5dr_matcher *matcher);

#endif
