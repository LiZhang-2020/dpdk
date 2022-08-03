# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from libc.stdint cimport uint8_t, uint16_t, uint32_t
cimport pydiru.pydiru_enums_c as e

cdef extern  from '../../../../lib/librte_eal/include/rte_eal.h':
    int rte_eal_init(int argc, char **argv)

cdef extern  from '../../../../lib/librte_eal/include/rte_errno.h':
    int rte_errno

cdef extern from '../../../../lib/librte_net/rte_ip.h':

    cdef struct rte_ipv4_hdr:
        uint8_t version_ihl
        uint8_t ihl
        uint8_t version
        uint8_t type_of_service
        uint16_t total_length
        uint16_t packet_id
        uint16_t fragment_offset
        uint8_t time_to_live
        uint8_t next_proto_id
        uint16_t hdr_checksum
        uint32_t src_addr
        uint32_t dst_addr

    cdef struct rte_ipv6_hdr:
        uint32_t vtc_flow
        uint16_t payload_len
        uint8_t proto
        uint8_t hop_limits
        uint8_t src_addr[16]
        uint8_t dst_addr[16]

cdef extern from '../../../../lib/librte_net/rte_tcp.h':

    cdef struct rte_tcp_hdr:
        uint16_t src_port
        uint16_t dst_port
        uint32_t sent_seq
        uint32_t recv_ack
        uint8_t data_off
        uint8_t rsrv
        uint8_t dt_off
        uint8_t tcp_flags
        uint8_t fin
        uint8_t syn
        uint8_t rst
        uint8_t psh
        uint8_t ack
        uint8_t urg
        uint8_t ecne
        uint8_t cwr
        uint16_t rx_win
        uint16_t cksum
        uint16_t tcp_urp

cdef extern  from '../../../../lib/librte_net/rte_udp.h':

    cdef struct rte_udp_hdr:
        uint16_t src_port
        uint16_t dst_port
        uint16_t dgram_len
        uint16_t dgram_cksum

cdef extern  from '../../../../lib/librte_net/rte_icmp.h':

    cdef struct rte_icmp_hdr:
        uint8_t  icmp_type
        uint8_t  icmp_code
        uint16_t icmp_cksum
        uint16_t icmp_ident
        uint16_t icmp_seq_nb

cdef extern  from '../../../../lib/librte_ethdev/rte_flow.h':

    cdef struct rte_flow_item_icmp6:
        uint8_t  type
        uint8_t  code
        uint16_t checksum

cdef extern  from '../../../../lib/librte_ethdev/rte_flow.h':

    cdef struct rte_flow_item:
        int type
        void *spec
        void *last
        void *mask

    struct rte_ether_addr:
        uint8_t addr_bytes[8]

    cdef struct rte_flow_item_eth:
        rte_ether_addr dst
        rte_ether_addr src
        uint16_t type
        uint32_t has_vlan
        uint32_t reserved

    cdef struct rte_flow_item_ipv4:
        rte_ipv4_hdr hdr

    cdef struct rte_flow_item_ipv6:
        rte_ipv6_hdr hdr
        uint32_t has_hop_ext
        uint32_t has_route_ext
        uint32_t has_frag_ext
        uint32_t has_auth_ext
        uint32_t has_esp_ext
        uint32_t has_dest_ext
        uint32_t has_mobil_ext
        uint32_t has_hip_ext
        uint32_t has_shim6_ext

    cdef struct rte_flow_item_tcp:
        rte_tcp_hdr hdr

    cdef struct rte_flow_item_udp:
        rte_udp_hdr hdr

    cdef struct rte_flow_item_icmp:
        rte_icmp_hdr hdr

    cdef struct rte_flow_op_result:
        uint32_t version
        e.rte_flow_op_status status
        void *user_data

    cdef struct rte_flow_item_gtp:
        uint8_t v_pt_rsv_flags
        uint8_t msg_type
        uint16_t msg_len
        uint32_t teid

    cdef struct rte_flow_item_gtp_psc:
        uint8_t pdu_type
        uint8_t qfi

    cdef struct rte_flow_item_ethdev:
        uint16_t port_id

    cdef struct rte_flow_item_vxlan:
        uint8_t flags
        uint8_t rsvd0[3]
        uint8_t vni[3]
        uint8_t rsvd1

    cdef struct rte_flow_item_vlan:
        uint16_t tci
        uint16_t inner_type

cdef extern  from '../../../../drivers/net/mlx5/mlx5_flow.h':

    cdef struct mlx5_rte_flow_item_sq:
        uint32_t queue

    cdef struct rte_flow_item_tag:
        uint32_t data
        uint8_t index
