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

cdef extern  from '../../../../lib/librte_ethdev/rte_flow.h':

    cdef struct rte_flow_item:
        e.rte_flow_item_type type
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

    cdef struct rte_flow_item_tcp:
        rte_tcp_hdr hdr

    cdef struct rte_flow_item_udp:
        rte_udp_hdr hdr

    cdef struct rte_flow_q_op_res:
        uint32_t version
        e.rte_flow_q_op_status status
        void *user_data
