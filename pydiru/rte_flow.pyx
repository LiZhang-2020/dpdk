# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from libc.stdlib cimport free, calloc
from libc.string cimport memcpy
import socket

import pydiru.pydiru_enums as e
import ipaddress


cdef class RteFlowItemEth(PydiruCM):
    def __init__(self, dst=bytes(), src=bytes(), eth_type=0, has_vlan=0):
        cdef char *dst_c = dst
        cdef char *src_c = src
        memcpy(<void *> self.item.dst.addr_bytes, dst_c, 6)
        memcpy(<void *> self.item.src.addr_bytes, src_c, 6)
        self.item.type = socket.htons(eth_type)
        self.item.has_vlan = has_vlan


cdef class RteFlowItemIpv4(PydiruCM):
    def __init__(self, version=0, ihl=0, tos=0, tot_length=0, pkt_id=0, fragment_offset=0,
                 ttl=0, next_proto=0, hdr_chksum=0, src_addr=0, dst_addr=0):
        self.item.hdr.version = version
        self.item.hdr.ihl = ihl
        self.item.hdr.type_of_service = tos
        self.item.hdr.total_length = tot_length
        self.item.hdr.packet_id = pkt_id
        self.item.hdr.fragment_offset = fragment_offset
        self.item.hdr.time_to_live = ttl
        self.item.hdr.next_proto_id = next_proto
        self.item.hdr.hdr_checksum = hdr_chksum
        self.item.hdr.src_addr = socket.htonl(int(ipaddress.ip_address(src_addr)))
        self.item.hdr.dst_addr = socket.htonl(int(ipaddress.ip_address(dst_addr)))


cdef class RteFlowItemTcp(PydiruCM):
    def __init__(self, src_port=0, dst_port=0, sent_seq=0, recv_ack=0, data_off=0,
                 rsrv=0, dt_off=0, tcp_flags=0, fin=0, syn=0, rst=0, psh=0, ack=0,
                 urg=0, ecne=0, cwr=0, rx_win=0, cksum=0, tcp_urp=0):
        self.item.hdr.src_port = socket.htons(src_port)
        self.item.hdr.dst_port = socket.htons(dst_port)
        self.item.hdr.sent_seq = sent_seq
        self.item.hdr.recv_ack = recv_ack
        self.item.hdr.data_off = data_off
        self.item.hdr.rsrv = rsrv
        self.item.hdr.dt_off = dt_off
        self.item.hdr.tcp_flags = tcp_flags
        self.item.hdr.fin = fin
        self.item.hdr.syn = syn
        self.item.hdr.rst = rst
        self.item.hdr.psh = psh
        self.item.hdr.ack = ack
        self.item.hdr.urg = urg
        self.item.hdr.ecne = ecne
        self.item.hdr.cwr = cwr
        self.item.hdr.rx_win = rx_win
        self.item.hdr.cksum = cksum
        self.item.hdr.tcp_urp = tcp_urp


cdef class RteFlowItemUdp(PydiruCM):
    def __init__(self, src_port=0, dst_port=0, length=0, cksum=0):
        self.item.hdr.src_port = socket.htons(src_port)
        self.item.hdr.dst_port = socket.htons(dst_port)
        self.item.hdr.dgram_len = length
        self.item.hdr.dgram_cksum = cksum


cdef class RteFlowItemGtp(PydiruCM):
    def __init__(self, flags=0, msg_type=0, msg_len=0, teid=0):
        """
        Initializes a RteFlowItemGtp object representing rte_flow_item_gtp C struct.
        :param flags: Version (3b), protocol type (1b), reserved (1b),
                      Extension header flag (1b),
                      Sequence number flag (1b),
                      N-PDU number flag (1b).
        :param msg_type: Message type
        :param msg_len: Message length
        :param teid: Tunnel endpoint identifier
        """
        self.item.v_pt_rsv_flags = flags
        self.item.msg_type = msg_type
        self.item.msg_len = msg_len
        self.item.teid = socket.htonl(teid)


cdef class RteFlowItemGtpPsc(PydiruCM):
    def __init__(self, pdu_type=0, qfi=0):
        """
        Initializes a RteFlowItemGtpPsc object representing rte_flow_item_gtp_psc C struct.
        :param pdu_type: PDU type
        :param qfi: QoS flow identifier
        """
        self.item.pdu_type = pdu_type
        self.item.qfi = qfi


cdef class RteFlowItem(PydiruCM):
    def __init__(self, flow_item_type, spec=None, mask=None, last=None):
        self.item.type = flow_item_type
        self.item.spec = NULL
        self.item.mask = NULL
        if flow_item_type == e.RTE_FLOW_ITEM_TYPE_ETH:
            size = sizeof(pdr.rte_flow_item_eth)
        if flow_item_type == e.RTE_FLOW_ITEM_TYPE_IPV4:
            size = sizeof(pdr.rte_flow_item_ipv4)
        if flow_item_type == e.RTE_FLOW_ITEM_TYPE_TCP:
            size = sizeof(pdr.rte_flow_item_tcp)
        if flow_item_type == e.RTE_FLOW_ITEM_TYPE_UDP:
            size = sizeof(pdr.rte_flow_item_udp)
        if flow_item_type in [e.RTE_FLOW_ITEM_TYPE_GTP,
                              e.RTE_FLOW_ITEM_TYPE_GTPC,
                              e.RTE_FLOW_ITEM_TYPE_GTPU]:
            size = sizeof(pdr.rte_flow_item_gtp)
        if flow_item_type == e.RTE_FLOW_ITEM_TYPE_GTP_PSC:
            size = sizeof(pdr.rte_flow_item_gtp_psc)
        if spec:
            self.item.spec = calloc(1, size)
            memcpy(self.item.spec, <void *>&((<RteFlowItem>spec).item), size)
        if mask:
            self.item.mask = calloc(1, size)
            memcpy(self.item.mask, <void *>&((<RteFlowItem>mask).item), size)
        self.item.last = NULL

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.item.spec != NULL:
            free(self.item.spec)
            self.item.spec = NULL
        if self.item.mask != NULL:
            free(self.item.mask)
            self.item.mask = NULL


cdef class RteFlowItemEnd(RteFlowItem):
     def __init__(self):
         super().__init__(e.RTE_FLOW_ITEM_TYPE_END)


cdef class RteFlowResult(PydiruObject):
    def __init__(self, status, user_data=None):
        """
        Initializes a RteFlowResult object representing rte_flow_q_op_res C struct.
        :param status: Status of the result
        :param user_data: Results's user's data
        """
        self.flow_res.version = 0
        self.flow_res.status = status
        self.flow_res.user_data = <void *>user_data if (user_data is not None) else NULL

    @property
    def status(self):
        return self.flow_res.status

    @property
    def user_data(self):
        return <object>self.flow_res.user_data