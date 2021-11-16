#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

import socket
import struct
import time

from pydiru.rte_flow import RteFlowItem, RteFlowItemIpv4, RteFlowItemEnd
from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError
from pyverbs.wr import SGE, SendWR, RecvWR
import pydiru.pydiru_enums as p
from pyverbs import enums as v


class TunnelType:
    GTP_U = 'GPT-U'


class PacketConsts:
    """
    Class to hold constant packets' values.
    """
    ETHER_HEADER_SIZE = 14
    IPV4_HEADER_SIZE = 20
    IPV6_HEADER_SIZE = 40
    UDP_HEADER_SIZE = 8
    TCP_HEADER_SIZE = 20
    VLAN_HEADER_SIZE = 4
    TCP_HEADER_SIZE_WORDS = 5
    IP_V4 = 4
    IP_V6 = 6
    TCP_PROTO = 'tcp'
    UDP_PROTO = 'udp'
    IP_V4_FLAGS = 2  # Don't fragment is set
    TTL_HOP_LIMIT = 64
    IHL = 5
    # Hardcoded values for flow matchers
    ETHER_TYPE_IPV4 = 0x800
    MAC_MASK = "ff:ff:ff:ff:ff:ff"
    ETHER_TYPE_IPV6 = 0x86DD
    SRC_MAC = "24:8a:07:a5:28:c8"
    # DST mac must be multicast
    DST_MAC = "01:50:56:19:20:a7"
    SRC_IP = "1.1.1.2"
    DST_IP = "2.2.2.3"
    SRC_PORT = 1234
    DST_PORT = 5678
    SRC_IP6 = "a0a1::a2a3:a4a5:a6a7:a8a9"
    DST_IP6 = "b0b1::b2b3:b4b5:b6b7:b8b9"
    SEQ_NUM = 1
    WINDOW_SIZE = 65535
    VXLAN_PORT = 4789
    VXLAN_VNI = 7777777
    VXLAN_FLAGS = 0x8
    VXLAN_HEADER_SIZE = 8
    VLAN_TPID = 0x8100
    VLAN_PRIO = 5
    VLAN_CFI = 1
    VLAN_ID = 0xc0c
    # GTPU consts
    GTP_U_PORT = 2152
    GTPU_VERSION = 1
    PROTO_TYPE = 1
    GTP_EX = 1
    GTPU_MSG_TYPE = 0xff
    GTP_SEQUENCE_NUMBER = 0
    GTP_NPDU_NUMBER = 0xda
    GTPU_MSG_LEN = 50
    GTPU_TEID = 0xdeadbeef
    GTPU_HEADER_SIZE = 8
    # GTP PSC consts
    GTP_PSC_TYPE = 0x85
    GTP_PSC_PDU_TYPE = 1
    GTP_PSC_QFI = 3


def gen_outer_headers(msg_size, tunnel=TunnelType.GTP_U, **kwargs):
    """
    Generates outer headers for encapsulation with tunnel: Ethernet, IPv4, UDP
    and the desired tunneling using the relevant values from the PacketConst class.
    :param msg_size: The size of the inner message (payload size)
    :param tunnel: The type of tunneling
    :param kwargs: Arguments:
            * *gtp_psc_qfi*
                QFI (QoS flow identifier) field to use in the GTP PSC header.
    :return: Outer headers
    """

    # Ethernet Header
    outer = struct.pack('!6s6s',
                        bytes.fromhex(PacketConsts.DST_MAC.replace(':', '')),
                        bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
    outer += PacketConsts.ETHER_TYPE_IPV4.to_bytes(2, 'big')

    if tunnel == TunnelType.GTP_U:
        tunnel_header_size = PacketConsts.GTPU_HEADER_SIZE
        dst_port = PacketConsts.GTP_U_PORT

    # IPv4 Header
    ip_total_len = msg_size + PacketConsts.UDP_HEADER_SIZE + \
                   PacketConsts.IPV4_HEADER_SIZE + \
                   tunnel_header_size
    outer += struct.pack('!2B3H2BH4s4s', (PacketConsts.IP_V4 << 4) +
                         PacketConsts.IHL, 0, ip_total_len, 0,
                         PacketConsts.IP_V4_FLAGS << 13,
                         PacketConsts.TTL_HOP_LIMIT, socket.IPPROTO_UDP, 0,
                         socket.inet_aton(PacketConsts.SRC_IP),
                         socket.inet_aton(PacketConsts.DST_IP))
    # UDP Header
    outer += struct.pack('!4H', PacketConsts.SRC_PORT, dst_port,
                         msg_size + PacketConsts.UDP_HEADER_SIZE + tunnel_header_size, 0)

    # GTP-U Header
    if tunnel == TunnelType.GTP_U:
        gtp_psc_qfi = kwargs.get('gtp_psc_qfi')
        gtp_psc_ex = 0 if gtp_psc_qfi is None else 1
        gtp_msg_len = PacketConsts.GTPU_MSG_LEN + 8 if gtp_psc_qfi else PacketConsts.GTPU_MSG_LEN
        gtpu_teid = kwargs.get('gtpu_teid', PacketConsts.GTPU_TEID)
        outer += struct.pack('!BBH', (PacketConsts.GTPU_VERSION << 5) +
                             (PacketConsts.PROTO_TYPE << 4) + (gtp_psc_ex << 2) + (gtp_psc_ex << 1),
                             PacketConsts.GTPU_MSG_TYPE, gtp_msg_len)
        outer += struct.pack('!I', gtpu_teid)

        if gtp_psc_qfi:
            extention_header_len = 1
            next_extention_type = 0
            outer += struct.pack('!HBB', PacketConsts.GTP_SEQUENCE_NUMBER,
                                 PacketConsts.GTP_NPDU_NUMBER, PacketConsts.GTP_PSC_TYPE)
            outer += struct.pack('!BBBB', extention_header_len, (PacketConsts.GTP_PSC_PDU_TYPE << 4),
                                  gtp_psc_qfi, next_extention_type)

    return outer


def gen_packet(msg_size, l3=PacketConsts.IP_V4, l4=PacketConsts.UDP_PROTO,
               with_vlan=False, tunnel=None, **kwargs):
    """
    Generates a Eth | IPv4 or IPv6 | UDP or TCP packet with hardcoded values in
    the headers and randomized payload.
    :param msg_size: total packet size
    :param l3: Packet layer 3 type: 4 for IPv4 or 6 for IPv6
    :param l4: Packet layer 4 type: 'tcp' or 'udp'
    :param with_vlan: if True add VLAN header to the packet
    :param tunnel: If set, the type of tunneling to use.
    :param kwargs: Arguments:
            * *src_mac*
                Source MAC address to use in the packet.
            * *src_ip*
                Source IPv4 address to use in the packet.
            * *src_port*
                Source L4 port to use in the packet.
            * *gtp_psc_qfi*
                QFI (QoS flow identifier) field to use in the GTP PSC header.
    :return: Bytes of the generated packet
    """
    if tunnel == TunnelType.GTP_U:
        tunnel_header_size = PacketConsts.GTPU_HEADER_SIZE
        outer_size = PacketConsts.ETHER_HEADER_SIZE + PacketConsts.IPV4_HEADER_SIZE + \
                     PacketConsts.UDP_HEADER_SIZE + tunnel_header_size
        if kwargs.get('gtp_psc_qfi'):
            outer_size += 8

        return gen_outer_headers(outer_size, tunnel, **kwargs) + \
            gen_packet(msg_size - outer_size, l3, l4, with_vlan, **kwargs)

    l3_header_size = getattr(PacketConsts, f'IPV{str(l3)}_HEADER_SIZE')
    l4_header_size = getattr(PacketConsts, f'{l4.upper()}_HEADER_SIZE')
    payload_size = max(0, msg_size - l3_header_size - l4_header_size -
                       PacketConsts.ETHER_HEADER_SIZE)
    next_hdr = getattr(socket, f'IPPROTO_{l4.upper()}')
    ip_total_len = msg_size - PacketConsts.ETHER_HEADER_SIZE

    # Ethernet header
    src_mac = kwargs.get('src_mac', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
    packet = struct.pack('!6s6s',
                         bytes.fromhex(PacketConsts.DST_MAC.replace(':', '')), src_mac)
    if with_vlan:
        packet += struct.pack('!HH', PacketConsts.VLAN_TPID, (PacketConsts.VLAN_PRIO << 13) +
                              (PacketConsts.VLAN_CFI << 12) + PacketConsts.VLAN_ID)
        payload_size -= PacketConsts.VLAN_HEADER_SIZE
        ip_total_len -= PacketConsts.VLAN_HEADER_SIZE

    if l3 == PacketConsts.IP_V4:
        packet += PacketConsts.ETHER_TYPE_IPV4.to_bytes(2, 'big')
    else:
        packet += PacketConsts.ETHER_TYPE_IPV6.to_bytes(2, 'big')

    if l3 == PacketConsts.IP_V4:
        # IPv4 header
        src_ip = kwargs.get('src_ip', PacketConsts.SRC_IP)
        packet += struct.pack('!2B3H2BH4s4s', (PacketConsts.IP_V4 << 4) +
                              PacketConsts.IHL, 0, ip_total_len, 0,
                              PacketConsts.IP_V4_FLAGS << 13,
                              PacketConsts.TTL_HOP_LIMIT, next_hdr, 0,
                              socket.inet_aton(src_ip),
                              socket.inet_aton(PacketConsts.DST_IP))
    else:
        # IPv6 header
        packet += struct.pack('!IH2B16s16s', (PacketConsts.IP_V6 << 28),
                       ip_total_len, next_hdr, PacketConsts.TTL_HOP_LIMIT,
                       socket.inet_pton(socket.AF_INET6, PacketConsts.SRC_IP6),
                       socket.inet_pton(socket.AF_INET6, PacketConsts.DST_IP6))

    src_port = kwargs.get('src_port', PacketConsts.SRC_PORT)
    if l4 == PacketConsts.UDP_PROTO:
        # UDP header
        packet += struct.pack('!4H', src_port, PacketConsts.DST_PORT,
                              payload_size + PacketConsts.UDP_HEADER_SIZE, 0)
    else:
        # TCP header
        packet += struct.pack('!2H2I4H', src_port, PacketConsts.DST_PORT, 0, 0,
                              PacketConsts.TCP_HEADER_SIZE_WORDS << 12,
                              PacketConsts.WINDOW_SIZE, 0, 0)
    # Payload
    packet += str.encode('a' * payload_size)
    return packet


def wc_status_to_str(status):
    try:
        return \
            {0: 'Success', 1: 'Local length error',
             2: 'local QP operation error', 3: 'Local EEC operation error',
             4: 'Local protection error', 5: 'WR flush error',
             6: 'Memory window bind error', 7: 'Bad response error',
             8: 'Local access error', 9: 'Remote invalidate request error',
             10: 'Remote access error', 11: 'Remote operation error',
             12: 'Retry exceeded', 13: 'RNR retry exceeded',
             14: 'Local RDD violation error',
             15: 'Remote invalidate RD request error',
             16: 'Remote aort error', 17: 'Invalidate EECN error',
             18: 'Invalidate EEC state error', 19: 'Fatal error',
             20: 'Response timeout error', 21: 'General error'}[status]
    except KeyError:
        return 'Unknown WC status ({s})'.format(s=status)


def poll_cq(cq, count=1, tag_value=None):
    polling_timeout = 5
    start_poll_t = time.perf_counter()
    while count > 0 and (time.perf_counter() - start_poll_t) < polling_timeout:
        nc, tmp_wcs = cq.poll(count)
        for wc in tmp_wcs:
            if tag_value:
                # In RAW traffic, qp_num field in WC stores the flow tag.
                if wc.qp_num != tag_value:
                    raise PyverbsError(f'Got flow tag {wc.qp_num} instead of expected {tag_value}.')
            if wc.status != v.IBV_WC_SUCCESS:
                raise PyverbsRDMAError('Completion status is {s}'.
                                       format(s=wc_status_to_str(wc.status)),
                                       wc.status)
        count -= nc

    if count > 0:
        raise PyverbsError(f'Got timeout on polling ({count} CQEs remaining)')


def post_recv(qp, mr, msg_size, n=1):
    for i in range(n):
        recv_sg = SGE(mr.buf, msg_size, mr.lkey)
        recv_wr = RecvWR(sg=[recv_sg], wr_id=i, num_sge=1)
        qp.post_recv(recv_wr)


def send_packets(agr_obj, packets, tag_value=None):
    for packet in packets:
        send_sg = SGE(agr_obj.mr.buf, len(packet), agr_obj.mr.lkey)
        agr_obj.mr.write(packet, len(packet))
        send_wr = SendWR(num_sge=1, sg=[send_sg])
        agr_obj.qp.post_send(send_wr)
        poll_cq(agr_obj.cq, tag_value=tag_value)


def validate_raw(msg_received, msg_expected, skip_idxs=None):
    size = len(msg_expected)
    skip_idxs  = [] if skip_idxs is None else skip_idxs
    for i in range(size):
        if (msg_received[i] != msg_expected[i]) and i not in skip_idxs:
            err_msg = f'Data validation failure:\nexpected {msg_expected}\n\nreceived {msg_received}'
            raise PyverbsError(err_msg)


def raw_traffic(client, server, num_msgs, packets, expected_packet=None, tag_value=None,
                skip_idxs=None):
    """
    Runs raw ethernet traffic between two sides
    :param client: client side, clients base class is BaseDrResources
    :param server: server side, servers base class is BaseDrResources
    :param num_msgs: number of msgs to send
    :param packets: packets to send.
    :param expected_packet: expected packet to receive.
    :param tag_value: Expected flow tag.
    :param skip_idxs: List of indexes of the packets that should be skipped when
                      verifying the packet.
    :return: None
    """
    skip_idxs  = [] if skip_idxs is None else skip_idxs
    expected_packet = packets[0] if expected_packet is None else expected_packet
    for _ in range(num_msgs):
        post_recv(server.wq, server.mr, server.msg_size)
        send_packets(client, packets)
        poll_cq(server.cq, tag_value=tag_value)
        msg_received = server.mr.read(server.msg_size, 0)
        validate_raw(msg_received, expected_packet, skip_idxs)


def create_sipv4_rte_items(sip_val=PacketConsts.SRC_IP):
    mask = RteFlowItemIpv4(src_addr=bytes(4 * [0xff]))
    val = RteFlowItemIpv4(src_addr=sip_val)
    return [RteFlowItem(p.RTE_FLOW_ITEM_TYPE_IPV4, val, mask), RteFlowItemEnd()]


def create_dipv4_rte_items(dip_val=PacketConsts.DST_IP):
    mask = RteFlowItemIpv4(dst_addr=bytes(4 * [0xff]))
    val = RteFlowItemIpv4(dst_addr=dip_val)
    return [RteFlowItem(p.RTE_FLOW_ITEM_TYPE_IPV4, val, mask), RteFlowItemEnd()]
