#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

import unittest
import socket
import struct
import time


from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError
from pyverbs.wr import SGE, SendWR, RecvWR
from pyverbs import enums as v
from pyverbs.cq import WC

from args_parser import parser


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


def gen_packet(msg_size, l3=PacketConsts.IP_V4, l4=PacketConsts.UDP_PROTO,
               with_vlan=False, **kwargs):
    """
    Generates a Eth | IPv4 or IPv6 | UDP or TCP packet with hardcoded values in
    the headers and randomized payload.
    :param msg_size: total packet size
    :param l3: Packet layer 3 type: 4 for IPv4 or 6 for IPv6
    :param l4: Packet layer 4 type: 'tcp' or 'udp'
    :param with_vlan: if True add VLAN header to the packet
    :param kwargs: Arguments:
            * *src_mac*
                Source MAC address to use in the packet.
            * *src_ip*
                Source IPv4 address to use in the packet.
            * *src_port*
                Source L4 port to use in the packet.
    :return: Bytes of the generated packet
    """
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


def poll_cq(cq, count=1):
    polling_timeout = 5
    start_poll_t = time.perf_counter()
    while count > 0 and (time.perf_counter() - start_poll_t) < polling_timeout:
        nc, tmp_wcs = cq.poll(count)
        for wc in tmp_wcs:
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


def send_packets(qp, mr, packets):
    for packet in packets:
        send_sg = SGE(mr.buf, len(packet), mr.lkey)
        mr.write(packet, len(packet))
        send_wr = SendWR(num_sge=1, sg=[send_sg])
        qp.post_send(send_wr)


def validate_raw(msg_received, msg_expected, skip_idxs = []):
    size = len(msg_expected)
    for i in range(size):
        if (msg_received[i] != msg_expected[i]) and i not in skip_idxs:
            err_msg = f'Data validation failure:\nexpected {msg_expected}\n\nreceived {msg_received}'
            raise PyverbsError(err_msg)


def raw_traffic(client, server, num_msgs, packets, expected_packet=None):
    """
    Runs raw ethernet traffic between two sides
    :param client: client side, clients base class is BaseDrResources
    :param server: server side, servers base class is BaseDrResources
    :param num_msgs: number of msgs to send
    :param packets: packets to send.
    :param expected_packet: expected packet to receive.
    :return:
    """
    expected_packet = packets[0] if expected_packet is None else expected_packet
    for _ in range(num_msgs):
        post_recv(server.wq, server.mr, server.msg_size)
        send_packets(client.qp, client.mr, packets)
        poll_cq(client.cq, len(packets))
        poll_cq(server.cq)
        msg_received = server.mr.read(server.msg_size, 0)
        validate_raw(msg_received, expected_packet)
