#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

import socket
import struct
import time

from pydiru.rte_flow import RteFlowItem, RteFlowItemEth, RteFlowItemIpv4, RteFlowItemIpv6, \
    RteFlowItemUdp, RteFlowItemTcp, RteFlowItemGtp, RteFlowItemGtpPsc, RteFlowItemEnd, RteFlowItemTag
from pydiru.providers.mlx5.steering.mlx5dr_rule import Mlx5drRuleAttr, Mlx5drRule
from pydiru.providers.mlx5.steering.mlx5dr_devx_objects import Mlx5drDevxObj
from pyverbs.pyverbs_error import PyverbsError, PyverbsRDMAError
import pydiru.providers.mlx5.steering.mlx5dr_enums as me
from pyverbs.providers.mlx5.mlx5dv import Mlx5DevxObj
from pyverbs.wr import SGE, SendWR, RecvWR
import pydiru.pydiru_enums as p
from pyverbs import enums as v

from .prm_structs import AllocFlowCounterIn, AllocFlowCounterOut, QueryFlowCounterIn, \
    QueryFlowCounterOut, TrafficCounter, QueryHcaCapIn, QueryQosCapOut, HcaCapOpMod, \
    GeneralObjInCmdHdr, CreateGeneralObjIn, CreateGeneralObjOut, de

MAX_DIFF_PACKETS = 5
BULK_COUNTER_SIZE = 512
BULK_512 = 0b100
MELLANOX_VENDOR_ID = 0x02c9

NEW_MAC_STR = '88:88:88:88:88:88'
POLLING_TIMEOUT = 5


class VendorPartID:
    CX6DX = 0x101d


class TunnelType:
    GTP_U = 'GPT-U'
    VXLAN = 'VXLAN'
    GRE = 'GRE'


class ModifyFieldId:
    OUT_SMAC_47_16 = 0x1
    OUT_SMAC_15_0 = 0x2
    OUT_IPV4_TTL = 0xa
    OUT_UDP_SPORT = 0xb
    OUT_UDP_DPORT = 0xc
    METEDATA_REG_C_1 = 0x52


class ModifyFieldLen:
    OUT_SMAC_47_16 = 32
    OUT_SMAC_15_0 = 16
    METEDATA_REG_C = 32


class PacketConsts:
    """
    Class to hold constant packets' values.
    """
    ETHER_HEADER_SIZE = 14
    IPV4_HEADER_SIZE = 20
    IPV6_HEADER_SIZE = 40
    UDP_HEADER_SIZE = 8
    TCP_HEADER_SIZE = 20
    ICMP_HEADER_SIZE = 8
    ICMPV6_HEADER_SIZE = 8
    VLAN_HEADER_SIZE = 4
    TCP_HEADER_SIZE_WORDS = 5
    IP_V4 = 4
    IP_V6 = 6
    TCP_PROTO = 'tcp'
    UDP_PROTO = 'udp'
    ICMP_PROTO = 'icmp'
    ICMPV6_PROTO = 'icmpv6'
    IP_V4_FLAGS = 2  # Don't fragment is set
    TTL_HOP_LIMIT = 64
    IHL = 5
    TOS = 0x33
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
    ICMP_TYPE = 13
    ICMP_CODE = 0
    ICMP_CKSUM = 0
    ICMP_IDENT = 100
    ICMP_SEQ = 1
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
    # Modify Action consts
    OUT_SMAC_47_16_FIELD_ID = 0x1
    OUT_SMAC_47_16_FIELD_LENGTH = 32
    OUT_SMAC_15_0_FIELD_ID = 0x2
    OUT_SMAC_15_0_FIELD_LENGTH = 16
    # GRE consts
    GRE_FLAGS = 0x3
    GRE_KEY = 0x12345678
    GRE_SEQUENCE_NUMBER = 32

def gen_outer_headers(msg_size, tunnel=TunnelType.GTP_U, **kwargs):
    """
    Generates outer headers for encapsulation with tunnel: Ethernet, IPv4, UDP
    and the desired tunneling using the relevant values from the PacketConst class.
    :param msg_size: The size of the inner message (payload size)
    :param tunnel: The type of tunneling
    :param kwargs: Arguments:
            * *gtp_psc_qfi*
                QFI (QoS flow identifier) field to use in the GTP PSC header.
            * *ttl*
                Time to live value to use in the packet.
            * *vxlan_vni*
                VXLAN VNI value to use in the packet.
    :return: Outer headers
    """

    # Ethernet Header
    outer = struct.pack('!6s6s',
                        bytes.fromhex(PacketConsts.DST_MAC.replace(':', '')),
                        bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
    outer += PacketConsts.ETHER_TYPE_IPV4.to_bytes(2, 'big')

    protocol = socket.IPPROTO_UDP

    if tunnel == TunnelType.GTP_U:
        dst_port = PacketConsts.GTP_U_PORT
    elif tunnel == TunnelType.VXLAN:
        dst_port = PacketConsts.VXLAN_PORT
    elif tunnel == TunnelType.GRE:
        protocol = socket.IPPROTO_GRE

    # IPv4 Header
    ttl = kwargs.get('ttl', PacketConsts.TTL_HOP_LIMIT)
    ip_total_len = msg_size - PacketConsts.ETHER_HEADER_SIZE
    outer += struct.pack('!2B3H2BH4s4s', (PacketConsts.IP_V4 << 4) +
                         PacketConsts.IHL, 0, ip_total_len, 0,
                         PacketConsts.IP_V4_FLAGS << 13,
                         ttl, protocol , 0,
                         socket.inet_aton(PacketConsts.SRC_IP),
                         socket.inet_aton(PacketConsts.DST_IP))

    if tunnel != TunnelType.GRE:
        # UDP Header
        udp_len = msg_size - PacketConsts.ETHER_HEADER_SIZE - PacketConsts.IPV4_HEADER_SIZE
        outer += struct.pack('!4H', PacketConsts.SRC_PORT, dst_port, udp_len, 0)

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
    elif tunnel == TunnelType.VXLAN:
        vxlan_flags = kwargs.get('vxlan_flags', PacketConsts.VXLAN_FLAGS)
        vxlan_vni = kwargs.get('vxlan_vni', PacketConsts.VXLAN_VNI)
        outer += struct.pack('!II', vxlan_flags << 24, vxlan_vni << 8)
    elif tunnel == TunnelType.GRE:
        gre_proto = kwargs.get('gre_proto', PacketConsts.ETHER_TYPE_IPV4)
        gre_key = kwargs.get('gre_key', PacketConsts.GRE_KEY)
        gre_seq = kwargs.get('gre_seq', PacketConsts.GRE_SEQUENCE_NUMBER)
        outer += struct.pack('!HHII', PacketConsts.GRE_FLAGS << 12, gre_proto, gre_key, gre_seq)

    return outer


def get_l2_header(src_mac=None, num_vlans=0, l3=PacketConsts.IP_V4,
                  vlan_id=PacketConsts.VLAN_ID):
    """
    Build l2 header.
    :param src_mac: Source MAC address to use in the packet.
    :param num_vlan: Number of VLAN headers in the packet
    :param l3: Packet layer 3 type: 4 for IPv4 or 6 for IPv6
    :param vlan_id: vlan id to use in the packet.
    :return: l2 header
    """
    src_mac = src_mac if src_mac else bytes.fromhex(PacketConsts.SRC_MAC.replace(':', ''))
    packet = struct.pack('!6s6s',
                         bytes.fromhex(PacketConsts.DST_MAC.replace(':', '')), src_mac)
    for _ in range(num_vlans):
        packet += struct.pack('!HH', PacketConsts.VLAN_TPID, (PacketConsts.VLAN_PRIO << 13) +
                              (PacketConsts.VLAN_CFI << 12) + vlan_id)
    if l3 == PacketConsts.IP_V4:
        packet += PacketConsts.ETHER_TYPE_IPV4.to_bytes(2, 'big')
    else:
        packet += PacketConsts.ETHER_TYPE_IPV6.to_bytes(2, 'big')
    return packet


def gen_packet(msg_size, l2=True, l3=PacketConsts.IP_V4, l4=PacketConsts.UDP_PROTO,
               num_vlans=0, tunnel=None, **kwargs):
    """
    Generates a Eth | IPv4 or IPv6 | UDP or TCP packet with hardcoded values in
    the headers and randomized payload.
    :param msg_size: total packet size
    :param l2: If True, Build packet with l2 Ethernet header
    :param l3: Packet layer 3 type: 4 for IPv4 or 6 for IPv6
    :param l4: Packet layer 4 type: 'tcp', 'udp', 'icmp' or 'icmpv6'
    :param num_vlans: Number of VLAN headers in the packet
    :param tunnel: If set, the type of tunneling to use.
    :param kwargs: Arguments:
            * *src_mac*
                Source MAC address to use in the packet.
            * *src_ip*
                Source IPv4/IPv6 address to use in the packet.
            * *dst_ip*
                Destination IPv4/IPv6 address to use in the packet.
            * *ttl*
                Time to live value to use in the packet.
            * *tos*
                Type of service value to use in the packet.
            * *src_port*
                Source L4 port to use in the packet.
            * *gtp_psc_qfi*
                QFI (QoS flow identifier) field to use in the GTP PSC header.
            * *vni*
                VXLAN VNI value to use in the packet.
            * *vlan_id*
                VLAN id value to use in the packet.
            * *icmp_type*
                ICMP type value to be used in packet.
    :return: Bytes of the generated packet
    """
    if tunnel:
        outer = gen_outer_headers(msg_size, tunnel, **kwargs)
        return outer + gen_packet(msg_size - len(outer), l2, l3, l4, num_vlans, **kwargs)

    l2_header_size = PacketConsts.ETHER_HEADER_SIZE if l2 else 0
    l3_header_size = getattr(PacketConsts, f'IPV{str(l3)}_HEADER_SIZE')
    l4_header_size = getattr(PacketConsts, f'{l4.upper()}_HEADER_SIZE')
    payload_size = max(0, msg_size - l3_header_size - l4_header_size -
                       l2_header_size)
    next_hdr = getattr(socket, f'IPPROTO_{l4.upper()}')
    ip_total_len = msg_size - l2_header_size

    # Ethernet header
    if l2:
        src_mac = kwargs.get('src_mac', bytes.fromhex(PacketConsts.SRC_MAC.replace(':', '')))
        vlan_id = kwargs.get('vlan_id', PacketConsts.VLAN_ID)
        packet = get_l2_header(src_mac, num_vlans, l3, vlan_id)
        payload_size -= PacketConsts.VLAN_HEADER_SIZE * num_vlans
        ip_total_len -= PacketConsts.VLAN_HEADER_SIZE * num_vlans
    else:
        packet = b''

    ttl = kwargs.get('ttl', PacketConsts.TTL_HOP_LIMIT)
    tos = kwargs.get('tos', 0)
    if l3 == PacketConsts.IP_V4:
        # IPv4 header
        src_ip = kwargs.get('src_ip', PacketConsts.SRC_IP)
        dst_ip = kwargs.get('dst_ip', PacketConsts.DST_IP)
        packet += struct.pack('!2B3H2BH4s4s', (PacketConsts.IP_V4 << 4) +
                              PacketConsts.IHL, tos, ip_total_len, 0,
                              PacketConsts.IP_V4_FLAGS << 13,
                              ttl, next_hdr, 0,
                              socket.inet_aton(src_ip),
                              socket.inet_aton(dst_ip))
    else:
        # IPv6 header
        src_ip = kwargs.get('src_ip', PacketConsts.SRC_IP6)
        dst_ip = kwargs.get('dst_ip', PacketConsts.DST_IP6)
        packet += struct.pack('!IH2B16s16s', (PacketConsts.IP_V6 << 28),
                              ip_total_len, next_hdr, ttl,
                              socket.inet_pton(socket.AF_INET6, src_ip),
                              socket.inet_pton(socket.AF_INET6, dst_ip))

    src_port = kwargs.get('src_port', PacketConsts.SRC_PORT)
    dst_port = kwargs.get('dst_port', PacketConsts.DST_PORT)
    icmp_type = kwargs.get('icmp_type', PacketConsts.ICMP_TYPE)
    if l4 == PacketConsts.ICMP_PROTO or l4 == PacketConsts.ICMPV6_PROTO:
        # ICMP header
        packet += struct.pack('!2B3H', icmp_type, PacketConsts.ICMP_CODE, PacketConsts.ICMP_CKSUM,
                              PacketConsts.ICMP_IDENT, PacketConsts.ICMP_SEQ)
    elif l4 == PacketConsts.UDP_PROTO:
        # UDP header
        packet += struct.pack('!4H', src_port, dst_port,
                              payload_size + PacketConsts.UDP_HEADER_SIZE, 0)
    else:
        # TCP header
        packet += struct.pack('!2H2I4H', src_port, dst_port, 0, 0,
                              PacketConsts.TCP_HEADER_SIZE_WORDS << 12,
                              PacketConsts.WINDOW_SIZE, 0, 0)
    # Payload
    return packet + str.encode('a' * payload_size)


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
    start_poll_t = time.perf_counter()
    while count > 0 and (time.perf_counter() - start_poll_t) < POLLING_TIMEOUT :
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


def send_packets(agr_obj, packets, tag_value=None, iters=1):
    for _ in range(iters):
        for packet in packets:
            send_sg = SGE(agr_obj.mr.buf, len(packet), agr_obj.mr.lkey)
            agr_obj.mr.write(packet, len(packet))
            send_wr = SendWR(num_sge=1, sg=[send_sg])
            agr_obj.qp.post_send(send_wr)
            poll_cq(agr_obj.cq, tag_value=tag_value)


def high_rate_send(agr_obj, packet, rate_limit):
    """
    Sends packet at high rate for 3 seconds.
    :param rate_limit: Minimal rate limit in MBps
    """
    send_sg = SGE(agr_obj.mr.buf, len(packet), agr_obj.mr.lkey)
    agr_obj.mr.write(packet, len(packet))
    send_wr = SendWR(num_sge=1, sg=[send_sg])
    iterations = 0
    timeout = 3
    start_send_t = time.perf_counter()
    while (time.perf_counter() - start_send_t) < timeout:
        agr_obj.qp.post_send(send_wr)
        poll_cq(agr_obj.cq)
        iterations += 1
    # Calculate the rate
    rate = agr_obj.msg_size * iterations / timeout / 1000000
    assert(rate > rate_limit)


def validate_raw(msg_received, msg_expected, skip_idxs=None):
    size = len(msg_expected)
    skip_idxs  = [] if skip_idxs is None else skip_idxs
    for i in range(size):
        if (msg_received[i] != msg_expected[i]) and i not in skip_idxs:
            exp = ''.join('{:02x} '.format(x) for x in msg_expected)
            recv = ''.join('{:02x} '.format(x) for x in msg_received)
            err_msg = f'Data validation failure:\nexpected {exp}\n\nreceived {recv}'
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
    assert(len(packets) <= MAX_DIFF_PACKETS)
    skip_idxs  = [] if skip_idxs is None else skip_idxs
    expected_packet = packets[0] if expected_packet is None else expected_packet
    for _ in range(num_msgs):
        post_recv(server.wq, server.mr, server.msg_size, len(packets))
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


def create_devx_counter(dv_ctx, bulk=0):
    devx_counter = Mlx5DevxObj(dv_ctx, AllocFlowCounterIn(flow_counter_bulk=bulk),
                               len(AllocFlowCounterOut()))
    counter_id = AllocFlowCounterOut(devx_counter.out_view).flow_counter_id
    return devx_counter, counter_id


def query_counter(devx_counter, flow_counter_id, counter_offset=0):
    num_counters = BULK_COUNTER_SIZE if counter_offset != 0 else 0
    query_in = QueryFlowCounterIn(num_of_counters=num_counters,
                                  flow_counter_id=flow_counter_id)
    tc_len = len(TrafficCounter())
    outlen = len(QueryFlowCounterOut()) + ((num_counters - 1) * tc_len \
        if num_counters > 1 else 0)
    counter_out = QueryFlowCounterOut(devx_counter.query(query_in, outlen))
    # Get the start index of the needed TC in the output mailbox
    start_idx = len(QueryFlowCounterOut()) + tc_len * (counter_offset - 1)
    stats = TrafficCounter(bytes(counter_out)[start_idx:start_idx + tc_len])
    return stats.packets, stats.octets


def create_eth_ipv4_l4_rte_items(next_proto=socket.IPPROTO_UDP):
    rte_flow_items = []
    # Eth
    mask = RteFlowItemEth(eth_type=0xffff)
    val = RteFlowItemEth(eth_type=PacketConsts.ETHER_TYPE_IPV4)
    rte_flow_items.append(RteFlowItem(p.RTE_FLOW_ITEM_TYPE_ETH, val, mask))
    # IPs
    mask = RteFlowItemIpv4(src_addr=bytes(4 * [0xff]), dst_addr=bytes(4 * [0xff]),
                           next_proto=0xff)
    val = RteFlowItemIpv4(src_addr=PacketConsts.SRC_IP, dst_addr=PacketConsts.DST_IP,
                          next_proto=next_proto)
    rte_flow_items.append(RteFlowItem(p.RTE_FLOW_ITEM_TYPE_IPV4, val, mask))
    # UDP/TCP
    if next_proto == socket.IPPROTO_UDP:
        mask = RteFlowItemUdp(src_port=0xffff, dst_port=0xffff)
        val = RteFlowItemUdp(src_port=PacketConsts.SRC_PORT, dst_port=PacketConsts.DST_PORT)
        rte_flow_items.append(RteFlowItem(p.RTE_FLOW_ITEM_TYPE_UDP, val, mask))
    else:
        mask = RteFlowItemTcp(src_port=0xffff, dst_port=0xffff)
        val = RteFlowItemTcp(src_port=PacketConsts.SRC_PORT, dst_port=PacketConsts.DST_PORT)
        rte_flow_items.append(RteFlowItem(p.RTE_FLOW_ITEM_TYPE_TCP, val, mask))
    rte_flow_items.append(RteFlowItemEnd())
    return rte_flow_items


def create_eth_ipv4_rte_items(dmac=None, ttl=None):
    rte_flow_items = []
    # Eth
    mask = RteFlowItemEth(eth_type=0xffff, dst=bytes(6 * [0xff]) if dmac is not None
                          else bytes())
    val = RteFlowItemEth(eth_type=PacketConsts.ETHER_TYPE_IPV4,
                         dst=dmac if dmac is not None else bytes())
    rte_flow_items.append(RteFlowItem(p.RTE_FLOW_ITEM_TYPE_ETH, val, mask))
    # IPs
    mask = RteFlowItemIpv4(ttl=0xff if ttl is not None else 0)
    val = RteFlowItemIpv4(ttl=ttl if ttl is not None else 0)
    rte_flow_items.append(RteFlowItem(p.RTE_FLOW_ITEM_TYPE_IPV4, val, mask))
    rte_flow_items.append(RteFlowItemEnd())
    return rte_flow_items


def create_eth_rte_item(dst=None, src=None, eth_type=None, has_vlan=None):
    mask = RteFlowItemEth(dst=bytes() if dst is None else bytes(6 * [0xff]),
                          src=bytes() if src is None else bytes(6 * [0xff]),
                          eth_type=0 if eth_type is None else 0xffff,
                          has_vlan=0 if has_vlan is None else 0xffffffff)
    val = RteFlowItemEth(dst=bytes() if dst is None else dst,
                         src=bytes() if src is None else src,
                         eth_type=0 if eth_type is None else eth_type,
                         has_vlan=0 if has_vlan is None else has_vlan)
    return RteFlowItem(p.RTE_FLOW_ITEM_TYPE_ETH, val, mask)

def create_ipv4_rte_item(**kwargs):
    dst_addr = kwargs.get('dst_addr', None)
    src_addr = kwargs.get('src_addr', None)
    next_proto = kwargs.get('next_proto', None)

    mask = RteFlowItemIpv4(src_addr=0 if src_addr is None else bytes(4 * [0xff]),
                           dst_addr=0 if dst_addr is None else bytes(4 * [0xff]),
                           next_proto=0 if next_proto is None else 0xff)
    val = RteFlowItemIpv4(src_addr=0 if src_addr is None else src_addr,
                          dst_addr=0 if dst_addr is None else dst_addr,
                          next_proto=0 if next_proto is None else next_proto)
    return RteFlowItem(p.RTE_FLOW_ITEM_TYPE_IPV4, val, mask)


def create_ipv6_rte_item(**kwargs):
    dst_addr = kwargs.get('dst_addr', None)
    src_addr = kwargs.get('src_addr', None)
    proto = kwargs.get('proto', None)
    hop_limits = kwargs.get('hop_limits', None)

    mask = RteFlowItemIpv6(src_addr='::' if src_addr is None else ("ffff:" * 8)[:-1],
                           dst_addr='::' if dst_addr is None else ("ffff:" * 8)[:-1],
                           proto=0 if proto is None else 0xff,
                           hop_limits=0 if hop_limits is None else 0xff)
    val = RteFlowItemIpv6(src_addr='::' if src_addr is None else src_addr,
                          dst_addr='::' if dst_addr is None else dst_addr,
                          proto=0 if proto is None else proto,
                          hop_limits=0 if hop_limits is None else hop_limits)
    return RteFlowItem(p.RTE_FLOW_ITEM_TYPE_IPV6, val, mask)


def create_tcp_rte_item(**kwargs):
    dst_port = kwargs.get('dst_port', None)
    src_port = kwargs.get('src_port', None)

    mask = RteFlowItemTcp(src_port=0 if src_port is None else 0xffff,
                          dst_port=0 if dst_port is None else 0xffff)
    val = RteFlowItemTcp(src_port=0 if src_port is None else src_port,
                         dst_port=0 if dst_port is None else dst_port)
    return RteFlowItem(p.RTE_FLOW_ITEM_TYPE_TCP, val, mask)

def create_udp_rte_item(src_port=None, dst_port=None, length=None, cksum=None):
    mask = RteFlowItemUdp(src_port=0 if src_port is None else 0xffff,
                          dst_port=0 if dst_port is None else 0xffff,
                          length=0 if length is None else 0xffff,
                          cksum=0 if cksum is None else 0xffff)
    val = RteFlowItemUdp(src_port=0 if src_port is None else src_port,
                         dst_port=0 if dst_port is None else dst_port,
                         length=0 if length is None else length,
                         cksum=0 if cksum is None else cksum)
    return RteFlowItem(p.RTE_FLOW_ITEM_TYPE_UDP, val, mask)

def create_gtp_rte_item(flags=None, msg_type=None, msg_len=None, teid=None):
    mask = RteFlowItemGtp(flags=0 if flags is None else 0xff,
                          msg_type=0 if msg_type is None else 0xff,
                          msg_len=0 if msg_len is None else 0xffff,
                          teid=0 if teid is None else 0xffffffff)
    val = RteFlowItemGtp(flags=0 if flags is None else flags,
                         msg_type=0 if msg_type is None else msg_type,
                         msg_len=0 if msg_len is None else msg_len,
                         teid=0 if teid is None else teid)
    return RteFlowItem(p.RTE_FLOW_ITEM_TYPE_GTP, val, mask)

def create_gtp_psc_rte_item(pdu_type=None, qfi=None):
    mask = RteFlowItemGtpPsc(pdu_type=0 if pdu_type is None else 0xff,
                             qfi=0 if qfi is None else 0xff)
    val = RteFlowItemGtpPsc(pdu_type=0 if pdu_type is None else pdu_type,
                            qfi=0 if qfi is None else qfi)
    return RteFlowItem(p.RTE_FLOW_ITEM_TYPE_GTP_PSC, val, mask)


def create_tunneled_gtp_flags_rte_items(with_psc=False):
    """
    Created RTE items to match on eth / ipv4 / udp / gpt flags or
                                  eth / ipv4 / udp / gpt flags / gtp psc pdu type
    """
    eth = create_eth_rte_item(eth_type=PacketConsts.ETHER_TYPE_IPV4,
                              dst=bytes([int(i, 16) for i in PacketConsts.DST_MAC.split(':')]))
    ipv4 = create_ipv4_rte_item(dst_addr=PacketConsts.DST_IP,
                                next_proto=socket.IPPROTO_UDP)
    udp = create_udp_rte_item()
    # GTP
    gtp_psc_ex = 1 if with_psc else 0
    gtp_flags = (PacketConsts.GTPU_VERSION << 5) + (PacketConsts.PROTO_TYPE << 4) + \
                (gtp_psc_ex << 2) + (gtp_psc_ex << 1)
    gtp = create_gtp_rte_item(flags=gtp_flags)
    rte_flow_items = [eth, ipv4, udp, gtp]
    if with_psc:
        rte_flow_items.append(create_gtp_psc_rte_item(pdu_type=PacketConsts.GTP_PSC_PDU_TYPE))
    rte_flow_items.append(RteFlowItemEnd())
    return rte_flow_items


def create_tunneled_gtp_teid_rte_items(with_qfi=False, inner_l4=socket.IPPROTO_UDP):
    """
    Created RTE items to match on eth / ipv4 / udp / gpt teid / ipv4 / inner l4 or
                                  eth / ipv4 / udp / gpt teid / gtp psc qfi / ipv4 / inner l4
    """
    eth = create_eth_rte_item()
    ipv4 = create_ipv4_rte_item(src_addr=PacketConsts.SRC_IP)
    udp = create_udp_rte_item()
    gtp = create_gtp_rte_item(teid=PacketConsts.GTPU_TEID)
    rte_flow_items = [eth, ipv4, udp, gtp]
    if with_qfi:
        rte_flow_items.append(create_gtp_psc_rte_item(qfi=PacketConsts.GTP_PSC_QFI))
    # Inner IPs
    rte_flow_items.append(create_ipv4_rte_item(src_addr=PacketConsts.SRC_IP,
                                               dst_addr=PacketConsts.DST_IP))
    # Inner UDP/TCP
    if inner_l4 == socket.IPPROTO_UDP:
        rte_flow_items.append(create_udp_rte_item(src_port=PacketConsts.SRC_PORT,
                                                  dst_port=PacketConsts.DST_PORT))
    else:
        rte_flow_items.append(create_tcp_rte_item(src_port=PacketConsts.SRC_PORT,
                                                  dst_port=PacketConsts.DST_PORT))
    rte_flow_items.append(RteFlowItemEnd())
    return rte_flow_items


def is_cx6dx(dev_attrs):
    return dev_attrs.vendor_id == MELLANOX_VENDOR_ID and \
        dev_attrs.vendor_part_id == VendorPartID.CX6DX


def create_counter_action(test, agr_obj, flags=me.MLX5DR_ACTION_FLAG_HWS_RX,
                          bulk=0, offset=0):
    devx_counter, counter_id = create_devx_counter(agr_obj.dv_ctx, bulk=bulk)
    test.devx_objects.append(devx_counter)
    dr_counter = Mlx5drDevxObj(devx_counter, counter_id)
    _, counter_ra = agr_obj.create_rule_action('counter', flags=flags,
                                               dr_counter=dr_counter)
    counter_ra.counter_offset = offset
    return devx_counter, counter_id, counter_ra


def verify_counter(test, agr_obj, devx_counter, counter_id, offset=0):
    packets, octets = query_counter(devx_counter, counter_id, offset)
    test.assertEqual(packets, agr_obj.num_msgs, 'Counter packets number is wrong.')
    test.assertEqual(octets, agr_obj.num_msgs * agr_obj.msg_size,
                     'Counter octets number is wrong.')


def get_qos_caps(dv_ctx):
    """
    Queries HCA caps.
    :param dv_ctx: DevX context
    :return: QoS caps
    """
    # From the PRM: op_mod's LSB indicates whether we want to query the
    # maximum or the current capabilities (0 for max). While bits[15:1]
    # indicates the capability type.
    query_cap_in = QueryHcaCapIn(op_mod=HcaCapOpMod.QOS_CAPS << 1 | 0x0)
    cmd_res = dv_ctx.devx_general_cmd(query_cap_in, len(QueryQosCapOut()))
    query_cap_out = QueryQosCapOut(cmd_res)
    if query_cap_out.status:
        raise PyverbsError(f'QUERY_HCA_CAP has failed with status ({query_cap_out.status}) and'
                           f'syndrome ({query_cap_out.syndrome})')
    return query_cap_out


def create_devx_general_object(devx_c, obj_type, obj_context, log_obj_range=0):
    """
    Create a general object
    :param devx_c: Devx context
    :param obj_type: Object type
    :param obj_context: Object context
    :param log_obj_range: Log (base 2) of the range of objects referenced by the
                          command
    :return: General devx object and its object ID
    """
    general_obj_hdr = GeneralObjInCmdHdr(
        opcode=de.MLX5_CMD_OP_CREATE_GENERAL_OBJECT, obj_type=obj_type,
        log_obj_range=log_obj_range)
    general_obj_in = CreateGeneralObjIn(
        general_obj_in_cmd_hdr=general_obj_hdr, obj_context=obj_context)
    general_obj = Mlx5DevxObj(devx_c, general_obj_in, len(CreateGeneralObjOut()))
    general_obj_out = CreateGeneralObjOut(general_obj.out_view)
    status = general_obj_out.general_obj_out_cmd_hdr.status
    if status :
        raise PyverbsError(f'Failed to create general devx object with status {status} '
                           f'and syndrome {general_obj_out.general_obj_out_cmd_hdr.syndrome}.')
    return general_obj, general_obj_out.general_obj_out_cmd_hdr.obj_id


def create_reg_c_rte_items(reg_c_val, reg_c_idx):
    mask = RteFlowItemTag(0xffffffff, reg_c_idx)
    val = RteFlowItemTag(reg_c_val, reg_c_idx)
    return [RteFlowItem(me.MLX5_RTE_FLOW_ITEM_TYPE_TAG, val, mask), RteFlowItemEnd()]


def create_counter_action(test, agr_obj, flags=me.MLX5DR_ACTION_FLAG_HWS_RX, bulk=0, offset=0):
    """
    Creates devx counter object, counter action and counter rule action.
    :param test: Test instance
    :param agr_obj :Aggregation object
    :param flags: Action flags
    :param bulk: Counter bulk size
    :param offset: Counter offset
    :return: Devx counter object, counter ID and counter rule action
    """
    devx_counter, counter_id = create_devx_counter(agr_obj.dv_ctx, bulk=bulk)
    test.devx_objects.append(devx_counter)
    dr_counter = Mlx5drDevxObj(devx_counter, counter_id)
    _, counter_ra = agr_obj.create_rule_action('counter', flags=flags, dr_counter=dr_counter)
    counter_ra.counter_offset = offset
    return devx_counter, counter_id, counter_ra


def init_resources_and_add_rules(test, agr_obj, root_rte, rte_items_list, actions_types,
                                 actions_list, table_type=me.MLX5DR_TABLE_TYPE_NIC_RX):
    """
    Inits steering resources and creates the rules on agr_obj with the provided
    lists of rte items and actions.
    The first set of items of rte_items_list are passed to the init_steering_resources()
    function of the agr_obj.
    """
    agr_obj.init_steering_resources(rte_items_list[0], table_type= table_type,
                                    root_rte_items=root_rte,
                                    action_types_list=actions_types)
    for i in range(len(rte_items_list)):
        test.hws_rules.append(Mlx5drRule(agr_obj.matcher, mt_idx=0, rte_items=rte_items_list[i],
                                         at_idx=i, rule_actions=actions_list[i],
                                         num_of_actions=len(actions_list[i]),
                                         rule_attr_create=Mlx5drRuleAttr(user_data=bytes(8)),
                                         dr_ctx=agr_obj.dr_ctx))
