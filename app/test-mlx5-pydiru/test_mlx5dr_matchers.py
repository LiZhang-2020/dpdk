# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

import struct
import socket

from pydiru.rte_flow import RteFlowItem, RteFlowItemEth, RteFlowItemIpv4, RteFlowItemTcp, RteFlowItemUdp, \
    RteFlowItemEnd, RteFlowItemGtp, RteFlowItemGtpPsc, RteFlowItemIpv6, RteFlowItemVxlan
from pydiru.providers.mlx5.steering.mlx5dr_rule import Mlx5drRuleAttr, Mlx5drRule
import pydiru.pydiru_enums as p

from .utils import raw_traffic, gen_packet, PacketConsts, TunnelType
from .base import BaseDrResources, PydiruTrafficTestCase


UN_EXPECTED_GTPU_TEID = 0xdeadbee0
UN_EXPECTED_GTP_PSC_QFI = 2
UN_EXPECTED_SRC_IP = '1.1.1.3'
UN_EXPECTED_IPV6 = "c0c1::c2c3:c4c5:c6c7:c8c9"
UN_EXPECTED_SRC_PORT = 1235
UN_EXPECTED_VXLAN_VNI = 8888888



class Mlx5drMatcherTest(PydiruTrafficTestCase):

    def setUp(self):
        super().setUp()
        self.server = BaseDrResources(self.dev_name, self.ib_port)
        self.client = BaseDrResources(self.dev_name, self.ib_port)
        self.devx_objects.append(self.server.tir_obj)
        self.devx_objects.append(self.client.tir_obj)
        self.traffic_args = {'client': self.client, 'server': self.server,
                             'num_msgs': self.server.num_msgs}

    @staticmethod
    def create_ipv4_rte_item():
        mask = RteFlowItemIpv4(src_addr=bytes(4 * [0xff]), dst_addr=bytes(4 * [0xff]))
        val = RteFlowItemIpv4(src_addr=PacketConsts.SRC_IP, dst_addr=PacketConsts.DST_IP)
        return RteFlowItem(p.RTE_FLOW_ITEM_TYPE_IPV4, val, mask)

    @staticmethod
    def create_ipv6_rte_item(msg_size, src=None, dst=None):
        mask = RteFlowItemIpv6(src_addr='::' if src is None else ("ffff:" * 8)[:-1],
                               dst_addr='::' if dst is None else ("ffff:" * 8)[:-1],
                               vtc_flow = 0xffffffff,
                               payload_len = 0xffff,
                               proto = 0xff,
                               hop_limits = 0xff)
        vtc_flow = PacketConsts.IP_V6 << 28
        val = RteFlowItemIpv6(src_addr='::' if src is None else src,
                              dst_addr='::' if dst is None else dst,
                              vtc_flow = vtc_flow,
                              payload_len = msg_size - PacketConsts.ETHER_HEADER_SIZE,
                              proto = socket.IPPROTO_UDP,
                              hop_limits = PacketConsts.TTL_HOP_LIMIT)
        return RteFlowItem(p.RTE_FLOW_ITEM_TYPE_IPV6, val, mask)

    @staticmethod
    def create_tcp_rte_item():
        mask = RteFlowItemTcp(src_port=0xffff, dst_port=0xffff)
        val = RteFlowItemTcp(src_port=PacketConsts.SRC_PORT,
                             dst_port=PacketConsts.DST_PORT)
        return RteFlowItem(p.RTE_FLOW_ITEM_TYPE_TCP, val, mask)

    @staticmethod
    def create_udp_rte_item():
        mask = RteFlowItemUdp(src_port=0xffff, dst_port=0xffff)
        val = RteFlowItemUdp(src_port=PacketConsts.SRC_PORT,
                             dst_port=PacketConsts.DST_PORT)
        return RteFlowItem(p.RTE_FLOW_ITEM_TYPE_UDP, val, mask)

    @staticmethod
    def create_gtp_rte_item():
        mask = RteFlowItemGtp(teid=0xffffffff)
        val = RteFlowItemGtp(teid=PacketConsts.GTPU_TEID)
        return RteFlowItem(p.RTE_FLOW_ITEM_TYPE_GTP, val, mask)

    @staticmethod
    def create_psc_rte_item():
        mask = RteFlowItemGtpPsc(qfi=0x3f)
        val = RteFlowItemGtpPsc(qfi=PacketConsts.GTP_PSC_QFI)
        return RteFlowItem(p.RTE_FLOW_ITEM_TYPE_GTP_PSC, val, mask)

    @staticmethod
    def create_vxlan_rte_item():
        mask = RteFlowItemVxlan(flags=0xff, vni=0xffffff)
        val = RteFlowItemVxlan(flags=PacketConsts.VXLAN_FLAGS, vni=PacketConsts.VXLAN_VNI)
        return RteFlowItem(p.RTE_FLOW_ITEM_TYPE_VXLAN, val, mask)

    def create_rx_rules(self, rte_item, root_rte_items=None):
        rte_items = [rte_item, RteFlowItemEnd()]
        if not root_rte_items:
            root_rte_items = [self.create_ipv4_rte_item(), RteFlowItemEnd()]
        self.server.init_steering_resources(rte_items=rte_items,
                                            root_rte_items=root_rte_items)
        _, tir_ra = self.server.create_rule_action('tir')
        self.tir_rule = Mlx5drRule(self.server.matcher, 0, rte_items, [tir_ra], 1,
                                   Mlx5drRuleAttr(user_data=bytes(8)), self.server.dr_ctx)

    def test_mlx5dr_matcher_ipv4(self):
        """
        Match on IPv4 header attributes.
        """
        self.create_rx_rules(self.create_ipv4_rte_item())
        exp_packet = gen_packet(self.server.msg_size)
        un_exp_packet = gen_packet(self.server.msg_size, src_ip=UN_EXPECTED_SRC_IP)
        packets = [exp_packet, un_exp_packet]
        raw_traffic(**self.traffic_args, packets=packets, expected_packet=exp_packet)

    def create_ipv6_matcher_and_rule(self, ipv6_match_items, un_exp_packet):
        """
        Creates empty matcher on root table to forward the rule to non root
        table and there create the rule for provided ipv6_match_items with
        action TIR and verifies IPv6 traffic.
        """
        root_items = []
        empty = RteFlowItemEth()
        root_items.append(RteFlowItem(p.RTE_FLOW_ITEM_TYPE_ETH, empty, empty))
        root_items.append(RteFlowItemEnd())
        self.create_rx_rules(ipv6_match_items, root_items)
        exp_packet = gen_packet(self.server.msg_size, l3=PacketConsts.IP_V6)

        packets = [exp_packet, un_exp_packet]
        raw_traffic(**self.traffic_args, packets=packets, expected_packet=exp_packet)

    def test_mlx5dr_matcher_ipv6_src(self):
        """
        Match on src IPv6.
        """
        un_exp_packet = gen_packet(self.server.msg_size, l3=PacketConsts.IP_V6,
                                   src_ip=UN_EXPECTED_IPV6)
        rte_items = self.create_ipv6_rte_item(self.server.msg_size, src=PacketConsts.SRC_IP6)
        self.create_ipv6_matcher_and_rule(rte_items, un_exp_packet)

    def test_mlx5dr_matcher_ipv6_dst(self):
        """
        Match on dst IPv6.
        """
        un_exp_packet = gen_packet(self.server.msg_size, l3=PacketConsts.IP_V6,
                                   dst_ip=UN_EXPECTED_IPV6)
        rte_items = self.create_ipv6_rte_item(self.server.msg_size, dst=PacketConsts.DST_IP6)
        self.create_ipv6_matcher_and_rule(rte_items, un_exp_packet)

    def test_mlx5dr_matcher_tcp(self):
        """
        Match on TCP header attributes.
        """
        self.create_rx_rules(self.create_tcp_rte_item())
        exp_packet = gen_packet(self.server.msg_size, l4=PacketConsts.TCP_PROTO)
        un_exp_packet = gen_packet(self.server.msg_size, l4=PacketConsts.TCP_PROTO,
                                   src_port=UN_EXPECTED_SRC_PORT)
        packets = [exp_packet, un_exp_packet]
        raw_traffic(**self.traffic_args, packets=packets, expected_packet=exp_packet)

    def test_mlx5dr_matcher_udp(self):
        """
        Match on UDP header attributes.
        """
        self.create_rx_rules(self.create_udp_rte_item())
        exp_packet = gen_packet(self.server.msg_size, l4=PacketConsts.UDP_PROTO)
        un_exp_packet = gen_packet(self.server.msg_size, l4=PacketConsts.UDP_PROTO,
                                   src_port=UN_EXPECTED_SRC_PORT)
        packets = [exp_packet, un_exp_packet]
        raw_traffic(**self.traffic_args, packets=packets, expected_packet=exp_packet)

    def test_mlx5dr_matcher_gtp_psc(self):
        """
        Match on GTP PSC header QFI attribute.
        """
        self.create_rx_rules(self.create_psc_rte_item())
        exp_packet = gen_packet(self.server.msg_size, tunnel=TunnelType.GTP_U,
                                gtp_psc_qfi=PacketConsts.GTP_PSC_QFI)
        un_exp_packet = gen_packet(self.server.msg_size, tunnel=TunnelType.GTP_U,
                                   gtp_psc_qfi=UN_EXPECTED_GTP_PSC_QFI)
        packets = [exp_packet, un_exp_packet]
        raw_traffic(**self.traffic_args, packets=packets, expected_packet=exp_packet, skip_idxs=[44, 45])

    def test_mlx5dr_matcher_gtpu(self):
        """
        Match on GTPU header TEID attribute.
        """
        self.create_rx_rules(self.create_gtp_rte_item())
        exp_packet = gen_packet(self.server.msg_size, tunnel=TunnelType.GTP_U)
        un_exp_packet = gen_packet(self.server.msg_size, tunnel=TunnelType.GTP_U,
                                   gtpu_teid=UN_EXPECTED_GTPU_TEID)
        packets = [exp_packet, un_exp_packet]
        raw_traffic(**self.traffic_args, packets=packets, expected_packet=exp_packet, skip_idxs=[44, 45])

    def test_mlx5dr_matcher_vxlan(self):
        """
        Match on vxlan flags and vni on non-root table and verify using action TIR.
        """
        self.create_rx_rules(self.create_vxlan_rte_item())
        exp_packet = gen_packet(self.server.msg_size, tunnel=TunnelType.VXLAN)
        un_exp_packet = gen_packet(self.server.msg_size, tunnel=TunnelType.VXLAN,
                                   vxlan_vni=UN_EXPECTED_VXLAN_VNI)
        packets = [exp_packet, un_exp_packet]
        raw_traffic(**self.traffic_args, packets=packets, expected_packet=exp_packet)
