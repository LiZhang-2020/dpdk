# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

import struct
import socket

from pydiru.rte_flow import RteFlowItem, RteFlowItemEth, RteFlowItemIpv4, RteFlowItemTcp, \
    RteFlowItemUdp, RteFlowItemEnd, RteFlowItemGtp, RteFlowItemGtpPsc, RteFlowItemIpv6, \
    RteFlowItemVxlan, RteFlowItemVlan, RteFlowItemIcmp, RteFlowItemIcmp6, RteFlowItemGreOption
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
UN_EXPECTED_VLAN_ID = 1212
UN_EXPECTED_TOS = 0x44
UN_EXPECTED_ICMP_TYPE = 14
UN_EXPECTED_GRE_KEY = 22
UN_EXPECTED_GRE_SEQUENCE_NUMBER = 25


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
    def create_ipv4_rte_item(tos=None):
        tos_mask = 0 if tos is None else 0xff
        tos_val = 0 if tos is None else tos
        mask = RteFlowItemIpv4(tos=tos_mask, src_addr=bytes(4 * [0xff]), dst_addr=bytes(4 * [0xff]))
        val = RteFlowItemIpv4(tos=tos_val, src_addr=PacketConsts.SRC_IP, dst_addr=PacketConsts.DST_IP)
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
    def create_icmp_rte_item(l4=PacketConsts.ICMP_PROTO):
        if l4 == PacketConsts.ICMP_PROTO:
            mask = RteFlowItemIcmp(icmp_type=0xff, code=0xff, cksum=0xffff, ident=0xffff,
                                   seq_nb=0xffff)
            val = RteFlowItemIcmp(icmp_type=PacketConsts.ICMP_TYPE, code=PacketConsts.ICMP_CODE,
                                cksum=PacketConsts.ICMP_CKSUM, ident=PacketConsts.ICMP_IDENT,
                                seq_nb=PacketConsts.ICMP_SEQ)
            item_type = p.RTE_FLOW_ITEM_TYPE_ICMP
        else:
            mask = RteFlowItemIcmp6(icmp_type=0xff, code=0xff, cksum=0xffff)
            val = RteFlowItemIcmp6(icmp_type=PacketConsts.ICMP_TYPE, code=PacketConsts.ICMP_CODE,
                                   cksum=PacketConsts.ICMP_CKSUM)
            item_type = p.RTE_FLOW_ITEM_TYPE_ICMP6
        return RteFlowItem(item_type, val, mask)

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

    @staticmethod
    def create_vlan_rte_item():
        mask = RteFlowItemVlan(tci=0xffff)
        tci = (PacketConsts.VLAN_PRIO << 13) + (PacketConsts.VLAN_CFI << 12) + \
              (PacketConsts.VLAN_ID)
        val = RteFlowItemVlan(tci=tci)
        return RteFlowItem(p.RTE_FLOW_ITEM_TYPE_VLAN, val, mask)

    @staticmethod
    def create_eth_has_vlan_rte_item(has_vlan=0):
        mask = RteFlowItemEth(has_vlan=0xffffffff)
        val = RteFlowItemEth(has_vlan=has_vlan)
        return RteFlowItem(p.RTE_FLOW_ITEM_TYPE_ETH, val, mask)

    @staticmethod
    def create_rte_gre_opt_item(key=PacketConsts.GRE_KEY, sequence=PacketConsts.GRE_SEQUENCE_NUMBER):
        mask = RteFlowItemGreOption(key=0xffffffff, sequence=0xffffffff)
        val = RteFlowItemGreOption(key=key, sequence=sequence)
        return RteFlowItem(p.RTE_FLOW_ITEM_TYPE_GRE_OPTION, val, mask)

    def create_rx_rules(self, rte_item, root_rte_items=None):
        rte_items = [rte_item, RteFlowItemEnd()]
        if not root_rte_items:
            root_rte_items = [self.create_ipv4_rte_item(), RteFlowItemEnd()]
        self.server.init_steering_resources(rte_items=rte_items,
                                            root_rte_items=root_rte_items)
        _, tir_ra = self.server.create_rule_action('tir')
        self.tir_rule = Mlx5drRule(self.server.matcher, 0, rte_items, 0, [tir_ra], 1,
                                   Mlx5drRuleAttr(user_data=bytes([1])), self.server.dr_ctx)

    def test_mlx5dr_matcher_has_vlan(self):
        """
        Match on has_vlan attribute of RteFlowItemEth with different values.
        """
        # Match on has_vlan = 0
        self.create_rx_rules(self.create_eth_has_vlan_rte_item())
        vlan_packet = gen_packet(self.server.msg_size, with_vlan=True)
        no_vlan_packet = gen_packet(self.server.msg_size)
        packets = [no_vlan_packet, vlan_packet]
        raw_traffic(**self.traffic_args, packets=packets)
        # Match on has_vlan = 1
        rte_has_vlan_1 = [self.create_eth_has_vlan_rte_item(has_vlan=1), RteFlowItemEnd()]
        _, tir_ra = self.server.create_rule_action('tir')
        self.tir_rule = Mlx5drRule(self.server.matcher, 0, rte_has_vlan_1, 0, [tir_ra], 1,
                                   Mlx5drRuleAttr(user_data=bytes(8)), self.server.dr_ctx)
        raw_traffic(**self.traffic_args, packets=packets, expected_packet=vlan_packet)

    def test_mlx5dr_matcher_ipv4(self):
        """
        Match on IPv4 header attributes.
        """
        self.create_rx_rules(self.create_ipv4_rte_item())
        exp_packet = gen_packet(self.server.msg_size)
        un_exp_packet = gen_packet(self.server.msg_size, src_ip=UN_EXPECTED_SRC_IP)
        packets = [exp_packet, un_exp_packet]
        raw_traffic(**self.traffic_args, packets=packets, expected_packet=exp_packet)

    def test_mlx5dr_matcher_ipv4_tos(self):
        """
        Match on IPv4 header with TOS attributes.
        """
        self.create_rx_rules(self.create_ipv4_rte_item(tos=PacketConsts.TOS))
        exp_packet = gen_packet(self.server.msg_size, tos=PacketConsts.TOS)
        un_exp_packet = gen_packet(self.server.msg_size, tos=UN_EXPECTED_TOS)
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

    def test_mlx5dr_matcher_vlan(self):
        """
        Match on vlan attributes.
        """
        self.create_rx_rules(self.create_vlan_rte_item())
        exp_packet = gen_packet(self.server.msg_size, num_vlans=1)
        un_exp_packet = gen_packet(self.server.msg_size, num_vlans=1, vlan_id=UN_EXPECTED_VLAN_ID)
        packets = [exp_packet, un_exp_packet]
        raw_traffic(**self.traffic_args, packets=packets, expected_packet=exp_packet)

    def test_mlx5dr_matcher_icmp(self):
        """
        Match on on ICMP item.
        """
        self.create_rx_rules(self.create_icmp_rte_item())
        exp_packet = gen_packet(self.server.msg_size, l4=PacketConsts.ICMP_PROTO)
        un_exp_packet = gen_packet(self.server.msg_size, l4=PacketConsts.ICMP_PROTO,
                                   icmp_type=UN_EXPECTED_ICMP_TYPE)
        packets = [exp_packet, un_exp_packet]
        raw_traffic(**self.traffic_args, packets=packets, expected_packet=exp_packet)

    def test_mlx5dr_matcher_icmp6(self):
        """
        Match on on ICMP6 item.
        """
        root_items = []
        empty_item = RteFlowItemEth()
        root_items.append(RteFlowItem(p.RTE_FLOW_ITEM_TYPE_ETH, empty_item, empty_item))
        root_items.append(RteFlowItemEnd())
        self.create_rx_rules(self.create_icmp_rte_item(l4=PacketConsts.ICMPV6_PROTO), root_items)
        exp_packet = gen_packet(self.server.msg_size, l3=PacketConsts.IP_V6,
                                l4=PacketConsts.ICMPV6_PROTO)
        un_exp_packet = gen_packet(self.server.msg_size, l3=PacketConsts.IP_V6,
                                   l4=PacketConsts.ICMPV6_PROTO, icmp_type=UN_EXPECTED_ICMP_TYPE)
        packets = [exp_packet, un_exp_packet]
        raw_traffic(**self.traffic_args, packets=packets, expected_packet=exp_packet)

    def test_mlx5dr_matcher_gre_option(self):
        """
        Match on GRE Option key and sequence number.
        """
        self.create_rx_rules(self.create_rte_gre_opt_item())
        exp_packet = gen_packet(self.server.msg_size, l2=False, tunnel=TunnelType.GRE)
        un_exp_packet = gen_packet(self.server.msg_size, l2=False, tunnel=TunnelType.GRE,
                                   gre_key=UN_EXPECTED_GRE_KEY,
                                   gre_seq=UN_EXPECTED_GRE_SEQUENCE_NUMBER)
        packets = [exp_packet, un_exp_packet]
        raw_traffic(**self.traffic_args, packets=packets, expected_packet=exp_packet)
