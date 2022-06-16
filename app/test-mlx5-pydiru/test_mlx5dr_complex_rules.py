# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022, Nvidia Inc. All rights reserved.

from pydiru.providers.mlx5.steering.mlx5dr_rule import Mlx5drRuleAttr, Mlx5drRule
from pydiru.providers.mlx5.steering.mlx5dr_matcher import Mlx5drMacherTemplate
from pydiru.providers.mlx5.steering.mlx5dr_action import Mlx5drActionTemplate
from pydiru.rte_flow import RteFlowItem, RteFlowItemEth, RteFlowItemEnd
import pydiru.providers.mlx5.steering.mlx5dr_enums as me
from .base import BaseDrResources, PydiruTrafficTestCase
import pydiru.pydiru_enums as p
from . import utils as u
import socket


TAG_VALUE_1 = 0x1234
TAG_VALUE_2 = 0x5678


class Mlx5drComplexTrafficTest(PydiruTrafficTestCase):

    def setUp(self):
        super().setUp()
        self.hws_rules = []
        self.server = BaseDrResources(self.dev_name, self.ib_port)
        self.client = BaseDrResources(self.dev_name, self.ib_port)
        self.devx_objects.append(self.server.tir_obj)
        self.devx_objects.append(self.client.tir_obj)

    @staticmethod
    def root_ttl_drops(agr_obj):
        """
        Creates two rules on root table to drop packets with TTL 1 or 0.
        """
        eth_ipv4_ttl0 = u.create_eth_ipv4_rte_items(ttl=0)
        eth_ipv4_ttl1 = u.create_eth_ipv4_rte_items(ttl=1)
        agr_obj.root_matcher_template_0 = [Mlx5drMacherTemplate(eth_ipv4_ttl0)]
        drop_temp = [Mlx5drActionTemplate([me.MLX5DR_ACTION_TYP_DROP, me.MLX5DR_ACTION_TYP_LAST])]
        agr_obj.root_matcher_0 = agr_obj.create_matcher(agr_obj.root_table,
                                                        agr_obj.root_matcher_template_0,
                                                        drop_temp, prio=0)
        _, drop_ra = agr_obj.create_rule_action('drop', flags=me.MLX5DR_ACTION_FLAG_ROOT_RX)
        agr_obj.drop0 = Mlx5drRule(agr_obj.root_matcher_0, 0, eth_ipv4_ttl0, 0, [drop_ra], 1,
                                   Mlx5drRuleAttr(user_data=bytes(8)), agr_obj.dr_ctx)
        agr_obj.drop1 = Mlx5drRule(agr_obj.root_matcher_0, 0, eth_ipv4_ttl1, 0, [drop_ra], 1,
                                   Mlx5drRuleAttr(user_data=bytes(8)), agr_obj.dr_ctx)

    @staticmethod
    def create_templates_and_matcher(agr_obj, rte_items, flags=0, table=None, actions=None):
        """
        Creates matcher templates for each rte_item and a matcher from those
        templates.
        """
        action_templates = []
        if actions is None:
            actions = [[me.MLX5DR_ACTION_TYP_TIR, me.MLX5DR_ACTION_TYP_LAST] * len(rte_items)]
        matcher_templates = []
        for i in range(len(rte_items)):
            action_templates.append(Mlx5drActionTemplate(actions[i]))
            matcher_templates.append(Mlx5drMacherTemplate(rte_items[i], flags))
        return agr_obj.create_matcher(table if table else agr_obj.table, matcher_templates,
                                      action_templates, prio=0)

    @staticmethod
    def create_rules(agr_obj, matcher, rte_items, actions):
        """
        Creates rules on a provided matcher iterating on the templates index,
        rte_items and actions.
        """
        assert(len(rte_items) == len(actions))
        rules = []
        for i in range(0, len(actions)):
            rules.append(Mlx5drRule(matcher, i, rte_items[i], i, actions[i], len(actions[i]),
                         Mlx5drRuleAttr(user_data=bytes(8)), agr_obj.dr_ctx))
        return rules

    def test_mlx5dr_action_def33_tag_tir(self):
        """
        Create root RX matcher(p0) eth/ipv4 ttl = 0 or 1 with action drop.
        Create root RX matcher(p1) dmac/ipv4 with action goto non root table.
        Create non root RX matchers matching on {eth / IPv4 src dst / UDP src dst}
        or {eth / IPv4 src dst / TCP src dst} (definer 33) with actions TAG + TIR.
        Send and verify TCP and UDP packets.
        Packets with TTL 0 and 1 should be dropped.
        """
        udp_rte_items = u.create_eth_ipv4_l4_rte_items(next_proto=socket.IPPROTO_UDP)
        tcp_rte_items = u.create_eth_ipv4_l4_rte_items(next_proto=socket.IPPROTO_TCP)
        dmac = bytes([int(i, 16) for i in u.PacketConsts.DST_MAC.split(':')])
        dmac_ipv4_rte_items = u.create_eth_ipv4_rte_items(dmac=dmac)

        # Root
        actions = [me.MLX5DR_ACTION_TYP_TAG, me.MLX5DR_ACTION_TYP_TIR, me.MLX5DR_ACTION_TYP_LAST]
        self.server.init_steering_resources(rte_items=dmac_ipv4_rte_items)
        self.root_ttl_drops(self.server)
        # Non root
        matcher = self.create_templates_and_matcher(self.server, [udp_rte_items, tcp_rte_items],
                                                    actions=[actions, actions])
        _, tag_ra1 = self.server.create_rule_action('tag')
        tag_ra1.tag_value = TAG_VALUE_1
        _, tir_ra = self.server.create_rule_action('tir')
        _, tag_ra2 = self.server.create_rule_action('tag')
        tag_ra2.tag_value = TAG_VALUE_2
        self.rules = self.create_rules(self.server, matcher, [udp_rte_items, tcp_rte_items],
                                       [[tag_ra1, tir_ra], [tag_ra2, tir_ra]])
        # Traffic
        packet_udp = u.gen_packet(self.server.msg_size)
        packet_tcp = u.gen_packet(self.server.msg_size, l4=u.PacketConsts.TCP_PROTO)
        packet_ttl_0 = u.gen_packet(self.server.msg_size, ttl=0)
        packet_ttl_1 = u.gen_packet(self.server.msg_size, l4=u.PacketConsts.TCP_PROTO, ttl=1)
        u.raw_traffic(self.client, self.server, self.server.num_msgs, [packet_udp, packet_ttl_0],
                      tag_value=TAG_VALUE_1)
        u.raw_traffic(self.client, self.server, self.server.num_msgs, [packet_tcp, packet_ttl_1],
                      tag_value=TAG_VALUE_2)

    @staticmethod
    def create_actions_decap_tag_tir(agr_obj, tag_value):
        _, tag_ra = agr_obj.create_rule_action('tag')
        tag_ra.tag_value = tag_value
        _, tir_ra = agr_obj.create_rule_action('tir')
        inner_l2 = u.get_l2_header()
        _, decap_ra = agr_obj.create_rule_action('reformat',
                                                 ref_type=me.MLX5DR_ACTION_REFORMAT_TYPE_TNL_L3_TO_L2,
                                                 data=inner_l2, data_sz=len(inner_l2), log_bulk_size=12)
        return [tag_ra, decap_ra, tir_ra]

    def def_34_test_traffic(self, outer, un_exp_outer, tag_val):
        l2_hdr = u.get_l2_header()
        inner_len = self.server.msg_size - len(outer) - len(l2_hdr)
        inner = u.gen_packet(inner_len, l2=False)
        exp_packet = l2_hdr + inner
        send_packet = outer + inner
        un_exp_packet = un_exp_outer + inner
        packets = [send_packet, un_exp_packet]
        u.raw_traffic(self.client, self.server, self.server.num_msgs, packets=packets,
                      expected_packet=exp_packet, tag_value=tag_val)

    def test_mlx5dr_action_def34_decap_tag_tir(self):
        """
        Create root RX matcher(p0) eth/ipv4 ttl = 0 or 1 with action drop.
        Create root RX matcher(p1) dmac/ipv4/UDP/GTP flags/GTP PSC pdu with action
        goto non root table 1.
        Create root RX matcher(p2) dmac/ipv4/UDP/GTP flags/ with action goto non
        root table 2.
        On non root table 1:
        Create non root RX matcher(p0) matching on eth, IPv4 src, UDP, GTP teid,
        GTP PSC qfi, inner IPv4 src and dest, TCP|UDP src and dst (definer 34)
        with actions DECAP L3 + TAG + TIR.
        On non root table 2:
        Create non root RX matcher(p0) matching on eth, IPv4 src, UDP, GTP teid,
        inner IPv4 src and dest, TCP|UDP src and dst (definer 34) with actions
        DECAP L3 + TAG + TIR.
        Send and verify packets.
        """
        # Root
        root_gtp_psc_rte_items = u.create_tunneled_gtp_flags_rte_items(with_psc=True)
        root_gtp_rte_items = u.create_tunneled_gtp_flags_rte_items(with_psc=False)
        self.server.root_matcher_templates = []
        self.server.tables = []
        self.server.root_rules = []
        self.server.root_table = self.server.create_table(0)
        self.root_ttl_drops(self.server)
        _, table, rule = self.server.create_root_fwd_rule(root_gtp_psc_rte_items)
        self.server.root_rules.append(rule)
        self.server.tables.append(table)
        _, table, rule = self.server.create_root_fwd_rule(root_gtp_rte_items, level=2,
                                                          table_type=me.MLX5DR_TABLE_TYPE_NIC_RX,
                                                          prio=2)
        self.server.root_rules.append(rule)
        self.server.tables.append(table)
        # Non root
        gtp_teid_qfi_tcp_rte_items = u.create_tunneled_gtp_teid_rte_items(with_qfi=True,
                                                                          inner_l4=socket.IPPROTO_TCP)
        gtp_teid_qfi_udp_rte_items = u.create_tunneled_gtp_teid_rte_items(with_qfi=True,
                                                                          inner_l4=socket.IPPROTO_UDP)
        gtp_teid_tcp_rte_items = u.create_tunneled_gtp_teid_rte_items(with_qfi=False,
                                                                      inner_l4=socket.IPPROTO_TCP)
        gtp_teid_udp_rte_items = u.create_tunneled_gtp_teid_rte_items(with_qfi=False,
                                                                      inner_l4=socket.IPPROTO_UDP)
        # Matchers
        actions = [me.MLX5DR_ACTION_TYP_TAG, me.MLX5DR_ACTION_TYP_TNL_L3_TO_L2,
                   me.MLX5DR_ACTION_TYP_TIR, me.MLX5DR_ACTION_TYP_LAST]
        relaxed_flag = me.MLX5DR_MATCH_TEMPLATE_FLAG_RELAXED_MATCH
        matcher1= self.create_templates_and_matcher(self.server, [gtp_teid_qfi_tcp_rte_items,
                                                    gtp_teid_qfi_udp_rte_items], relaxed_flag,
                                                    self.server.tables[0], [actions, actions])
        matcher2= self.create_templates_and_matcher(self.server, [gtp_teid_tcp_rte_items,
                                                    gtp_teid_udp_rte_items], relaxed_flag,
                                                    self.server.tables[1], [actions, actions])
        # Actions
        self.server.rule_actions = self.create_actions_decap_tag_tir(self.server, TAG_VALUE_1)
        # Rules
        self.server.rules = []
        self.server.rules.append(self.create_rules(self.server, matcher1,
                                                   [gtp_teid_qfi_tcp_rte_items, gtp_teid_qfi_udp_rte_items],
                                                   [self.server.rule_actions] * 2))
        self.server.rule_actions[0].tag_value = TAG_VALUE_2
        self.server.rules.append(self.create_rules(self.server, matcher2,
                                                   [gtp_teid_tcp_rte_items, gtp_teid_udp_rte_items],
                                                   [self.server.rule_actions] * 2))
        # Traffic
        outer = u.gen_outer_headers(self.server.msg_size, tunnel=u.TunnelType.GTP_U,
                                    gtp_psc_qfi=u.PacketConsts.GTP_PSC_QFI)
        un_exp_outer = u.gen_outer_headers(self.server.msg_size,  tunnel=u.TunnelType.GTP_U,
                                           gtp_psc_qfi=u.PacketConsts.GTP_PSC_QFI, ttl=0)
        self.def_34_test_traffic(outer, un_exp_outer, TAG_VALUE_1)

        outer = u.gen_outer_headers(self.server.msg_size, tunnel=u.TunnelType.GTP_U)
        un_exp_outer = u.gen_outer_headers(self.server.msg_size, tunnel=u.TunnelType.GTP_U, ttl=1)
        self.def_34_test_traffic(outer, un_exp_outer, TAG_VALUE_2)

    def test_mlx5dr_action_def33_encap_tx(self):
        """
        Create root TX matcher eth with action go to non root table.
        On non root table create TX matcher eth / IPv4 src, dst /UDP src, dst
        with action encap GTP + PSC
        On non root table create TX matcher eth / IPv4 src, dst /TCP src, dst
        with action encap GTP + PSC
        Send traffic and verify.
        """
        rte_items = [RteFlowItem(p.RTE_FLOW_ITEM_TYPE_ETH, RteFlowItemEth(), RteFlowItemEth()),
                     RteFlowItemEnd()]
        udp_rte_items = u.create_eth_ipv4_l4_rte_items(next_proto=socket.IPPROTO_UDP)
        tcp_rte_items = u.create_eth_ipv4_l4_rte_items(next_proto=socket.IPPROTO_TCP)
        tx_actions = [me.MLX5DR_ACTION_TYP_L2_TO_TNL_L3, me.MLX5DR_ACTION_TYP_LAST]
        self.server.init_steering_resources(rte_items=rte_items)
        self.client.init_steering_resources(rte_items=rte_items,
                                            table_type=me.MLX5DR_TABLE_TYPE_NIC_TX,
                                            action_types_list=[tx_actions])
        # Override matcher_templates and matcher on TX
        self.client.matcher_templates =  [Mlx5drMacherTemplate(udp_rte_items),
                                          Mlx5drMacherTemplate(tcp_rte_items)]
        tx_at = [Mlx5drActionTemplate(tx_actions)]
        self.client.matcher = self.client.create_matcher(self.client.table,
                                                         self.client.matcher_templates,
                                                         tx_at, prio=0)
        encap_data = u.gen_outer_headers(self.server.msg_size, tunnel=u.TunnelType.GTP_U,
                                         gtp_psc_qfi=u.PacketConsts.GTP_PSC_QFI)
        _, tir_ra = self.server.create_rule_action('tir')
        _, encap_ra = self.client.create_rule_action('reformat', me.MLX5DR_ACTION_FLAG_HWS_TX,
                                                     ref_type=me.MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L3,
                                                     data=encap_data,
                                                     data_sz=len(encap_data), log_bulk_size=12)
        self.tx_rule_udp = Mlx5drRule(self.client.matcher, 0, udp_rte_items, 0, [encap_ra], 1,
                                      Mlx5drRuleAttr(user_data=bytes(8)), self.client.dr_ctx)
        self.tx_rule_tcp = Mlx5drRule(self.client.matcher, 1, tcp_rte_items, 0, [encap_ra], 1,
                                      Mlx5drRuleAttr(user_data=bytes(8)), self.client.dr_ctx)
        self.rx_rule = Mlx5drRule(self.server.matcher, 0, rte_items, 0, [tir_ra], 1,
                                  Mlx5drRuleAttr(user_data=bytes(8)), self.server.dr_ctx)
        # Build packets
        send_packet = u.gen_packet(self.server.msg_size - len(encap_data))
        l3_packet_len = self.server.msg_size - len(encap_data) - u.PacketConsts.ETHER_HEADER_SIZE
        expected_packet = encap_data + u.gen_packet(l3_packet_len, l2=False)
        # Skip indexes which are offloaded by HW (UDP {source port and len},
        # ipv4 {id, checksum and total len}, gtp-u {length})
        u.raw_traffic(self.client, self.server, self.server.num_msgs, [send_packet], expected_packet,
                      skip_idxs=[16, 17, 18, 19, 24, 25, 34, 35, 38, 39, 44, 45])
