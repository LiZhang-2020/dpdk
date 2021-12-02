# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from pydiru.providers.mlx5.steering.mlx5dr_action import Mlx5drRuleAction, Mlx5drActionModify
from pydiru.providers.mlx5.steering.mlx5dr_rule import Mlx5drRuleAttr, Mlx5drRule
from pydiru.providers.mlx5.steering.mlx5dr_matcher import Mlx5drMacherTemplate
import pydiru.providers.mlx5.steering.mlx5dr_enums as me

from .utils import raw_traffic, gen_packet, PacketConsts, create_sipv4_rte_items, \
    create_dipv4_rte_items, TunnelType, gen_outer_headers
from .base import BaseDrResources, PydiruTrafficTestCase

from .prm_structs import SetActionIn
import struct
import socket


OUT_SMAC_47_16_FIELD_ID = 0x1
OUT_SMAC_47_16_FIELD_LENGTH = 32
OUT_SMAC_15_0_FIELD_ID = 0x2
OUT_SMAC_15_0_FIELD_LENGTH = 16
SET_ACTION = 0x1


class Mlx5drTrafficTest(PydiruTrafficTestCase):

    def setUp(self):
        super().setUp()
        self.server = BaseDrResources(self.dev_name, self.ib_port)
        self.client = BaseDrResources(self.dev_name, self.ib_port)

    def test_mlx5dr_tir(self):
        """
        Create TIR and recv packets using TIR action.
        """
        tir_rte_items = create_sipv4_rte_items(PacketConsts.SRC_IP)
        self.server.init_steering_resources(rte_items=tir_rte_items)
        tir_a, tir_ra = self.server.create_rule_action('tir')
        self.tir_rule = Mlx5drRule(self.server.matcher, 0, tir_rte_items, [tir_ra], 1,
                              Mlx5drRuleAttr(user_data=bytes(8)), self.server.dr_ctx)
        packet = gen_packet(self.server.msg_size)
        raw_traffic(self.client, self.server, self.server.num_msgs, [packet])

    def test_mlx5dr_tag(self):
        """
        Use Tag action on the recv packets and verify that the packets is tagged.
        """
        rte_items = create_sipv4_rte_items(PacketConsts.SRC_IP)
        self.server.init_steering_resources(rte_items)
        _, tag_ra = self.server.create_rule_action('tag')
        tag_ra.tag_value = 0x1234
        _, tir_ra = self.server.create_rule_action('tir')
        self.tir_rule = Mlx5drRule(self.server.matcher, mt_idx=0, rte_items=rte_items,
                                   rule_actions=[tag_ra, tir_ra], num_of_actions=2,
                                   rule_attr=Mlx5drRuleAttr(user_data=bytes(8)),
                                   dr_ctx=self.server.dr_ctx)
        packet = gen_packet(self.server.msg_size)
        raw_traffic(self.client, self.server, self.server.num_msgs, [packet],
                    tag_value=0x1234)

    def test_mlx5dr_modify(self):
        """
        Create modify action on RX with two set actions to change the src mac, send
        packet and verify using TIR action.
        """
        rte_items = create_sipv4_rte_items(PacketConsts.SRC_IP)
        self.server.init_steering_resources(rte_items=rte_items)
        smac_47_16 = 0x88888888
        smac_15_0 = 0x8888
        str_smac = "88:88:88:88:88:88"
        self.action1 = SetActionIn(action_type=SET_ACTION, field=OUT_SMAC_47_16_FIELD_ID,
                                   length=OUT_SMAC_47_16_FIELD_LENGTH, data=smac_47_16)
        self.action2 = SetActionIn(action_type=SET_ACTION, field=OUT_SMAC_15_0_FIELD_ID,
                                   length=OUT_SMAC_15_0_FIELD_LENGTH, data=smac_15_0)
        self.modify_action = Mlx5drActionModify(self.server.dr_ctx, pattern_sz=2 * 8,
                                                actions=[self.action1, self.action2],
                                                log_bulk_size=12,
                                                flags=me.MLX5DR_ACTION_FLAG_HWS_RX)
        self.modify_ra = Mlx5drRuleAction(self.modify_action)
        self.modify_ra.modify_data =  [self.action1, self.action2]
        self.modify_ra.modify_offset = 0
        _, tir_ra = self.server.create_rule_action('tir')
        self.modify_rule = Mlx5drRule(matcher=self.server.matcher, mt_idx=0, rte_items=rte_items,
                                      rule_actions=[self.modify_ra, tir_ra], num_of_actions=2,
                                      rule_attr=Mlx5drRuleAttr(user_data=bytes(8)),
                                      dr_ctx=self.server.dr_ctx)
        exp_src_mac = struct.pack('!6s', bytes.fromhex(str_smac.replace(':', '')))
        exp_packet = gen_packet(self.server.msg_size, src_mac=exp_src_mac)
        packet = gen_packet(self.server.msg_size)
        raw_traffic(self.client, self.server, self.server.num_msgs, [packet], exp_packet)

    @staticmethod
    def create_miss_rule(agr_obj, rte_items, rule_actions):
        return Mlx5drRule(matcher=agr_obj.matcher, mt_idx=0, rte_items=rte_items,
                          rule_actions=rule_actions, num_of_actions=len(rule_actions),
                          rule_attr=Mlx5drRuleAttr(user_data=bytes(8)), dr_ctx=agr_obj.dr_ctx)

    def test_mlx5dr_default_miss(self):
        """
        Create default miss action on RX and on TX, recv and verify packets using TIR action.
        Create 3 rules:
        priority - 1 with miss action. (match sip - SRC_IP) on TX.
        priority - 1 with miss action. (match sip - SRC_IP + 1) on RX.
        priority - 9 with TIR action. (match dip) on RX.
        Root matcher on RX matches on dip and forwards packets to SW steering table.
        Send two packets (SRC_IP, SRC_IP+1).
        Expected only the first + validate data of SRC_IP.
        """
        # TODO: Add counter to verify default miss action on TX actually works
        sip_int = struct.unpack("!I", socket.inet_aton(PacketConsts.SRC_IP))[0]
        sip_miss = socket.inet_ntoa(struct.pack("!I", sip_int + 1))
        sip_miss_rte = create_sipv4_rte_items(sip_miss)
        dip_rte = create_dipv4_rte_items()
        sip_rte = create_sipv4_rte_items()
        # TX
        self.client.init_steering_resources(rte_items=sip_rte,
                                            table_type=me.MLX5DR_TABLE_TYPE_NIC_TX)
        _, miss_tx_ra = self.client.create_rule_action('def_miss',
                                                       flags=me.MLX5DR_ACTION_FLAG_HWS_TX)
        self.miss_tx_rule = self.create_miss_rule(self.client, rte_items=sip_rte,
                                                  rule_actions=[miss_tx_ra])
        # RX
        self.server.init_steering_resources(rte_items=sip_rte, root_rte_items=dip_rte)
        _, miss_rx_ra = self.server.create_rule_action('def_miss')
        self.miss_rx_rule = self.create_miss_rule(self.server, rte_items=sip_miss_rte,
                                                  rule_actions=[miss_rx_ra])
        # Second RX matcher
        mt_2 = Mlx5drMacherTemplate(dip_rte)
        self.server.dip_matcher = self.server.create_matcher(self.server.table, [mt_2],
                                                             mode=me.MLX5DR_MATCHER_RESOURCE_MODE_RULE,
                                                             prio=9, row=2)
        _, tir_ra = self.server.create_rule_action('tir')
        self.tir_rule = Mlx5drRule(matcher=self.server.dip_matcher, mt_idx=0,
                                   rte_items=dip_rte, rule_actions=[tir_ra],
                                   num_of_actions=1, rule_attr=Mlx5drRuleAttr(user_data=bytes(8)),
                                   dr_ctx=self.server.dr_ctx)
        # Traffic
        packet1 = gen_packet(self.server.msg_size)
        packet2 = gen_packet(self.server.msg_size, src_ip=sip_miss)
        raw_traffic(self.client, self.server, self.server.num_msgs, [packet1, packet2],
                    expected_packet=packet1)

    def encap_rule_traffic(self, encap_type=me.MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L2):
        """
        Execute traffic with TX table rules and encap l2/l3 action
        """
        tir_rte_items = create_sipv4_rte_items(PacketConsts.SRC_IP)
        self.server.init_steering_resources(rte_items=tir_rte_items)
        self.client.init_steering_resources(rte_items=tir_rte_items,
                                            table_type=me.MLX5DR_TABLE_TYPE_NIC_TX)
        outer_size = PacketConsts.ETHER_HEADER_SIZE + PacketConsts.IPV4_HEADER_SIZE + \
                     PacketConsts.UDP_HEADER_SIZE + PacketConsts.VXLAN_HEADER_SIZE
        encap_data = gen_outer_headers(outer_size, tunnel=TunnelType.VXLAN)
        _, tir_ra = self.server.create_rule_action('tir')
        _, encap_ra = self.client.create_rule_action('reformat', me.MLX5DR_ACTION_FLAG_HWS_TX,
                                                     ref_type=encap_type, data=encap_data,
                                                     data_sz=len(encap_data), log_bulk_size=12)
        self.tx_rule = Mlx5drRule(self.client.matcher, 0, tir_rte_items, [encap_ra], 1,
                                  Mlx5drRuleAttr(user_data=bytes(8)), self.client.dr_ctx)
        self.rx_rule = Mlx5drRule(self.server.matcher, 0, tir_rte_items, [tir_ra], 1,
                                  Mlx5drRuleAttr(user_data=bytes(8)), self.server.dr_ctx)
        # Build packets
        send_packet = gen_packet(self.server.msg_size - len(encap_data))
        l3_packet_len = self.server.msg_size - len(encap_data) - PacketConsts.ETHER_HEADER_SIZE
        l3_packet = gen_packet(l3_packet_len, l2=False)
        exp_inner = l3_packet if encap_type == me.MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L3 \
                        else send_packet
        expected_packet = encap_data + exp_inner
        # Skip indexes which are offloaded by HW(UDP source port and len, ipv4 id, checksum and
        # total len)
        raw_traffic(self.client, self.server, self.server.num_msgs, [send_packet], expected_packet,
                    skip_idxs=[16, 17, 18, 19, 24, 25, 34, 35, 38, 39, 53, 75])

    def test_mlx5dr_encap_l2(self):
        """
        Execute traffic with TX table rules and encap l2 action
        """
        self.encap_rule_traffic()

    def test_mlx5dr_encap_l3(self):
        """
        Execute traffic with TX table rules and encap l3 action
        """
        self.encap_rule_traffic(me.MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L3)
