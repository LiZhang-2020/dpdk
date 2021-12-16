# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from pydiru.providers.mlx5.steering.mlx5dr_action import Mlx5drRuleAction, Mlx5drActionModify
from pydiru.providers.mlx5.steering.mlx5dr_rule import Mlx5drRuleAttr, Mlx5drRule
from pydiru.providers.mlx5.steering.mlx5dr_matcher import Mlx5drMacherTemplate
from pydiru.providers.mlx5.steering.mlx5dr_devx_objects import Mlx5drDevxObj
import pydiru.providers.mlx5.steering.mlx5dr_enums as me

from .utils import raw_traffic, gen_packet, PacketConsts, create_sipv4_rte_items, TunnelType, gen_outer_headers, \
                    get_l2_header, create_dipv4_rte_items, create_devx_counter, query_counter
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
        self.devx_objects.append(self.server.tir_obj)
        self.devx_objects.append(self.client.tir_obj)

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
                                   rule_attr_create=Mlx5drRuleAttr(user_data=bytes(8)),
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
                                      rule_attr_create=Mlx5drRuleAttr(user_data=bytes(8)),
                                      dr_ctx=self.server.dr_ctx)
        exp_src_mac = struct.pack('!6s', bytes.fromhex(str_smac.replace(':', '')))
        exp_packet = gen_packet(self.server.msg_size, src_mac=exp_src_mac)
        packet = gen_packet(self.server.msg_size)
        raw_traffic(self.client, self.server, self.server.num_msgs, [packet], exp_packet)

    @staticmethod
    def create_miss_rule(agr_obj, rte_items, rule_actions):
        return Mlx5drRule(matcher=agr_obj.matcher, mt_idx=0, rte_items=rte_items,
                          rule_actions=rule_actions, num_of_actions=len(rule_actions),
                          rule_attr_create=Mlx5drRuleAttr(user_data=bytes(8)), dr_ctx=agr_obj.dr_ctx)

    def create_counter_action(self, agr_obj, flags=me.MLX5DR_ACTION_FLAG_HWS_RX,
                              bulk=0, offset=0):
        devx_counter, counter_id = create_devx_counter(agr_obj.dv_ctx, bulk=bulk)
        self.devx_objects.append(devx_counter)
        dr_counter = Mlx5drDevxObj(devx_counter, counter_id)
        _, counter_ra = agr_obj.create_rule_action('counter', flags=flags,
                                                   dr_counter=dr_counter)
        counter_ra.counter_offset = offset
        return devx_counter, counter_id, counter_ra

    def verify_counter(self, agr_obj, devx_counter, counter_id, offset=0):
        packets, octets = query_counter(devx_counter, counter_id, offset)
        self.assertEqual(packets, agr_obj.num_msgs, 'Counter packets number is wrong.')
        self.assertEqual(octets, agr_obj.num_msgs * agr_obj.msg_size,
                         'Counter octets number is wrong.')

    def test_mlx5dr_default_miss(self):
        """
        Create default miss action on RX and on TX, recv and verify packets using TIR action.
        Create 3 rules:
        priority - 1 with counter and miss action. (match sip - SRC_IP) on TX.
        priority - 1 with miss action. (match sip - SRC_IP + 1) on RX.
        priority - 9 with TIR action. (match dip) on RX.
        Root matcher on RX matches on dip and forwards packets to SW steering table.
        Send two packets (SRC_IP, SRC_IP+1).
        Expected only the first + validate data of SRC_IP.
        Validate counter.
        """
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
        devx_counter, counter_id, counter_tx_ra = \
            self.create_counter_action(self.client, flags=me.MLX5DR_ACTION_FLAG_HWS_TX)
        self.miss_tx_rule = self.create_miss_rule(self.client, rte_items=sip_rte,
                                                  rule_actions=[counter_tx_ra, miss_tx_ra])
        # RX
        self.server.init_steering_resources(rte_items=sip_rte, root_rte_items=dip_rte)
        _, miss_rx_ra = self.server.create_rule_action('def_miss')
        self.miss_rx_rule = self.create_miss_rule(self.server, rte_items=sip_miss_rte,
                                                  rule_actions=[miss_rx_ra])
        # Second RX matcher
        mt_2 = Mlx5drMacherTemplate(dip_rte)
        self.server.dip_matcher = self.server.create_matcher(self.server.table, [mt_2],
                                                             mode=me.MLX5DR_MATCHER_RESOURCE_MODE_RULE,
                                                             prio=9, log_row=2)
        _, tir_ra = self.server.create_rule_action('tir')
        self.tir_rule = Mlx5drRule(matcher=self.server.dip_matcher, mt_idx=0,
                                   rte_items=dip_rte, rule_actions=[tir_ra],
                                   num_of_actions=1, rule_attr_create=Mlx5drRuleAttr(user_data=bytes(8)),
                                   dr_ctx=self.server.dr_ctx)
        # Traffic
        packet1 = gen_packet(self.server.msg_size)
        packet2 = gen_packet(self.server.msg_size, src_ip=sip_miss)
        raw_traffic(self.client, self.server, self.server.num_msgs, [packet1, packet2],
                    expected_packet=packet1)
        # Verify counter
        self.verify_counter(self.client, devx_counter, counter_id)

    def decap_rule_traffic(self, decap_type=me.MLX5DR_ACTION_REFORMAT_TYPE_TNL_L2_TO_L2):
        """
        Execute traffic with RX table rules and decap L2/L3 action.
        In case of L2 to L2 decap, a VXLAN tunneled packet is usesd.
        In case of L3 to L2 decap, a GTP_U packet is used instead, otherwise, a
        change of a FLEX parser is needed to decap VXLAN.
        """
        tir_rte_items = create_sipv4_rte_items(PacketConsts.SRC_IP)
        self.server.init_steering_resources(rte_items=tir_rte_items)
        _, tir_ra = self.server.create_rule_action('tir')
        if decap_type == me.MLX5DR_ACTION_REFORMAT_TYPE_TNL_L3_TO_L2:
            outer = gen_outer_headers(self.server.msg_size, tunnel=TunnelType.GTP_U)
            l2_hdr = get_l2_header()
            inner_len = self.server.msg_size - len(outer) - len(l2_hdr)
            inner = gen_packet(inner_len, l2=False)
            decap_a, decap_ra = self.server.create_rule_action('reformat', ref_type=decap_type,
                                                               data=l2_hdr, data_sz=len(l2_hdr),
                                                               bulk_size=12)
            exp_packet = l2_hdr + inner
        else:
            outer = gen_outer_headers(self.server.msg_size, tunnel=TunnelType.VXLAN)
            inner_len = self.server.msg_size - len(outer)
            inner = gen_packet(inner_len)
            decap_a, decap_ra = self.server.create_rule_action('reformat')
            exp_packet = inner
        packet = outer + inner
        self.tir_rule = Mlx5drRule(self.server.matcher, 0, tir_rte_items, [decap_ra, tir_ra], 2,
                                   Mlx5drRuleAttr(user_data=bytes(8)), self.server.dr_ctx)
        raw_traffic(self.client, self.server, self.server.num_msgs, [packet], exp_packet)

    def encap_rule_traffic(self, encap_type=me.MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L2):
        """
        Execute traffic with TX table rules and encap l2/l3 action
        """
        tir_rte_items = create_sipv4_rte_items(PacketConsts.SRC_IP)
        self.server.init_steering_resources(rte_items=tir_rte_items)
        self.client.init_steering_resources(rte_items=tir_rte_items,
                                            table_type=me.MLX5DR_TABLE_TYPE_NIC_TX)
        encap_data = gen_outer_headers(self.server.msg_size, tunnel=TunnelType.VXLAN)
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

    def test_mlx5dr_decap_l2(self):
        """
        Execute traffic with RX table rules and decap l2 action of a VXLAN
        tunneled packet.
        """
        self.decap_rule_traffic()

    def test_mlx5dr_decap_l3(self):
        """
        Execute traffic with RX table rules and decap l3 action of a GTP_U
        tunneled packet.
        """
        self.decap_rule_traffic(me.MLX5DR_ACTION_REFORMAT_TYPE_TNL_L3_TO_L2)

    def test_mlx5dr_drop(self):
        """
        Create Drop actions on RX and TX and TIR action, recv packets using TIR WQ.
        Create 3 rules:
        With drop action. (match ip - 2.2.2.2) on TX.
        With drop action. (match ip - 3.3.3.3) on RX.
        With TIR action. (match ip - 1.1.1.1) on RX.
        Send three packets (1.1.1.1, 2.2.2.2, 3.3.3.3).
        Expected only the third + validate data of 1.1.1.1.
        """
        sip_rte_items = create_sipv4_rte_items(PacketConsts.SRC_IP)
        tx_items = create_sipv4_rte_items('2.2.2.2')
        rx_items = create_sipv4_rte_items('3.3.3.3')

        dip_rte_items = create_dipv4_rte_items(PacketConsts.DST_IP)
        self.server.init_steering_resources(rte_items=sip_rte_items, root_rte_items=dip_rte_items)
        self.client.init_steering_resources(rte_items=sip_rte_items, root_rte_items=dip_rte_items,
                                            table_type=me.MLX5DR_TABLE_TYPE_NIC_TX)
        _, rx_ra = self.server.create_rule_action('drop')
        _, tx_ra = self.client.create_rule_action('drop', me.MLX5DR_ACTION_FLAG_HWS_TX)
        _, tir_ra = self.server.create_rule_action('tir')

        template_relaxed_match = me.MLX5DR_MATCH_TEMPLATE_FLAG_RELAXED_MATCH
        matcher_templates = [Mlx5drMacherTemplate(dip_rte_items, flags=template_relaxed_match)]
        tir_matcher = self.server.create_matcher(self.server.table, matcher_templates,
                                                 mode=me.MLX5DR_MATCHER_RESOURCE_MODE_HTABLE,
                                                 prio=2)
        self.tir_rule = Mlx5drRule(tir_matcher, 0, dip_rte_items, [tir_ra], 1,
                                   Mlx5drRuleAttr(user_data=bytes(8)), self.server.dr_ctx)
        self.rx_rule = Mlx5drRule(self.server.matcher, 0, rx_items, [rx_ra], 1,
                                  Mlx5drRuleAttr(user_data=bytes(8)), self.server.dr_ctx)
        self.tx_rule = Mlx5drRule(self.client.matcher, 0, tx_items, [tx_ra], 1,
                                  Mlx5drRuleAttr(user_data=bytes(8)), self.client.dr_ctx)
        packets = []
        for i in [3, 2, 1]:
            src_ip = '.'.join(str(i) * 4)
            packets.append(gen_packet(self.server.msg_size, src_ip=src_ip))
        raw_traffic(self.client, self.server, self.server.num_msgs, packets, packets[2])
