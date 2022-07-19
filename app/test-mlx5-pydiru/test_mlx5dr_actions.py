# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from pydiru.providers.mlx5.steering.mlx5dr_matcher import Mlx5drMatcherAttr, \
    Mlx5drMatcher
from pydiru.providers.mlx5.steering.mlx5dr_rule import Mlx5drRuleAttr, Mlx5drRule
from pydiru.providers.mlx5.steering.mlx5dr_matcher import Mlx5drMacherTemplate
from pydiru.providers.mlx5.steering.mlx5dr_action import Mlx5drActionTemplate
from .prm_structs import SetActionIn, CopyActionIn, AddActionIn
from .base import BaseDrResources, PydiruTrafficTestCase
import pydiru.providers.mlx5.steering.mlx5dr_enums as me
from pyverbs.pyverbs_error import PyverbsError
from pydiru.pydiru_error import PydiruError
from . import utils as u
import struct
import random
import socket
import time


class Mlx5drTrafficTest(PydiruTrafficTestCase):

    def setUp(self):
        super().setUp()
        self.hws_rules = []
        self.server = BaseDrResources(self.dev_name, self.ib_port)
        self.client = BaseDrResources(self.dev_name, self.ib_port)
        self.devx_objects.append(self.server.tir_obj)
        self.devx_objects.append(self.client.tir_obj)

    def verify_rule_removal(self, rte_item, agr_objs, packet):
        """
        Remove the test rules and create new rules with low priority, same fields
        with matcher and counter actions.
        Those new rules verify that when removing the test rules, the packets
        are not caught by the old test rules.
        :param rte_item: RTE item to match on the low priority rules.
        :param agr_objs: List of aggregate objects to replace the rules by
                         removing the previously created, and add new rules.
        :param packet: Packet that was supposed to match the old rules and now
                       it's expected to hit the new rules.
        """
        for player in agr_objs:
            at = [Mlx5drActionTemplate([me.MLX5DR_ACTION_TYP_CTR, me.MLX5DR_ACTION_TYP_LAST])]
            template_relaxed_match = me.MLX5DR_MATCH_TEMPLATE_FLAG_RELAXED_MATCH
            final_matcher_templates = [Mlx5drMacherTemplate(rte_item, flags=template_relaxed_match)]
            attr = Mlx5drMatcherAttr(priority=99, mode=me.MLX5DR_MATCHER_RESOURCE_MODE_RULE,
                                     rule_log=2)
            player.final_matcher = Mlx5drMatcher(player.table, final_matcher_templates,
                                                 len(final_matcher_templates), attr, at)
            flag = me.MLX5DR_ACTION_FLAG_HWS_TX if player == self.client \
                else me.MLX5DR_ACTION_FLAG_HWS_RX
            player.devx_counter = u.create_counter_action(self, player, flags=flag,
                                                          bulk=u.BULK_512)
            player.final_rule = Mlx5drRule(player.final_matcher, 0, rte_item, 0,
                                           [player.devx_counter[2]], 1,
                                           Mlx5drRuleAttr(user_data=bytes(8)), player.dr_ctx)
        # Remove the test rules and verify that the packet flow skip those rules.
        for rule in self.hws_rules:
            rule.close()
        u.send_packets(self.client, [packet], iters=10)
        for player in agr_objs:
            packets_cnt, _ = u.query_counter(player.devx_counter[0], player.devx_counter[1])
            self.assertEqual(packets_cnt, 10,
                             f'Counter packets value is {packets_cnt} while '
                             'expecting 10 after removing the test rules')

    def test_mlx5dr_tir(self):
        """
        Create TIR and recv packets using TIR action.
        """
        tir_rte_items = u.create_sipv4_rte_items(u.PacketConsts.SRC_IP)
        actions_types = [[me.MLX5DR_ACTION_TYP_TIR, me.MLX5DR_ACTION_TYP_LAST]]
        self.server.init_steering_resources(rte_items=tir_rte_items, action_types_list=actions_types)
        tir_a, tir_ra = self.server.create_rule_action('tir')
        self.hws_rules.append(Mlx5drRule(self.server.matcher, 0, tir_rte_items, 0, [tir_ra], 1,
                              Mlx5drRuleAttr(user_data=bytes(8)), self.server.dr_ctx))
        self.server.dr_ctx.dump('/tmp/hws_dump/test_mlx5dr_tir')
        packet = u.gen_packet(self.server.msg_size)
        u.raw_traffic(self.client, self.server, self.server.num_msgs, [packet])
        self.verify_rule_removal(tir_rte_items, [self.server], packet)

    def test_mlx5dr_tag(self):
        """
        Use Tag action on the recv packets and verify that the packets is tagged.
        """
        rte_items = u.create_sipv4_rte_items(u.PacketConsts.SRC_IP)
        actions_types = [[me.MLX5DR_ACTION_TYP_TAG, me.MLX5DR_ACTION_TYP_TIR, me.MLX5DR_ACTION_TYP_LAST]]
        self.server.init_steering_resources(rte_items, action_types_list=actions_types)
        _, tag_ra = self.server.create_rule_action('tag')
        tag_ra.tag_value = 0x1234
        _, tir_ra = self.server.create_rule_action('tir')
        self.hws_rules.append(Mlx5drRule(self.server.matcher, mt_idx=0, rte_items=rte_items,
                                   at_idx=0, rule_actions=[tag_ra, tir_ra], num_of_actions=2,
                                   rule_attr_create=Mlx5drRuleAttr(user_data=bytes(8)),
                                   dr_ctx=self.server.dr_ctx))
        self.server.dr_ctx.dump('/tmp/hws_dump/test_mlx5dr_tag')
        packet = u.gen_packet(self.server.msg_size)
        u.raw_traffic(self.client, self.server, self.server.num_msgs, [packet],
                      tag_value=0x1234)
        self.verify_rule_removal(rte_items, [self.server], packet)

    def smac_modify_rule_traffic(self, smac_15_0_only=False):
        """
        Create modify action on RX with one/two set actions to change the src mac, send
        packet and verify using TIR action.
        :param smac_15_0_only: If True modify only the last 2 bytes of smac
        """
        rte_items = u.create_sipv4_rte_items(u.PacketConsts.SRC_IP)
        actions_types = [[me.MLX5DR_ACTION_TYP_MODIFY_HDR, me.MLX5DR_ACTION_TYP_TIR,
                    me.MLX5DR_ACTION_TYP_LAST]]
        self.server.init_steering_resources(rte_items=rte_items, action_types_list=actions_types)
        smac_47_16 = 0x88888888
        smac_15_0 = 0x8888
        actions = []
        if not smac_15_0_only:
            actions.append(SetActionIn(field=u.ModifyFieldId.OUT_SMAC_47_16,
                                       length=u.ModifyFieldLen.OUT_SMAC_47_16, data=smac_47_16))
        actions.append(SetActionIn(field=u.ModifyFieldId.OUT_SMAC_15_0,
                                   length=u.ModifyFieldLen.OUT_SMAC_15_0, data=smac_15_0))
        _, self.modify_ra = self.server.create_rule_action('modify', log_bulk_size=12, offset=0,
                                                           actions=actions)
        _, tir_ra = self.server.create_rule_action('tir')
        self.hws_rules.append(Mlx5drRule(matcher=self.server.matcher, mt_idx=0,
                                      rte_items=rte_items, at_idx=0,
                                      rule_actions=[self.modify_ra, tir_ra], num_of_actions=2,
                                      rule_attr_create=Mlx5drRuleAttr(user_data=bytes(8)),
                                      dr_ctx=self.server.dr_ctx))
        str_smac = u.PacketConsts.SRC_MAC[:12] + u.NEW_MAC_STR[12:] if smac_15_0_only else \
                   u.NEW_MAC_STR
        exp_src_mac = struct.pack('!6s', bytes.fromhex(str_smac.replace(':', '')))
        exp_packet = u.gen_packet(self.server.msg_size, src_mac=exp_src_mac)
        packet = u.gen_packet(self.server.msg_size)
        u.raw_traffic(self.client, self.server, self.server.num_msgs, [packet], exp_packet)
        self.verify_rule_removal(rte_items, [self.server], packet)

    def test_mlx5dr_modify(self):
        """
        Create modify action on RX with two set actions to change the src mac,
        send packet and verify using TIR action.
        """
        self.smac_modify_rule_traffic()

    def test_mlx5dr_modify_single_action(self):
        """
        Create modify action with single set action on RX and validate by
        sending a packet and verifying using TIR action.
        """
        self.smac_modify_rule_traffic(smac_15_0_only=True)

    def test_mlx5dr_modify_shared(self):
        """
        Create shared modify action and 3 RX matchers, use this action on all matchers
        and validate with traffic.
        """
        items = [u.create_sipv4_rte_items(f'{i}.{i}.{i}.{i}') for i in range(1, 4)]
        dip_rte = u.create_dipv4_rte_items()
        actions_types = [[me.MLX5DR_ACTION_TYP_MODIFY_HDR, me.MLX5DR_ACTION_TYP_TIR,
                    me.MLX5DR_ACTION_TYP_LAST]]
        self.server.init_steering_resources(rte_items=items[0], root_rte_items=dip_rte,
                                            action_types_list=actions_types)
        self.server.matcher2 = self.server.create_matcher(self.server.table,
                                                          [Mlx5drMacherTemplate(items[1])],
                                                          [Mlx5drActionTemplate(actions_types[0])],
                                                          prio=2)
        self.server.matcher3 = self.server.create_matcher(self.server.table,
                                                          [Mlx5drMacherTemplate(items[2])],
                                                          [Mlx5drActionTemplate(actions_types[0])],
                                                          prio=3)
        matchers = [self.server.matcher, self.server.matcher2, self.server.matcher3]
        action1 = SetActionIn(field=u.ModifyFieldId.OUT_SMAC_47_16,
                              length=u.ModifyFieldLen.OUT_SMAC_47_16, data=0x88888888)
        action2 = SetActionIn(field=u.ModifyFieldId.OUT_SMAC_15_0,
                              length=u.ModifyFieldLen.OUT_SMAC_15_0, data=0x8888)
        modify_flags = me.MLX5DR_ACTION_FLAG_SHARED | me.MLX5DR_ACTION_FLAG_HWS_RX
        _, self.modify_ra = self.server.create_rule_action('modify', flags=modify_flags,
                                                           log_bulk_size=0, offset=0,
                                                           actions=[action1, action2])
        _, tir_ra = self.server.create_rule_action('tir')
        dr_rule_attr = Mlx5drRuleAttr(user_data=bytes(8))
        for i in range(len(matchers)):
            self.hws_rules.append(Mlx5drRule(matcher=matchers[i], mt_idx=0, rte_items=items[i],
                                             at_idx=0, rule_actions=[self.modify_ra, tir_ra],
                                             num_of_actions=2,rule_attr_create=dr_rule_attr,
                                             dr_ctx=self.server.dr_ctx))
        exp_src_mac = struct.pack('!6s', bytes.fromhex(u.NEW_MAC_STR.replace(':', '')))
        self.server.dr_ctx.dump('/tmp/hws_dump/test_mlx5dr_modify_shared')
        for i in range(1, 4):
            sip = f'{i}.{i}.{i}.{i}'
            exp_packet = u.gen_packet(self.server.msg_size, src_ip=sip, src_mac=exp_src_mac)
            packet = u.gen_packet(self.server.msg_size, src_ip=sip)
            u.raw_traffic(self.client, self.server, self.server.num_msgs, [packet], exp_packet)
        self.verify_rule_removal(dip_rte, [self.server], packet)

    def modify_rule_traffic(self, rte_items, modify_actions, exp_packet):
        """
        Create modify action on RX with modify actions to change the packet, send
        packet and verify using TIR action.
        :param rte_items: RTE flow items to match on
        :param modify_actions: Actions that modify packets
        :param exp_packet: Expected packet after modifications
        """
        actions_types = [[me.MLX5DR_ACTION_TYP_MODIFY_HDR, me.MLX5DR_ACTION_TYP_TIR,
                    me.MLX5DR_ACTION_TYP_LAST]]
        self.server.init_steering_resources(rte_items=rte_items, action_types_list=actions_types)

        _, self.modify_ra = self.server.create_rule_action('modify', log_bulk_size=12, offset=0,
                                                           actions=modify_actions)
        _, tir_ra = self.server.create_rule_action('tir')
        self.hws_rules.append(Mlx5drRule(matcher=self.server.matcher, mt_idx=0,
                                         rte_items=rte_items, at_idx=0,
                                         rule_actions=[self.modify_ra, tir_ra],
                                         rule_attr_create=Mlx5drRuleAttr(user_data=bytes(8)),
                                         num_of_actions=2, dr_ctx=self.server.dr_ctx))
        packet = u.gen_packet(self.server.msg_size)
        u.raw_traffic(self.client, self.server, self.server.num_msgs, [packet], exp_packet,
                      skip_idxs=[24, 25])  # Skipping IP checksum

    def test_mlx5dr_modify_copy(self):
        """
        Verify modify action copy by copying UDP dst port to src port.
        """
        copy_action = CopyActionIn(src_field=u.ModifyFieldId.OUT_UDP_DPORT,
                                   dst_field=u.ModifyFieldId.OUT_UDP_SPORT,
                                   length=16)
        exp_packet = u.gen_packet(self.server.msg_size, src_port=u.PacketConsts.DST_PORT)
        rte_items = u.create_sipv4_rte_items(u.PacketConsts.SRC_IP)
        self.modify_rule_traffic(rte_items, [copy_action],  exp_packet)
        self.verify_rule_removal(rte_items, [self.server], exp_packet)

    def test_mlx5dr_modify_add(self):
        """
        Verify modify action add by increasing TTL by 1.
        """
        inc = 1
        add_action = AddActionIn(field=u.ModifyFieldId.OUT_IPV4_TTL, data=inc)
        exp_packet = u.gen_packet(self.server.msg_size, ttl=u.PacketConsts.TTL_HOP_LIMIT + inc)
        rte_items = u.create_sipv4_rte_items(u.PacketConsts.SRC_IP)
        self.modify_rule_traffic(rte_items, [add_action],  exp_packet)
        self.verify_rule_removal(rte_items, [self.server], exp_packet)

    @staticmethod
    def create_miss_rule(agr_obj, rte_items, rule_actions):
        return Mlx5drRule(matcher=agr_obj.matcher, mt_idx=0, rte_items=rte_items, at_idx=0,
                          rule_actions=rule_actions, num_of_actions=len(rule_actions),
                          rule_attr_create=Mlx5drRuleAttr(user_data=bytes(8)), dr_ctx=agr_obj.dr_ctx)


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
        sip_int = struct.unpack("!I", socket.inet_aton(u.PacketConsts.SRC_IP))[0]
        sip_miss = socket.inet_ntoa(struct.pack("!I", sip_int + 1))
        sip_miss_rte = u.create_sipv4_rte_items(sip_miss)
        dip_rte = u.create_dipv4_rte_items()
        sip_rte = u.create_sipv4_rte_items()
        tx_actions_types = [[me.MLX5DR_ACTION_TYP_CTR, me.MLX5DR_ACTION_TYP_MISS,
                             me.MLX5DR_ACTION_TYP_LAST]]
        rx_actions_types = [[me.MLX5DR_ACTION_TYP_MISS, me.MLX5DR_ACTION_TYP_LAST]]
        # TX
        self.client.init_steering_resources(rte_items=sip_rte, action_types_list=tx_actions_types,
                                            table_type=me.MLX5DR_TABLE_TYPE_NIC_TX)
        _, miss_tx_ra = self.client.create_rule_action('def_miss',
                                                       flags=me.MLX5DR_ACTION_FLAG_HWS_TX)
        devx_counter, counter_id, counter_tx_ra = \
            u.create_counter_action(self, self.client, flags=me.MLX5DR_ACTION_FLAG_HWS_TX)
        self.miss_tx_rule = self.create_miss_rule(self.client, rte_items=sip_rte,
                                                  rule_actions=[counter_tx_ra, miss_tx_ra])
        # RX
        self.server.init_steering_resources(rte_items=sip_rte, root_rte_items=dip_rte,
                                            action_types_list=rx_actions_types)
        _, miss_rx_ra = self.server.create_rule_action('def_miss')
        self.miss_rx_rule = self.create_miss_rule(self.server, rte_items=sip_miss_rte,
                                                  rule_actions=[miss_rx_ra])
        # Second RX matcher
        mt_2 = Mlx5drMacherTemplate(dip_rte)
        at = [Mlx5drActionTemplate([me.MLX5DR_ACTION_TYP_TIR, me.MLX5DR_ACTION_TYP_LAST])]
        self.server.dip_matcher = \
            self.server.create_matcher(self.server.table, [mt_2], at,
                                       mode=me.MLX5DR_MATCHER_RESOURCE_MODE_RULE,
                                       prio=9, log_row=2)
        _, tir_ra = self.server.create_rule_action('tir')
        self.hws_rules.append(Mlx5drRule(matcher=self.server.dip_matcher, mt_idx=0,
                                         rte_items=dip_rte, at_idx=0, rule_actions=[tir_ra],
                                         num_of_actions=1,
                                         rule_attr_create=Mlx5drRuleAttr(user_data=bytes(8)),
                                         dr_ctx=self.server.dr_ctx))
        # Traffic
        packet1 = u.gen_packet(self.server.msg_size)
        packet2 = u.gen_packet(self.server.msg_size, src_ip=sip_miss)
        self.server.dr_ctx.dump('/tmp/hws_dump/test_mlx5dr_default_miss_rx')
        self.client.dr_ctx.dump('/tmp/hws_dump/test_mlx5dr_default_miss_tx')
        u.raw_traffic(self.client, self.server, self.server.num_msgs, [packet1, packet2],
                      expected_packet=packet1)
        # Verify counter
        u.verify_counter(self, self.client, devx_counter, counter_id)
        self.verify_rule_removal(sip_rte, [self.server], packet1)

    def decap_rule_traffic(self, decap_type=me.MLX5DR_ACTION_REFORMAT_TYPE_TNL_L2_TO_L2):
        """
        Execute traffic with RX table rules and decap L2/L3 action.
        In case of L2 to L2 decap, a VXLAN tunneled packet is usesd.
        In case of L3 to L2 decap, a GTP_U packet is used instead, otherwise, a
        change of a FLEX parser is needed to decap VXLAN.
        """
        tir_rte_items = u.create_sipv4_rte_items(u.PacketConsts.SRC_IP)
        _, tir_ra = self.server.create_rule_action('tir')
        if decap_type == me.MLX5DR_ACTION_REFORMAT_TYPE_TNL_L3_TO_L2:
            dump_file = '/tmp/hws_dump/test_mlx5dr_decap_l3'
            action_enum = me.MLX5DR_ACTION_TYP_TNL_L3_TO_L2
            outer = u.gen_outer_headers(self.server.msg_size, tunnel=u.TunnelType.GTP_U)
            l2_hdr = u.get_l2_header()
            inner_len = self.server.msg_size - len(outer) - len(l2_hdr)
            inner = u.gen_packet(inner_len, l2=False)
            decap_a, decap_ra = self.server.create_rule_action('reformat', ref_type=decap_type,
                                                               data=l2_hdr, data_sz=len(l2_hdr),
                                                               bulk_size=12)
            exp_packet = l2_hdr + inner
        else:
            dump_file = '/tmp/hws_dump/test_mlx5dr_decap_l2'
            action_enum = me.MLX5DR_ACTION_TYP_TNL_L2_TO_L2
            outer = u.gen_outer_headers(self.server.msg_size, tunnel=u.TunnelType.VXLAN)
            inner_len = self.server.msg_size - len(outer)
            inner = u.gen_packet(inner_len)
            decap_a, decap_ra = self.server.create_rule_action('reformat')
            exp_packet = inner
        packet = outer + inner
        actions_types = [[action_enum, me.MLX5DR_ACTION_TYP_TIR, me.MLX5DR_ACTION_TYP_LAST]]
        self.server.init_steering_resources(rte_items=tir_rte_items, action_types_list=actions_types)
        self.hws_rules.append(Mlx5drRule(self.server.matcher, 0, tir_rte_items, 0,
                                         [decap_ra, tir_ra], 2, Mlx5drRuleAttr(user_data=bytes(8)),
                                         self.server.dr_ctx))
        self.server.dr_ctx.dump(dump_file)
        u.raw_traffic(self.client, self.server, self.server.num_msgs, [packet], exp_packet)
        self.verify_rule_removal(tir_rte_items, [self.server], packet)

    def encap_rule_traffic(self, encap_type=me.MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L2):
        """
        Execute traffic with TX table rules and encap l2/l3 action
        """
        tir_rte_items = u.create_sipv4_rte_items(u.PacketConsts.SRC_IP)
        self.server.init_steering_resources(rte_items=tir_rte_items)
        action_enum = me.MLX5DR_ACTION_TYP_L2_TO_TNL_L2
        dump_file = '/tmp/hws_dump/test_mlx5dr_encap_l2'
        if encap_type != me.MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L2:
            action_enum = me.MLX5DR_ACTION_TYP_L2_TO_TNL_L3
            dump_file = '/tmp/hws_dump/test_mlx5dr_encap_l3'
        actions_types = [[action_enum, me.MLX5DR_ACTION_TYP_LAST]]
        self.client.init_steering_resources(rte_items=tir_rte_items, action_types_list=actions_types,
                                            table_type=me.MLX5DR_TABLE_TYPE_NIC_TX)
        encap_data = u.gen_outer_headers(self.server.msg_size, tunnel=u.TunnelType.VXLAN)
        _, tir_ra = self.server.create_rule_action('tir')
        _, encap_ra = self.client.create_rule_action('reformat', me.MLX5DR_ACTION_FLAG_HWS_TX,
                                                     ref_type=encap_type, data=encap_data,
                                                     data_sz=len(encap_data), log_bulk_size=12)
        self.hws_rules.append(Mlx5drRule(self.client.matcher, 0, tir_rte_items, 0, [encap_ra], 1,
                                         Mlx5drRuleAttr(user_data=bytes(8)), self.client.dr_ctx))
        self.hws_rules.append(Mlx5drRule(self.server.matcher, 0, tir_rte_items, 0, [tir_ra], 1,
                                         Mlx5drRuleAttr(user_data=bytes(8)), self.server.dr_ctx))
        # Build packets
        send_packet = u.gen_packet(self.server.msg_size - len(encap_data))
        l3_packet_len = self.server.msg_size - len(encap_data) - u.PacketConsts.ETHER_HEADER_SIZE
        l3_packet = u.gen_packet(l3_packet_len, l2=False)
        exp_inner = l3_packet if encap_type == me.MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L3 \
                        else send_packet
        expected_packet = encap_data + exp_inner
        # Skip indexes which are offloaded by HW(UDP source port and len, ipv4 id, checksum and
        # total len)
        self.client.dr_ctx.dump(dump_file)
        u.raw_traffic(self.client, self.server, self.server.num_msgs, [send_packet], expected_packet,
                      skip_idxs=[16, 17, 18, 19, 24, 25, 34, 35, 38, 39, 53, 75])
        self.verify_rule_removal(tir_rte_items, [self.server, self.client], send_packet)

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
        sip_rte_items = u.create_sipv4_rte_items(u.PacketConsts.SRC_IP)
        tx_items = u.create_sipv4_rte_items('2.2.2.2')
        rx_items = u.create_sipv4_rte_items('3.3.3.3')

        dip_rte_items = u.create_dipv4_rte_items(u.PacketConsts.DST_IP)
        actions_types = [[me.MLX5DR_ACTION_TYP_DROP, me.MLX5DR_ACTION_TYP_LAST]]
        self.server.init_steering_resources(rte_items=sip_rte_items, root_rte_items=dip_rte_items,
                                            action_types_list=actions_types)
        self.client.init_steering_resources(rte_items=sip_rte_items, root_rte_items=dip_rte_items,
                                            table_type=me.MLX5DR_TABLE_TYPE_NIC_TX,
                                            action_types_list=actions_types)
        _, rx_ra = self.server.create_rule_action('drop')
        _, tx_ra = self.client.create_rule_action('drop', me.MLX5DR_ACTION_FLAG_HWS_TX)
        _, tir_ra = self.server.create_rule_action('tir')

        template_relaxed_match = me.MLX5DR_MATCH_TEMPLATE_FLAG_RELAXED_MATCH
        matcher_templates = [Mlx5drMacherTemplate(dip_rte_items, flags=template_relaxed_match)]
        tir_temp = [Mlx5drActionTemplate([me.MLX5DR_ACTION_TYP_TIR, me.MLX5DR_ACTION_TYP_LAST])]
        tir_matcher = self.server.create_matcher(self.server.table, matcher_templates, tir_temp,
                                                 mode=me.MLX5DR_MATCHER_RESOURCE_MODE_HTABLE,
                                                 prio=2)
        self.hws_rules.append(Mlx5drRule(tir_matcher, 0, dip_rte_items, 0, [tir_ra], 1,
                                         Mlx5drRuleAttr(user_data=bytes(8)), self.server.dr_ctx))
        self.hws_rules.append(Mlx5drRule(self.server.matcher, 0, rx_items, 0, [rx_ra], 1,
                                         Mlx5drRuleAttr(user_data=bytes(8)), self.server.dr_ctx))
        self.hws_rules.append(Mlx5drRule(self.client.matcher, 0, tx_items, 0, [tx_ra], 1,
                                         Mlx5drRuleAttr(user_data=bytes(8)), self.client.dr_ctx))
        packets = []
        for i in [3, 2, 1]:
            src_ip = '.'.join(str(i) * 4)
            packets.append(u.gen_packet(self.server.msg_size, src_ip=src_ip))
        self.server.dr_ctx.dump('/tmp/hws_dump/test_mlx5dr_drop')
        u.raw_traffic(self.client, self.server, self.server.num_msgs, packets, packets[2])
        self.verify_rule_removal(dip_rte_items, [self.server, self.client], packets[2])

    def test_mlx5dr_counter(self):
        """
        Create counter action on TX and counter + TIR actions on RX, recv packets
        and verify counters.
        """
        rte_items = u.create_sipv4_rte_items(u.PacketConsts.SRC_IP)
        tx_actions_types = [[me.MLX5DR_ACTION_TYP_CTR, me.MLX5DR_ACTION_TYP_LAST]]
        rx_actions_types = [[me.MLX5DR_ACTION_TYP_CTR, me.MLX5DR_ACTION_TYP_TIR,
                             me.MLX5DR_ACTION_TYP_LAST]]
        self.server.init_steering_resources(rte_items=rte_items, action_types_list=rx_actions_types)
        self.client.init_steering_resources(rte_items=rte_items, action_types_list=tx_actions_types,
                                            table_type=me.MLX5DR_TABLE_TYPE_NIC_TX)
        _, tir_ra = self.server.create_rule_action('tir')
        # Set const values for counters' offsets for easier debug
        tx_offset = 0x123
        rx_offset = 0x111
        tx_devx_counter, tx_counter_id, counter_tx_ra = \
            u.create_counter_action(self, self.client, flags=me.MLX5DR_ACTION_FLAG_HWS_TX,
                                    bulk=u.BULK_512, offset=tx_offset)
        rx_devx_counter, rx_counter_id, counter_rx_ra = \
            u.create_counter_action(self, self.server, flags=me.MLX5DR_ACTION_FLAG_HWS_RX,
                                    bulk=u.BULK_512, offset=rx_offset)
        self.rx_rule = Mlx5drRule(self.server.matcher, 0, rte_items, 0,
                                  [counter_rx_ra, tir_ra], 2,
                                  Mlx5drRuleAttr(user_data=bytes(8)),
                                  self.server.dr_ctx)
        self.tx_rule = Mlx5drRule(self.client.matcher, 0, rte_items, 0,
                                  [counter_tx_ra], 1,
                                  Mlx5drRuleAttr(user_data=bytes(8)),
                                  self.client.dr_ctx)
        packet = u.gen_packet(self.server.msg_size)
        u.raw_traffic(self.client, self.server, self.server.num_msgs, [packet])
        self.server.dr_ctx.dump('/tmp/hws_dump/test_mlx5dr_counter')
        # Verify counters
        u.verify_counter(self, self.client, tx_devx_counter, tx_counter_id, tx_offset)
        # RX steering counters include FCS\VCRC in the byte count on cx6dx.
        # Add extra 4 bytes to each packet.
        if u.is_cx6dx(self.attr):
            self.server.msg_size += 4
        u.verify_counter(self, self.server, rx_devx_counter, rx_counter_id, rx_offset)

    def create_burst_rules_without_polling(self, is_burst):
        """
        Function creates a rule with burst flag on. Verifies with traffic that
        the rule wasn't written. Forces the rule to be written by creating
        another rule with bust flag off or by drain action flag using send
        queue action API. Verifies with traffic that the rule was written.
        :param is_burst: If true - the second rule is created with burst flag off. If false -
                         use send queue action API with action drain flag.
        """
        tir_rte_items = u.create_sipv4_rte_items(u.PacketConsts.SRC_IP)
        _, tir_ra = self.server.create_rule_action('tir')
        packet = u.gen_packet(self.server.msg_size)
        action_types = [[me.MLX5DR_ACTION_TYP_TIR, me.MLX5DR_ACTION_TYP_LAST],
                        [me.MLX5DR_ACTION_TYP_TAG, me.MLX5DR_ACTION_TYP_LAST]]
        self.server.init_steering_resources(rte_items=tir_rte_items, action_types_list=action_types)
        self.tir_rule1 = Mlx5drRule(self.server.matcher, 0, tir_rte_items, 0, [tir_ra], 1,
                                    Mlx5drRuleAttr(user_data=bytes(8), burst=1))
        try:
            u.raw_traffic(self.client, self.server, self.server.num_msgs, [packet])
        except PyverbsError:
            self.logger.debug("Not receiving packet yet as expected.")
        except Exception as ex:
            raise ex
        if is_burst:
            _, tag_ra = self.server.create_rule_action('tag')
            tag_ra.tag_value = 0x1234
            self.tir_rule2 = Mlx5drRule(self.server.matcher, 0,
                                        u.create_sipv4_rte_items(u.PacketConsts.DST_IP), 1,
                                        [tag_ra], 1, Mlx5drRuleAttr(user_data=bytes(8)),
                                        self.server.dr_ctx)
            self.server.dr_ctx.dump('/tmp/hws_dump/test_mlx5dr_burst')
        else:
            self.server.dr_ctx.send_queue_action(0, me.MLX5DR_SEND_QUEUE_ACTION_DRAIN)
        res = []
        polling_timeout = 5
        start_poll_t = time.perf_counter()
        while not res and (time.perf_counter() - start_poll_t) < polling_timeout:
            res = self.server.dr_ctx.poll_send_queue(0, 1)
        if not res:
            raise PyverbsError(f'Got timeout on polling.')
        u.raw_traffic(self.client, self.server, self.server.num_msgs, [packet])

    def test_mlx5dr_burst(self):
        """
        Create rule with burst flag on.
        Send packet - validate rule wasn't created.
        Add another rule with burst=0.
        Resend the packet to check the rule was created.
        """
        self.create_burst_rules_without_polling(is_burst=True)


    def test_mlx5dr_drain(self):
        """
        Create rule with burst flag on.
        Send packet - validate rule wasn't created.
        Use send queue action with DRAIN flag to force rule to be written.
        Resend the packet to check the rule was created.
        """
        self.create_burst_rules_without_polling(is_burst=False)

    @staticmethod
    def create_set_action_smac_idx(idx):
        str_smac = "88:88:88:88:88:8" + str(idx)
        action1 = SetActionIn(field=u.PacketConsts.OUT_SMAC_47_16_FIELD_ID,
                              length=u.PacketConsts.OUT_SMAC_47_16_FIELD_LENGTH,
                              data=0x88888888)
        action2 = SetActionIn(field=u.PacketConsts.OUT_SMAC_15_0_FIELD_ID,
                              length=u.PacketConsts.OUT_SMAC_15_0_FIELD_LENGTH,
                              data=0x8880 + idx)
        return [action1, action2], str_smac

    def test_mlx5dr_complex_rule_decap_modify(self):
        """
        Complex Rule RX with decap + modify smac + tir.
        """
        tir_rte_items = u.create_sipv4_rte_items(u.PacketConsts.SRC_IP)
        action_types = [me.MLX5DR_ACTION_TYP_TNL_L2_TO_L2, me.MLX5DR_ACTION_TYP_MODIFY_HDR,
                        me.MLX5DR_ACTION_TYP_TIR, me.MLX5DR_ACTION_TYP_LAST]
        self.server.init_steering_resources(rte_items=tir_rte_items,
                                            action_types_list=[action_types] * 4)
        outer = u.gen_outer_headers(self.server.msg_size, tunnel=u.TunnelType.VXLAN)
        inner_len = self.server.msg_size - len(outer)
        inner = u.gen_packet(inner_len)
        packet = outer + inner
        decap_a, decap_ra = self.server.create_rule_action('reformat')
        at_idx = random.choice(range(4))
        smac_actions, str_smac = self.create_set_action_smac_idx(at_idx)
        modify_flags = me.MLX5DR_ACTION_FLAG_SHARED | me.MLX5DR_ACTION_FLAG_HWS_RX
        _, modify_ra = self.server.create_rule_action('modify', flags=modify_flags,
                                                      log_bulk_size=0, offset=0,
                                                      actions=smac_actions)
        _, tir_ra = self.server.create_rule_action('tir')
        exp_src_mac = struct.pack('!6s',
                                  bytes.fromhex(str_smac.replace(':', '')))
        exp_packet = u.gen_packet(inner_len, src_mac=exp_src_mac)
        self.tir_rule = Mlx5drRule(self.server.matcher, 0, tir_rte_items, at_idx,
                                   [decap_ra, modify_ra, tir_ra], 3,
                                   Mlx5drRuleAttr(user_data=bytes(8)),
                                   self.server.dr_ctx)
        self.server.dr_ctx.dump('/tmp/hws_dump/test_mlx5dr_complex_rule_decap_modify')
        u.raw_traffic(self.client, self.server, self.server.num_msgs, [packet], exp_packet)

    def test_mlx5dr_complex_rule_modify_encap(self):
        """
        Complex Rule TX with modify smac + encap.
        """
        tir_rte_items = u.create_sipv4_rte_items(u.PacketConsts.SRC_IP)
        action_types = [me.MLX5DR_ACTION_TYP_MODIFY_HDR, me.MLX5DR_ACTION_TYP_L2_TO_TNL_L2,
                        me.MLX5DR_ACTION_TYP_LAST]
        self.server.init_steering_resources(rte_items=tir_rte_items)
        self.client.init_steering_resources(rte_items=tir_rte_items,
                                            table_type=me.MLX5DR_TABLE_TYPE_NIC_TX,
                                            action_types_list=[action_types] * 4)
        encap_data = u.gen_outer_headers(self.server.msg_size, tunnel=u.TunnelType.VXLAN)
        send_packet = u.gen_packet(self.server.msg_size - len(encap_data))
        _, encap_ra = self.client.create_rule_action('reformat',
                                                     me.MLX5DR_ACTION_FLAG_HWS_TX,
                                                     ref_type=me.MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L2,
                                                     data=encap_data,
                                                     data_sz=len(encap_data),
                                                     log_bulk_size=12)
        at_idx = random.choice(range(4))
        smac_actions, str_smac = self.create_set_action_smac_idx(at_idx)
        modify_flags = me.MLX5DR_ACTION_FLAG_SHARED | me.MLX5DR_ACTION_FLAG_HWS_TX
        _, modify_ra = self.client.create_rule_action('modify', flags=modify_flags,
                                                      log_bulk_size=0, offset=0,
                                                      actions=smac_actions)
        _, tir_ra = self.server.create_rule_action('tir')
        exp_src_mac = struct.pack('!6s',
                                  bytes.fromhex(str_smac.replace(':', '')))
        exp_packet = u.gen_packet(self.server.msg_size - len(encap_data), src_mac=exp_src_mac)
        exp_packet = encap_data + exp_packet
        self.tx_rule = Mlx5drRule(self.client.matcher, 0, tir_rte_items, at_idx,
                                   [modify_ra, encap_ra], 2,
                                   Mlx5drRuleAttr(user_data=bytes(8)),
                                   self.client.dr_ctx)
        self.rx_rule = Mlx5drRule(self.server.matcher, 0, tir_rte_items, 0,
                                  [tir_ra], 1,
                                  Mlx5drRuleAttr(user_data=bytes(8)),
                                  self.server.dr_ctx)
        # Skip indexes which are offloaded by HW (UDP source port and len,
        # ipv4 id, checksum and total len)
        dump_file = '/tmp/hws_dump/test_mlx5dr_complex_rule_modify_encap'
        self.client.dr_ctx.dump(dump_file)
        u.raw_traffic(self.client, self.server, self.server.num_msgs, [send_packet],
                      exp_packet, skip_idxs=[16, 17, 18, 19, 24, 25, 34, 35, 38, 39, 53, 75])

    def test_mlx5dr_pop_vlan(self):
        """
        Pop VLAN action test
        Create non root RX rule to pop VLAN and verify with traffic.
        Create non root TX rule to pop VLAN twice and verify with traffic.
        """
        rx_rte_items = u.create_sipv4_rte_items(u.PacketConsts.SRC_IP)
        tx_ip = "3.3.3.4"
        tx_rte_items = u.create_sipv4_rte_items(tx_ip)
        root_rte = u.create_dipv4_rte_items()
        rx_actions_types = [[me.MLX5DR_ACTION_TYP_POP_VLAN, me.MLX5DR_ACTION_TYP_TIR,
                             me.MLX5DR_ACTION_TYP_LAST],
                            [me.MLX5DR_ACTION_TYP_TIR, me.MLX5DR_ACTION_TYP_LAST]]
        tx_actions_types = [[me.MLX5DR_ACTION_TYP_POP_VLAN, me.MLX5DR_ACTION_TYP_POP_VLAN,
                             me.MLX5DR_ACTION_TYP_LAST]]
        _, rx_pop_ra = self.server.create_rule_action('pop')
        _, tir_ra = self.server.create_rule_action('tir')
        _, tx_pop_ra = self.client.create_rule_action('pop', flags=me.MLX5DR_ACTION_FLAG_HWS_TX)
        u.init_resources_and_add_rules(self, self.server, root_rte,
                                       [rx_rte_items, tx_rte_items], rx_actions_types,
                                       [[rx_pop_ra, tir_ra],[tir_ra]])
        u.init_resources_and_add_rules(self, self.client, None, [tx_rte_items], tx_actions_types,
                                       [[tx_pop_ra, tx_pop_ra]],
                                       table_type=me.MLX5DR_TABLE_TYPE_NIC_TX)
        packet = u.gen_packet(self.server.msg_size, num_vlans=1)
        exp_packet = u.gen_packet(self.server.msg_size - u.PacketConsts.VLAN_HEADER_SIZE,
                                  num_vlans=0)
        u.raw_traffic(self.client, self.server, self.server.num_msgs, [packet], exp_packet)
        packet = u.gen_packet(self.server.msg_size, num_vlans=2, src_ip=tx_ip)
        exp_packet = u.gen_packet(self.server.msg_size - 2 * u.PacketConsts.VLAN_HEADER_SIZE,
                                  num_vlans=0, src_ip=tx_ip)
        self.server.dr_ctx.dump('/tmp/hws_dump/test_mlx5dr_pop_vlan_rx')
        self.client.dr_ctx.dump('/tmp/hws_dump/test_mlx5dr_pop_vlan_tx')
        u.raw_traffic(self.client, self.server, self.server.num_msgs, [packet], exp_packet)

    def test_mlx5dr_push_vlan(self):
        """
        Push VLAN action test
        Create non root TX rule to push VLAN and verify with traffic.
        Create non root RX rule to push VLAN twice and verify with traffic.
        """
        tx_rte_items = u.create_sipv4_rte_items(u.PacketConsts.SRC_IP)
        root_rte_item = u.create_dipv4_rte_items()
        rx_ip = "3.3.3.4"
        rx_rte_items = u.create_sipv4_rte_items(rx_ip)
        tx_actions_types = [[me.MLX5DR_ACTION_TYP_PUSH_VLAN, me.MLX5DR_ACTION_TYP_LAST]]
        rx_actions_types = [[me.MLX5DR_ACTION_TYP_PUSH_VLAN, me.MLX5DR_ACTION_TYP_PUSH_VLAN,
                             me.MLX5DR_ACTION_TYP_TIR, me.MLX5DR_ACTION_TYP_LAST],
                            [me.MLX5DR_ACTION_TYP_TIR, me.MLX5DR_ACTION_TYP_LAST]]
        _, tx_push_ra = self.client.create_rule_action('push', flags=me.MLX5DR_ACTION_FLAG_HWS_TX)
        _, rx_push_ra = self.server.create_rule_action('push')
        _, tir_ra = self.server.create_rule_action('tir')
        vlan_hdr = (u.PacketConsts.VLAN_TPID << 16) + (u.PacketConsts.VLAN_PRIO << 13) + \
                   (u.PacketConsts.VLAN_CFI << 12) + u.PacketConsts.VLAN_ID
        tx_push_ra.vlan_hdr = vlan_hdr
        rx_push_ra.vlan_hdr = vlan_hdr
        u.init_resources_and_add_rules(self, self.server, root_rte_item,
                                       [rx_rte_items, tx_rte_items], rx_actions_types,
                                       [[rx_push_ra, rx_push_ra, tir_ra],[tir_ra]])
        u.init_resources_and_add_rules(self, self.client, None, [tx_rte_items], tx_actions_types,
                                       [[tx_push_ra]], table_type=me.MLX5DR_TABLE_TYPE_NIC_TX)
        packet = u.gen_packet(self.server.msg_size - u.PacketConsts.VLAN_HEADER_SIZE, num_vlans=0)
        exp_packet = u.gen_packet(self.server.msg_size, num_vlans=1)
        u.raw_traffic(self.client, self.server, self.server.num_msgs, [packet], exp_packet)
        packet = u.gen_packet(self.server.msg_size - 2 * u.PacketConsts.VLAN_HEADER_SIZE,
                              num_vlans=0, src_ip=rx_ip)
        exp_packet = u.gen_packet(self.server.msg_size, num_vlans=2, src_ip=rx_ip)
        self.server.dr_ctx.dump('/tmp/hws_dump/test_mlx5dr_push_vlan_rx')
        self.client.dr_ctx.dump('/tmp/hws_dump/test_mlx5dr_push_vlan_tx')
        u.raw_traffic(self.client, self.server, self.server.num_msgs, [packet], exp_packet)
