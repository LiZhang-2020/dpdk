# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022, Nvidia Inc. All rights reserved.

from operator import itemgetter
from .utils import raw_traffic, gen_packet, create_sipv4_rte_items, create_dipv4_rte_items,\
    PacketConsts, SET_ACTION, NEW_MAC_STR
from pydiru.providers.mlx5.steering.mlx5dr_rule import Mlx5drRuleAttr, Mlx5drRule
from pydiru.providers.mlx5.steering.mlx5dr_matcher import Mlx5drMacherTemplate
from .base import BaseDrResources, PydiruTrafficTestCase, NUM_OF_QUEUES
import pydiru.providers.mlx5.steering.mlx5dr_enums as me
from .prm_structs import SetActionIn
import pydiru.pydiru_enums as p
import struct


class Mlx5drTrafficTest(PydiruTrafficTestCase):

    def setUp(self):
        super().setUp()
        self.server = BaseDrResources(self.dev_name, self.ib_port)
        self.client = BaseDrResources(self.dev_name, self.ib_port)
        self.devx_objects.append(self.server.tir_obj)
        self.devx_objects.append(self.client.tir_obj)

    @staticmethod
    def create_src_mac_set_action():
        action1 = SetActionIn(action_type=SET_ACTION, field=PacketConsts.OUT_SMAC_47_16_FIELD_ID,
                              length=PacketConsts.OUT_SMAC_47_16_FIELD_LENGTH, data=0x88888888)
        action2 = SetActionIn(action_type=SET_ACTION, field=PacketConsts.OUT_SMAC_15_0_FIELD_ID,
                              length=PacketConsts.OUT_SMAC_15_0_FIELD_LENGTH, data=0x8888)
        return [action1, action2]

    def test_mlx5dr_insert_rules_on_multi_queue(self):
        """
        Create shared modify action and NUM_OF_QUEUES RX matchers,
        use this action on all matchers and validate with traffic.
        """
        actions_types = [[me.MLX5DR_ACTION_TYP_MODIFY_HDR, me.MLX5DR_ACTION_TYP_TIR,
                    me.MLX5DR_ACTION_TYP_LAST]]
        items = [create_sipv4_rte_items(f'{i}.{i}.{i}.{i}') for i in range(1, NUM_OF_QUEUES+1)]
        dip_rte = create_dipv4_rte_items()
        self.server.init_steering_resources(rte_items=items[0], root_rte_items=dip_rte,
                                            action_types_list=actions_types)
        _, self.modify_ra = self.server.create_rule_action('modify', flags=me.MLX5DR_ACTION_FLAG_HWS_RX,
                                                           log_bulk_size=0, offset=0,
                                                           actions=self.create_src_mac_set_action())
        _, tir_ra = self.server.create_rule_action('tir')
        modify_rules = []
        for i in range(NUM_OF_QUEUES):
            dr_rule_attr = Mlx5drRuleAttr(queue_id=i, user_data=bytes(8))
            modify_rules.append(Mlx5drRule(matcher=self.server.matcher, mt_idx=0, rte_items=items[i],
                                           at_idx=0, rule_actions=[self.modify_ra, tir_ra],
                                           num_of_actions=2, rule_attr_create=dr_rule_attr,
                                           dr_ctx=self.server.dr_ctx))
        exp_src_mac = struct.pack('!6s', bytes.fromhex(NEW_MAC_STR.replace(':', '')))
        for i in range(1, NUM_OF_QUEUES+1):
            src_ip = f'{i}.{i}.{i}.{i}'
            exp_packet = gen_packet(self.server.msg_size, src_ip=src_ip, src_mac=exp_src_mac)
            packet = gen_packet(self.server.msg_size, src_ip=src_ip)
            raw_traffic(self.client, self.server, self.server.num_msgs, [packet], exp_packet)
