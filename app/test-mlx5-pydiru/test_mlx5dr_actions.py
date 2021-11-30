# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.


from pydiru.providers.mlx5.steering.mlx5dr_rule import Mlx5drRuleAttr, Mlx5drRule

from .utils import raw_traffic, gen_packet, PacketConsts, create_sipv4_rte_items
from .base import BaseDrResources, PydiruTrafficTestCase


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
        tag_ra.value = 0x1234
        _, tir_ra = self.server.create_rule_action('tir')
        self.tir_rule = Mlx5drRule(self.server.matcher, mt_idx=0, rte_items=rte_items,
                                   rule_actions=[tag_ra, tir_ra], num_of_actions=2,
                                   rule_attr=Mlx5drRuleAttr(user_data=bytes(8)),
                                   dr_ctx=self.server.dr_ctx)
        packet = gen_packet(self.server.msg_size)
        raw_traffic(self.client, self.server, self.server.num_msgs, [packet],
                    tag_value=0x1234)
