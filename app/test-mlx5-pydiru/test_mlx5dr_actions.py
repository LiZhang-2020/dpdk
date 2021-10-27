# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.


from pydiru.providers.mlx5.steering.mlx5dr_rule import Mlx5drRuleAttr, Mlx5drRule
from pydiru.rte_flow import RteFlowItem, RteFlowItemIpv4, RteFlowItemEnd
import pydiru.pydiru_enums as p

from .base import BaseDrResources, PydiruTrafficTestCase
from .utils import raw_traffic, gen_packet, PacketConsts


class Mlx5drTrafficTest(PydiruTrafficTestCase):

    def setUp(self):
        super().setUp()
        self.server = BaseDrResources(self.dev_name, self.ib_port)
        self.client = BaseDrResources(self.dev_name, self.ib_port)

    @staticmethod
    def create_sipv4_rte_items(sip_val):
        mask = RteFlowItemIpv4(src_addr=bytes(4 * [0xff]))
        val = RteFlowItemIpv4(src_addr=sip_val)
        return [RteFlowItem(p.RTE_FLOW_ITEM_TYPE_IPV4, val, mask), RteFlowItemEnd()]

    def test_mlx5dr_tir(self):
        """
        Create TIR and recv packets using TIR action.
        """
        tir_rte_items = self.create_sipv4_rte_items(PacketConsts.SRC_IP)
        self.server.init_steering_resources(rte_items=tir_rte_items)
        self.server.create_root_dest_tbl_rule(tir_rte_items)
        tir_a, tir_ra = self.server.create_rule_action('tir')
        self.tir_rule = Mlx5drRule(self.server.matcher, 0, tir_rte_items, [tir_ra], 1,
                              Mlx5drRuleAttr(user_data=bytes(8)), self.server.dr_ctx)
        packet = gen_packet(self.server.msg_size)
        raw_traffic(self.client, self.server, self.server.num_msgs, [packet])
