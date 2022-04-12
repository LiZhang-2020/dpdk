# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022, Nvidia Inc. All rights reserved.

from .utils import raw_traffic, gen_packet, PacketConsts, create_sipv4_rte_items, \
    create_counter_action, verify_counter, send_packets, poll_cq
from pydiru.rte_flow import RteFlowItem, RteFlowItemEthdev, RteFlowItemIpv4, Mlx5RteFlowItemTxQueue,\
    RteFlowItemEnd
from pydiru.providers.mlx5.steering.mlx5dr_rule import Mlx5drRuleAttr, Mlx5drRule
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsError
from pydiru.providers.mlx5.mlx5_flow import FlowPortInfo
from .base import BaseDrResources, PydiruTrafficTestCase
import pydiru.providers.mlx5.steering.mlx5dr_enums as me
from pyverbs.providers.mlx5.mlx5dv import Mlx5Context
from pydiru.base import PydiruErrno
import pydiru.pydiru_enums as p
import unittest
import errno


class Mlx5drFDBTest(PydiruTrafficTestCase):

    def setUp(self):
        super().setUp()
        self.vf_name = self.config['vf']
        if not self.vf_name:
            raise  unittest.SkipTest(f'VF RDMA device must be provided')
        self.server = BaseDrResources(self.dev_name, self.ib_port)
        self.client = BaseDrResources(self.dev_name, self.ib_port)
        self.vf = BaseDrResources(self.vf_name, 1)
        self.devx_objects.append(self.server.tir_obj)
        self.devx_objects.append(self.client.tir_obj)
        self.devx_objects.append(self.vf.tir_obj)

    def tearDown(self):
        if self.vf:
            self.vf.dr_ctx.close()
        super().tearDown()

    def vport_to_ib_port(self, vport_num):
        for i in range(1, self.attr.phys_port_cnt + 1):
            try:
                dv_port_attr = Mlx5Context.query_mlx5_port(self.ctx, i)
            except PyverbsRDMAError as ex:
                if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                    continue  # Port is inactive
                raise ex
            if vport_num == dv_port_attr.vport:
                return i
        raise PyverbsError( f'Failed to find IB port for vport {vport_num}.')

    def vf_to_ib_port(self, vf_name):
        """
        Converts VF name to IB port number
        """
        assert(vf_name[-2] == 'v'), 'Wrong assumption that VF name ends with v0 or v1'
        vport_num = int(vf_name[-1]) + 1
        return self.vport_to_ib_port(vport_num)

    @staticmethod
    def create_fdb_rule(agr_obj, rte_item, actions, actions_temp):
        rte_items = [rte_item, RteFlowItemEnd()]
        mask = RteFlowItemIpv4(src_addr=bytes(4 * [0xff]), dst_addr=bytes(4 * [0xff]))
        val = RteFlowItemIpv4(src_addr=PacketConsts.SRC_IP, dst_addr=PacketConsts.DST_IP)
        root_rte_items = [RteFlowItem(p.RTE_FLOW_ITEM_TYPE_IPV4, val, mask),  RteFlowItemEnd()]
        agr_obj.init_steering_resources(rte_items=rte_items, table_type=me.MLX5DR_TABLE_TYPE_FDB,
                                        root_rte_items=root_rte_items, actions=actions_temp)
        agr_obj.rule = Mlx5drRule(agr_obj.matcher, 0, rte_items, 0, actions, len(actions),
                                  Mlx5drRuleAttr(user_data=bytes(8)), agr_obj.dr_ctx)

    def reg_c_to_port_id(self, reg_c):
        """
        Finds port ID for provided reg c value.
        """
        for i in range(1, self.attr.phys_port_cnt + 1):
            try:
                p = FlowPortInfo(i)
            except PydiruErrno as ex:
                    continue  # Port is inactive
            if reg_c == p.reg_c_value:
                return i
        raise PyverbsError( f'Failed to find port ID for reg c value {reg_c}.')

    def test_mlx5dr_match_sqn_action_vport(self):
        """
        Create action vport on non root FDB table matching on PF's send QP number.
        Create TIR action on VF to catch packets.
        Send packets from PF and verify them on VF.
        """

        ib_port = self.vf_to_ib_port(self.vf_name)
        ip_rte_items = create_sipv4_rte_items(PacketConsts.SRC_IP)
        mask = Mlx5RteFlowItemTxQueue(qp_num=0xffffffff)
        val = Mlx5RteFlowItemTxQueue(qp_num=self.client.qp.qp_num)
        rte_flow_item = [RteFlowItem(me.MLX5_RTE_FLOW_ITEM_TYPE_TX_QUEUE, val, mask),
                         RteFlowItemEnd()]
        vf_actions = [[me.MLX5DR_ACTION_TYP_TIR, me.MLX5DR_ACTION_TYP_LAST]]
        pf_actions = [[me.MLX5DR_ACTION_TYP_VPORT, me.MLX5DR_ACTION_TYP_LAST]]
        self.server.init_steering_resources(rte_items=rte_flow_item,
                                            table_type=me.MLX5DR_TABLE_TYPE_FDB,
                                            root_rte_items=ip_rte_items,
                                            action_types_list=pf_actions)
        vport_a, vport_ra = self.server.create_rule_action('vport',
                                                           flags=me.MLX5DR_ACTION_FLAG_HWS_FDB,
                                                           vport=ib_port)
        self.vport_rule = Mlx5drRule(self.server.matcher, 0, rte_flow_item, 0, [vport_ra], 1,
                                     Mlx5drRuleAttr(user_data=bytes(8)), self.server.dr_ctx)
        # Create TIR rule on VF
        self.vf.init_steering_resources(rte_items=rte_flow_item, root_rte_items=ip_rte_items,
                                        action_types_list=vf_actions)
        tir_a, tir_ra = self.vf.create_rule_action('tir')
        self.vf.tir_rule = Mlx5drRule(self.vf.matcher, 0, rte_flow_item, 0, [tir_ra], 1,
                                      Mlx5drRuleAttr(user_data=bytes(8)), self.vf.dr_ctx)
        packet = gen_packet(self.server.msg_size)
        raw_traffic(self.client, self.vf, self.server.num_msgs, [packet])

    def test_mlx5dr_matcher_port_id(self):
        """
        Create FDB rule that matches on pord ID of the VF with action counter.
        Send traffic from VF and verify counter.
        """
        vf_ib_port = self.vf_to_ib_port(self.vf_name)
        dv_port_attr = Mlx5Context.query_mlx5_port(self.ctx, vf_ib_port)
        reg_c = dv_port_attr.reg_c0_value
        port_id = self.reg_c_to_port_id(reg_c)

        mask = RteFlowItemEthdev(port_id=0xffff)
        val = RteFlowItemEthdev(port_id=port_id)
        rte_flow_item = RteFlowItem(p.RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT, val, mask)
        devx_counter, counter_id, counter_ra = \
            create_counter_action(self, self.client, flags=me.MLX5DR_ACTION_FLAG_HWS_FDB)
        actions_temp = [[me.MLX5DR_ACTION_TYP_CTR, me.MLX5DR_ACTION_TYP_LAST]]
        self.create_fdb_rule(self.client, rte_flow_item, [counter_ra], actions_temp)

        # Send traffic from VF
        packet = gen_packet(self.server.msg_size)
        for _ in range(self.vf.num_msgs):
            send_packets(self.vf, [packet])
        verify_counter(self, self.client, devx_counter, counter_id)
