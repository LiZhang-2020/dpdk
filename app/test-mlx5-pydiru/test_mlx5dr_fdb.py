# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022, Nvidia Inc. All rights reserved.

from .utils import raw_traffic, gen_packet, PacketConsts, create_sipv4_rte_items, \
    create_counter_action, verify_counter, send_packets, create_ipv4_rte_item, create_eth_rte_item, \
    NEW_MAC_STR, ModifyFieldId, ModifyFieldLen
from pydiru.rte_flow import RteFlowItem, RteFlowItemEthdev, RteFlowItemIpv4, Mlx5RteFlowItemSq,\
    RteFlowItemEnd
from pydiru.providers.mlx5.steering.mlx5dr_action import Mlx5drRuleAction, Mlx5drActionDestTable, \
    Mlx5drActionTemplate
from pydiru.providers.mlx5.steering.mlx5dr_rule import Mlx5drRuleAttr, Mlx5drRule
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsError
from pydiru.providers.mlx5.mlx5_flow import FlowPortInfo
from .base import BaseDrResources, PydiruTrafficTestCase
import pydiru.providers.mlx5.steering.mlx5dr_enums as me
from pyverbs.providers.mlx5.mlx5dv import Mlx5Context
from .prm_structs import SetActionIn
from pydiru.base import PydiruErrno
import pydiru.pydiru_enums as p
import unittest
import struct
import errno
import os
import csv

MLX5DR_DEBUG_RES_TYPE_MATCHER_ATTR = 4201


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
                                        root_rte_items=root_rte_items, action_types_list=actions_temp)
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
        mask = Mlx5RteFlowItemSq(qp_num=0xffffffff)
        val = Mlx5RteFlowItemSq(qp_num=self.client.qp.qp_num)
        rte_flow_item = [RteFlowItem(me.MLX5_RTE_FLOW_ITEM_TYPE_SQ, val, mask),
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

    def create_tmp_rule_and_verify(self, at_idx, actions, send_packets, exp_packet):
        """
        Creates a rule with provided actions and action template index.
        Sends and verifies packets.
        Removes the rule.
        """
        rte_items = [create_ipv4_rte_item(src_addr=PacketConsts.SRC_IP)]
        mask = Mlx5RteFlowItemSq(qp_num=0xffffffff)
        val = Mlx5RteFlowItemSq(qp_num=self.client.qp.qp_num)
        rte_items.append(RteFlowItem(me.MLX5_RTE_FLOW_ITEM_TYPE_SQ, val, mask))
        rte_items.append(RteFlowItemEnd())
        self.tmp_rule = Mlx5drRule(self.server.matcher, 0, rte_items, at_idx, actions, len(actions),
                                   Mlx5drRuleAttr(user_data=bytes(8)), self.server.dr_ctx)
        raw_traffic(self.client, self.vf, self.server.num_msgs, send_packets,
                    expected_packet=exp_packet)
        self.tmp_rule.close()

    def test_mlx5dr_fdb_actions(self):
        """
        Verify actions on fdb by creating different rules on the same non root matcher:
        Counter + Vport
        Drop
        Modify header + Vport
        Goto FT and goto Vport on the next FT
        Verify traffic on Vport using action TIR.
        """
        ib_port = self.vf_to_ib_port(self.vf_name)
        eth_rte_items = [create_eth_rte_item(), RteFlowItemEnd()]
        src_ip_rte_items = [create_ipv4_rte_item(src_addr=PacketConsts.SRC_IP)]
        mask = Mlx5RteFlowItemSq(qp_num=0xffffffff)
        val = Mlx5RteFlowItemSq(qp_num=self.client.qp.qp_num)
        qpn_rte_item = RteFlowItem(me.MLX5_RTE_FLOW_ITEM_TYPE_SQ, val, mask)
        src_ip_rte_items.append(qpn_rte_item)
        src_ip_rte_items.append(RteFlowItemEnd())
        dst_ip_items = [create_ipv4_rte_item(dst_addr=PacketConsts.DST_IP), RteFlowItemEnd()]
        action_types_list = [[me.MLX5DR_ACTION_TYP_DROP, me.MLX5DR_ACTION_TYP_LAST],
                             [me.MLX5DR_ACTION_TYP_CTR, me.MLX5DR_ACTION_TYP_VPORT,
                              me.MLX5DR_ACTION_TYP_LAST],
                             [me.MLX5DR_ACTION_TYP_MODIFY_HDR, me.MLX5DR_ACTION_TYP_VPORT,
                              me.MLX5DR_ACTION_TYP_LAST],
                             [me.MLX5DR_ACTION_TYP_FT, me.MLX5DR_ACTION_TYP_LAST]]
        self.server.init_steering_resources(rte_items=src_ip_rte_items,
                                            table_type=me.MLX5DR_TABLE_TYPE_FDB,
                                            root_rte_items=eth_rte_items,
                                            action_types_list=action_types_list)
        _, vport_ra = self.server.create_rule_action('vport', flags=me.MLX5DR_ACTION_FLAG_HWS_FDB,
                                                     vport=ib_port)
        packet = gen_packet(self.server.msg_size)
        # Create TIR rule on VF
        self.vf.init_steering_resources(rte_items=dst_ip_items)
        _, tir_ra = self.vf.create_rule_action('tir')
        self.vf.tir_rule = Mlx5drRule(self.vf.matcher, 0, dst_ip_items, 0, [tir_ra], 1,
                                      Mlx5drRuleAttr(user_data=bytes(8)), self.vf.dr_ctx)
        # Drop
        drop_ip = "1.1.1.3"
        _, drop_ra = self.server.create_rule_action('drop', flags=me.MLX5DR_ACTION_FLAG_HWS_FDB)
        packet_drop = gen_packet(self.server.msg_size, src_ip=drop_ip)
        drop_rte_items = [create_ipv4_rte_item(src_addr=drop_ip), qpn_rte_item, RteFlowItemEnd()]
        self.drop_rule = Mlx5drRule(self.server.matcher, 0, drop_rte_items, 0,
                                    [drop_ra], 1, Mlx5drRuleAttr(user_data=bytes(8)),
                                    self.server.dr_ctx)
        # Counter
        devx_counter, counter_id, counter_ra = \
            create_counter_action(self, self.server, flags=me.MLX5DR_ACTION_FLAG_HWS_FDB)
        # Verify that packet_drop is dropped and the other packet is passed
        # through counter and vport actions and reached TIR on VF.
        self.create_tmp_rule_and_verify(1, [counter_ra, vport_ra], [packet, packet_drop], packet)
        verify_counter(self, self.server, devx_counter, counter_id)

        # Modify
        smac_15_0 = 0x8888
        modify_actions = [SetActionIn(field=ModifyFieldId.OUT_SMAC_15_0,
                                      length=ModifyFieldLen.OUT_SMAC_15_0, data=smac_15_0)]
        _, modify_ra = self.server.create_rule_action('modify', log_bulk_size=12, offset=0,
                                                      actions=modify_actions,
                                                      flags=me.MLX5DR_ACTION_FLAG_HWS_FDB)
        exp_str_smac = PacketConsts.SRC_MAC[:12] + NEW_MAC_STR[12:]
        exp_src_mac = struct.pack('!6s', bytes.fromhex(exp_str_smac.replace(':', '')))
        exp_modify_packet = gen_packet(self.server.msg_size, src_mac=exp_src_mac)
        self.create_tmp_rule_and_verify(2, [modify_ra, vport_ra], [packet, packet_drop],
                                        exp_modify_packet)
        # Goto FT
        self.server.table2 = self.server.create_table(table_type=me.MLX5DR_TABLE_TYPE_FDB)
        tbl_action = Mlx5drActionDestTable(self.server.dr_ctx, self.server.table2,
                                           me.MLX5DR_ACTION_FLAG_HWS_FDB)
        tbl_ra = Mlx5drRuleAction(tbl_action)
        # Goto vport on table2
        table2_at = Mlx5drActionTemplate([me.MLX5DR_ACTION_TYP_VPORT, me.MLX5DR_ACTION_TYP_LAST])
        table2_matcher = self.server.create_matcher(self.server.table2,
                                                    self.server.matcher_templates,
                                                    [table2_at])
        self.ft_rule = Mlx5drRule(table2_matcher, 0, src_ip_rte_items, 0, [vport_ra], 1,
                                  Mlx5drRuleAttr(user_data=bytes(8)), self.server.dr_ctx)
        self.create_tmp_rule_and_verify(3, [tbl_ra], [packet, packet_drop], packet)
        self.vf.dr_ctx.dump('/tmp/hws_dump/test_mlx5dr_fdb_actions_vf')
        self.server.dr_ctx.dump('/tmp/hws_dump/test_mlx5dr_fdb_actions_fdb')

    def verify_fdb_matcher_with_flow_src(self, flow_src=me.MLX5DR_MATCHER_FLOW_SRC_ANY):
        """
        Create FDB matcher with specific flow_src.
        Use flow_dump to verify the matcher attribute.
        """

        actions = [[me.MLX5DR_ACTION_TYP_DROP, me.MLX5DR_ACTION_TYP_LAST]]
        self.server.init_steering_resources(table_type=me.MLX5DR_TABLE_TYPE_FDB,
                                            action_types_list=actions,
                                            flow_src=flow_src)
        dump_path = '/tmp/hws_flow_src_dump.csv'
        self.server.dr_ctx.dump(dump_path)
        data = {}
        self.assertTrue(os.path.isfile(dump_path), 'Dump file does not exist.')
        keys = ["mlx5dr_debug_res_type", "matcher_id", "priority", "mode", "sz_row_log",
                "sz_col_log", "use_rule_idx", "flow_src"]
        csv_file = open(dump_path, 'r+')
        csv_reader = csv.reader(csv_file)
        for line in csv_reader:
            if int(line[0]) == MLX5DR_DEBUG_RES_TYPE_MATCHER_ATTR:
                data = dict(zip(keys, line + [None] * (len(keys) - len(line))))
                # skip root matcher
                if int(data['mode']) == me.MLX5DR_MATCHER_RESOURCE_MODE_HTABLE:
                    break
        csv_file.close()
        self.assertGreater(len(data), 0, 'Empty HWS matcher attribute')
        self.assertTrue(int(data['flow_src']) == flow_src, 'Matcher attribute is not right')
        os.remove(dump_path)

    def test_mlx5dr_check_ingress_attr(self):
        """
        Create FDB ingress only matcher and check attribute
        """
        self.verify_fdb_matcher_with_flow_src(flow_src=me.MLX5DR_MATCHER_FLOW_SRC_WIRE)

    def test_mlx5dr_check_egress_attr(self):
        """
        Create FDB egress only matcher and check attribute
        """
        self.verify_fdb_matcher_with_flow_src(flow_src=me.MLX5DR_MATCHER_FLOW_SRC_VPORT)

    def test_mlx5dr_check_bidirectional_attr(self):
        """
        Create FDB bi-direction matcher and check attribute
        """
        self.verify_fdb_matcher_with_flow_src(flow_src=me.MLX5DR_MATCHER_FLOW_SRC_ANY)
