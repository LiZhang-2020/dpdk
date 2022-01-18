#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

import unittest
import logging

from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr
from pyverbs.providers.mlx5.mlx5dv import Mlx5DevxObj
from pyverbs.qp import QPInitAttr, QPAttr, QP, QPCap
from pyverbs.providers.mlx5 import mlx5_enums as dv
from pyverbs.wq import WQ, WQInitAttr, WQAttr
from pyverbs import enums as v
import pyverbs.device as d
from pyverbs.pd import PD
from pyverbs.cq import CQ
from pyverbs.mr import MR

from pydiru.providers.mlx5.steering.mlx5dr_matcher import Mlx5drMacherTemplate, Mlx5drMatcherAttr, Mlx5drMatcher
from pydiru.providers.mlx5.steering.mlx5dr_action import Mlx5drRuleAction, \
    Mlx5drActionDestTable, Mlx5drActionDestTir, Mlx5drActionTag, Mlx5drActionDefaultMiss, \
    Mlx5drActionReformat, Mlx5drActionCounter, Mlx5drActionDrop
from pydiru.providers.mlx5.steering.mlx5dr_context import Mlx5drContextAttr, Mlx5drContext
from pydiru.providers.mlx5.steering.mlx5dr_table import Mlx5drTableAttr, Mlx5drTable
from pydiru.providers.mlx5.steering.mlx5dr_rule import Mlx5drRuleAttr, Mlx5drRule
from pydiru.providers.mlx5.steering.mlx5dr_devx_objects import Mlx5drDevxObj
import pydiru.providers.mlx5.steering.mlx5dr_enums as me

from .prm_structs import Tirc, CreateTirIn
from .utils import MAX_DIFF_PACKETS
from args_parser import parser

NUM_OF_QUEUES = 16
QUEUE_SIZE = 256
MATCHER_ROW = 5


class PydiruAPITestCase(unittest.TestCase):
    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
        # Hold the command line arguments
        self.config = parser.get_config()
        self.dev_name = None
        self.ctx = None
        # DevX objects should be stored in-order here, to be freed after closing
        # DR context, and before closing the verbs context
        self.devx_objects = []

    def setUp(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.INFO)
        self.ib_port = self.config['port']
        self.dev_name = self.config['dev']
        if not self.dev_name:
            dev_list = d.get_device_list()
            if not dev_list:
                raise unittest.SkipTest('No IB devices found')
            self.dev_name = dev_list[0].name.decode()

        Mlx5drContext.rte_init(self.config)
        self.ctx = d.Context(name=self.dev_name)

    def tearDown(self):
        if self.resources:
            self.resources.dr_ctx.close()
        for obj in self.devx_objects:
            obj.close()
        self.ctx.close()


class PydiruTrafficTestCase(unittest.TestCase):
    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
        # Hold the command line arguments
        self.config = parser.get_config()
        self.dev_name = None
        self.ib_port = None
        self.ctx = None
        self.attr = None
        self.attr_ex = None
        self.server = None
        self.client = None
        # DevX objects should be stored in-order here, to be freed after closing
        # DR context, and before closing the verbs context
        self.devx_objects = []

    def setUp(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.INFO)
        self.ib_port = self.config['port']
        self.dev_name = self.config['dev']
        if not self.dev_name:
            dev_list = d.get_device_list()
            if not dev_list:
                raise unittest.SkipTest('No IB devices found')
            self.dev_name = dev_list[0].name.decode()

        Mlx5drContext.rte_init(self.config)
        self.ctx = d.Context(name=self.dev_name)
        self.attr = self.ctx.query_device()
        self.attr_ex = self.ctx.query_device_ex()

    def tearDown(self):
        if self.server:
            self.server.dr_ctx.close()
        if self.client:
            self.client.dr_ctx.close()
        for obj in self.devx_objects:
            obj.close()
        self.ctx.close()


class BaseDrResources(object):
    """
    Basic DR resources class. It provides the basic RDMA resources and basic HW
    Steering functionality and its resources.
    """
    def __init__(self, dev_name, ib_port, qp_count=1, msg_size=1024, num_msgs=10):
        """
        Initializes a BaseDrResources object with the given values.
        :param dev_name: Device name to be used.
        :param ib_port: IB port of the device.
        :param qp_count: Number of QPs to create. Use 1 as default.
        :param msg_size: Size of a msg to send/receive. Use 1024 as default.
        :param num_msgs: number of msgs to send/receive. Use 10 as default.
        """
        self.dev_name = dev_name
        self.ib_port = ib_port
        self.msg_size = msg_size
        self.num_msgs = num_msgs
        self.qp_count = qp_count
        self.dv_ctx = None
        self.dr_ctx = None
        self.tir_obj = None
        self.tir_dr_devx_obj = None
        self.pd = None
        self.mr = None
        self.cq = None
        self.qp = None
        self.wq = None
        self.init_rdma_resources()

    def create_mlx5dv_context(self):
        ctx_attr = Mlx5DVContextAttr(dv.MLX5DV_CONTEXT_FLAGS_DEVX)
        self.dv_ctx = Mlx5Context(ctx_attr, name=self.dev_name)

    def create_mlx5dr_context(self):
        ctx_attr = Mlx5drContextAttr(NUM_OF_QUEUES, QUEUE_SIZE)
        self.dr_ctx = Mlx5drContext(self.dv_ctx, ctx_attr)

    def create_pd(self):
        self.pd = PD(self.dv_ctx)

    def create_cq(self):
        self.cq = CQ(self.dv_ctx, self.num_msgs * MAX_DIFF_PACKETS)

    def create_mr(self):
        self.mr = MR(self.pd, self.msg_size * MAX_DIFF_PACKETS, v.IBV_ACCESS_LOCAL_WRITE)

    def create_qp(self):
        qp_init_attr = QPInitAttr(qp_type=v.IBV_QPT_RAW_PACKET, scq=self.cq, rcq=self.cq,
                                  cap=QPCap(max_recv_wr=self.num_msgs * MAX_DIFF_PACKETS,
                                            max_send_wr=self.num_msgs * MAX_DIFF_PACKETS))
        qp_attr = QPAttr(port_num=self.ib_port)
        self.qp = QP(self.pd, qp_init_attr, qp_attr)

    def create_wq(self):
        wq_attrs = WQInitAttr(self.dv_ctx, self.pd, self.cq, wq_type=v.IBV_WQT_RQ,
                              max_wr=self.num_msgs * MAX_DIFF_PACKETS,
                              max_sge=self.dv_ctx.query_device().max_sge)
        self.wq = WQ(self.dv_ctx, wq_attrs)
        self.wq.modify(WQAttr(attr_mask=v.IBV_WQ_ATTR_STATE, wq_state=v.IBV_WQS_RDY))

    def create_tir(self):
        ctx = Tirc(inline_rqn=self.wq.wqn)
        create_tir = CreateTirIn(tir_context=ctx)
        self.tir_obj = Mlx5DevxObj(self.dv_ctx, create_tir, len(create_tir))
        tirn = int(self.tir_obj.out_view[9:12].hex(), 16)
        self.tir_dr_devx_obj = Mlx5drDevxObj(self.tir_obj, tirn)

    def init_rdma_resources(self):
        self.create_mlx5dv_context()
        self.create_mlx5dr_context()
        self.create_pd()
        self.create_cq()
        self.create_mr()
        self.create_qp()
        self.create_wq()
        self.create_tir()

    def create_table(self, level=1, table_type=me.MLX5DR_TABLE_TYPE_NIC_RX):
        attr = Mlx5drTableAttr(table_type, level)
        return Mlx5drTable(self.dr_ctx, attr)

    def create_matcher(self, table, matcher_templates,
                       mode=me.MLX5DR_MATCHER_RESOURCE_MODE_RULE,
                       prio=1, log_row=0, log_col=0, log_rules=2):
        attr = Mlx5drMatcherAttr(prio, mode, log_row, log_col, log_rules)
        return Mlx5drMatcher(table, matcher_templates, len(matcher_templates), attr)

    def create_root_fwd_rule(self, rte_items, level=1, table_type=me.MLX5DR_TABLE_TYPE_NIC_RX,
                             prio=1, action_flag=me.MLX5DR_ACTION_FLAG_ROOT_RX):
        self.root_matcher_templates.append([Mlx5drMacherTemplate(rte_items)])
        root_matcher = self.create_matcher(self.root_table, self.root_matcher_templates[-1],
                                           prio=prio)
        table = self.create_table(table_type=table_type, level=level)
        tbl_action = Mlx5drActionDestTable(self.dr_ctx, table, action_flag)
        root_ra = Mlx5drRuleAction(tbl_action)
        rule = Mlx5drRule(root_matcher, 0, rte_items, [root_ra], 1,
                                        Mlx5drRuleAttr(user_data=bytes(8)), self.dr_ctx)
        return root_matcher, table, rule

    def init_steering_resources(self, rte_items=None, table_type=me.MLX5DR_TABLE_TYPE_NIC_RX,
                                root_rte_items=None):
        """
        Init the basic steering resources.
        :param rte_items: The rte_items to use in the matchers. If not set, use sipv4 rte item.
        :param table_type: The tables type.
        :param root_rte_items: rte_items to use in the root matcher. If not set,
                               use rte_items for both root and non-root matchers
        """
        if rte_items is None:
            rte_items = self.create_sipv4_rte_item()
        self.root_table = self.create_table(0, table_type=table_type)
        self.table = self.create_table(table_type=table_type)
        root_rte_items = root_rte_items if root_rte_items is not None else rte_items
        # Create root rule.
        self.root_matcher_templates = []
        self.root_matcher, self.table, self.root_dest_tbl_rule = \
            self.create_root_fwd_rule(root_rte_items, level=1, table_type=table_type)

        template_relaxed_match = me.MLX5DR_MATCH_TEMPLATE_FLAG_RELAXED_MATCH
        # Create table 1 matcher.
        self.matcher_templates = [Mlx5drMacherTemplate(rte_items, flags=template_relaxed_match)]
        self.matcher = self.create_matcher(self.table, self.matcher_templates, log_row=MATCHER_ROW,
                                           mode=me.MLX5DR_MATCHER_RESOURCE_MODE_HTABLE)

    def create_second_matcher(self, rte_items):
        template_relaxed_match = me.MLX5DR_MATCH_TEMPLATE_FLAG_RELAXED_MATCH
        self.second_matcher_templates = [Mlx5drMacherTemplate(rte_items, flags=template_relaxed_match)]
        self.second_matcher = \
            self.create_matcher(self.table, self.second_matcher_templates, log_row=MATCHER_ROW,
                                mode=me.MLX5DR_MATCHER_RESOURCE_MODE_HTABLE, prio=1)

    def create_rule_action(self, action_str, flags=me.MLX5DR_ACTION_FLAG_HWS_RX, **kwargs):
        if action_str == 'tir':
            action = Mlx5drActionDestTir(self.dr_ctx, self.tir_dr_devx_obj,
                                         flags)
        elif action_str == 'tag':
            action = Mlx5drActionTag(self.dr_ctx, flags)
        elif action_str == 'def_miss':
            action = Mlx5drActionDefaultMiss(self.dr_ctx, flags)
        elif action_str == 'drop':
            action = Mlx5drActionDrop(self.dr_ctx, flags)
        elif action_str == 'reformat':
            ref_type = kwargs.get('ref_type', me.MLX5DR_ACTION_REFORMAT_TYPE_TNL_L2_TO_L2)
            data = kwargs.get('data')
            data_sz = kwargs.get('data_sz', 0)
            log_bulk_size = kwargs.get('log_bulk_size', 0)
            action = Mlx5drActionReformat(self.dr_ctx, ref_type, data_sz, data, log_bulk_size, flags)
            return action, Mlx5drRuleAction(action, data=data)
        elif action_str == 'counter':
            mlx5_dr_counter = kwargs.get('dr_counter')
            action = Mlx5drActionCounter(self.dr_ctx, mlx5_dr_counter, flags)
        else:
            raise unittest.SkipTest(f'Unsupported action {action_str}')
        return action, Mlx5drRuleAction(action)
