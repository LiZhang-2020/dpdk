# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

import struct
import socket
import time
import os

from pydiru.providers.mlx5.steering.mlx5dr_rule import Mlx5drRuleAttr, Mlx5drRule
from pydiru.providers.mlx5.steering.mlx5dr_action import Mlx5drActionTemplate
import pydiru.providers.mlx5.steering.mlx5dr_enums as me
from pydiru.pydiru_error import PydiruError
import pydiru.pydiru_enums as p

from .base import BaseDrResources, PydiruAPITestCase
from .utils import PacketConsts, create_sipv4_rte_items


class Mlx5drMatcherTest(PydiruAPITestCase):

    def setUp(self):
        super().setUp()
        self.resources = BaseDrResources(self.dev_name, self.ib_port)
        self.devx_objects.append(self.resources.tir_obj)

    def small_matcher(self, mode=me.MLX5DR_MATCHER_RESOURCE_MODE_RULE):
        """
        Creates a small matcher for 2 rules using rule mode or 4 rules using table
        mode and tries to add 5 rules. Two rules must fit, 4 may fit, 5 - at least
        one must return completion with error.
        """
        rte_items = create_sipv4_rte_items(PacketConsts.SRC_IP)
        at = [Mlx5drActionTemplate([me.MLX5DR_ACTION_TYP_TIR, me.MLX5DR_ACTION_TYP_LAST])]
        self.resources.init_steering_resources(rte_items=rte_items)
        if mode == me.MLX5DR_MATCHER_RESOURCE_MODE_RULE:
            matcher = self.resources.create_matcher(self.resources.table,
                                                    self.resources.matcher_templates,
                                                    at, log_rules=1)
        else:
            matcher = self.resources.create_matcher(self.resources.table,
                                                    self.resources.matcher_templates, at,
                                                    mode=me.MLX5DR_MATCHER_RESOURCE_MODE_HTABLE,
                                                    log_row=1, log_col=1)
        # Override the matcher
        self.resources.matcher = matcher
        tir_a, tir_ra = self.resources.create_rule_action('tir')
        self.rules = []
        num_of_rules = 5
        rule_attr = Mlx5drRuleAttr(user_data=bytes(8))
        sip = struct.unpack("!I", socket.inet_aton(PacketConsts.SRC_IP))[0]
        for i in range(num_of_rules):
            item = create_sipv4_rte_items(socket.inet_ntoa(struct.pack("!I", sip + i)))
            rule = Mlx5drRule(self.resources.matcher, 0, item, 0, [tir_ra], 1, rule_attr)
            self.rules.append(rule)
            res = []
            # Poll for 1 completion
            polling_timeout = 5
            start_poll_t = time.perf_counter()
            while not res and (time.perf_counter() - start_poll_t) < polling_timeout:
                res = self.resources.dr_ctx.poll_send_queue(0, 1)
            if res[0].status == p.RTE_FLOW_OP_ERROR:
                # Two rules have to fit in 2x2 table or a table for 2 rules
                if i < 2:
                    raise PydiruError(f'Failed to add {i+1} rules to table that'
                                      ' should fit them.')
                # Adding more rules than the table can fit is expected to fail
                self.logger.info(f'{i} rules fit.')
                return
        raise PydiruError(f'Sucessfully sent {num_of_rules} rules in table '
                          f'that should not fit them.')

    def test_mlx5dr_matchers_rule_based(self):
        """
        Bad flow. Create non root matcher using rule based mode for 2 rules.
        Try creating 5 rules. Expect at least one completion with error.
        """
        self.small_matcher(mode=me.MLX5DR_MATCHER_RESOURCE_MODE_RULE)

    def test_mlx5dr_matchers_table_based(self):
        """
        Bad flow. Create non root matcher 2x2 using table based mode.
        Try creating 5 rules. Expect at least one completion with error.
        """
        self.small_matcher(mode=me.MLX5DR_MATCHER_RESOURCE_MODE_HTABLE)

    def test_dr_dump_sanity(self):
        """
        Create HWS resources then open dump file and verify it's created and not
        empty.
        """
        dump_path = '/tmp/hws_dump'
        rte_items = create_sipv4_rte_items(PacketConsts.SRC_IP)
        self.resources.init_steering_resources(rte_items=rte_items)
        self.resources.dr_ctx.dump(dump_path)
        self.assertTrue(os.path.isfile(dump_path), 'Dump file does not exist.')
        self.assertGreater(os.path.getsize(dump_path), 0, 'Dump file is empty')
