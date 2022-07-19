# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022, Nvidia Inc. All rights reserved.

from pyverbs.providers.mlx5.mlx5dv_objects import Mlx5DvObj
import pyverbs.providers.mlx5.mlx5_enums as dv

from pydiru.providers.mlx5.steering.mlx5dr_action import Mlx5drRuleAction, Mlx5drActionDestTable
from pydiru.providers.mlx5.steering.mlx5dr_action import Mlx5drRuleAction, Mlx5drAsoFlowMeter, \
    Mlx5drActionCtAso
from pydiru.providers.mlx5.steering.mlx5dr_rule import Mlx5drRuleAttr, Mlx5drRule
from pydiru.providers.mlx5.steering.mlx5dr_matcher import Mlx5drMacherTemplate
from pydiru.providers.mlx5.steering.mlx5dr_action import Mlx5drActionTemplate
from pydiru.providers.mlx5.steering.mlx5dr_devx_objects import Mlx5drDevxObj
from .base import BaseDrResources, PydiruTrafficTestCase, AsoResources
from .prm_structs import FlowMeterAsoObj, FlowMeterParams, ConnTrackOffload, ConnTrackAso
import pydiru.providers.mlx5.steering.mlx5dr_enums as me
from . import utils as u

import random

FLOW_METER_BUCKET_OVERFLOW = 0x1
FLOW_METER_ASO = 0x24
CT_ASO = 0x31
CT_VALID_SYND = 0x1
CT_INVALID_SYND = 0x80


class Mlx5drAsoTest(PydiruTrafficTestCase):

    def setUp(self):
        super().setUp()
        self.server = BaseDrResources(self.dev_name, self.ib_port)
        self.client = BaseDrResources(self.dev_name, self.ib_port)
        self.devx_objects.append(self.server.tir_obj)
        self.devx_objects.append(self.client.tir_obj)

    @staticmethod
    def get_flow_meter_reg_id(dv_ctx):
        """
        Queries hca caps for supported reg C indexes for flow meter.
        :param dv_ctx: Devx context
        :return: List of supported reg C indexes
        """
        query_cap_out = u.get_qos_caps(dv_ctx)
        bit_regs = query_cap_out.capability.flow_meter_reg_id
        result = []
        for i in range(0, bit_regs.bit_length()):
            if bit_regs & (1 << i) != 0:
                result.append(i)
        return result

    @staticmethod
    def create_flow_meter_aso_obj(agr_obj, meter_params=[]):
        """
        Creates ASO flow meter object
        :param agr_obj: Aggregation object
        :param meter_params: Array with flow meter parameters
        :return: ASO flow meter object and its object ID
        """
        pd = agr_obj.pd
        dv_pd = Mlx5DvObj(dv.MLX5DV_OBJ_PD, pd=pd).dvpd
        flow_meter_aso = FlowMeterAsoObj(modify_field_select=0, flow_hit_aso_access_pd=dv_pd.pdn,
                                         flow_meter_parameters=meter_params)
        general_obj, obj_id = u.create_devx_general_object(agr_obj.dv_ctx, FLOW_METER_ASO,
                                                           flow_meter_aso)
        return general_obj, obj_id

    def create_aso_flow_meter_ra(self, flag, reg_c):
        meter_params = []
        meter_params.append(FlowMeterParams(valid=0x1, bucket_overflow=FLOW_METER_BUCKET_OVERFLOW,
                                            start_color=me.MLX5DR_ACTION_ASO_METER_COLOR_GREEN,
                                            cir_mantissa=1,  # 8 * (10 ^9) * 1 * 2^(-1 * 6) bps
                                            cir_exponent=6)) # 15.625MBps
        meter_params.append(FlowMeterParams(valid=0x1, bucket_overflow=FLOW_METER_BUCKET_OVERFLOW,
                                            start_color=me.MLX5DR_ACTION_ASO_METER_COLOR_UNDEFINED,
                                            cir_mantissa=1,  # 8 * (10^9) * 1 * 2^(-6) bps
                                            cir_exponent=6)) # 15.625MBps
        if flag == me.MLX5DR_ACTION_FLAG_HWS_TX:
            agr_obj = self.client
            index = 0
        else:
            agr_obj = self.server
            index = 1
        # Create ASO flow meters
        devx_aso_obj, obj_id = self.create_flow_meter_aso_obj(agr_obj, [FlowMeterParams(valid=0x1),
                                                              FlowMeterParams(valid=0x1)])
        self.logger.debug(f'Flow Meter ASO object with ID {obj_id} is created.')
        self.devx_objects.append(devx_aso_obj)
        # Init ASO flow meters
        aso_res = AsoResources(agr_obj.dv_ctx, agr_obj.pd, agr_obj.ib_port)
        aso_res.configure_aso_object(meter_params[index], obj_id)
        dr_aso_obj = Mlx5drDevxObj(devx_aso_obj, obj_id)
        flow_meter_action = Mlx5drAsoFlowMeter(agr_obj.dr_ctx, dr_aso_obj, flag, reg_c=reg_c)
        return Mlx5drRuleAction(flow_meter_action,
                                meter_init_color=me.MLX5DR_ACTION_ASO_METER_COLOR_GREEN,
                                offset=0)

    @staticmethod
    def verify_meter_counters(green_devx_counter, green_counter_id, red_devx_counter, red_counter_id):
        packets, octets = u.query_counter(green_devx_counter, green_counter_id, 0)
        green_rate = octets / 1000000 / 3
        error_margin = 1.1  # Set error to 10%
        assert(green_rate <= 15.625 * error_margin), f'Actual green rate is {green_rate}.'
        assert(green_rate > 12), f'Actual green rate is {green_rate}.'
        packets, octets = u.query_counter(red_devx_counter, red_counter_id, 0)
        red_rate = octets / 1000000 / 3
        assert(green_rate < red_rate), f'Actual green rate is {green_rate} and red rate is {red_rate}.'

    def create_aso_rules(self, agr_obj, flag, rte_items, fm_ra, counter_green_ra, counter_red_ra, reg_c):
        table_type = me.MLX5DR_TABLE_TYPE_NIC_RX if flag == me.MLX5DR_ACTION_FLAG_HWS_RX \
                else me.MLX5DR_TABLE_TYPE_NIC_TX
        at = [Mlx5drActionTemplate(
            [me.MLX5DR_ACTION_TYP_CTR, me.MLX5DR_ACTION_TYP_LAST])]
        agr_obj.tbl2 = agr_obj.create_table(level=2, table_type=table_type)
        agr_obj.table2_a = Mlx5drActionDestTable(agr_obj.dr_ctx, agr_obj.tbl2, flag)
        agr_obj.t_ra = Mlx5drRuleAction(agr_obj.table2_a)
        # Create rule with aso flow meter and forward actions
        agr_obj.aso_rule = Mlx5drRule(agr_obj.matcher, 0, rte_items, 0, [fm_ra, agr_obj.t_ra], 2,
                                      Mlx5drRuleAttr(user_data=bytes(8)), agr_obj.dr_ctx)
        # Create counter rules on table 2
        green_rte = u.create_reg_c_rte_items(me.MLX5DR_ACTION_ASO_METER_COLOR_GREEN, reg_c + 3)
        reg_c_matcher_template = [Mlx5drMacherTemplate(green_rte,
                                                       flags=me.MLX5DR_MATCH_TEMPLATE_FLAG_RELAXED_MATCH)]
        agr_obj.matcher2 = agr_obj.create_matcher(agr_obj.tbl2, reg_c_matcher_template, at)
        agr_obj.green_rule = Mlx5drRule(agr_obj.matcher2, 0, green_rte, 0, [counter_green_ra], 1,
                                        Mlx5drRuleAttr(user_data=bytes(8)), agr_obj.dr_ctx)
        red_rte = u.create_reg_c_rte_items(me.MLX5DR_ACTION_ASO_METER_COLOR_RED, reg_c + 3)
        agr_obj.red_rule = Mlx5drRule(agr_obj.matcher2, 0, red_rte, 0, [counter_red_ra], 1,
                                      Mlx5drRuleAttr(user_data=bytes(8)), agr_obj.dr_ctx)

    def test_mlx5dr_aso_flow_meter(self):
        """
        Create rules with ASO flow meter configured to 15MBps both on RX and TX non root tables.
        Create rules with counters to calculate RED and Green packets. Send traffic with rate above
        30Mbps and check green and red packets rates on TX nad RX.
        """
        actions_types = [[me.MLX5DR_ACTION_TYP_ASO_METER, me.MLX5DR_ACTION_TYP_FT,
                    me.MLX5DR_ACTION_TYP_LAST]]
        rte_items = u.create_sipv4_rte_items(u.PacketConsts.SRC_IP)
        # RX
        self.server.init_steering_resources(rte_items=rte_items, action_types_list=actions_types)
        regs = self.get_flow_meter_reg_id(self.server.dv_ctx)
        reg_c_rx=regs[0]
        rx_fm_ra = self.create_aso_flow_meter_ra(me.MLX5DR_ACTION_FLAG_HWS_RX, reg_c=reg_c_rx)
        green_devx_counter_rx, green_counter_id_rx, counter_green_ra_rx = \
            u.create_counter_action(self, self.server, flags=me.MLX5DR_ACTION_FLAG_HWS_RX)
        red_devx_counter_rx, red_counter_id_rx, counter_red_ra_rx = \
            u.create_counter_action(self, self.server, flags=me.MLX5DR_ACTION_FLAG_HWS_RX)
        self.create_aso_rules(self.server, me.MLX5DR_ACTION_FLAG_HWS_RX, rte_items, rx_fm_ra,
                              counter_green_ra_rx, counter_red_ra_rx, reg_c_rx)
        # TX
        self.client.init_steering_resources(rte_items=rte_items, action_types_list=actions_types,
                                    table_type=me.MLX5DR_TABLE_TYPE_NIC_TX)
        reg_c_tx=regs[1]
        tx_fm_ra = self.create_aso_flow_meter_ra(me.MLX5DR_ACTION_FLAG_HWS_TX, reg_c=reg_c_tx)
        green_devx_counter_tx, green_counter_id_tx, counter_green_ra_tx = \
            u.create_counter_action(self, self.client, flags=me.MLX5DR_ACTION_FLAG_HWS_TX)
        red_devx_counter_tx, red_counter_id_tx, counter_red_ra_tx = \
            u.create_counter_action(self, self.client, flags=me.MLX5DR_ACTION_FLAG_HWS_TX)

        self.create_aso_rules(self.client, me.MLX5DR_ACTION_FLAG_HWS_TX, rte_items, tx_fm_ra,
                              counter_green_ra_tx, counter_red_ra_tx, reg_c_tx)
        self.server.dr_ctx.dump('/tmp/hws_dump/test_mlx5dr_aso_flow_meter_rx')
        self.client.dr_ctx.dump('/tmp/hws_dump/test_mlx5dr_aso_flow_meter_tx')
        # Lower message size to keep sending rate not too high
        self.client.msg_size = 500
        packet = u.gen_packet(self.client.msg_size)
        # We want to send at least at 30MBps speed
        rate_limit = 30
        u.high_rate_send(self.client, packet, rate_limit)
        self.verify_meter_counters(green_devx_counter_rx, green_counter_id_rx,
                                   red_devx_counter_rx, red_counter_id_rx)
        self.verify_meter_counters(green_devx_counter_tx, green_counter_id_tx,
                                   red_devx_counter_tx, red_counter_id_tx)

    @staticmethod
    def create_ct_aso_obj(agr_obj, ct_aso_param):
        """
        Creates CT ASO DEVX object
        :param agr_obj: Aggregation object
        :return: CT ASO object and its object ID
        """
        pd = agr_obj.pd
        dv_pd = Mlx5DvObj(dv.MLX5DV_OBJ_PD, pd=pd).dvpd
        ct_aso_obj = ConnTrackOffload(conn_track_aso_access_pd=dv_pd.pdn,
                                      conn_track_aso=ct_aso_param)
        # log_obj_range: Log (base 2) of the range of objects referenced
        # by the command.
        # For CREATE, this field indicates the amount of
        # consecutive objects to create.
        # This param must be 6 in order to successfully create the object otherwise
        # it fails with bad param syndrome
        general_obj, obj_id = u.create_devx_general_object(agr_obj.dv_ctx,
                                                           CT_ASO, ct_aso_obj,
                                                           log_obj_range=6)
        return general_obj, obj_id

    def create_ct_aso_ra(self, reg_c, syndrome, flag=me.MLX5DR_ACTION_FLAG_HWS_RX):
        """
        Create CT ASO rule action and enables the CT ASO feature
        :param reg_c: Register C index to use for CT ASO syndromes
        :param syndrome: Indicate what syndrome to validate
        :param flag: Action type
        :return: CT ASO rule action
        """
        if flag == me.MLX5DR_ACTION_FLAG_HWS_TX:
            agr_obj = self.client
            direction = me.MLX5DR_ACTION_ASO_CT_DIRECTION_INITIATOR
        else:
            agr_obj = self.server
            direction = me.MLX5DR_ACTION_ASO_CT_DIRECTION_RESPONDER
        # Create CT ASO
        ct_aso_param = ConnTrackAso(valid=1, state=1)
        devx_aso_obj, obj_id = self.create_ct_aso_obj(agr_obj, ct_aso_param)
        self.logger.debug(f'CT ASO object with ID {obj_id} is created.')
        self.devx_objects.append(devx_aso_obj)
        # Init ASO resources
        if syndrome == CT_VALID_SYND:
            aso_res = AsoResources(agr_obj.dv_ctx, agr_obj.pd, agr_obj.ib_port)
            aso_res.configure_aso_object(ct_aso_param, obj_id, 'ct')
        dr_aso_obj = Mlx5drDevxObj(devx_aso_obj, obj_id)
        ct_action = Mlx5drActionCtAso(agr_obj.dr_ctx, dr_aso_obj, flag, reg_c=reg_c)
        return Mlx5drRuleAction(ct_action, direction=direction, offset=0)

    def hws_ct_aso(self, synd=CT_VALID_SYND):
        """
        Validate CT ASO action on RX and TX sides:
        TX: Create TX root table and forward all traffic to non root, on non
        root match on sip with actions CT ASO and forward to FT, on the next
        table match on syndrome which is stored in reg C with counter action,
        validate counter with expected octets and number of packets.
        RX: Create RX root table and forward all traffic to non root, on
        non-root match on sip with actions CT ASO and forward to FT, on the next
        table match on syndrome which is stored in reg C and then forward to
        TIR and validate packets.
        :param synd: Syndrome to match on reg C
        """
        actions_types = [[me.MLX5DR_ACTION_TYP_ASO_CT, me.MLX5DR_ACTION_TYP_FT,
                          me.MLX5DR_ACTION_TYP_LAST]]
        rte_items = u.create_sipv4_rte_items(u.PacketConsts.SRC_IP)
        self.server.init_steering_resources(rte_items=rte_items,
                                            action_types_list=actions_types)
        self.client.init_steering_resources(rte_items=rte_items, action_types_list=actions_types,
                                            table_type=me.MLX5DR_TABLE_TYPE_NIC_TX)
        regs = self.get_flow_meter_reg_id(self.server.dv_ctx)
        # TX
        reg_c_tx = regs[0]
        tx_ct_ra = self.create_ct_aso_ra(reg_c_tx, synd, me.MLX5DR_ACTION_FLAG_HWS_TX)
        tx_tbl2 = self.client.create_table(level=2, table_type=me.MLX5DR_TABLE_TYPE_NIC_TX)
        tx_tbl2_a = Mlx5drActionDestTable(self.client.dr_ctx, tx_tbl2,
                                          me.MLX5DR_ACTION_FLAG_HWS_TX)
        tx_tbl2_ra = Mlx5drRuleAction(tx_tbl2_a)
        ct_aso_rule2 = Mlx5drRule(self.client.matcher, 0, rte_items, 0, [tx_ct_ra, tx_tbl2_ra], 2,
                                  Mlx5drRuleAttr(user_data=bytes(8)), self.client.dr_ctx)
        counter_at = [Mlx5drActionTemplate([me.MLX5DR_ACTION_TYP_CTR, me.MLX5DR_ACTION_TYP_LAST])]
        devx_counter_tx, counter_id_tx, counter_ra_tx = \
            u.create_counter_action(self, self.client, flags=me.MLX5DR_ACTION_FLAG_HWS_TX)
        reg_c_rte2 = u.create_reg_c_rte_items(synd, reg_c_tx + 3)
        reg_c_mt_tx = [Mlx5drMacherTemplate(reg_c_rte2,
                                            flags=me.MLX5DR_MATCH_TEMPLATE_FLAG_RELAXED_MATCH)]
        tx_matcher2 = self.client.create_matcher(tx_tbl2, reg_c_mt_tx, counter_at)
        tx_ctr_rule = Mlx5drRule(tx_matcher2, 0, reg_c_rte2, 0, [counter_ra_tx], 1,
                                 Mlx5drRuleAttr(user_data=bytes(8)), self.client.dr_ctx)
        # RX
        reg_c_rx = regs[1]
        rx_ct_ra = self.create_ct_aso_ra(reg_c_rx, synd)
        rx_tbl2 = self.server.create_table(level=2, table_type=me.MLX5DR_TABLE_TYPE_NIC_RX)
        rx_tbl2_a = Mlx5drActionDestTable(self.server.dr_ctx, rx_tbl2,
                                          me.MLX5DR_ACTION_FLAG_HWS_RX)
        rx_tbl2_ra = Mlx5drRuleAction(rx_tbl2_a)
        rx_aso_rule = Mlx5drRule(self.server.matcher, 0, rte_items, 0, [rx_ct_ra, rx_tbl2_ra], 2,
                                 Mlx5drRuleAttr(user_data=bytes(8)), self.server.dr_ctx)
        tir_at = [Mlx5drActionTemplate([me.MLX5DR_ACTION_TYP_TIR, me.MLX5DR_ACTION_TYP_LAST])]
        tir_a, tir_ra = self.server.create_rule_action('tir')
        reg_c_rte = u.create_reg_c_rte_items(synd, reg_c_rx + 3)
        reg_c_matcher_template = [Mlx5drMacherTemplate(reg_c_rte,
                                                       flags=me.MLX5DR_MATCH_TEMPLATE_FLAG_RELAXED_MATCH)]
        rx_matcher2 = self.server.create_matcher(rx_tbl2, reg_c_matcher_template, tir_at)
        rx_tir_rule = Mlx5drRule(rx_matcher2, 0, reg_c_rte, 0, [tir_ra], 1,
                                 Mlx5drRuleAttr(user_data=bytes(8)), self.server.dr_ctx)
        if synd == CT_VALID_SYND:
            self.server.dr_ctx.dump('/tmp/hws_dump/test_mlx5dr_ct_aso_valid_rx')
            self.client.dr_ctx.dump('/tmp/hws_dump/test_mlx5dr_ct_aso_valid_tx')
        packet = u.gen_packet(self.server.msg_size)
        u.raw_traffic(self.client, self.server, self.server.num_msgs, [packet])
        u.verify_counter(self, self.client, devx_counter_tx, counter_id_tx)

    def test_mlx5dr_ct_aso_valid(self):
        """
        CT ASO action on TX and RX with valid syndrome matching on reg C
        """
        self.hws_ct_aso()

    def test_mlx5dr_ct_aso_invalid(self):
        """
        CT ASO action on TX and RX with invalid syndrome matching on reg C
        """
        self.hws_ct_aso(synd=CT_INVALID_SYND)
