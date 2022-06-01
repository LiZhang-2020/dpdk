# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022, Nvidia Inc. All rights reserved.

from pyverbs.providers.mlx5.mlx5dv_objects import Mlx5DvObj
import pyverbs.providers.mlx5.mlx5_enums as dv

from pydiru.providers.mlx5.steering.mlx5dr_action import Mlx5drRuleAction, Mlx5drActionDestTable
from pydiru.providers.mlx5.steering.mlx5dr_action import Mlx5drRuleAction, Mlx5drAsoFlowMeter
from pydiru.providers.mlx5.steering.mlx5dr_rule import Mlx5drRuleAttr, Mlx5drRule
from pydiru.providers.mlx5.steering.mlx5dr_matcher import Mlx5drMacherTemplate
from pydiru.providers.mlx5.steering.mlx5dr_action import Mlx5drActionTemplate
from pydiru.providers.mlx5.steering.mlx5dr_devx_objects import Mlx5drDevxObj
from .base import BaseDrResources, PydiruTrafficTestCase, AsoResources
from .prm_structs import FlowMeterAsoObj, FlowMeterParams
import pydiru.providers.mlx5.steering.mlx5dr_enums as me
from . import utils as u

FLOW_METER_BUCKET_OVERFLOW = 0x1
FLOW_METER_ASO = 0x24


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
