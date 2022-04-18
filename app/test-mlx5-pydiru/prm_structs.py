#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from scapy.fields import BitField, ByteField, IntField, \
     ShortField, LongField, StrFixedLenField, PacketField, \
     FieldListField
from scapy.packet import Packet


class DevxOps:
    MLX5_CMD_OP_QUERY_HCA_CAP                 = 0x100
    MLX5_CMD_OP_CREATE_TIR                    = 0x900
    MLX5_CMD_OP_MODIFY_TIR                    = 0x901
    MLX5_CMD_OP_DESTROY_TIR                   = 0x902
    MLX5_CMD_OP_QUERY_TIR                     = 0x903
    MLX5_CMD_OP_ALLOC_FLOW_COUNTER            = 0x939
    MLX5_CMD_OP_QUERY_FLOW_COUNTER            = 0x93b


de = DevxOps()


class HcaCapOpMod:
    QOS_CAPS = 0xc


class RxHashFieldSelect(Packet):
    fields_desc = [
        BitField('l3_prot_type', 0, 1),
        BitField('l4_prot_type', 0, 1),
        BitField('selected_fields', 0, 30),
    ]


class Tirc(Packet):
    fields_desc = [
        StrFixedLenField('reserved1', None, length=4),
        BitField('disp_type', 0, 4),
        BitField('tls_en', 0, 1),
        BitField('nvmeotcp_zerocopy_en', 0, 1),
        BitField('nvmeotcp_crc_en', 0, 1),
        BitField('reserved2', 0, 25),
        StrFixedLenField('reserved3', None, length=8),
        BitField('reserved4', 0, 4),
        BitField('lro_timeout_period_usecs', 0, 16),
        BitField('lro_enable_mask', 0, 4),
        ByteField('lro_max_msg_sz', 0),
        ByteField('reserved5', 0),
        BitField('afu_id', 0, 24),
        BitField('inline_rqn_vhca_id_valid', 0, 1),
        BitField('reserved6', 0, 15),
        ShortField('inline_rqn_vhca_id', 0),
        BitField('reserved7', 0, 5),
        BitField('inline_q_type', 0, 3),
        BitField('inline_rqn', 0, 24),
        BitField('rx_hash_symmetric', 0, 1),
        BitField('reserved8', 0, 1),
        BitField('tunneled_offload_en', 0, 1),
        BitField('reserved9', 0, 5),
        BitField('indirect_table', 0, 24),
        BitField('rx_hash_fn', 0, 4),
        BitField('reserved10', 0, 2),
        BitField('self_lb_en', 0, 2),
        BitField('transport_domain', 0, 24),
        FieldListField('rx_hash_toeplitz_key', [0 for x in range(10)], IntField('', 0), count_from=lambda pkt:10),
        PacketField('rx_hash_field_selector_outer', RxHashFieldSelect(), RxHashFieldSelect),
        PacketField('rx_hash_field_selector_inner', RxHashFieldSelect(), RxHashFieldSelect),
        IntField('nvmeotcp_tag_buffer_table_id', 0),
        StrFixedLenField('reserved11', None, length=148),
    ]


class CreateTirIn(Packet):
    fields_desc = [
        ShortField('opcode', de.MLX5_CMD_OP_CREATE_TIR),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        StrFixedLenField('reserved2', None, length=24),
        PacketField('tir_context', Tirc(), Tirc),
    ]


class CreateTirOut(Packet):
    fields_desc = [
        ByteField('status', 0),
        BitField('icm_address_63_40', 0, 24),
        IntField('syndrome', 0),
        ByteField('icm_address_39_32', 0),
        BitField('tirn', 0, 24),
        IntField('icm_address_31_0', 0),
    ]


class ModifyTirIn(Packet):
    fields_desc = [
        ShortField('opcode', de.MLX5_CMD_OP_MODIFY_TIR),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        ByteField('reserved2', 0),
        BitField('tirn', 0, 24),
        StrFixedLenField('reserved3', None, length=4),
        LongField('modify_bitmask', 0),
        StrFixedLenField('reserved4', None, length=8),
        PacketField('tir_context', Tirc(), Tirc),
    ]


class ModifyTirOut(Packet):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        StrFixedLenField('reserved2', None, length=8),
    ]


class DestroyTirIn(Packet):
    fields_desc = [
        ShortField('opcode', de.MLX5_CMD_OP_DESTROY_TIR),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        ByteField('reserved2', 0),
        BitField('tirn', 0, 24),
        StrFixedLenField('reserved3', None, length=4),
    ]


class DestroyTirOut(Packet):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        StrFixedLenField('reserved2', None, length=8),
    ]


class QueryTirIn(Packet):
    fields_desc = [
        ShortField('opcode', de.MLX5_CMD_OP_QUERY_TIR),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        ByteField('reserved2', 0),
        BitField('tirn', 0, 24),
        StrFixedLenField('reserved3', None, length=4),
    ]


class QueryTirOut(Packet):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        StrFixedLenField('reserved2', None, length=24),
        PacketField('tir_context', Tirc(), Tirc),
    ]


class SetActionIn(Packet):
    fields_desc = [
        BitField('action_type', 0, 4),
        BitField('field', 0, 12),
        BitField('reserved1', 0, 3),
        BitField('offset', 0, 5),
        BitField('reserved2', 0, 3),
        BitField('length', 0, 5),
        IntField('data', 0),
    ]


class CopyActionIn(Packet):
    fields_desc = [
        BitField('action_type', 3, 4),
        BitField('src_field', 0, 12),
        BitField('reserved1', 0, 3),
        BitField('src_offset', 0, 5),
        BitField('reserved2', 0, 3),
        BitField('length', 0, 5),
        BitField('reserved3', 0, 4),
        BitField('dst_field', 0, 12),
        BitField('reserved4', 0, 3),
        BitField('dst_offset', 0, 5),
        ByteField('reserved5', 0),
    ]


class AddActionIn(Packet):
    fields_desc = [
        BitField('action_type', 2, 4),
        BitField('field', 0, 12),
        ShortField('reserved1', 0),
        IntField('data', 0),
    ]


class AllocFlowCounterIn(Packet):
    fields_desc = [
        ShortField('opcode', de.MLX5_CMD_OP_ALLOC_FLOW_COUNTER),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        IntField('flow_counter_id', 0),
        BitField('reserved2', 0, 24),
        ByteField('flow_counter_bulk', 0),
    ]


class AllocFlowCounterOut(Packet):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        IntField('flow_counter_id', 0),
        StrFixedLenField('reserved2', None, length=4),
    ]


class QueryFlowCounterIn(Packet):
    fields_desc = [
        ShortField('opcode', de.MLX5_CMD_OP_QUERY_FLOW_COUNTER),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        StrFixedLenField('reserved2', None, length=4),
        IntField('mkey', 0),
        LongField('address', 0),
        BitField('clear', 0, 1),
        BitField('dump_to_memory', 0, 1),
        BitField('num_of_counters', 0, 30),
        IntField('flow_counter_id', 0),
    ]


class TrafficCounter(Packet):
    fields_desc = [
        LongField('packets', 0),
        LongField('octets', 0),
    ]


class QueryFlowCounterOut(Packet):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        StrFixedLenField('reserved2', None, length=8),
        PacketField('flow_statistics', TrafficCounter(), TrafficCounter),
    ]


class QueryHcaCapIn(Packet):
    fields_desc = [
        ShortField('opcode', de.MLX5_CMD_OP_QUERY_HCA_CAP),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        BitField('other_function', 0, 1),
        BitField('reserved2', 0, 15),
        ShortField('function_id', 0),
        StrFixedLenField('reserved3', None, length=4),
    ]


class QosCaps(Packet):
    fields_desc = [
        BitField('packet_pacing', 0, 1),
        BitField('esw_scheduling', 0, 1),
        BitField('esw_bw_share', 0, 1),
        BitField('esw_rate_limit', 0, 1),
        BitField('hll', 0, 1),
        BitField('packet_pacing_burst_bound', 0, 1),
        BitField('packet_pacing_typical_size', 0, 1),
        BitField('flow_meter_old', 0, 1),
        BitField('nic_sq_scheduling', 0, 1),
        BitField('nic_bw_share', 0, 1),
        BitField('nic_rate_limit', 0, 1),
        BitField('packet_pacing_uid', 0, 1),
        BitField('log_esw_max_sched_depth', 0, 4),
        ByteField('log_max_flow_meter', 0),
        ByteField('flow_meter_reg_id', 0),
        BitField('wqe_rate_pp', 0, 1),
        BitField('nic_qp_scheduling', 0, 1),
        BitField('reserved1', 0, 2),
        BitField('log_nic_max_sched_depth', 0, 4),
        BitField('flow_meter', 0, 1),
        BitField('reserved2', 0, 1),
        BitField('qos_remap_pp', 0, 1),
        BitField('log_max_qos_nic_queue_group', 0, 5),
        ShortField('reserved3', 0),
        IntField('packet_pacing_max_rate', 0),
        IntField('packet_pacing_min_rate', 0),
        BitField('reserved4', 0, 11),
        BitField('log_esw_max_rate_limit', 0, 5),
        ShortField('packet_pacing_rate_table_size', 0),
        ShortField('esw_element_type', 0),
        ShortField('esw_tsar_type', 0),
        ShortField('reserved5', 0),
        ShortField('max_qos_para_vport', 0),
        IntField('max_tsar_bw_share', 0),
        ShortField('nic_element_type', 0),
        ShortField('nic_tsar_type', 0),
        BitField('reserved6', 0, 3),
        BitField('log_meter_aso_granularity', 0, 5),
        BitField('reserved7', 0, 3),
        BitField('log_meter_aso_max_alloc', 0, 5),
        BitField('reserved8', 0, 3),
        BitField('log_max_num_meter_aso', 0, 5),
        ByteField('reserved9', 0),
        BitField('reserved10', 0, 3),
        BitField('log_max_qos_nic_scheduling_element', 0, 5),
        BitField('reserved11', 0, 3),
        BitField('log_max_qos_esw_scheduling_element', 0, 5),
        ShortField('reserved12', 0),
        StrFixedLenField('reserved13', None, length=212),
    ]


class QueryQosCapOut(Packet):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        StrFixedLenField('reserved2', None, length=8),
        PadField(PacketField('capability', QosCaps(), QosCaps), 4096, padwith=b"\x00"),
    ]
