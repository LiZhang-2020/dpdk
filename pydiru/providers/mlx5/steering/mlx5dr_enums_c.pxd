# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

cdef extern  from '../../../../drivers/net/mlx5/steering/mlx5dr.h':

    cpdef enum mlx5dr_table_type:
        MLX5DR_TABLE_TYPE_NIC_RX
        MLX5DR_TABLE_TYPE_NIC_TX
        MLX5DR_TABLE_TYPE_FDB
        MLX5DR_TABLE_TYPE_MAX

    cpdef enum mlx5dr_matcher_resource_mode:
        MLX5DR_MATCHER_RESOURCE_MODE_RULE
        MLX5DR_MATCHER_RESOURCE_MODE_HTABLE

    cpdef enum mlx5dr_match_template_flags:
        MLX5DR_MATCH_TEMPLATE_FLAG_RELAXED_MATCH

    cpdef enum mlx5dr_action_flags:
        MLX5DR_ACTION_FLAG_ROOT_RX
        MLX5DR_ACTION_FLAG_ROOT_TX
        MLX5DR_ACTION_FLAG_ROOT_FDB
        MLX5DR_ACTION_FLAG_HWS_RX
        MLX5DR_ACTION_FLAG_HWS_TX
        MLX5DR_ACTION_FLAG_HWS_FDB
        MLX5DR_ACTION_FLAG_SHARED

    cpdef enum mlx5dr_action_reformat_type:
        MLX5DR_ACTION_REFORMAT_TYPE_TNL_L2_TO_L2
        MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L2
        MLX5DR_ACTION_REFORMAT_TYPE_TNL_L3_TO_L2
        MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L3

    cpdef enum mlx5dr_send_queue_actions:
        MLX5DR_SEND_QUEUE_ACTION_DRAIN

    cpdef enum mlx5dr_action_type:
        MLX5DR_ACTION_TYP_LAST
        MLX5DR_ACTION_TYP_TNL_L2_TO_L2
        MLX5DR_ACTION_TYP_L2_TO_TNL_L2
        MLX5DR_ACTION_TYP_TNL_L3_TO_L2
        MLX5DR_ACTION_TYP_L2_TO_TNL_L3
        MLX5DR_ACTION_TYP_DROP
        MLX5DR_ACTION_TYP_TIR
        MLX5DR_ACTION_TYP_FT
        MLX5DR_ACTION_TYP_CTR
        MLX5DR_ACTION_TYP_TAG
        MLX5DR_ACTION_TYP_MODIFY_HDR
        MLX5DR_ACTION_TYP_VPORT
        MLX5DR_ACTION_TYP_MISS
        MLX5DR_ACTION_TYP_POP_VLAN
        MLX5DR_ACTION_TYP_PUSH_VLAN
        MLX5DR_ACTION_TYP_ASO_METER
        MLX5DR_ACTION_TYP_ASO_CT
        MLX5DR_ACTION_TYP_MAX

    cpdef enum mlx5dr_action_aso_ct_flags:
        MLX5DR_ACTION_ASO_CT_DIRECTION_INITIATOR
        MLX5DR_ACTION_ASO_CT_DIRECTION_RESPONDER

cdef extern  from '../../../../drivers/net/mlx5/mlx5_flow.h':

    cpdef enum mlx5_rte_flow_item_type:
        MLX5_RTE_FLOW_ITEM_TYPE_END
        MLX5_RTE_FLOW_ITEM_TYPE_TAG
        MLX5_RTE_FLOW_ITEM_TYPE_TX_QUEUE
        MLX5_RTE_FLOW_ITEM_TYPE_VLAN
        MLX5_RTE_FLOW_ITEM_TYPE_TUNNEL

    cpdef enum mlx5dr_action_aso_meter_color:
        MLX5DR_ACTION_ASO_METER_COLOR_RED
        MLX5DR_ACTION_ASO_METER_COLOR_YELLOW
        MLX5DR_ACTION_ASO_METER_COLOR_GREEN
        MLX5DR_ACTION_ASO_METER_COLOR_UNDEFINED
