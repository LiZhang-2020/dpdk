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
