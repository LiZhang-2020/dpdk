# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

cdef extern  from '../../../../drivers/net/mlx5/steering/mlx5dr.h':

    cpdef enum mlx5dr_table_type:
        MLX5DR_TABLE_TYPE_NIC_RX
        MLX5DR_TABLE_TYPE_NIC_TX
        MLX5DR_TABLE_TYPE_FDB
        MLX5DR_TABLE_TYPE_MAX
