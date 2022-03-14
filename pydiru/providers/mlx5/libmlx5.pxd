# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from libc.stdint cimport uint16_t, uint32_t
cimport pydiru.libibverbs as v

cdef extern from 'infiniband/mlx5dv.h':

    cdef struct mlx5dv_devx_obj


cdef extern from '../../../../drivers/net/mlx5/mlx5_flow.h':

    cdef struct flow_hw_port_info:
        uint32_t regc_mask
        uint32_t regc_value
        uint32_t is_wire

    flow_hw_port_info *flow_hw_conv_port_id(uint16_t port_id)
