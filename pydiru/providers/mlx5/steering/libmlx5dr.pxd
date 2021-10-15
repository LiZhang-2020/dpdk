# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t, uintptr_t
cimport pydiru.providers.mlx5.steering.mlx5dr_enums_c as me
cimport pydiru.libibverbs as v

cdef extern  from '../../../../drivers/net/mlx5/steering/mlx5dr.h':

    cdef struct mlx5dr_context

    cdef struct mlx5dr_table

    cdef struct mlx5dr_matcher

    cdef struct mlx5dr_rule

    cdef struct mlx5dr_context_attr:
        uint16_t queues
        uint16_t queue_size
        size_t initial_log_ste_memory
        v.ibv_pd *pd

    cdef struct mlx5dr_table_attr:
        me.mlx5dr_table_type type
        uint32_t level

    mlx5dr_context *mlx5dr_context_open(v.ibv_context *ibv_ctx,
                                        mlx5dr_context_attr *attr)
    int mlx5dr_context_close(mlx5dr_context *ctx)
    mlx5dr_table *mlx5dr_table_create(mlx5dr_context *ctx,
                                      mlx5dr_table_attr *attr)
    int mlx5dr_table_destroy(mlx5dr_table *tbl)
