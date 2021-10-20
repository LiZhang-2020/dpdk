# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

cdef extern from 'infiniband/mlx5dv.h':

    cdef struct mlx5dv_devx_obj
