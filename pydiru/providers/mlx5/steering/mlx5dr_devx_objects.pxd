# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

cimport pydiru.providers.mlx5.steering.libmlx5dr as dr
from pydiru.base cimport PydiruCM


cdef class Mlx5drDevxObj(PydiruCM):
    cdef dr.mlx5dr_devx_obj dr_devx_obj
    cdef object devx_obj
    cdef object dr_actions
