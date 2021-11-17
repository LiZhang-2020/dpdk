# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

cimport pydiru.providers.mlx5.steering.libmlx5dr as dr
from pydiru.base cimport PydiruCM, PydiruObject
cimport pydiru.libpydiru as p

cdef class Mlx5drContextAttr(PydiruObject):
    cdef dr.mlx5dr_context_attr attr

cdef class Mlx5drContext(PydiruCM):
    cdef dr.mlx5dr_context *context
    cdef object mlx5dr_tables
    cdef object mlx5dr_actions
    cdef object ibv_context
    cdef add_ref(self, obj)
