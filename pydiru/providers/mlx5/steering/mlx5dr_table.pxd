# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from pydiru.providers.mlx5.steering.mlx5dr_context cimport Mlx5drContext
cimport pydiru.providers.mlx5.steering.libmlx5dr as dr
from pydiru.base cimport PydiruCM, PydiruObject

cdef class Mlx5drTableAttr(PydiruObject):
    cdef dr.mlx5dr_table_attr attr

cdef class Mlx5drTable(PydiruCM):
    cdef dr.mlx5dr_table *table
    cdef Mlx5drContext mlx5dr_context
