# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from pydiru.providers.mlx5.steering.mlx5dr_devx_objects cimport Mlx5drDevxObj
from pydiru.providers.mlx5.steering.mlx5dr_table cimport Mlx5drTable
cimport pydiru.providers.mlx5.steering.libmlx5dr as dr
from pydiru.base cimport PydiruCM, PydiruObject

cdef class Mlx5drAction(PydiruCM):
    cdef dr.mlx5dr_action *action
    cdef object mlx5dr_rules
    cdef add_ref(self, obj)

cdef class Mlx5drActionDrop(Mlx5drAction):
    pass

cdef class Mlx5drActionTag(Mlx5drAction):
    pass

cdef class Mlx5drActionDestTable(Mlx5drAction):
    cdef Mlx5drTable mlx5dr_table

cdef class Mlx5drActionDestTir(Mlx5drAction):
    cdef Mlx5drDevxObj tir

cdef class Mlx5drActionReformat(Mlx5drAction):
    pass

cdef class Mlx5drRuleAction(PydiruObject):
    cdef dr.mlx5dr_rule_action rule_action
    cdef Mlx5drAction action
