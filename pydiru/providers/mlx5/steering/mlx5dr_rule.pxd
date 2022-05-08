# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from pydiru.providers.mlx5.steering.mlx5dr_matcher cimport Mlx5drMatcher
cimport pydiru.providers.mlx5.steering.libmlx5dr as dr
from pydiru.base cimport PydiruCM

cdef class Mlx5drRuleAttr(PydiruCM):
    cdef dr.mlx5dr_rule_attr attr
    cdef object user_data

cdef class Mlx5drRule(PydiruCM):
    cdef dr.mlx5dr_rule *rule
    cdef Mlx5drRuleAttr rule_attr_destroy
    cdef object actions
    cdef Mlx5drMatcher mlx5dr_matcher
