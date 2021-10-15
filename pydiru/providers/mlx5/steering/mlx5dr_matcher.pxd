# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from pydiru.providers.mlx5.steering.mlx5dr_table cimport Mlx5drTable
cimport pydiru.providers.mlx5.steering.libmlx5dr as dr
from pydiru.base cimport PydiruCM, PydiruObject

cdef class Mlx5drMacherTemplate(PydiruCM):
    cdef dr.mlx5dr_match_template *matcher_template
    cdef object mlx5dr_matchers
    cdef add_ref(self, obj)

cdef class Mlx5drMatcherAttr(PydiruObject):
    cdef dr.mlx5dr_matcher_attr attr

cdef class Mlx5drMatcher(PydiruCM):
    cdef dr.mlx5dr_matcher *matcher
    cdef Mlx5drTable mlx5dr_table
    cdef object matcher_templates
    cdef object mlx5dr_rules
    cdef add_ref(self, obj)
