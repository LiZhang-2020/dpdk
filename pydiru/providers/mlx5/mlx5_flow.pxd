# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022, Nvidia Inc. All rights reserved.

from pydiru.base cimport PydiruObject
cimport pydiru.providers.mlx5.libmlx5 as dv

cdef class FlowPortInfo(PydiruObject):
    cdef dv.flow_hw_port_info *port_info
