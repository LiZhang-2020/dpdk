# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022, Nvidia Inc. All rights reserved.

from pydiru.providers.mlx5.mlx5 cimport _flow_hw_conv_port_id
from libc.stdlib cimport calloc, free
from pydiru.base import PydiruErrno
cimport pydiru.libibverbs as v


cdef class FlowPortInfo(PydiruObject):
    def __init__(self, port_id):
        super().__init__()
        self.port_info = _flow_hw_conv_port_id(port_id)
        if self.port_info == NULL:
            raise PydiruErrno('Failed getting port id info.')

    @property
    def reg_c_mask(self):
        return self.port_info.regc_mask

    @property
    def reg_c_value(self):
        return self.port_info.regc_value

    @property
    def is_wire(self):
        return True if self.port_info.regc_value else False

    def __str__(self):
        return f'FlowPortInfo:\n'\
               f'\tregc_mask = {hex(self.port_info.regc_mask)}\n'\
               f'\tregc_value = {hex(self.port_info.regc_value)}\n'\
               f'\tis_wire = {(self.port_info.is_wire)}\n'

