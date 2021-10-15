# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from pydiru.base cimport PydiruCM
cimport pydiru.libpydiru as pdr


cdef class RteFlowItemEth(PydiruCM):
    cdef pdr.rte_flow_item_eth item

cdef class RteFlowItem(PydiruCM):
    cdef pdr.rte_flow_item item

cdef class RteFlowItemEnd(RteFlowItem):
    pass
