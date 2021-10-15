# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from libc.stdlib cimport free, calloc
from libc.string cimport memcpy
import socket

import pydiru.pydiru_enums as e


cdef class RteFlowItemEth(PydiruCM):
    def __init__(self, dst=bytes(), src=bytes(), eth_type=0, has_vlan=0):
        cdef char *dst_c = dst
        cdef char *src_c = src
        memcpy(<void *> self.item.dst.addr_bytes, dst_c, 6)
        memcpy(<void *> self.item.src.addr_bytes, src_c, 6)
        self.item.type = socket.htons(eth_type)
        self.item.has_vlan = has_vlan


cdef class RteFlowItem(PydiruCM):
    def __init__(self, flow_item_type, spec=None, mask=None, last=None):
        self.item.type = flow_item_type
        self.item.spec = NULL
        self.item.mask = NULL
        if flow_item_type == e.RTE_FLOW_ITEM_TYPE_ETH:
            size = sizeof(pdr.rte_flow_item_eth)
        if spec:
            self.item.spec = calloc(1, size)
            memcpy(self.item.spec, <void *>&((<RteFlowItemEth>spec).item), size)
        if mask:
            self.item.mask = calloc(1, size)
            memcpy(self.item.mask, <void *>&((<RteFlowItemEth>mask).item), size)
        self.item.last = NULL

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.item.spec != NULL:
            free(self.item.spec)
            self.item.spec = NULL
        if self.item.mask != NULL:
            free(self.item.mask)
            self.item.mask = NULL


cdef class RteFlowItemEnd(RteFlowItem):
     def __init__(self):
         super().__init__(e.RTE_FLOW_ITEM_TYPE_END)
