# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from pydiru.base cimport PydiruCM, PydiruObject
cimport pydiru.libpydiru as pdr


cdef class RteFlowItemEth(PydiruCM):
    cdef pdr.rte_flow_item_eth item

cdef class RteFlowItemIpv4(PydiruCM):
    cdef pdr.rte_flow_item_ipv4 item

cdef class RteFlowItemIpv6(PydiruCM):
    cdef pdr.rte_flow_item_ipv6 item

cdef class RteFlowItemTcp(PydiruCM):
    cdef pdr.rte_flow_item_tcp item

cdef class RteFlowItemUdp(PydiruCM):
    cdef pdr.rte_flow_item_udp item

cdef class RteFlowItemGtp(PydiruCM):
    cdef pdr.rte_flow_item_gtp item

cdef class RteFlowItemGtpPsc(PydiruCM):
    cdef pdr.rte_flow_item_gtp_psc item

cdef class RteFlowItem(PydiruCM):
    cdef pdr.rte_flow_item item

cdef class RteFlowItemEnd(RteFlowItem):
    pass

cdef class RteFlowResult(PydiruObject):
    cdef pdr.rte_flow_op_result flow_res
