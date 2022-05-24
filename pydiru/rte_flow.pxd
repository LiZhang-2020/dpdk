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

cdef class RteFlowItemIcmp(PydiruCM):
    cdef pdr.rte_flow_item_icmp item

cdef class RteFlowItemIcmp6(PydiruCM):
    cdef pdr.rte_flow_item_icmp6 item

cdef class RteFlowItemGtp(PydiruCM):
    cdef pdr.rte_flow_item_gtp item

cdef class RteFlowItemGtpPsc(PydiruCM):
    cdef pdr.rte_flow_item_gtp_psc item

cdef class RteFlowItemEthdev(PydiruCM):
    cdef pdr.rte_flow_item_ethdev item

cdef class RteFlowItemVxlan(PydiruCM):
    cdef pdr.rte_flow_item_vxlan item

cdef class Mlx5RteFlowItemTxQueue(PydiruCM):
    cdef pdr.mlx5_rte_flow_item_sq item

cdef class RteFlowItemTag(PydiruCM):
    cdef pdr.rte_flow_item_tag item

cdef class RteFlowItemGreOption(PydiruCM):
    cdef pdr.rte_flow_item_gre_opt item

cdef class RteFlowItem(PydiruCM):
    cdef pdr.rte_flow_item item

cdef class RteFlowItemEnd(RteFlowItem):
    pass

cdef class RteFlowResult(PydiruObject):
    cdef pdr.rte_flow_op_result flow_res

cdef class RteFlowItemVlan(PydiruCM):
    cdef pdr.rte_flow_item_vlan item
