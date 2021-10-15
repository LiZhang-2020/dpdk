# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from libc.stdint cimport uint8_t, uint16_t, uint32_t
cimport pydiru.pydiru_enums_c as e

cdef extern  from '../../../../lib/librte_eal/include/rte_eal.h':
    int rte_eal_init(int argc, char **argv)

cdef extern  from '../../../../lib/librte_eal/include/rte_errno.h':
    int rte_errno

cdef extern  from '../../../../lib/librte_ethdev/rte_flow.h':

    cdef struct rte_flow_item:
        e.rte_flow_item_type type
        void *spec
        void *last
        void *mask

    struct rte_ether_addr:
        uint8_t addr_bytes[8]

    cdef struct rte_flow_item_eth:
        rte_ether_addr dst
        rte_ether_addr src
        uint16_t type
        uint32_t has_vlan
        uint32_t reserved

    cdef struct rte_flow_q_op_res:
        uint32_t version
        e.rte_flow_q_op_status status
        void *user_data
