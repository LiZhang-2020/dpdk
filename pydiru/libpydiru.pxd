# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

cdef extern  from '../../../../lib/librte_eal/include/rte_eal.h':
    int rte_eal_init(int argc, char **argv)

cdef extern  from '../../../../lib/librte_eal/include/rte_errno.h':
    int rte_errno
