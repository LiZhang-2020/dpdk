# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

cdef extern from 'infiniband/verbs.h':
    cdef struct ibv_context

    cdef struct ibv_pd
