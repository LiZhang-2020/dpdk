# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

#cython: language_level=3
cimport pydiru.libpydiru as p

cdef class PydiruObject:
    cdef object logger

cdef class PydiruCM(PydiruObject):
    cpdef close(self)

