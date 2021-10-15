# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

import logging

from pydiru.pydiru_error import PydiruError
cimport pydiru.libpydiru as pdr

LOG_LEVEL=logging.INFO
LOG_FORMAT='[%(levelname)s] %(asctime)s %(filename)s:%(lineno)s: %(message)s'
logging.basicConfig(format=LOG_FORMAT, level=LOG_LEVEL, datefmt='%d %b %Y %H:%M:%S')


cpdef PydiruErrno(str msg):
    return PydiruError(msg, pdr.rte_errno)


cdef class PydiruObject:

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def set_log_level(self, val):
        self.logger.setLevel(val)


cdef class PydiruCM(PydiruObject):
    """
    This is a base class for Pydiru's context manager objects. It includes
    __enter__ and __exit__ functions.
    close() is also declared but it should be overridden by each inheriting
    class.
    """

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return self.close()

    cpdef close(self):
        pass

cdef close_weakrefs(iterables):
    """
    For each iterable element of iterables, pop each element and
    call its close() method. This method is used when an object is being
    closed while other objects still hold C references to it; the object
    holds weakrefs to such other object, and closes them before trying to
    teardown the C resources.
    :param iterables: an array of WeakSets
    :return: None
    """
    # None elements can be present if an object's close() was called more
    # than once (e.g. GC and by another object)
    for it in iterables:
        if it is None:
            continue
        while True:
            try:
                tmp = it.pop()
                tmp.close()
            except KeyError: # popping an empty set
                break
