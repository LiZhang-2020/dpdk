# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from pydiru.providers.mlx5.steering.libmlx5dr cimport mlx5dr_context_close
from pydiru.pydiru_error import PydiruError
from libc.stdlib cimport calloc, free
from pydiru.base import PydiruErrno
cimport pydiru.libibverbs as v


DEF MAX_ARGC = 10

RTE_INITIALIZED = False


cdef class Mlx5drContextAttr(PydiruObject):
    def __init__(self, queues=1, queue_size=1, initial_log_ste_memory=0, pd=None):
        """
        Initializes a Mlx5drContextAttr object representing mlx5dr_context_attr
        struct.
        :param queues: Number of queues
        :param queue_size: Size of each queue
        :param initial_log_ste_memory: Size of memory to preallocate
        :param pd: PD to use (if provided)
        """
        super().__init__()
        self.attr.queues = queues
        self.attr.queue_size = queue_size
        self.attr.initial_log_ste_memory = initial_log_ste_memory
        if pd:
            self.pd = pd


cdef class Mlx5drContext(PydiruCM):
    def __init__(self, context, Mlx5drContextAttr attr):
        """
        Initializes a Mlx5drContext object representing mlx5dr_context struct.
        :param context: Pyverbs object that represent ibv context
        :param attr: Attributes for creating Mlx5drContext
        """
        super().__init__()
        cdef v.ibv_context *ctx_ptr = <v.ibv_context *>(context.context)
        self.context = dr.mlx5dr_context_open(ctx_ptr,
                                              <dr.mlx5dr_context_attr *>&(attr.attr))
        if self.context == NULL:
            raise PydiruErrno('Failed creating Mlx5drContext')

    @staticmethod
    def rte_init(args):
        global RTE_INITIALIZED
        if RTE_INITIALIZED:
            return

        if not args['prog']:
            raise PydiruError('Prog must be provided')

        cdef char* argv[MAX_ARGC]
        cdef char* no_huge = '--no-huge'
        cdef char* allow = '-a'

        argc = 0
        prog = args['prog'].encode('UTF-8')
        argv[argc] = prog
        argc += 1
        if args['no_huge']:
            argv[argc] = no_huge
            argc += 1
        if args['a']:
            argv[argc] = allow
            argc += 1
            # Take the pci device together with dv_flow_en if passed by the user
            pci_flow_en = args['a'].encode('UTF-8')
            argv[argc] = pci_flow_en
            argc += 1
        res = p.rte_eal_init(argc, argv)
        if res < 0:
            raise PydiruError('Failed initializing RTE')

        RTE_INITIALIZED = True

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.context != NULL:
            self.logger.debug('Closing Mlx5drContext.')
            rc = mlx5dr_context_close(<dr.mlx5dr_context *>(self.context))
            if rc:
                raise PydiruError('Failed to destroy Mlx5drContext.', rc)
            self.context = NULL
