# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from pydiru.providers.mlx5.steering.mlx5dr_context cimport Mlx5drContext
from pydiru.providers.mlx5.steering.mlx5dr_table cimport Mlx5drTable
from pydiru.providers.mlx5.steering.mlx5dr_rule cimport Mlx5drRule
from pydiru.pydiru_error import PydiruError
from pydiru.base cimport close_weakrefs
from libc.stdlib cimport free, calloc
from pydiru.base import PydiruErrno
import weakref


cdef class Mlx5drAction(PydiruCM):
    def __init__(self, Mlx5drContext ctx):
        super().__init__()
        self.mlx5dr_rules = weakref.WeakSet()
        ctx.add_ref(self)
        self.mlx5dr_context = ctx

    cdef add_ref(self, obj):
        if isinstance(obj, Mlx5drRule):
            self.mlx5dr_rules.add(obj)
        else:
            raise PydiruError('Unrecognized object type')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action != NULL:
            self.logger.debug('Closing Mlx5drAction.')
            close_weakrefs([self.mlx5dr_rules])
            rc = dr.mlx5dr_action_destroy(self.action)
            if rc:
                raise PydiruError('Failed to destroy Mlx5drAction.', rc)
            self.action = NULL
            self.mlx5dr_context = None


cdef class Mlx5drActionDrop(Mlx5drAction):
    def __init__(self, Mlx5drContext ctx, flags):
        """
        Initializes a destination drop action.
        :param ctx: Mlx5drContext context
        :param flags: Action flags
        """
        super().__init__(ctx)
        self.action = dr.mlx5dr_action_create_dest_drop(ctx.context, flags)
        if self.action == NULL:
            raise PydiruErrno('Mlx5drActionDrop creation failed.')


cdef class Mlx5drActionTag(Mlx5drAction):
    def __init__(self, Mlx5drContext ctx, flags):
        """
        Initializes a tag action.
        :param ctx: Mlx5drContext context
        :param flags: Action flags
        """
        super().__init__(ctx)
        self.action = dr.mlx5dr_action_create_tag(ctx.context, flags)
        if self.action == NULL:
            raise PydiruErrno('Mlx5drActionTag creation failed.')


cdef class Mlx5drActionDestTable(Mlx5drAction):
    def __init__(self, Mlx5drContext ctx, Mlx5drTable table, flags):
        """
        Initializes a destination table action.
        :param ctx: Mlx5drContext context
        :param table: Destination table
        :param flags: Action flags
        """
        super().__init__(ctx)
        self.action = dr.mlx5dr_action_create_dest_table(ctx.context, table.table, flags)
        if self.action == NULL:
            raise PydiruErrno('Mlx5drActionDestTable creation failed.')


cdef class Mlx5drActionDestTir(Mlx5drAction):
    def __init__(self, Mlx5drContext ctx, Mlx5drDevxObj tir, flags):
        """
        Initializes a destination TIR action.
        :param ctx: Mlx5drContext context
        :param tir: Destination TIR
        :param flags: Action flags
        """
        super().__init__(ctx)
        self.action = dr.mlx5dr_action_create_dest_tir(ctx.context, &tir.dr_devx_obj, flags)
        if self.action == NULL:
            raise PydiruErrno('Mlx5drActionDestTir creation failed.')
        self.tir = tir
        tir.dr_actions.add(self)


cdef class Mlx5drActionReformat(Mlx5drAction):
    def __init__(self, Mlx5drContext ctx, ref_type, data_sz, data, bulk_size, flags):
        """
        Initializes a packet reformat action.
        :param ctx: Mlx5drContext context
        :param ref_type: Reformat type
        :param data_sz: Size of the data
        :param data: Data
        :param bulk_size: Bulk size
        :param flags: Action flags
        """
        super().__init__(ctx)
        cdef char* c_data = NULL
        if data:
            arr = bytearray(data)
            c_data = <char *>calloc(1, data_sz)
            if c_data == NULL:
                raise MemoryError('Memory allocation failed.')
            for i in range(data_sz):
                c_data[i] = arr[i]
        self.action = dr.mlx5dr_action_create_reformat(ctx.context, ref_type, data_sz,
                                                       c_data if data else NULL,
                                                       bulk_size, flags)
        if c_data != NULL:
            free(c_data)
        if self.action == NULL:
            raise PydiruErrno('Mlx5drActionReformat creation failed.')


cdef class Mlx5drRuleAction(PydiruObject):
    """
    Class Mlx5drRuleAction representing mlx5dr_rule_action struct.
    Action to be used for rule creation.
    """
    def __init__(self, Mlx5drAction action):
        """
        Initializes the Mlx5drRuleAction object representing mlx5dr_rule_action struct.
        """
        super().__init__()
        self.rule_action.action = action.action
        self.action = action

    @property
    def value(self):
        return self.rule_action.tag.value

    @value.setter
    def value(self, value):
        self.rule_action.tag.value = value

    @property
    def action(self):
        return self.action

    @action.setter
    def action(self, Mlx5drAction value):
        self.rule_action.action = value.action
        self.action = value
