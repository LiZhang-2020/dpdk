# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from pydiru.providers.mlx5.steering.mlx5dr_table cimport Mlx5drTable
import pydiru.providers.mlx5.steering.mlx5dr_enums as me
from pydiru.pydiru_error import PydiruError
from pydiru.rte_flow cimport RteFlowItem
from pydiru.base cimport close_weakrefs
from libc.stdlib cimport free, calloc
from pydiru.base import PydiruErrno
from libc.stdint cimport uint8_t
from libc.string cimport memcpy
cimport pydiru.libpydiru as pdr
import weakref


cdef class Mlx5drMacherTemplate(PydiruCM):
    def __init__(self, rte_flow_items=[], flags=0):
        """
        Initializes a Mlx5drMacherTemplate object representing mlx5dr_match_template struct.
        :param rte_flow_items: List of rte flow items
        :param flags: MLX5DR_MATCH_TEMPLATE_FLAG_RELAXED_MATCH to allow relaxed matching
                      by skipping derived dependent match fields
        """
        super().__init__()
        cdef pdr.rte_flow_item *item_ptr = <pdr.rte_flow_item *>calloc(len(rte_flow_items),
                                                                       sizeof(pdr.rte_flow_item))
        if item_ptr == NULL:
            raise MemoryError('Failed to allocate memory')
        for i in range(len(rte_flow_items)):
            r = <RteFlowItem>(rte_flow_items[i])
            memcpy(<void *>&(item_ptr[i]), <void *>&(r.item), sizeof(pdr.rte_flow_item))
        self.matcher_template = dr.mlx5dr_match_template_create(item_ptr, flags)
        free(item_ptr)
        if self.matcher_template == NULL:
            raise PydiruErrno('Failed to create Mlx5drMacherTemplate')
        self.mlx5dr_matchers = weakref.WeakSet()

    cdef add_ref(self, obj):
        if isinstance(obj, Mlx5drMatcher):
            self.mlx5dr_matchers.add(obj)
        else:
            raise PydiruError('Unrecognized object type')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.matcher_template != NULL:
            self.logger.debug('Closing Mlx5drMacherTemplate.')
            close_weakrefs([self.mlx5dr_matchers])
            rc = dr.mlx5dr_match_template_destroy(self.matcher_template)
            if rc:
                raise PydiruError('Failed to destroy Mlx5drMacherTemplate.', rc)
            self.matcher_template = NULL


cdef class Mlx5drMatcherAttr(PydiruObject):
    def __init__(self, priority, mode, row_log=0, col_log=0, rule_log=0):
        """
         Initialize a Mlx5drMatcherAttr object representing mlx5dr_matcher_attr C struct.
        :param priority: Table priority
        :param mode: Table resourse mode:
                     MLX5DR_MATCHER_RESOURCE_MODE_RULE - Allocate resources based on
                     number of rules with minimal failure probability.
                     MLX5DR_MATCHER_RESOURCE_MODE_HTABLE - Allocate fixed size hash
                     table based on given column and rows.
        :param row_log: Hint for the log number of rows to be created
        :param col_log: Hint for the log number of colunms to be created
        :param rule_log: Hint for the log number of rules to be created
        """
        super().__init__()
        self.attr.priority = priority
        self.attr.mode = mode
        if mode == me.MLX5DR_MATCHER_RESOURCE_MODE_HTABLE:
            self.attr.table.sz_row_log = row_log
            self.attr.table.sz_col_log = col_log
        else:
            self.attr.rule.num_log = rule_log


cdef class Mlx5drMatcher(PydiruCM):
    def __init__(self, Mlx5drTable table, matcher_templates, num_of_templates,
                 Mlx5drMatcherAttr matcher_attr):
        """
        Initializes a Mlx5Mlx5drMatcherdrContext object representing mlx5dr_matcher struct.
        :param table: Matcher table
        :param matcher_templates: List of matcher templates
        :param num_of_templates: Number of matcher templates
        :param matcher_attr: Attributes for creating Mlx5drMatcher
        """
        super().__init__()
        cdef dr.mlx5dr_match_template **mt
        mt = <dr.mlx5dr_match_template **>calloc(num_of_templates, sizeof(dr.mlx5dr_match_template *))
        if mt == NULL:
            raise MemoryError('Failed allocating memory.')
        for i in range(num_of_templates):
            matcher_template = <Mlx5drMacherTemplate>(matcher_templates[i])
            mt[i] = <dr.mlx5dr_match_template *>(matcher_template.matcher_template)
        self.matcher = dr.mlx5dr_matcher_create(table.table, mt, num_of_templates, &matcher_attr.attr)
        free(mt)
        if self.matcher == NULL:
            raise PydiruErrno('Failed creating Mlx5drMatcher.')
        self.matcher_templates = matcher_templates[:]
        for m in matcher_templates:
            (<Mlx5drMacherTemplate>m).add_ref(self)
        table.add_ref(self)
        self.mlx5dr_table = table

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.matcher != NULL:
            self.logger.debug('Closing Mlx5drMatcher.')
            rc = dr.mlx5dr_matcher_destroy(self.matcher)
            if rc:
                raise PydiruError('Failed to destroy Mlx5drMatcher.', rc)
            self.matcher = NULL
            self.matcher_templates = None
            self.mlx5dr_table = None
