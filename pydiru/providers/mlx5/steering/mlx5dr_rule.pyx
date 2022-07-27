# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from pydiru.providers.mlx5.steering.mlx5dr_action cimport Mlx5drRuleAction
from pydiru.providers.mlx5.steering.mlx5dr_context cimport Mlx5drContext
from pydiru.providers.mlx5.steering.mlx5dr_matcher cimport Mlx5drMatcher
from pydiru.pydiru_error import PydiruError
cimport pydiru.providers.mlx5.mlx5 as mlx5
from pydiru.rte_flow cimport RteFlowResult
from pydiru.rte_flow cimport RteFlowItem
from libc.stdlib cimport free, calloc
from pydiru.base import PydiruErrno
from libc.string cimport memcpy
cimport pydiru.pydiru_enums_c as e
cimport pydiru.libpydiru as pdr
import time

POLLING_TIMEOUT = 5


cdef class Mlx5drRuleAttr(PydiruCM):
    def __init__(self, queue_id=0, user_data=None, burst=0, rule_idx=0):
        super().__init__()

        self.attr.queue_id = queue_id
        self.attr.user_data = <void *>user_data if user_data else NULL
        self.attr.burst = burst
        self.attr.rule_idx = rule_idx
        self.user_data = user_data

    @property
    def user_data(self):
        return self.user_data


cdef class Mlx5drRule(PydiruCM):
    def __init__(self, Mlx5drMatcher matcher, mt_idx, rte_items, at_idx, rule_actions,
                 num_of_actions, Mlx5drRuleAttr rule_attr_create, Mlx5drContext dr_ctx=None,
                 Mlx5drRuleAttr rule_attr_destroy=None):
        """
        Initializes a Mlx5drRule object representing mlx5dr_rule struct.
        :param matcher: Matcher to create a rule with
        :param mt_idx: Index of the matcher template to use
        :param rte_items: Rte items defining values to match on
        :param at_idx: Index of the action template to use
        :param rule_actions: Actions to perform on match
        :param num_of_actions: Number of rule actions
        :param rule_attr_create: Attributes for rule creation
        :param dr_ctx: If provided poll send queue for rule creation completion
        :param rule_attr_destroy: Attributes for rule destruction (if not provided,
                                  rule_attr_create is used for destruction instead)
        """
        super().__init__()
        cdef dr.mlx5dr_rule *rule = NULL
        cdef pdr.rte_flow_item *item_ptr = NULL
        cdef dr.mlx5dr_rule_action rule_action
        cdef dr.mlx5dr_rule_action *actions_ptr = NULL

        self.res = []
        rule = <dr.mlx5dr_rule *>calloc(1, mlx5._rule_get_handle_size())
        item_ptr = <pdr.rte_flow_item *>calloc(len(rte_items), sizeof(pdr.rte_flow_item))
        actions_ptr = <dr.mlx5dr_rule_action *>calloc(num_of_actions, sizeof(dr.mlx5dr_rule_action))

        if actions_ptr == NULL or item_ptr == NULL or actions_ptr == NULL:
            free(item_ptr)
            free(rule)
            free(actions_ptr)
            raise MemoryError('Memory allocation failed.')

        for i in range(num_of_actions):
            actions_ptr[i] = (<Mlx5drRuleAction>rule_actions[i]).rule_action

        # Copy RTE flow items
        for i in range(len(rte_items)):
            r = <RteFlowItem>(rte_items[i])
            memcpy(<void *>&(item_ptr[i]), <void *>&(r.item), sizeof(pdr.rte_flow_item))

        rc = mlx5._rule_create(matcher.matcher, mt_idx, item_ptr, at_idx, actions_ptr,
                               &rule_attr_create.attr, rule)
        free(item_ptr)
        free(actions_ptr)
        if rc:
            free(rule)
            raise PydiruErrno('Failed to create Mlx5drRule.')
        self.actions = []
        for ra in rule_actions:
            self.actions.append((<Mlx5drRuleAction>ra).action)
            (<Mlx5drRuleAction>ra).action.add_ref(self)
        self.rule = rule
        self.rule_attr_destroy = rule_attr_destroy if rule_attr_destroy else rule_attr_create
        self.mlx5dr_matcher = matcher
        matcher.add_ref(self)
        if dr_ctx:
            start_poll_t = time.perf_counter()
            self.res = []
            while not self.res and (time.perf_counter() - start_poll_t) < POLLING_TIMEOUT:
                self.res = dr_ctx.poll_send_queue(rule_attr_create.attr.queue_id, 1)
            if not self.res:
                raise PydiruError(f'Got timeout on polling queue id {rule_attr_create.attr.queue_id}.')
            if <RteFlowResult>(self.res[0]).status != e.RTE_FLOW_OP_SUCCESS:
                raise PydiruError(f'ERROR completion returned from queue ID: {rule_attr_create.attr.queue_id} '
                                  f'with status: {self.res[0]).status}.')
            user_data_from_addr = <RteFlowResult>(self.res[0]).user_data
            if  user_data_from_addr != rule_attr_create.user_data:
                raise PydiruError(f'ERROR completion returned from queue ID: {rule_attr_create.attr.queue_id} '
                                  f'with differnt user_data: {user_data_from_addr}.')

    @property
    def comp_results(self):
        return self.res

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.rule != NULL:
            self.logger.debug('Closing Mlx5drRule.')
            attr = self.rule_attr_destroy
            rc = mlx5._rule_destroy(self.rule, <dr.mlx5dr_rule_attr *>&(attr.attr))
            if rc:
                raise PydiruError('Failed to destroy Mlx5drRule.', rc)
            free(self.rule)
            self.rule = NULL
            self.mlx5dr_matcher = None
            self.actions = None
