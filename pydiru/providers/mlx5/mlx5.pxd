# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022, Nvidia Inc. All rights reserved.

cimport pydiru.providers.mlx5.steering.mlx5dr_enums_c as me
cimport pydiru.providers.mlx5.steering.libmlx5dr as dr
cimport pydiru.providers.mlx5.libmlx5 as dv
from libc.stdint cimport uint16_t, uint64_t
cimport pydiru.libpydiru as pdr
cimport pydiru.libibverbs as v
cimport libc.stdio as s

cdef dr.mlx5dr_context *_context_open(v.ibv_context *context, dr.mlx5dr_context_attr *attr)
cdef _rte_init(argc, char** argv)
cdef _send_queue_poll(dr.mlx5dr_context *ctx, queue_id, pdr.rte_flow_op_result *res, res_nb)
cdef _debug_dump(dr.mlx5dr_context *ctx, s.FILE *f)
cdef _send_queue_action(dr.mlx5dr_context *ctx, queue_id, actions)
cdef _context_close(dr.mlx5dr_context *ctx)
cdef dr.mlx5dr_table *_table_create(dr.mlx5dr_context *ctx,
                                    dr.mlx5dr_table_attr *attr)
cdef _table_destroy(dr.mlx5dr_table *tbl)
cdef dr.mlx5dr_match_template *_match_template_create(pdr.rte_flow_item *items, flags)
cdef _match_template_destroy(dr.mlx5dr_match_template *mt)
cdef dr.mlx5dr_matcher *_matcher_create(dr.mlx5dr_table *table,
                                        dr.mlx5dr_match_template *mt[],
                                        num_of_mt, dr.mlx5dr_action_template *at[],
                                        num_of_at, dr.mlx5dr_matcher_attr *attr)
cdef _matcher_destroy(dr.mlx5dr_matcher *matcher)
cdef _rule_create(dr.mlx5dr_matcher *matcher, mt_idx, pdr.rte_flow_item *items,
                  at_idx, dr.mlx5dr_rule_action rule_actions[],
                  dr.mlx5dr_rule_attr *attr, dr.mlx5dr_rule *rule_handle)
cdef _rule_destroy(dr.mlx5dr_rule *rule, dr.mlx5dr_rule_attr *attr)
cdef dr.mlx5dr_action *_action_create_dest_drop(dr.mlx5dr_context *ctx, flags)
cdef dr.mlx5dr_action *_action_create_tag(dr.mlx5dr_context *ctx, flags)
cdef dr.mlx5dr_action *_action_create_dest_table(dr.mlx5dr_context *ctx, dr.mlx5dr_table *tbl, flags)
cdef dr.mlx5dr_action *_action_create_dest_tir(dr.mlx5dr_context *ctx, dr.mlx5dr_devx_obj *obj,
                                               flags)
cdef dr.mlx5dr_action *_action_create_reformat(dr.mlx5dr_context *ctx, reformat_type, data_sz,
                                               void *data, bulk_size, flags)
cdef dr.mlx5dr_action *_action_create_modify_header(dr.mlx5dr_context *ctx, pattern_sz,
                                                    uint64_t pattern[], log_bulk_size, flags)
cdef dr.mlx5dr_action *_action_create_default_miss(dr.mlx5dr_context *ctx, flags)
cdef dr.mlx5dr_action *_action_create_counter(dr.mlx5dr_context *ctx, dr.mlx5dr_devx_obj *obj, flags)
cdef dr.mlx5dr_action *_action_create_dest_vport(dr.mlx5dr_context *ctx, ib_port_num, flags)
cdef dr.mlx5dr_action *_action_create_aso_flow_meter(dr.mlx5dr_context *ctx,
                                                     dr.mlx5dr_devx_obj *devx_obj, return_reg_c,
                                                     flags)
cdef dr.mlx5dr_action *_action_create_ct_aso(dr.mlx5dr_context *ctx,
                                             dr.mlx5dr_devx_obj *devx_obj, return_reg_c, flags)
cdef dr.mlx5dr_action *_action_create_push_vlan(dr.mlx5dr_context *ctx, flags)
cdef dr.mlx5dr_action *_action_create_pop_vlan(dr.mlx5dr_context *ctx, flags)
cdef _action_destroy(dr.mlx5dr_action *action)
cdef int _rule_get_handle_size()
cdef dv.flow_hw_port_info *_flow_hw_conv_port_id(uint16_t port_id)
cdef dr.mlx5dr_action_template *_action_template_create(me.mlx5dr_action_type *actions_type)
cdef _action_template_destroy(dr.mlx5dr_action_template *action_template)
