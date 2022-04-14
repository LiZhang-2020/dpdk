# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022, Nvidia Inc. All rights reserved.

cimport pydiru.libpydiru as p


cdef _rte_init(argc, char** argv):
    return p.rte_eal_init(argc, argv)

cdef _send_queue_poll(dr.mlx5dr_context *ctx, queue_id, pdr.rte_flow_op_result *res, res_nb):
    return dr.mlx5dr_send_queue_poll(ctx, queue_id, res, res_nb)

cdef _debug_dump(dr.mlx5dr_context *ctx, s.FILE *f):
    return dr.mlx5dr_debug_dump(ctx, f)

cdef _send_queue_action(dr.mlx5dr_context *ctx, queue_id, actions):
    return dr.mlx5dr_send_queue_action(ctx, queue_id, actions)

cdef dr.mlx5dr_context *_context_open( v.ibv_context *context, dr.mlx5dr_context_attr *attr):
    return dr.mlx5dr_context_open(context, attr)

cdef _context_close(dr.mlx5dr_context *ctx):
    return dr.mlx5dr_context_close(ctx)

cdef dr.mlx5dr_table *_table_create(dr.mlx5dr_context *ctx,
                                    dr.mlx5dr_table_attr *attr):
    return dr.mlx5dr_table_create(ctx, attr)

cdef _table_destroy(dr.mlx5dr_table *tbl):
    return dr.mlx5dr_table_destroy(tbl)

cdef _match_template_destroy(dr.mlx5dr_match_template *mt):
    return dr.mlx5dr_match_template_destroy(mt)

cdef dr.mlx5dr_match_template *_match_template_create(pdr.rte_flow_item *items, flags):
    return dr.mlx5dr_match_template_create(items, flags)

cdef dr.mlx5dr_matcher *_matcher_create(dr.mlx5dr_table *table,
                                        dr.mlx5dr_match_template *mt[],
                                        num_of_mt, dr.mlx5dr_matcher_attr *attr):
    return dr.mlx5dr_matcher_create(table, mt, num_of_mt, attr)

cdef _matcher_destroy(dr.mlx5dr_matcher *matcher):
    return dr.mlx5dr_matcher_destroy(matcher)

cdef _rule_create(dr.mlx5dr_matcher *matcher, mt_idx, pdr.rte_flow_item *items,
                  dr.mlx5dr_rule_action rule_actions[], num_of_actions,
                  dr.mlx5dr_rule_attr *attr, dr.mlx5dr_rule *rule_handle):
    return dr.mlx5dr_rule_create(matcher, mt_idx, items, rule_actions, num_of_actions,
                                 attr, rule_handle)
cdef _rule_destroy(dr.mlx5dr_rule *rule, dr.mlx5dr_rule_attr *attr):
    return dr.mlx5dr_rule_destroy(rule, attr)

cdef dr.mlx5dr_action *_action_create_dest_drop(dr.mlx5dr_context *ctx, flags):
    return dr.mlx5dr_action_create_dest_drop(ctx, flags)

cdef dr.mlx5dr_action *_action_create_tag(dr.mlx5dr_context *ctx, flags):
    return dr.mlx5dr_action_create_tag(ctx, flags)

cdef dr.mlx5dr_action *_action_create_dest_table(dr.mlx5dr_context *ctx, dr.mlx5dr_table *tbl, flags):
    return dr.mlx5dr_action_create_dest_table(ctx, tbl, flags)

cdef dr.mlx5dr_action *_action_create_dest_tir(dr.mlx5dr_context *ctx, dr.mlx5dr_devx_obj *obj,
                                               flags):
    return dr.mlx5dr_action_create_dest_tir(ctx, obj, flags)

cdef dr.mlx5dr_action *_action_create_reformat(dr.mlx5dr_context *ctx, reformat_type, data_sz,
                                               void *data, bulk_size, flags):
    return dr.mlx5dr_action_create_reformat(ctx, reformat_type, data_sz, data, bulk_size, flags)

cdef dr.mlx5dr_action *_action_create_modify_header(dr.mlx5dr_context *ctx, pattern_sz,
                                                    uint64_t pattern[], log_bulk_size, flags):
    return dr.mlx5dr_action_create_modify_header(ctx, pattern_sz, pattern, log_bulk_size, flags)

cdef dr.mlx5dr_action *_action_create_default_miss(dr.mlx5dr_context *ctx, flags):
    return dr.mlx5dr_action_create_default_miss(ctx, flags)

cdef dr.mlx5dr_action *_action_create_counter(dr.mlx5dr_context *ctx, dr.mlx5dr_devx_obj *obj, flags):
    return dr.mlx5dr_action_create_counter(ctx, obj, flags)

cdef _action_destroy(dr.mlx5dr_action *action):
    return dr.mlx5dr_action_destroy(action)

cdef int _rule_get_handle_size():
    return dr.mlx5dr_rule_get_handle_size()
