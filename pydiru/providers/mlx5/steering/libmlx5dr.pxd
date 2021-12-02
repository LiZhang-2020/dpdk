# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.

from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t, uintptr_t
cimport pydiru.providers.mlx5.steering.mlx5dr_enums_c as me
cimport pydiru.providers.mlx5.libmlx5 as dv
cimport pydiru.libpydiru as pdr
cimport pydiru.libibverbs as v

cdef extern  from '../../../../drivers/net/mlx5/steering/mlx5dr.h':

    cdef struct mlx5dr_context

    cdef struct mlx5dr_table

    cdef struct mlx5dr_matcher

    cdef struct mlx5dr_rule

    cdef struct mlx5dr_context_attr:
        uint16_t queues
        uint16_t queue_size
        size_t initial_log_ste_memory
        v.ibv_pd *pd

    cdef struct mlx5dr_table_attr:
        me.mlx5dr_table_type type
        uint32_t level

    cdef struct mlx5dr_match_template

    cdef struct table_:
        uint8_t sz_row_log
        uint8_t sz_col_log

    cdef struct rule_:
        uint8_t num_log

    cdef struct mlx5dr_matcher_attr:
        uint32_t priority
        me.mlx5dr_matcher_resource_mode mode
        table_ table
        rule_ rule


    cdef struct mlx5dr_action:
        pass

    cdef struct tag_:
        uint32_t value

    cdef struct modify_header_:
        uint32_t offset
        uint8_t *data

    cdef struct reformat_:
        uint32_t offset
        uint8_t *data

    cdef struct mlx5dr_rule_action:
        mlx5dr_action *action
        tag_ tag
        modify_header_ modify_header
        reformat_ reformat
        uint32_t vlan_hdr

    cdef struct mlx5dr_rule:
        pass

    cdef struct mlx5dr_rule_attr:
        uint16_t queue_id
        void *user_data
        uint32_t burst

    cdef struct mlx5dr_devx_obj:
        dv.mlx5dv_devx_obj *obj
        uint32_t id

    mlx5dr_context *mlx5dr_context_open(v.ibv_context *ibv_ctx,
                                        mlx5dr_context_attr *attr)
    int mlx5dr_context_close(mlx5dr_context *ctx)
    mlx5dr_table *mlx5dr_table_create(mlx5dr_context *ctx,
                                      mlx5dr_table_attr *attr)
    int mlx5dr_table_destroy(mlx5dr_table *tbl)
    mlx5dr_match_template *mlx5dr_match_template_create(pdr.rte_flow_item *items,
                                                        me.mlx5dr_match_template_flags flags)
    int mlx5dr_match_template_destroy(mlx5dr_match_template *mt)
    mlx5dr_matcher *mlx5dr_matcher_create(mlx5dr_table *table,
                                          mlx5dr_match_template *mt[],
                                          uint8_t num_of_mt,
                                          mlx5dr_matcher_attr *attr)
    int mlx5dr_matcher_destroy(mlx5dr_matcher *matcher)

    int mlx5dr_rule_get_handle_size()
    int mlx5dr_rule_create(mlx5dr_matcher *matcher, uint8_t mt_idx, pdr.rte_flow_item *items,
                           mlx5dr_rule_action rule_actions[], uint8_t num_of_actions,
                           mlx5dr_rule_attr *attr, mlx5dr_rule *rule_handle)
    int mlx5dr_rule_destroy(mlx5dr_rule *rule, mlx5dr_rule_attr *attr)

    mlx5dr_action *mlx5dr_action_create_dest_drop(mlx5dr_context *ctx, me.mlx5dr_action_flags flags)
    mlx5dr_action *mlx5dr_action_create_tag(mlx5dr_context *ctx, me.mlx5dr_action_flags flags)
    mlx5dr_action *mlx5dr_action_create_dest_table(mlx5dr_context *ctx, mlx5dr_table *tbl,
                                                   me.mlx5dr_action_flags flags)
    mlx5dr_action *mlx5dr_action_create_dest_tir(mlx5dr_context *ctx, mlx5dr_devx_obj *obj,
                                                 me.mlx5dr_action_flags flags)
    mlx5dr_action *mlx5dr_action_create_reformat(mlx5dr_context *ctx,
                                                 me.mlx5dr_action_reformat_type reformat_type,
                                                 size_t data_sz, void *data, uint32_t bulk_size,
                                                 uint32_t flags)
    mlx5dr_action *mlx5dr_action_create_modify_header(mlx5dr_context *ctx, size_t pattern_sz,
                                                      uint64_t pattern[], uint32_t log_bulk_size,
                                                      me.mlx5dr_action_flags flags)
    mlx5dr_action *mlx5dr_action_create_default_miss(mlx5dr_context *ctx,
                                                     me.mlx5dr_action_flags flags)
    int mlx5dr_action_destroy(mlx5dr_action *action)

    int mlx5dr_send_queue_poll(mlx5dr_context *ctx, uint16_t queue_id, pdr.rte_flow_q_op_res *res,
                               uint32_t res_nb)