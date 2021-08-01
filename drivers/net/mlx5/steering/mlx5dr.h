/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_H_
#define MLX5DR_H_

struct mlx5dr_context;
struct mlx5dr_table;
struct mlx5dr_matcher;
struct mlx5dr_rule;

enum mlx5dr_table_type {
	MLX5DR_TABLE_TYPE_NIC_RX,
	MLX5DR_TABLE_TYPE_NIC_TX,
	MLX5DR_TABLE_TYPE_FDB,
	MLX5DR_TABLE_TYPE_MAX,
};

enum mlx5dr_matcher_insertion_mode {
	MLX5DR_MATCHER_INSERTION_MODE_ASSURED,
	MLX5DR_MATCHER_INSERTION_MODE_BEST_EFFORT,
};

enum mlx5dr_action_flags {
	MLX5DR_ACTION_FLAG_ROOT_RX = 1 << 0,
	MLX5DR_ACTION_FLAG_ROOT_TX = 1 << 1,
	MLX5DR_ACTION_FLAG_ROOT_FDB = 1 << 2,
	MLX5DR_ACTION_FLAG_HWS_RX = 1 << 3,
	MLX5DR_ACTION_FLAG_HWS_TX = 1 << 4,
	MLX5DR_ACTION_FLAG_HWS_FDB = 1 << 5,
	MLX5DR_ACTION_FLAG_INLINE = 1 << 6,
};

enum mlx5dr_action_reformat_type {
	MLX5DR_ACTION_REFORMAT_TYPE_TNL_L2_TO_L2,
	MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L2,
	MLX5DR_ACTION_REFORMAT_TYPE_TNL_L3_TO_L2,
	MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L3,
};

struct mlx5dr_context_attr {
	uint16_t queues;
	uint16_t queue_size;
	size_t initial_log_ste_memory;
	struct ibv_pd *pd;
};

struct mlx5dr_table_attr {
	enum mlx5dr_table_type type;
	uint32_t level;
};

struct mlx5dr_matcher_attr {
	uint32_t priority;
	enum mlx5dr_matcher_insertion_mode insertion_mode;
	uint32_t size_hint_rows_log;
	uint32_t size_hint_column_log;
};

struct mlx5dr_rule_attr {
	uint16_t queue_id;
	void *user_data;
	uint32_t requst_comp:1;
	uint32_t burst:1;
};

struct mlx5dr_devx_obj {
	struct mlx5dv_devx_obj *obj;
	uint32_t id;
};

struct mlx5dr_rule_action {
	struct mlx5dr_action *action;
	union {
		struct {
			uint32_t value;
		} tag;

		struct {
			uint32_t offset;
		} counter;

		struct {
			uint32_t offset;
			uint8_t *data;
		} modify_header;
	};
};

struct mlx5dr_context *
mlx5dr_context_open(struct ibv_context *ibv_ctx,
		    struct mlx5dr_context_attr *attr);

int mlx5dr_context_close(struct mlx5dr_context *ctx);

struct mlx5dr_table *
mlx5dr_table_create(struct mlx5dr_context *ctx,
		    struct mlx5dr_table_attr *attr);

int mlx5dr_table_destroy(struct mlx5dr_table *tbl);

struct mlx5dr_matcher *
mlx5dr_matcher_create(struct mlx5dr_table *table,
		      struct rte_flow_item items[],
		      struct mlx5dr_matcher_attr *attr);

int mlx5dr_matcher_destroy(struct mlx5dr_matcher *matcher);

size_t mlx5dr_rule_get_handle_size(void);

int mlx5dr_rule_create(struct mlx5dr_matcher *matcher,
		       struct rte_flow_item items[],
		       struct mlx5dr_rule_action rule_actions[],
		       uint8_t num_of_actions,
		       struct mlx5dr_rule_attr *attr,
		       struct mlx5dr_rule *rule_handle);

int mlx5dr_rule_destroy(struct mlx5dr_rule *rule,
			struct mlx5dr_rule_attr *attr);

struct mlx5dr_action *
mlx5dr_action_create_drop(struct mlx5dr_context *ctx,
			  enum mlx5dr_action_flags flags);

struct mlx5dr_action *
mlx5dr_action_create_default_miss(struct mlx5dr_context *ctx,
				  enum mlx5dr_action_flags flags);

struct mlx5dr_action *
mlx5dr_action_create_tag(struct mlx5dr_context *ctx,
			 enum mlx5dr_action_flags flags);

struct mlx5dr_action *
mlx5dr_action_create_dest_table(struct mlx5dr_context *ctx,
				struct mlx5dr_table *tbl,
				enum mlx5dr_action_flags flags);

struct mlx5dr_action *
mlx5dr_action_create_dest_tir(struct mlx5dr_context *ctx,
			      struct mlx5dr_devx_obj *obj,
			      enum mlx5dr_action_flags flags);

struct mlx5dr_action *
mlx5dr_action_create_reformat(struct mlx5dr_context *ctx,
			      enum mlx5dr_action_reformat_type reformat_type,
			      size_t data_sz,
			      void *data,
			      uint32_t bulk_size,
			      uint32_t flags);

int mlx5dr_action_destroy(struct mlx5dr_action *action);

#endif
