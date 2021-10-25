/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */
#ifndef MLX5DR_PAT_ARG_H_
#define MLX5DR_PAT_ARG_H_

/* modify-header arg pool */
enum mlx5dr_arg_chunk_size {
	MLX5DR_ARG_CHUNK_SIZE_1,
	MLX5DR_ARG_CHUNK_SIZE_MIN = MLX5DR_ARG_CHUNK_SIZE_1, /* keep updated when changing */
	MLX5DR_ARG_CHUNK_SIZE_2,
	MLX5DR_ARG_CHUNK_SIZE_3,
	MLX5DR_ARG_CHUNK_SIZE_4,
	MLX5DR_ARG_CHUNK_SIZE_MAX,
};

enum {
	MLX5DR_MODIFY_ACTION_SIZE = 8,
	MLX5DR_ARG_DATA_SIZE = 64,
};

struct mlx5dr_pattern_cache {
	pthread_spinlock_t lock; /* protect pattern list */
	LIST_HEAD(pattern_head, mlx5dr_pat_cached_pattern) head;
};

struct mlx5dr_pat_cached_pattern {
	enum mlx5dr_action_type type;
	struct {
		struct mlx5dr_devx_obj *pattern_obj;
		struct dr_icm_chunk *chunk;
		uint8_t *data;
		uint16_t num_of_actions;
	} mh_data;
	rte_atomic32_t refcount;
	LIST_ENTRY(mlx5dr_pat_cached_pattern) next;
};

enum mlx5dr_arg_chunk_size
mlx5dr_arg_get_arg_log_size(uint16_t num_of_actions);
enum mlx5dr_arg_chunk_size
mlx5dr_arg_data_size_to_arg_log_size(uint16_t data_size);

int mlx5dr_pat_init_pattern_cache(struct mlx5dr_pattern_cache **cache);

void mlx5dr_pat_uninit_pattern_cache(struct mlx5dr_pattern_cache *cache);

int mlx5dr_pat_arg_create_modify_header(struct mlx5dr_context *ctx,
					struct mlx5dr_action *action,
					size_t pattern_sz,
					__be64 pattern[],
					uint32_t bulk_size);

void mlx5dr_pat_arg_destroy_modify_header(struct mlx5dr_context *ctx,
					  struct mlx5dr_action *action);

void mlx5dr_arg_write(struct mlx5dr_send_engine *queue,
		      struct mlx5dr_rule *rule,
		      uint32_t arg_idx,
		      uint8_t *arg_data,
		      size_t data_size);
int mlx5dr_arg_write_inline_arg_data(struct mlx5dr_action *action,
				     __be64 *pattern);


#endif
