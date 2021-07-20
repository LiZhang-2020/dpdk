/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_RULE_H_
#define MLX5DR_RULE_H_

enum {
	MLX5DR_MATCH_TAG_SZ = 32,
	MLX5DR_JAMBO_TAG_SZ = 44,
};

enum mlx5dr_rule_status {
	MLX5DR_RULE_UNKNOWN,
	MLX5DR_RULE_IN_QUEUE,
	MLX5DR_RULE_COMPLETED_SUCC,
	MLX5DR_RULE_COMPLETED_ERR,
	MLX5DR_RULE_DELETED,
};

struct mlx5dr_rule {
	struct mlx5dr_matcher *matcher;
	union {
		uint8_t match_tag[MLX5DR_MATCH_TAG_SZ];
		struct ibv_flow *flow;
	};
	enum mlx5dr_rule_status rule_status;
};

#endif
