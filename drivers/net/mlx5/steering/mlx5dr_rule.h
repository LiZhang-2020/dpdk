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
	MLX5DR_RULE_STATUS_UNKNOWN,
	MLX5DR_RULE_STATUS_CREATING,
	MLX5DR_RULE_STATUS_CREATED,
	MLX5DR_RULE_STATUS_DELETING,
	MLX5DR_RULE_STATUS_DELETED,
	MLX5DR_RULE_STATUS_FAILED,
};

struct mlx5dr_rule {
	struct mlx5dr_matcher *matcher;
	union {
		uint8_t match_tag[MLX5DR_MATCH_TAG_SZ];
		struct ibv_flow *flow;
	};
	enum mlx5dr_rule_status status;
	uint8_t wait_on_wqes; // TODO see if can be moved out of mlx5dr_rule struct
};

#endif
