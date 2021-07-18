/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_ACTION_H_
#define MLX5DR_ACTION_H_

enum mlx5dr_action_type {
	MLX5DR_ACTION_TYP_TNL_L2_TO_L2,
	MLX5DR_ACTION_TYP_L2_TO_TNL_L2,
	MLX5DR_ACTION_TYP_TNL_L3_TO_L2,
	MLX5DR_ACTION_TYP_L2_TO_TNL_L3,
	MLX5DR_ACTION_TYP_DROP,
	MLX5DR_ACTION_TYP_QP,
	MLX5DR_ACTION_TYP_FT,
	MLX5DR_ACTION_TYP_CTR,
	MLX5DR_ACTION_TYP_TAG,
	MLX5DR_ACTION_TYP_MODIFY_HDR,
	MLX5DR_ACTION_TYP_VPORT,
	MLX5DR_ACTION_TYP_METER,
	MLX5DR_ACTION_TYP_MISS,
	MLX5DR_ACTION_TYP_POP_VLAN,
	MLX5DR_ACTION_TYP_PUSH_VLAN,
	MLX5DR_ACTION_TYP_SAMPLER,
	MLX5DR_ACCELERATED_MODIFY_ACTION_LIST,
	MLX5DR_ACTION_TYP_DEST_ARRAY,
	MLX5DR_ACTION_TYP_ASO_FIRST_HIT,
	MLX5DR_ACTION_TYP_ASO_FLOW_METER,
	MLX5DR_ACTION_TYP_ASO_CT,
	MLX5DR_ACTION_TYP_MAX,
};

struct mlx5dr_action {
	uint8_t type;
	union {
		struct mlx5dr_table *tbl;
		struct {
			uint32_t rx_id;
			uint32_t tx_id;
		} stc;
		uint32_t stc_id;
	};
};

int mlx5dr_action_root_build_attr(struct mlx5dr_rule_action rule_actions[],
				  uint32_t num_actions,
				  struct mlx5dv_flow_action_attr *attr);

#endif
