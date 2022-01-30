/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */
#ifndef MLX5DR_ACTION_H_
#define MLX5DR_ACTION_H_

enum mlx5dr_action_stc_idx {
	MLX5DR_ACTION_STC_IDX_CTRL = 0,
	MLX5DR_ACTION_STC_IDX_HIT = 1,
	MLX5DR_ACTION_STC_IDX_DW5 = 2,
	MLX5DR_ACTION_STC_IDX_DW6 = 3,
	MLX5DR_ACTION_STC_IDX_DW7 = 4,
	MLX5DR_ACTION_STC_IDX_MAX = 5,
	/* STC combo1: CTR, SINGLE, DOUBLE, Hit */
	MLX5DR_ACTION_STC_IDX_LAST_COMBO1 = 3,
	/* STC combo2: CTR, 3 x SINGLE, Hit */
	MLX5DR_ACTION_STC_IDX_LAST_COMBO2 = 4,
};

enum mlx5dr_action_offset {
	MLX5DR_ACTION_OFFSET_DW0 = 0,
	MLX5DR_ACTION_OFFSET_DW5 = 5,
	MLX5DR_ACTION_OFFSET_DW6 = 6,
	MLX5DR_ACTION_OFFSET_DW7 = 7,
	MLX5DR_ACTION_OFFSET_HIT = 3,
};

enum mlx5dr_action_type {
	MLX5DR_ACTION_TYP_TNL_L2_TO_L2,
	MLX5DR_ACTION_TYP_L2_TO_TNL_L2,
	MLX5DR_ACTION_TYP_TNL_L3_TO_L2,
	MLX5DR_ACTION_TYP_L2_TO_TNL_L3,
	MLX5DR_ACTION_TYP_DROP,
	MLX5DR_ACTION_TYP_QP,
	MLX5DR_ACTION_TYP_TIR,
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
	MLX5DR_ACTION_TYP_DEST_ARRAY,
	MLX5DR_ACTION_TYP_ASO_FIRST_HIT,
	MLX5DR_ACTION_TYP_ASO_FLOW_METER,
	MLX5DR_ACTION_TYP_ASO_CT,
	MLX5DR_ACTION_TYP_MH_SET,
	MLX5DR_ACTION_TYP_MH_ADD,
	MLX5DR_ACTION_TYP_MH_COPY,
	MLX5DR_ACTION_TYP_MAX,
};

enum {
	MLX5DR_ACTION_DOUBLE_SIZE = 8,
	MLX5DR_ACTION_INLINE_DATA_SIZE = 4,
	MLX5DR_ACTION_HDR_LEN_L2_MACS = 12,
	MLX5DR_ACTION_HDR_LEN_L2_VLAN = 4,
	MLX5DR_ACTION_HDR_LEN_L2_ETHER = 2,
	MLX5DR_ACTION_HDR_LEN_L2 = (MLX5DR_ACTION_HDR_LEN_L2_MACS + MLX5DR_ACTION_HDR_LEN_L2_ETHER),
	MLX5DR_ACTION_HDR_LEN_L2_W_VLAN = (MLX5DR_ACTION_HDR_LEN_L2 + MLX5DR_ACTION_HDR_LEN_L2_VLAN),
	MLX5DR_ACTION_REFORMAT_DATA_SIZE = 64,
	DECAP_L3_NUM_ACTIONS_W_NO_VLAN = 6,
	DECAP_L3_NUM_ACTIONS_W_VLAN = 7,
};

struct mlx5dr_action_default_stc {
	struct mlx5dr_pool_chunk nop_ctr;
	struct mlx5dr_pool_chunk nop_dw5;
	struct mlx5dr_pool_chunk nop_dw6;
	struct mlx5dr_pool_chunk nop_dw7;
	struct mlx5dr_pool_chunk default_hit;
	uint32_t refcount;
};

struct mlx5dr_action_shared_stc {
	struct mlx5dr_pool_chunk remove_header;
	rte_atomic32_t refcount;
};

struct mlx5dr_action {
	uint8_t type;
	uint8_t flags;
	struct mlx5dr_context *ctx;
	union {
		struct {
			struct mlx5dr_pool_chunk stc[MLX5DR_TABLE_TYPE_MAX];
			union {
				struct {
					struct mlx5dr_devx_obj *pattern_obj;
					struct mlx5dr_devx_obj *arg_obj;
					uint16_t num_of_actions;
				} modify_header;
				struct {
					uint16_t src_field;
					uint8_t src_offset;
					uint8_t length;
					uint16_t dst_field;
					uint8_t dst_offset;
					__be32 data;
				} modify_action;
				struct {
					struct mlx5dr_devx_obj *arg_obj;
					uint32_t header_size;
				} reformat;
			};
		};

		struct ibv_flow_action *flow_action;
		struct mlx5dv_devx_obj *devx_obj;
		struct ibv_qp *qp;
	};
};

int mlx5dr_action_root_build_attr(struct mlx5dr_rule_action rule_actions[],
				  uint32_t num_actions,
				  struct mlx5dv_flow_action_attr *attr);

int mlx5dr_action_get_default_stc(struct mlx5dr_context *ctx,
				  uint8_t tbl_type);

void mlx5dr_action_put_default_stc(struct mlx5dr_context *ctx,
				   uint8_t tbl_type);

int mlx5dr_actions_quick_apply(struct mlx5dr_send_engine *queue,
			       struct mlx5dr_context_common_res *common_res,
			       struct mlx5dr_wqe_gta_ctrl_seg *wqe_ctrl,
			       struct mlx5dr_wqe_gta_data_seg_ste *wqe_data,
			       struct mlx5dr_rule_action rule_actions[],
			       uint8_t num_actions,
			       enum mlx5dr_table_type tbl_type);

void
mlx5dr_action_prepare_decap_l3_data(uint8_t *src, uint8_t *dst,
				    uint16_t num_of_actions);
#endif

