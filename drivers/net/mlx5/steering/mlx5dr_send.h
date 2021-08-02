/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_SEND_H_
#define MLX5DR_SEND_H_

#define MLX5DR_NUM_SEND_RINGS 1

struct mlx5dr_send_ring_cq {
        uint8_t *buf;
        uint32_t cons_index;
	uint32_t ncqe_mask;
	uint32_t buf_sz;
        uint32_t ncqe;
	uint32_t cqe_log_sz;
        __be32 *db;
	uint16_t poll_wqe;
        struct ibv_cq *ibv_cq;
        uint32_t cqn;
        uint32_t cqe_sz;
};

struct mlx5dr_send_ring_priv {
	struct mlx5dr_rule *rule;
	uint32_t num_wqebbs;
};

struct mlx5dr_send_ring_sq {
	char *buf;
	uint32_t sqn;
	__be32 *db;
	void *reg_addr;
	uint16_t cur_post;
	uint16_t buf_mask;
	struct mlx5dr_send_ring_priv *wr_priv;

	struct mlx5dr_devx_obj *obj;
	struct mlx5dv_devx_umem *buf_umem;
	struct mlx5dv_devx_umem *db_umem;
};

struct mlx5dr_send_ring {
	struct mlx5dr_send_ring_cq send_cq;
	struct mlx5dr_send_ring_sq send_sq;
};

TAILQ_HEAD(completed_rules_list, mlx5dr_rule);

struct mlx5dr_send_engine {
	struct mlx5dr_send_ring send_ring[MLX5DR_NUM_SEND_RINGS]; /* For now 1:1 mapping */
	struct mlx5dv_devx_uar *uar; /* Uar is shared between rings of a queue */
	struct completed_rules_list completed;
	uint16_t rings;
	uint16_t queue_num_entries;
};

struct mlx5dr_send_engine_post_ctrl {
	struct mlx5dr_send_engine *queue;
	struct mlx5dr_send_ring *send_ring;
	size_t num_wqebbs;
};

struct mlx5dr_send_engine_post_attr {
	uint32_t opcode;
	size_t len;
	struct mlx5dr_rule *rule;
	uint32_t id;
	void *user_data;
	uint8_t notify_hw;
};

/**
 * Provide safe 64bit store operation to mlx5 UAR region for both 32bit and
 * 64bit architectures.
 *
 * @param val
 *   value to write in CPU endian format.
 * @param addr
 *   Address to write to.
 * @param lock
 *   Address of the lock to use for that UAR access.
 */
static __rte_always_inline void
mlx5dr_uar_write64_relaxed(uint64_t val, void *addr)
{
#ifdef RTE_ARCH_64
	*(uint64_t *)addr = val;
#else /* !RTE_ARCH_64 */
	*(uint32_t *)addr = val;
	rte_io_wmb();
	*((uint32_t *)addr + 1) = val >> 32;
#endif
}

/* WQE Control segment. */
struct mlx5dr_wqe_ctrl_seg {
        __be32 opmod_idx_opcode;
        __be32 qpn_ds;
        __be32 flags;
        __be32 imm;
};

enum mlx5dr_wqe_gta_op {
	MLX5DR_WQR_GTA_OP_ACTIVATE = 0,
	MLX5DR_WQR_GTA_OP_DEACTIVATE = 1,
};

struct mlx5dr_wqe_gta_ctrl_seg {
	__be32 op_dirix;
	__be32 stc_ix[5];
	__be32 rsvd0[6];
};

struct mlx5dr_wqe_gta_data_seg_ste {
	__be32 rsvd0_ctr_id;
	__be32 rsvd1[4];
	__be32 action[3];
	__be32 tag[8];
};

struct mlx5dr_wqe_gta_data_seg_arg {
	__be32 action_args[8];
};

struct mlx5dr_wqe_gta {
	struct mlx5dr_wqe_gta_ctrl_seg gta_ctrl;
	union {
		struct mlx5dr_wqe_gta_data_seg_ste seg_ste;
		struct mlx5dr_wqe_gta_data_seg_arg seg_arg;
	};
};

void mlx5dr_send_queues_close(struct mlx5dr_context *ctx);
int mlx5dr_send_queues_open(struct mlx5dr_context *ctx,
			    uint16_t queues,
			    uint16_t queue_size);

struct mlx5dr_send_engine_post_ctrl
mlx5dr_send_engine_post_start(struct mlx5dr_send_engine *queue);
void mlx5dr_send_engine_post_req_wqe(struct mlx5dr_send_engine_post_ctrl *ctrl,
				     char **buf, size_t *len);
void mlx5dr_send_engine_post_end(struct mlx5dr_send_engine_post_ctrl *ctrl,
				 struct mlx5dr_send_engine_post_attr *attr);

#endif
