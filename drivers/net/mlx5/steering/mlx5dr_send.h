/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_SEND_H_
#define MLX5DR_SEND_H_

#include "mlx5dr_internal.h"

#define MLX5DR_NUM_SEND_RINGS 1

struct mlx5dr_send_ring_cq {
        uint8_t *buf;
        uint32_t cons_index;
        uint32_t ncqe;
        __be32 *db;
        struct ibv_cq *ibv_cq;
        uint32_t cqn;
        uint32_t cqe_sz;
};

struct mlx5dr_send_ring_priv {
	void *rule;
};

struct mlx5dr_send_ring_sq {
	void *buf;
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

struct mlx5dr_send_engine {
	struct mlx5dr_send_ring send_ring[MLX5DR_NUM_SEND_RINGS]; /* For now 1:1 mapping */
	struct mlx5dv_devx_uar *uar; /* Uar is shared between rings of a queue */
	uint16_t rings;
	uint16_t queue_num_entries;
};

void mlx5dr_send_queues_close(struct mlx5dr_context *ctx);
int mlx5dr_send_queues_open(struct mlx5dr_context *ctx,
			    uint16_t queues,
			    uint16_t queue_size);
#endif
