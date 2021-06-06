/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_CONTEXT_H_
#define MLX5DR_CONTEXT_H_

struct mlx5dr_context {
	struct ibv_context *ibv_ctx;
	struct ibv_pd *pd;
	struct mlx5dr_send_engine *send_ring[];
};

#endif
