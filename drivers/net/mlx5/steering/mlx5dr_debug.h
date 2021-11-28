/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_DEBUG_H_
#define MLX5DR_DEBUG_H_

#define DEBUG_VERSION "1.0"

enum mlx5dr_debug_res_type {
	MLX5DR_DEBUG_RES_TYPE_CONTEXT = 4000,
	MLX5DR_DEBUG_RES_TYPE_CONTEXT_ATTR = 4001,
	MLX5DR_DEBUG_RES_TYPE_CONTEXT_CAPS = 4002,
	MLX5DR_DEBUG_RES_TYPE_CONTEXT_SEND_ENGINE = 4003,
	MLX5DR_DEBUG_RES_TYPE_CONTEXT_SEND_RING = 4004,

	MLX5DR_DEBUG_RES_TYPE_TABLE = 4100,
	MLX5DR_DEBUG_RES_TYPE_TABLE_NIC_RX = 4101,
	MLX5DR_DEBUG_RES_TYPE_TABLE_NIC_TX = 4102,

	MLX5DR_DEBUG_RES_TYPE_MATCHER = 4200,
	MLX5DR_DEBUG_RES_TYPE_MATCHER_ATTR = 4201,
	MLX5DR_DEBUG_RES_TYPE_MATCHER_NIC_RX = 4202,
	MLX5DR_DEBUG_RES_TYPE_MATCHER_NIC_TX = 4203,
	MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE = 4204,
	MLX5DR_DEBUG_RES_TYPE_MATCHER_TEMPLATE_DEFINER = 4205,
};

#endif
