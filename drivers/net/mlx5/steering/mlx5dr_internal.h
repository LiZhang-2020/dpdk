/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_INTERNAL_H_
#define MLX5DR_INTERNAL_H_

#include <stdint.h>
#include <sys/queue.h>
/* Verbs headers do not support -pedantic. */
#ifdef PEDANTIC
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>
#ifdef PEDANTIC
#pragma GCC diagnostic error "-Wpedantic"
#endif
#include <rte_flow.h>
#include <rte_gtp.h>

#include "mlx5_prm.h"
#include "mlx5_glue.h"
#include "mlx5_flow.h"
#include "mlx5_utils.h"
#include "mlx5_malloc.h"

#include "mlx5dr.h"
#include "mlx5dr_pool.h"
#include "mlx5dr_context.h"
#include "mlx5dr_table.h"
#include "mlx5dr_matcher.h"
#include "mlx5dr_send.h"
#include "mlx5dr_rule.h"
#include "mlx5dr_action.h"
#include "mlx5dr_cmd.h"
#include "mlx5dr_definer.h"
#include "mlx5dr_debug.h"
#include "mlx5dr_pat_arg.h"

#define DW_SIZE		4
#define IS_BIT_SET(_value, _bit) (_value & (1ULL << (_bit)))

#ifdef RTE_LIBRTE_MLX5_DEBUG
/* Prevent double function name print when debug is set */
#define DR_LOG DRV_LOG
#else
/* Print function name as part of the log */
#define DR_LOG(level, ...) \
	DRV_LOG(level, RTE_FMT("[%s]: " RTE_FMT_HEAD(__VA_ARGS__,) "\n", __func__, RTE_FMT_TAIL(__VA_ARGS__,)))
#endif

static inline void *simple_malloc(size_t size)
{
	return mlx5_malloc(MLX5_MEM_SYS,
			   size,
			   MLX5_MALLOC_ALIGNMENT,
			   SOCKET_ID_ANY);
}

static inline void *simple_calloc(size_t nmemb, size_t size)
{
	return mlx5_malloc(MLX5_MEM_SYS | MLX5_MEM_ZERO,
			   nmemb * size,
			   MLX5_MALLOC_ALIGNMENT,
			   SOCKET_ID_ANY);
}

static inline void simple_free(void *addr)
{
	mlx5_free(addr);
}

#endif
