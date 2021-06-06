/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_INTERNAL_H_
#define MLX5DR_INTERNAL_H_

#include <stdint.h>
#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>

#include "mlx5_prm.h"
#include "mlx5_glue.h"
#include "mlx5_utils.h"
#include "mlx5_malloc.h"

#include "mlx5dr.h"
#include "mlx5dr_context.h"

static inline void *simple_malloc(size_t size)
{
	return mlx5_malloc(MLX5_MEM_ANY,
			   size,
			   MLX5_MALLOC_ALIGNMENT,
			   SOCKET_ID_ANY);
}

static inline void *simple_calloc(size_t size)
{
	return mlx5_malloc(MLX5_MEM_SYS | MLX5_MEM_ZERO,
			   size,
			   MLX5_MALLOC_ALIGNMENT,
			   SOCKET_ID_ANY);
}

static inline void simple_free(void *addr)
{
	return mlx5_free(addr);
}

#endif
