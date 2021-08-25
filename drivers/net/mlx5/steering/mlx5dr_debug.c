/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_internal.h"

int mlx5dr_debug_context(struct mlx5dr_context *ctx)
{
	pthread_spin_lock(&ctx->ctrl_lock);
	printf("Not supported yet %p\n", (void *)ctx);
	pthread_spin_unlock(&ctx->ctrl_lock);

	return 0;
}
