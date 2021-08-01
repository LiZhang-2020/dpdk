/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#ifndef MLX5DR_TEST_H_
#define MLX5DR_TEST_H_

#include <infiniband/verbs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <rte_flow.h>
#include "../../drivers/net/mlx5/steering/mlx5dr.h"
#include "/usr/include/infiniband/mlx5dv.h"

#include "../../drivers/net/mlx5/steering/mlx5dr_context.h"
#include "../../drivers/net/mlx5/steering/mlx5dr_send.h"
#include "../../drivers/net/mlx5/steering/mlx5dr_rule.h"

#define MAX_ITEMS 10

/* Tests */

int run_test_post_send(struct ibv_context *ibv_ctx);
int run_test_rule_insert(struct ibv_context *ibv_ctx);

#endif

