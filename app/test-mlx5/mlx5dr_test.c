/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include <infiniband/verbs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <rte_flow.h>
#include "../../drivers/net/mlx5/steering/mlx5dr.h"
#include "/usr/include/infiniband/mlx5dv.h"

char dev_name[] = "mlx5_0";

static int run_test(struct ibv_context *ibv_ctx)
{
	struct mlx5dr_context *ctx;
	struct mlx5dr_context_attr dr_ctx_attr = {0};

	dr_ctx_attr.initial_log_ste_memory = 0;
	dr_ctx_attr.pd = NULL;
	dr_ctx_attr.queues = 16;
	dr_ctx_attr.queues_size = 1024;

	ctx = mlx5dr_context_open(ibv_ctx, &dr_ctx_attr);
	if (!ctx)
		goto out_err;

	mlx5dr_context_close(ctx);

	return 0;

out_err:
	return -1;
}

int main(int argc, char **argv)
{
	struct mlx5dv_context_attr dv_ctx_attr = {};
	struct ibv_device **dev_list;
	struct ibv_context *ibv_ctx;
	struct ibv_device *dev;
	int i, ret;

	if (argc && argv)
		printf("ignoring params");

	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		printf("Failed to get IB devices list");
		return 1;
	}

	for (i = 0; dev_list[i]; ++i)
		if(!strcmp(ibv_get_device_name(dev_list[i]), dev_name))
			break;

	dev = dev_list[i];
	if (!dev) {
		fprintf(stderr, "IB device %s not found\n", dev_name);
		goto free_dev_list;
	}
	fprintf(stderr, "IB device %s found\n", dev_name);

	dv_ctx_attr.flags = MLX5DV_CONTEXT_FLAGS_DEVX;
	ibv_ctx = mlx5dv_open_device(dev, &dv_ctx_attr);
	if (!ibv_ctx) {
	        fprintf(stderr,"Couldn't get context for %s\n", ibv_get_device_name(dev));
	        goto free_dev_list;
	}
	fprintf(stderr, "IB device %s Context found\n", dev_name);

	ret = run_test(ibv_ctx);
	if (ret) {
		fprintf(stderr,"Fail to run test\n");
		goto close_ib_dev;
	}
	fprintf(stderr, "Test done\n");

	ibv_close_device(ibv_ctx);
	ibv_free_device_list(dev_list);

	return 0;

close_ib_dev:
	ibv_close_device(ibv_ctx);
free_dev_list:
	ibv_free_device_list(dev_list);
	return ret;
}
