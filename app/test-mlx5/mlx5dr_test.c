/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */

#include "mlx5dr_test.h"

char def_dev_name[] = "mlx5_0";

struct test_structs test;

struct test_structs {
	int (*run_test)(struct ibv_context *);
	const char *test_name;
};

#define MLX5DR_INIT_TEST(str, func) \
	{ .test_name = #str, .run_test = func}

static struct test_structs tests[] = {
	MLX5DR_INIT_TEST(rule_insert, run_test_rule_insert),
	MLX5DR_INIT_TEST(post_send, run_test_post_send),
};

static int test_run(struct ibv_context *ibv_ctx)
{
	int ret;

	ret = test.run_test(ibv_ctx);
	if (ret)
		printf("Test %s: Failed\n", test.test_name);
        else
		printf("Test %s: Passed\n", test.test_name);

        return ret;
}

#ifndef min
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

static void test_selection(void)
{
	const char *s = getenv("MLX5DR_TEST");
	size_t i;

	test = tests[0];

	printf("Avalible tests (selected by setting MLX5DR_TEST=\"test_name\"):\n");
	for (i = 0; i < sizeof(tests)/ sizeof(tests[0]); i++)
		printf("\tTest: %s\n", tests[i].test_name);

	for (i = 0; i < sizeof(tests)/ sizeof(tests[0]); i++) {
		if (memcmp(tests[i].test_name, s, min(strlen(s), strlen(tests[i].test_name))))
			continue;
		test = tests[i];
		break;
	}
	printf("Test selected: %s\n", test.test_name);
}

int main(int argc, char **argv)
{
	struct mlx5dv_context_attr dv_ctx_attr = {};
	char *dev_name = def_dev_name;
	struct ibv_device **dev_list;
	struct ibv_context *ibv_ctx;
	struct ibv_device *dev;
	int i, ret;

	if (argc >= 3 && !memcmp("-d", argv[argc - 2], 2)) {
		dev_name = argv[argc - 1];
		argc -=2;
	}
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, ":: invalid EAL arguments\n");

	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		printf("Failed to get IB devices list\n");
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

	test_selection();
	ret = test_run(ibv_ctx);
	if (ret)
		goto close_ib_dev;

	ibv_close_device(ibv_ctx);
	ibv_free_device_list(dev_list);

	return 0;

close_ib_dev:
	ibv_close_device(ibv_ctx);
free_dev_list:
	ibv_free_device_list(dev_list);
	return ret;
}
