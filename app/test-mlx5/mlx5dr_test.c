/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved.
 */
#include <rte_ethdev.h>
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
	MLX5DR_INIT_TEST(rte_insert, run_test_rte_insert),
	MLX5DR_INIT_TEST(rule_insert, run_test_rule_insert),
	MLX5DR_INIT_TEST(rule_insert_mult, run_test_rule_insert_mult),
	MLX5DR_INIT_TEST(post_send, run_test_post_send),
	MLX5DR_INIT_TEST(modify_header, run_test_modify_header_action),
	MLX5DR_INIT_TEST(test_pool, run_test_pool),
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

static int test_selection(void)
{
	const char *s = getenv("MLX5DR_TEST");
	size_t i;

	test = tests[0];

	printf("Avalible tests (selected by setting MLX5DR_TEST=\"test_name\"):\n");
	for (i = 0; i < sizeof(tests)/ sizeof(tests[0]); i++)
		printf("\tTest: %s\n", tests[i].test_name);

	if (!s)
		goto out;

	for (i = 0; i < sizeof(tests)/ sizeof(tests[0]); i++) {
		if (strlen(s) != strlen(tests[i].test_name))
			continue;

		if (memcmp(tests[i].test_name, s, min(strlen(s), strlen(tests[i].test_name))))
			continue;
		test = tests[i];
		break;
	}
out:
	printf("Test selected: %s\n", test.test_name);
	return 0;
}

int main(int argc, char **argv)
{
	uint16_t nr_ports;
	struct mlx5dv_context_attr dv_ctx_attr = {};
	char *dev_name = def_dev_name;
	struct ibv_device **dev_list = NULL;
	struct ibv_context *ibv_ctx = NULL;
	struct ibv_device *dev = NULL;
	int i, ret;

	if (argc >= 3 && !memcmp("-d", argv[argc - 2], 2)) {
		dev_name = argv[argc - 1];
		argc -=2;
	}
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, ":: invalid EAL arguments\n");

	nr_ports = rte_eth_dev_count_avail();
	printf("nr_ports:%d\n", nr_ports);
	if (!nr_ports)
		return -1;
	ret = test_selection();
	if (ret)
		goto close_ib_dev;
	if (test.run_test != run_test_rte_insert) {
		dev_list = ibv_get_device_list(NULL);
		if (!dev_list) {
			printf("Failed to get IB devices list\n");
			return 1;
		}

		for (i = 0; dev_list[i]; ++i)
			if (!strcmp(ibv_get_device_name(dev_list[i]), dev_name))
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
			fprintf(stderr, "Couldn't get context for %s\n",
				ibv_get_device_name(dev));
			goto free_dev_list;
		}
		fprintf(stderr, "IB device %s Context found\n", dev_name);
	}
	ret = test_run(ibv_ctx);
	if (ret)
		goto close_ib_dev;

	if (ibv_ctx)
		ibv_close_device(ibv_ctx);
	if (dev_list)
		ibv_free_device_list(dev_list);

	return 0;

close_ib_dev:
	if (ibv_ctx)
		ibv_close_device(ibv_ctx);
free_dev_list:
	if (dev_list)
		ibv_free_device_list(dev_list);
	return ret;
}
