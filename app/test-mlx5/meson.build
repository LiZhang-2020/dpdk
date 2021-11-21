# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Mellanox Technologies, Ltd

dlopen_ibverbs = (get_option('ibverbs_link') == 'dlopen')
static_build = (get_option('default_library') == 'static')

if static_build and not dlopen_ibverbs
sources = files(
	'mlx5dr_test.c',
	'mlx5dr_test_rule_insert.c',
	'mlx5dr_test_rule_insert_mult.c',
	'mlx5dr_test_post_send.c',
	'mlx5dr_test_pattern_args.c',
	'mlx5dr_test_pool.c',
)
else
	sources = files('mlx5dr_test_dummy.c')
endif
deps += ['ethdev']
