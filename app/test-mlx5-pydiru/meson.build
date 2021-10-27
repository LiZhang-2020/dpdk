# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

static_build = (get_option('default_library') == 'static')

if not get_option('pydiru')
	subdir_done()
endif

if not static_build
	message('The libraries are not static - skipping pydiru installation')
	subdir_done()
endif

pydiru_python_tests = [
    '__init__.py',
    'args_parser.py',
    'base.py',
    'prm_structs.py',
    'run_tests.py',
    'utils.py'
]


foreach py_file:pydiru_python_tests
    python3.install_sources(
        pydiru_python_tests,
        subdir : join_paths(get_option('prefix'),
                            'bin/dpdk-test-mlx5-pydiru')
    )
endforeach
