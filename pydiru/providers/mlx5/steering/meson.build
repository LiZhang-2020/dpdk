# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

includes += global_inc

pydiru_cython_modules = [
    'mlx5dr_action.pyx',
    'mlx5dr_context.pyx',
    'mlx5dr_devx_objects.pyx',
    'mlx5dr_enums.pyx',
    'mlx5dr_matcher.pyx',
    'mlx5dr_rule.pyx',
    'mlx5dr_table.pyx'
]

pydiru_python_modules = [
    '__init__.py'
]

link_libs = []
if get_option('default_library') == 'static'
    link_libs = dpdk_static_libraries + dpdk_drivers
endif


foreach pyx_file:pydiru_cython_modules
	python3.extension_module(
		pyx_file.split('.')[0],
		pyx_file,
		dependencies : py3_dep,
		link_whole: link_libs,
		include_directories : includes,
		install_dir : python3.get_path('platlib') + '/pydiru/providers/mlx5/steering',
		install : true
	)
endforeach

foreach py_file:pydiru_python_modules
	python3.install_sources(
		pydiru_python_modules,
		subdir : python3.get_path('platlib') + '/pydiru/providers/mlx5/steering'
	)
endforeach
