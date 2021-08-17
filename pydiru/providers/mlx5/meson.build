# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.


pydiru_cython_modules = [
]

pydiru_python_modules = [
    '__init__.py'
]


foreach pyx_file:pydiru_cython_modules
	python3.extension_module(
		pyx_file.split('.')[0],
		pyx_file,
		dependencies : py3_dep,
		include_directories : includes,
		install_dir : python3.get_path('platlib') + '/pydiru/providers/mlx5',
		install : true
	)
endforeach

foreach py_file:pydiru_python_modules
	python3.install_sources(
		pydiru_python_modules,
		subdir : python3.get_path('platlib') + '/pydiru/providers/mlx5'
	)
endforeach

subdir('steering')
