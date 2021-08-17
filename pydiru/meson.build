# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

PYDIRU_SUPPORTED = false

if not get_option('pydiru')
	subdir_done()
endif

get_meson_ver = run_command('meson', '--version')
if get_meson_ver.stdout().version_compare('< 0.59.0')
	message('Skipping pydiru: meson version 0.59.0 and above is required')
else
	# Check for cython installation
	cython = find_program('cython', required:false)
	if not cython.found()
		message('Cython3 was not found - skipping pydiru')
	else
		# Check for python installation
		if not python3.found()
			message('Python3 was not found - skipping pydiru')
		else
			PYDIRU_SUPPORTED = true
		endif
	endif
endif

if not PYDIRU_SUPPORTED
	subdir_done()
endif


includes += global_inc

pydiru_cython_modules = [
	'base.pyx'
]

pydiru_python_modules = [
	'__init__.py'
]

py3_dep = python3.dependency(required:false)
foreach pyx_file:pydiru_cython_modules
	python3.extension_module(
		pyx_file.split('.')[0],
		pyx_file,
		dependencies : py3_dep,
		include_directories : includes,
		install_dir : python3.get_path('platlib') + '/pydiru',
		install : true
	)
endforeach

foreach py_file:pydiru_python_modules
	python3.install_sources(
		pydiru_python_modules,
		subdir : python3.get_path('platlib') + '/pydiru'
	)
endforeach


subdir('providers/mlx5')
