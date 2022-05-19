# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017-2019 Intel Corporation

if is_windows
	subdir_done()
endif

apps = [
	'pdump',
	'proc-info',
	'test-acl',
	'test-bbdev',
	'test-cmdline',
	'test-compress-perf',
	'test-crypto-perf',
	'test-eventdev',
	'test-gpudev',
	'test-fib',
	'test-flow-perf',
	'test-pipeline',
	'test-pmd',
	'test-regex',
	'test-sad',
	'test-mlx5']

extra_apps = run_command(list_dir_globs, get_option('apps'), check: true).stdout().split()
if extra_apps.length() >= 1 and extra_apps[0] != '.'
	apps = apps + extra_apps
endif

default_cflags = machine_args + ['-DALLOW_EXPERIMENTAL_API']
default_ldflags = []
if get_option('default_library') == 'static' and not is_windows
	default_ldflags += ['-Wl,--export-dynamic']
endif

foreach app:apps
	build = true
	name = app
	sources = []
	includes = []
	cflags = default_cflags
	ldflags = default_ldflags
	objs = [] # other object files to link against, used e.g. for
	          # instruction-set optimized versions of code

	# use "deps" for internal DPDK dependencies, and "ext_deps" for
	# external package/library requirements
	ext_deps = []
	deps = []

	subdir(name)

	if build
		dep_objs = []
		foreach d:deps
			dep_objs += get_variable(get_option('default_library')
				 + '_rte_' + d)
		endforeach

		link_libs = []
		if get_option('default_library') == 'static'
			link_libs = dpdk_static_libraries + dpdk_drivers
		endif

		executable('dpdk-' + name,
				sources,
				c_args: cflags,
				link_args: ldflags,
				link_whole: link_libs,
				dependencies: dep_objs,
				include_directories: includes,
				install_rpath: join_paths(get_option('prefix'),
						 driver_install_path),
				install: true)
	endif
endforeach

# special case the autotests
subdir('test')
if PYDIRU_SUPPORTED
	subdir('test-mlx5-pydiru')
endif
