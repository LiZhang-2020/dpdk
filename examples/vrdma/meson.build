# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2022 Nvidia Inc. All rights reserved.

# meson file, for building this example as part of a main DPDK build.
#
# To build this example as a standalone application with an already-installed
# DPDK instance, use 'make'

if not is_linux
	build = false
	subdir_done()
endif

# deps += 'vrdma'
allow_experimental_apis = true
sources = files(
	'main.c'
)
