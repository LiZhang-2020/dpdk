#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

import argparse
import sys


class ArgsParser:
    def __init__(self):
        self.args = None

    def get_config(self):
        return self.args

    def parse_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--dev',
                            help='RDMA device to run the tests on')
        parser.add_argument('--vf',
                            help='Second RDMA device (VF) for FDB tests')
        parser.add_argument('-a',
                            help='PCI device to run the tests on.\n'
                                 'Passed to the DPDK RTE initialization.')
        parser.add_argument('--port',
                            help='Use port <port> of RDMA device', type=int,
                            default=1)
        parser.add_argument('-v', '--verbose', dest='verbosity',
                            action='store_const',
                            const=2, help='Verbose output')
        parser.add_argument('--list-tests', action='store_true', default=False,
                            help='Print a list of the full test names that are '
                                 'loaded by default and exit without running '
                                 'them.')
        parser.add_argument('--no-huge', action='store_true', default=False,
                            help='Use anonymous memory instead of hugepages.')
        ns, args = parser.parse_known_args()
        self.args = vars(ns)
        self.args['prog'] = sys.argv[0]
        if self.args['verbosity']:
            args += ['--verbose']
        sys.argv[1:] = args


parser = ArgsParser()
