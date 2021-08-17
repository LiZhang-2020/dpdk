#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

import unittest

from args_parser import parser


class PydiruAPITestCase(unittest.TestCase):
    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
        # Hold the command line arguments
        self.config = parser.get_config()
        self.dev_name = None
        self.ctx = None

    def setUp(self):
        pass

    def tearDown(self):
        pass
