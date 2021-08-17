#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from importlib.machinery import SourceFileLoader
from args_parser import parser
import unittest
import os


module_path = os.path.join(os.path.dirname(__file__), '__init__.py')
tests = SourceFileLoader('test-mlx5-pydiru', module_path).load_module()
parser.parse_args()
unittest.main(module=tests)
