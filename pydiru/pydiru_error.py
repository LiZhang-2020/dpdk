# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.
import os


class PydiruError(Exception):
    """
    Base exception class for Pydiru.
    """
    def __init__(self, msg, error_code=-1):
        """
        Initializes a PydiruError instance
        :param msg: The exception's message
        :param error_code: errno value
        """
        if error_code != -1:
            msg = f'{msg}. Errno: {error_code}, {os.strerror(error_code)}'
        super(PydiruError, self).__init__(msg)
        self._error_code = error_code

    @property
    def error_code(self):
        return self._error_code
