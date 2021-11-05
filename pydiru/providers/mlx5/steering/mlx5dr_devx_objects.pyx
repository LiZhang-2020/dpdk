# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from pydiru.providers.mlx5.steering.mlx5dr_action cimport Mlx5drAction
cimport pydiru.providers.mlx5.libmlx5 as dv
from pydiru.pydiru_error import PydiruError
from pydiru.base cimport close_weakrefs
import weakref


cdef class Mlx5drDevxObj(PydiruCM):
    def __init__(self, devx_obj, devx_obj_id):
        super().__init__()
        self.devx_obj = devx_obj
        self.dr_actions = weakref.WeakSet()
        self.dr_devx_obj.obj = <dv.mlx5dv_devx_obj *>devx_obj.obj
        self.dr_devx_obj.id = devx_obj_id

    cdef add_ref(self, obj):
        if isinstance(obj, Mlx5drAction):
            self.dr_actions.add(obj)
        else:
            raise PydiruError('Unrecognized object type')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        self.logger.debug(f'Closing Mlx5drDevxObj. with {len(self.dr_actions)} actions')
        close_weakrefs([self.dr_actions])
        self.devx_obj = None
