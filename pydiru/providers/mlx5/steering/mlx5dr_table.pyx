# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.


from pydiru.providers.mlx5.steering.mlx5dr_context cimport Mlx5drContext
from pydiru.pydiru_error import PydiruError
from pydiru.base import PydiruErrno


cdef class Mlx5drTableAttr(PydiruObject):
    def __init__(self, table_type, level):
        """
        Initialize a Mlx5drTableAttr object representing mlx5dr_table_attr C struct.
        :param table_type: Table type
        :param level: Table level
        """
        super().__init__()
        self.attr.type = table_type
        self.attr.level = level


cdef class Mlx5drTable(PydiruCM):
    def __init__(self, Mlx5drContext context, Mlx5drTableAttr attr):
        """
        Initialize a Mlx5drTable object representing mlx5dr_table C struct.
        :param context: Mlx5drContext context
        :param attr: Attributes for creating Mlx5drTable
        """
        super().__init__()
        self.table = dr.mlx5dr_table_create(context.context,
                                            <dr.mlx5dr_table_attr *>&(attr.attr))
        if self.table == NULL:
            raise PydiruErrno('Failed creating Mlx5drTable')
        self.mlx5dr_context = context
        context.add_ref(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.table != NULL:
            self.logger.debug('Closing Mlx5drTable.')
            rc = dr.mlx5dr_table_destroy(<dr.mlx5dr_table *>(self.table))
            if rc:
                raise PydiruError('Failed to destroy Mlx5drTable.', rc)
            self.table = NULL
            self.mlx5dr_context = None
