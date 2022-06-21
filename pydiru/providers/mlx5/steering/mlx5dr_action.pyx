# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Nvidia Inc. All rights reserved.

from pydiru.providers.mlx5.steering.mlx5dr_context cimport Mlx5drContext
from pydiru.providers.mlx5.steering.mlx5dr_table cimport Mlx5drTable
from pydiru.providers.mlx5.steering.mlx5dr_rule cimport Mlx5drRule
cimport pydiru.providers.mlx5.steering.mlx5dr_enums_c as me
from pydiru.pydiru_error import PydiruError
cimport pydiru.providers.mlx5.mlx5 as mlx5
from pydiru.base cimport close_weakrefs
from libc.stdlib cimport free, calloc
from pydiru.base import PydiruErrno
from libc.stdint cimport uint8_t
import weakref
import struct
import socket

be64toh = lambda num: struct.unpack('Q'.encode(), struct.pack('!8s'.encode(), num))[0]


cdef class Mlx5drAction(PydiruCM):
    def __init__(self, Mlx5drContext ctx):
        super().__init__()
        self.mlx5dr_rules = weakref.WeakSet()
        ctx.add_ref(self)
        self.mlx5dr_context = ctx

    cdef add_ref(self, obj):
        if isinstance(obj, Mlx5drRule):
            self.mlx5dr_rules.add(obj)
        else:
            raise PydiruError('Unrecognized object type')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action != NULL:
            self.logger.debug('Closing Mlx5drAction.')
            close_weakrefs([self.mlx5dr_rules])
            rc = mlx5._action_destroy(self.action)
            if rc:
                raise PydiruError('Failed to destroy Mlx5drAction.', rc)
            self.action = NULL
            self.mlx5dr_context = None


cdef class Mlx5drActionDrop(Mlx5drAction):
    def __init__(self, Mlx5drContext ctx, flags):
        """
        Initializes a destination drop action.
        :param ctx: Mlx5drContext context
        :param flags: Action flags
        """
        super().__init__(ctx)
        self.action = mlx5._action_create_dest_drop(ctx.context, flags)
        if self.action == NULL:
            raise PydiruErrno('Mlx5drActionDrop creation failed.')


cdef class Mlx5drActionTag(Mlx5drAction):
    def __init__(self, Mlx5drContext ctx, flags):
        """
        Initializes a tag action.
        :param ctx: Mlx5drContext context
        :param flags: Action flags
        """
        super().__init__(ctx)
        self.action = mlx5._action_create_tag(ctx.context, flags)
        if self.action == NULL:
            raise PydiruErrno('Mlx5drActionTag creation failed.')


cdef class Mlx5drActionDestTable(Mlx5drAction):
    def __init__(self, Mlx5drContext ctx, Mlx5drTable table, flags):
        """
        Initializes a destination table action.
        :param ctx: Mlx5drContext context
        :param table: Destination table
        :param flags: Action flags
        """
        super().__init__(ctx)
        self.action = mlx5._action_create_dest_table(ctx.context, table.table, flags)
        if self.action == NULL:
            raise PydiruErrno('Mlx5drActionDestTable creation failed.')


cdef class Mlx5drActionDestTir(Mlx5drAction):
    def __init__(self, Mlx5drContext ctx, Mlx5drDevxObj tir, flags):
        """
        Initializes a destination TIR action.
        :param ctx: Mlx5drContext context
        :param tir: Destination TIR
        :param flags: Action flags
        """
        super().__init__(ctx)
        self.action = mlx5._action_create_dest_tir(ctx.context, &tir.dr_devx_obj, flags)
        if self.action == NULL:
            raise PydiruErrno('Mlx5drActionDestTir creation failed.')
        self.tir = tir
        tir.dr_actions.add(self)


cdef class Mlx5drActionReformat(Mlx5drAction):
    def __init__(self, Mlx5drContext ctx, ref_type, data_sz, data, bulk_size, flags):
        """
        Initializes a packet reformat action.
        :param ctx: Mlx5drContext context
        :param ref_type: Reformat type
        :param data_sz: Size of the data
        :param data: Data
        :param bulk_size: Bulk size
        :param flags: Action flags
        """
        super().__init__(ctx)
        cdef unsigned char* c_data = NULL
        if data:
            arr = bytearray(data)
            c_data = <unsigned char *>calloc(1, data_sz)
            if c_data == NULL:
                raise MemoryError('Memory allocation failed.')
            for i in range(data_sz):
                c_data[i] = arr[i]
        self.action = mlx5._action_create_reformat(ctx.context, ref_type, data_sz,
                                                   c_data if data else NULL, bulk_size, flags)
        if c_data != NULL:
            free(c_data)
        if self.action == NULL:
            raise PydiruErrno('Mlx5drActionReformat creation failed.')


cdef class Mlx5drActionModify(Mlx5drAction):
    def __init__(self, Mlx5drContext ctx, pattern_sz, actions, log_bulk_size, flags):
        """
        Initializes a modify header action.
        :param ctx: Mlx5drContext context
        :param pattern_sz: Byte size of the pattern array
        :param actions: PRM format modify action array
        :param log_bulk_size: Number of unique values used with this pattern
        :param flags: Action flags
        """
        super().__init__(ctx)
        cdef unsigned long long *buf = <unsigned long long*>calloc(1, pattern_sz)
        if buf == NULL:
           raise MemoryError('Failed to allocate memory')
        if pattern_sz != len(actions) * 8:
            self.logger.warning(f'Pattern size ({pattern_sz}) must be equal to'
                                f' num of actions {len(actions)} * 8')
        for i in range(len(actions)):
            buf[i] = be64toh(bytes(actions[i]))
        self.action = mlx5._action_create_modify_header(ctx.context, pattern_sz, buf,
                                                        log_bulk_size, flags)
        free(buf)
        if self.action == NULL:
            raise PydiruErrno('Mlx5drActionModify creation failed.')


cdef class Mlx5drActionDefaultMiss(Mlx5drAction):
    def __init__(self, Mlx5drContext ctx, flags):
        """
        Initializes a default miss action.
        :param ctx:  Mlx5drContext context
        :param flags: Action flags
        """
        super().__init__(ctx)
        self.action = mlx5._action_create_default_miss(ctx.context, flags)
        if self.action == NULL:
            raise PydiruErrno('Mlx5drActionDefaultMiss creation failed.')


cdef class Mlx5drActionCounter(Mlx5drAction):
    def __init__(self, Mlx5drContext ctx, Mlx5drDevxObj counter, flags):
        """
        Initializes a counter action.
        :param ctx: Mlx5drContext context
        :param counter: DR devx counter object
        :param flags: Action flags
        """
        super().__init__(ctx)
        self.action = mlx5._action_create_counter(ctx.context, &counter.dr_devx_obj, flags)
        if self.action == NULL:
            raise PydiruErrno('Mlx5drActionCounter creation failed.')
        self.counter = counter
        counter.add_ref(self)


cdef class Mlx5drActionDestVport(Mlx5drAction):
    def __init__(self, Mlx5drContext ctx, ib_port_num, flags):
        """
        Initializes a destination VPort action.
        :param ctx: Mlx5drContext context
        :param ib_port_num: IB port number
        :param flags: Action flags
        """
        super().__init__(ctx)
        self.action = mlx5._action_create_dest_vport(ctx.context, ib_port_num, flags)
        if self.action == NULL:
            raise PydiruErrno('Mlx5drActionDestVport creation failed.')


cdef class Mlx5drAsoFlowMeter(Mlx5drAction):
    def __init__(self, Mlx5drContext ctx, Mlx5drDevxObj aso_obj, flags, reg_c=0):
        """
        Initializes ASO flow meter action
        :param ctx: Mlx5drContext context
        :param aso_obj: DR devx ASO object
        :param flags: Action flags
        :param reg_c: Reg C index for setting the color
        """
        super().__init__(ctx)
        self.action = mlx5._action_create_aso_flow_meter(ctx.context, &aso_obj.dr_devx_obj, reg_c, flags)
        if self.action == NULL:
            raise PydiruErrno('Mlx5drAsoFlowMeter creation failed.')
        self.aso_obj = aso_obj
        aso_obj.add_ref(self)


cdef class Mlx5drActionPushVlan(Mlx5drAction):
    def __init__(self, Mlx5drContext ctx, flags):
        """
        Initializes a push VLAN action.
        :param ctx: Mlx5drContext context
        :param flags: Action flags
        """
        super().__init__(ctx)
        self.action = mlx5._action_create_push_vlan(ctx.context, flags)
        if self.action == NULL:
            raise PydiruErrno('Mlx5drActionPushVlan creation failed.')


cdef class Mlx5drActionPopVlan(Mlx5drAction):
    def __init__(self, Mlx5drContext ctx, flags):
        """
        Initializes a pop VLAN action.
        :param ctx: Mlx5drContext context
        :param flags: Action flags
        """
        super().__init__(ctx)
        self.action = mlx5._action_create_pop_vlan(ctx.context, flags)
        if self.action == NULL:
            raise PydiruErrno('Mlx5drActionPopVlan creation failed.')


cdef class Mlx5drActionCtAso(Mlx5drAction):
    def __init__(self, Mlx5drContext ctx, Mlx5drDevxObj aso_obj, flags, reg_c=0):
        """
        Initializes CT ASO action
        :param ctx: Mlx5drContext context
        :param aso_obj: DR devx ASO object
        :param flags: Action flags
        :param reg_c: Reg C index for setting the color
        """
        super().__init__(ctx)
        self.action = mlx5._action_create_ct_aso(ctx.context, &aso_obj.dr_devx_obj, reg_c, flags)
        if self.action == NULL:
            raise PydiruErrno('Mlx5drActionCtAso creation failed.')
        self.aso_obj = aso_obj
        aso_obj.add_ref(self)


cdef class Mlx5drRuleAction(PydiruCM):
    """
    Class Mlx5drRuleAction representing mlx5dr_rule_action struct.
    Action to be used for rule creation.
    """
    def __init__(self, Mlx5drAction action, **kwargs):
        """
        Initializes the Mlx5drRuleAction object representing mlx5dr_rule_action struct.
        :param action: Mlx5drAction action
        :param kwargs: value - for tag value
                       data - for modify or reformat actions data
                       offset - offset for modify, reformat, ASO flow meter or counter actions
                       meter_init_color - init color for ASO flow meter
        """
        super().__init__()
        self.rule_action.action = action.action
        self.action = action
        self.data_buf = NULL
        data = kwargs.get('data')
        offset = kwargs.get('offset', 0)
        if isinstance(self.action, Mlx5drActionTag):
            self.tag_value = kwargs.get('value', 0)
        elif isinstance(self.action, Mlx5drActionModify):
            if data:
                self.modify_data = data
            self.modify_offset = offset
        elif isinstance(self.action, Mlx5drActionReformat):
            if data:
                self.reformat_data = data
            self.reformat_offset = offset
        elif isinstance(self.action, Mlx5drActionCounter):
            self.counter_offset = kwargs.get('offset', 0)
        elif isinstance(self.action, Mlx5drAsoFlowMeter):
            self.aso_flow_meter_offset = kwargs.get('offset', 0)
            self.aso_flow_meter_init_color = kwargs.get('meter_init_color', 0)
        elif isinstance(self.action, Mlx5drActionCtAso):
            self.ct_aso_offset = kwargs.get('offset', 0)
            self.direction = kwargs.get('direction', 0)
        elif isinstance(self.action, Mlx5drActionPushVlan):
            self.vlan_hdr = kwargs.get('vlan_hdr', 0)

    @property
    def tag_value(self):
        return self.rule_action.tag.value

    @tag_value.setter
    def tag_value(self, value):
        self.rule_action.tag.value = value

    @property
    def action(self):
        return self.action

    @action.setter
    def action(self, Mlx5drAction value):
        self.rule_action.action = value.action
        self.action = value

    @property
    def counter_offset(self):
        return self.rule_action.counter.offset

    @counter_offset.setter
    def counter_offset(self, offset):
        self.rule_action.counter.offset = offset

    @property
    def modify_data(self):
        return <object>self.rule_action.modify_header.data

    @modify_data.setter
    def modify_data(self, actions):
        self.data_buf = <unsigned long long*>calloc(1, len(actions) * 8)
        if self.data_buf == NULL:
           raise MemoryError('Failed to allocate memory')
        for i in range(len(actions)):
            (<unsigned long long*>self.data_buf)[i] = \
                <unsigned long long>(be64toh(bytes(actions[i])))
        self.rule_action.modify_header.data = <uint8_t *>self.data_buf

    @property
    def modify_offset(self):
        return self.rule_action.modify_header.offset

    @modify_offset.setter
    def modify_offset(self, offset):
        self.rule_action.modify_header.offset = offset

    @property
    def reformat_data(self):
        return <object>self.rule_action.reformat.data

    @reformat_data.setter
    def reformat_data(self, data):
        arr = bytearray(data)
        self.data_buf = <uint8_t *> calloc(1, len(arr))
        if self.data_buf == NULL:
           raise MemoryError('Failed to allocate memory')
        for i in range(len(arr)):
            (<uint8_t *>self.data_buf)[i] = arr[i]
        self.rule_action.reformat.data = <uint8_t *>self.data_buf

    @property
    def reformat_offset(self):
        return self.rule_action.reformat.offset

    @reformat_offset.setter
    def reformat_offset(self, offset):
        self.rule_action.reformat.offset = offset

    @property
    def aso_flow_meter_offset(self):
        return self.rule_action.aso_meter.offset

    @aso_flow_meter_offset.setter
    def aso_flow_meter_offset(self, offset):
        self.rule_action.aso_meter.offset = offset

    @property
    def aso_flow_meter_init_color(self):
        return self.rule_action.aso_meter.init_color

    @aso_flow_meter_init_color.setter
    def aso_flow_meter_init_color(self, init_color):
        self.rule_action.aso_meter.init_color = init_color

    @property
    def ct_aso_offset(self):
        return self.rule_action.aso_ct.offset

    @ct_aso_offset.setter
    def ct_aso_offset(self, offset):
        self.rule_action.aso_ct.offset = offset

    @property
    def direction(self):
        return self.rule_action.aso_ct.direction

    @direction.setter
    def direction(self, direction):
        self.rule_action.aso_ct.direction = direction

    @property
    def vlan_hdr(self):
        return socket.ntohl(self.rule_action.push_vlan.vlan_hdr)

    @vlan_hdr.setter
    def vlan_hdr(self, vlan_hdr):
        self.rule_action.push_vlan.vlan_hdr = socket.htonl(vlan_hdr)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action:
            self.logger.debug('Closing Mlx5drRuleAction.')
            self.action = None
            if self.data_buf:
                free(self.data_buf)
                self.data_buf = NULL


cdef class Mlx5drActionTemplate(PydiruCM):
    def __init__(self, actions_types):
        """
        Initializes a Mlx5drActionTemplate object representing mlx5dr_action_template struct.
        :param actions_types: List of action types
        """
        super().__init__()
        cdef me.mlx5dr_action_type *action_types_arr = NULL
        action_types_arr = <me.mlx5dr_action_type *>calloc(len(actions_types),
                                                           sizeof(me.mlx5dr_action_type))
        if action_types_arr == NULL:
            raise MemoryError('Memory allocation failed.')
        for i in range(len(actions_types)):
            action_types_arr[i] = actions_types[i]
        self.action_template = mlx5._action_template_create(action_types_arr)
        free(action_types_arr)
        if self.action_template == NULL:
            raise PydiruErrno('Mlx5drActionTemplate creation failed.')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.action_template != NULL:
            self.logger.debug('Closing Mlx5drActionTemplate.')
            rc = mlx5._action_template_destroy(self.action_template)
            if rc:
                raise PydiruError('Failed to destroy Mlx5drActionTemplate.', rc)
            self.action_template = NULL
