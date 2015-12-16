# Copyright (c) 2015, The Linux Foundation. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and
# only version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

import linux_list
from print_out import print_out_str
from parser_util import register_parser, RamParser
from collections import defaultdict


@register_parser('--cpr3-info', 'Print CPR3 information')
class CPR3Info(RamParser):
    def __init__(self, *args):
        super(CPR3Info, self).__init__(*args)
        self.head = ''
        self.cprinfo_fields = ['speed_bin', 'cpr_fuse_revision',
                               'cpr_fuse_map_match', 'num_fuse_corners',
                               'num_corners', 'corner']
        self.voltages = ['ceiling_volt', 'open_loop_volt',
                         'last_volt', 'floor_volt']
        self.corner_info = ['cpr_fuse_target_quot',
                            'quot_adjust', 'corner_map']
        self.value_list = defaultdict(list)
        self.attr_list = defaultdict(list)
        self.output = []
        self.consumer_head = ''

    def get_cpr(self):
        # Return if the cpr3_regulator_list is not available
        cpr = self.ramdump.address_of('cpr3_controller_list')
        if cpr is None:
            self.output_file.write(
                "NOTE: 'cpr3_regulator_list' list " +
                "not found to extract cpr information")
            return

        head = self.ramdump.read_word(cpr)
        self.head = cpr
        node_offset = self.ramdump.field_offset('struct cpr3_controller',
                                                'list')
        c_w = linux_list.ListWalker(self.ramdump, head, node_offset)
        c_w.walk(head, self.cpr_walker)

    def get_kryo(self):
        kryo_addr = self.ramdump.address_of('kryo_regulator_list')
        if kryo_addr is None:
            print(
                "NOTE: 'kryo_regulator_list' list " +
                "not found to extract kryo_addr information")
            return
        head = self.ramdump.read_word(kryo_addr)
        self.head = kryo_addr
        node_offset = self.ramdump.field_offset('struct kryo_regulator',
                                                'link')
        k_w = linux_list.ListWalker(self.ramdump, head, node_offset)
        tmp = "=" * 80 + "\n"
        tmp += "Kryo Regulator (LDO/BHS management)\n"
        tmp += "=" * 80 + "\n"
        self.output.append(tmp)
        k_w.walk(head, self.kryo_walker)

    def dump_cpr3_regulator_voltages(self, vreg_addr):
        corner_count = self.ramdump.read_int(
            vreg_addr +
            self.ramdump.field_offset(
                'struct cpr3_regulator',
                'corner_count'))
        tmp = 'CPR voltages(uV) and Target Quotients\n'
        tmp += "%-7s%-3s%-10s%-10s%-10s%-21s%-40s\n" % (
               "Corner", "-", "Floor", "Open-Loop", "Ceiling",
               "Cached closed-loop",
               "Target Quotients")
        self.output.append(tmp)
        base_addr = self.ramdump.read_word(
            vreg_addr +
            self.ramdump.field_offset('struct cpr3_regulator', 'corner'))
        size = self.ramdump.sizeof('struct cpr3_corner')
        for i in range(corner_count):
            corner_addr = base_addr + size * i
            try:
                self.dump_cpr3_corner_info(corner_addr, i + 1, 1, 1)
            except:
                self.output.append(
                    "Note: Failed to dump cpr3 regulator voltage\n")
                return

    def dump_cpr3_corner_info(self, aggr_corner_addr, corner_num,
                              print_quots, list_format):
        if aggr_corner_addr is None:
            return
        ceiling = self.ramdump.read_int(
            aggr_corner_addr +
            self.ramdump.field_offset(
                'struct cpr3_corner', 'ceiling_volt'))
        open_loop = self.ramdump.read_int(
            aggr_corner_addr +
            self.ramdump.field_offset(
                'struct cpr3_corner', 'open_loop_volt'))
        last = self.ramdump.read_int(
            aggr_corner_addr +
            self.ramdump.field_offset(
                'struct cpr3_corner', 'last_volt'))
        floor = self.ramdump.read_int(
            aggr_corner_addr +
            self.ramdump.field_offset(
                'struct cpr3_corner', 'floor_volt'))
        quots = ""
        if print_quots == 1:
            t0 = aggr_corner_addr + self.ramdump.field_offset(
                'struct cpr3_corner', 'target_quot')
            size = self.ramdump.sizeof('u32')
            num = self.ramdump.sizeof('((struct cpr3_corner*)0)->target_quot') \
                / size
            for i in range(num):
                quot = self.ramdump.read_u32(t0 + i * size)
                quots = quots + " " + str(quot)

        if list_format == 0:
            tmp = '%-30s = %d uV\n' % ("Ceiling volt", ceiling)
            tmp += '%-30s = %d uV\n' % ("Open-loop", open_loop)
            tmp += '%-30s = %d uV\n' % ("Cached closed-loop", last)
            tmp += '%-30s = %d uV\n' % ("Floor", floor)
            self.output.append(tmp)
            if print_quots == 1:
                tmp = "\n%-30s = %s\n" % ("Target quotients", quots)
                self.output.append(tmp)
            self.output.append("\n")
        else:
            tmp = "%-7d%-3s%-10d%-10d%-10d%-20d" % (
                corner_num, "-", floor, open_loop, ceiling, last)
            tmp += quots
            tmp += "\n"
            self.output.append(tmp)

    def dump_vdd_regulator(self, ctrl_addr):
        tmp = ""
        vdd_reg_addr = self.ramdump.read_word(
            ctrl_addr +
            self.ramdump.field_offset(
                'struct cpr3_controller', 'vdd_regulator'))
        if vdd_reg_addr is None:
            return
        rdev_addr = self.ramdump.read_word(
            vdd_reg_addr +
            self.ramdump.field_offset(
                'struct regulator',
                'rdev'))
        reg_data_addr = self.ramdump.read_word(
            rdev_addr +
            self.ramdump.field_offset('struct regulator_dev', 'reg_data'))

        desc_addr = self.ramdump.read_word(
            rdev_addr +
            self.ramdump.field_offset('struct regulator_dev', 'desc'))

        desc_ops_addr = self.ramdump.read_word(
            desc_addr +
            self.ramdump.field_offset('struct regulator_desc', 'ops'))

        name_addr = self.ramdump.read_word(
            desc_addr +
            self.ramdump.field_offset('struct regulator_desc', 'name'))

        name = self.ramdump.read_cstring(name_addr, 48)
        tmp += '\n%-30s = %s\n' % ("PMIC supply", name)
        duple = self.ramdump.unwind_lookup(desc_ops_addr)
        function_name = duple[0]

        if "qpnp" in function_name:
            # QPNP-regulator
            set_points_addr = self.ramdump.read_word(
                reg_data_addr + self.ramdump.field_offset(
                    'struct qpnp_regulator',
                    'set_points'))
            range_addr = self.ramdump.read_word(
                set_points_addr +
                self.ramdump.field_offset(
                    'struct qpnp_voltage_set_points', 'range'))
            step_uV = self.ramdump.read_int(
                range_addr +
                self.ramdump.field_offset(
                    'struct qpnp_voltage_range',
                    'step_uV'))
            min_uV = self.ramdump.read_int(
                range_addr +
                self.ramdump.field_offset(
                    'struct qpnp_voltage_range', 'min_uV'))
            volt_sel = self.ramdump.read_byte(
                reg_data_addr + 1 +
                self.ramdump.field_offset(
                    'struct qpnp_regulator', 'ctrl_reg'))
            volt = (volt_sel * step_uV) + min_uV
            tmp += "%-30s = %d uV\n" % ("PMIC voltage", volt)
        if "spm" in function_name:
            last_set_volt = self.ramdump.read_int(
                reg_data_addr + self.ramdump.field_offset(
                    'struct spm_vreg', 'last_set_uV'))
            tmp += "%-30s = %d uV\n" % ("PMIC last set voltage",
                                        last_set_volt)
        self.output.append(tmp)

    def get_apm_threshold(self, addr_ctrl):
        apm_addr = self.ramdump.read_word(
            addr_ctrl + self.ramdump.field_offset('struct cpr3_controller',
                                                  'apm'))
        if apm_addr is None:
            return
        apm_thresh_volt = self.ramdump.read_int(
            addr_ctrl + self.ramdump.field_offset(
                'struct cpr3_controller', 'apm_threshold_volt'))
        if apm_thresh_volt == 0:
            return
        tmp = '%-30s = %d uV\n' % ("APM threshold", apm_thresh_volt)
        apm_supply = self.ramdump.read_int(
            apm_addr + self.ramdump.field_offset('struct msm_apm_ctrl_dev',
                                                 'supply'))
        if apm_supply is None:
            print_out_str("could not read APM supply")
        elif apm_supply == 0:
            tmp += '%-30s = %s\n' % ("APM supply", "APCC")
        elif apm_supply == 1:
            tmp += '%-30s = %s\n' % ("APM supply", "MX")
        self.output.append(tmp)

    def get_aging_info(self, ctrl_addr):
        test = self.ramdump.field_offset(
            'struct cpr3_controller', 'aging_required')
        if test is None:
            return
        aging_required = self.ramdump.read_bool(
            ctrl_addr +
            self.ramdump.field_offset(
                'struct cpr3_controller', 'aging_required'))
        aging_succeeded = self.ramdump.read_bool(
            ctrl_addr +
            self.ramdump.field_offset(
                'struct cpr3_controller', 'aging_succeeded'))
        aging_failed = self.ramdump.read_bool(
            ctrl_addr +
            self.ramdump.field_offset(
                'struct cpr3_controller', 'aging_failed'))
        tmp = ""
        if (aging_required or aging_succeeded or aging_failed):
            if aging_succeeded:
                aging_ref_adjust_volt = self.ramdump.read_int(
                    ctrl_addr +
                    self.ramdump.field_offset(
                        'struct cpr3_controller', 'aging_ref_adjust_volt'))
                tmp += '%-30s = %s\n' % ("Aging measurement", "succeeded")
                tmp += '%-30s = %d uV\n' % ("Aging adjustment voltage",
                                            aging_ref_adjust_volt)
            elif aging_failed:
                tmp += '%-30s = %s\n' % ("Aging measurement",
                                         "failed")
            else:
                tmp += '%-30s = %s\n' % ("Aging measurement",
                                         "not yet executed")
        self.output.append(tmp)

    def dump_cpr3_regulator_state(self, vreg_addr):
        tmp = ""
        if vreg_addr is None:
            return
        name_addr = self.ramdump.read_word(
            vreg_addr + self.ramdump.field_offset(
                'struct cpr3_regulator', 'name'))
        name = self.ramdump.read_cstring(name_addr, 48)
        tmp += "-" * 80 + "\n"
        tmp += "Regulator: %s\n" % name
        tmp += "-" * 80 + "\n"
        vreg_enabled = self.ramdump.read_bool(
            vreg_addr + self.ramdump.field_offset(
                'struct cpr3_regulator',
                'vreg_enabled'))
        current_corner = self.ramdump.read_int(
            vreg_addr + self.ramdump.field_offset(
                'struct cpr3_regulator', 'current_corner'))
        corner_count = self.ramdump.read_int(
            vreg_addr + self.ramdump.field_offset(
                'struct cpr3_regulator',
                'corner_count'))
        ldo_regulator_addr = self.ramdump.read_word(
            vreg_addr + self.ramdump.field_offset(
                'struct cpr3_regulator', 'ldo_regulator'))
        ldo_mode_allowed = self.ramdump.read_bool(
            vreg_addr + self.ramdump.field_offset(
                'struct cpr3_regulator', 'ldo_mode_allowed'))
        cpr_rev_fuse = self.ramdump.read_int(
            vreg_addr + self.ramdump.field_offset(
                'struct cpr3_regulator', 'cpr_rev_fuse'))
        if ldo_regulator_addr != 0:
            ldo_mode_bool = self.ramdump.read_bool(
                vreg_addr + self.ramdump.field_offset(
                    'struct cpr3_regulator',
                    'ldo_regulator_bypass'))
            if ldo_mode_bool:
                ldo_mode = "LDO"
            else:
                ldo_mode = "BHS"

        tmp += "%-30s = %d\n" % ("CPR fuse revision", cpr_rev_fuse)
        fuse_combo = self.ramdump.read_int(
            vreg_addr +
            self.ramdump.field_offset(
                'struct cpr3_regulator', 'fuse_combo'))
        tmp += "%-30s = %d\n" % ("CPR fuse combo", fuse_combo)
        speed_bin_fuse = self.ramdump.read_int(
            vreg_addr +
            self.ramdump.field_offset(
                'struct cpr3_regulator',
                'speed_bin_fuse'))
        tmp += "%-30s = %d\n" % ("Speed-bin fuse", speed_bin_fuse)

        tmp += "\n%-30s = %d/%d\n" % ("CPR corner", current_corner + 1,
                                      corner_count)
        if vreg_enabled is True:
            vreg_enabled = 1
        else:
            vreg_enabled = 0
        tmp += "%-30s = %d\n" % ("Enabled", vreg_enabled)

        if ldo_regulator_addr != 0:
            if ldo_mode_allowed is True:
                ldo_mode_allowed = 1
            else:
                ldo_mode_allowed = 0
            tmp += "\n%-30s = %d\n" % ("LDO mode allowed", ldo_mode_allowed)
            tmp += "%-30s = %s\n" % ("LDO/BHS mode", ldo_mode)
        tmp += "\nCurrent CPR voltages:\n"
        self.output.append(tmp)
        tmp = ""
        corner_addr = self.ramdump.read_word(
            vreg_addr + self.ramdump.field_offset(
                'struct cpr3_regulator', 'corner'))
        size = self.ramdump.sizeof("struct cpr3_corner")
        corner_addr = corner_addr + current_corner * size
        self.dump_cpr3_corner_info(corner_addr, 0, 1, 0)
        self.dump_cpr3_regulator_voltages(vreg_addr)

        rdev_addr = self.ramdump.read_word(
            vreg_addr + self.ramdump.field_offset('struct cpr3_regulator',
                                                  'rdev'))
        offset = self.ramdump.field_offset('struct regulator_dev',
                                           'consumer_list')
        self.dump_consumer(rdev_addr + offset)

    def dump_cpr3_thread_state(self, thread_addr):
        tmp = ""
        thread_id = self.ramdump.read_u32(
            thread_addr + self.ramdump.field_offset(
                'struct cpr3_thread', 'thread_id'))
        aggr_corner_addr = thread_addr + self.ramdump.field_offset(
            'struct cpr3_thread', 'aggr_corner')
        tmp += "-" * 80 + "\n"
        tmp += "Thread: %d\n" % thread_id
        tmp += "-" * 80 + "\n"
        tmp += "CPR aggregated voltages:\n"
        self.output.append(tmp)

        self.dump_cpr3_corner_info(aggr_corner_addr, 0, 1, 0)
        vreg_addr = self.ramdump.read_word(
            thread_addr +
            self.ramdump.field_offset('struct cpr3_thread', 'vreg'))
        vreg_count = self.ramdump.read_int(
            thread_addr +
            self.ramdump.field_offset(
                'struct cpr3_thread', 'vreg_count'))

        size_reg = self.ramdump.sizeof('struct cpr3_regulator')
        for i in range(vreg_count):
            self.dump_cpr3_regulator_state(vreg_addr + i * size_reg)

    def cpr_walker(self, ctrl_addr):
        if ctrl_addr == self.head:
            return
        cpr_controller_name_addr = self.ramdump.read_word(
            ctrl_addr + self.ramdump.field_offset('struct cpr3_controller',
                                                  'name'))
        cpr_controller_name = self.ramdump.read_cstring(
            cpr_controller_name_addr, 48)
        supports_hw_closed_loop = self.ramdump.read_bool(
            ctrl_addr + self.ramdump.field_offset(
                'struct cpr3_controller',
                'supports_hw_closed_loop'))
        use_hw_closed_loop = self.ramdump.read_bool(
            ctrl_addr + self.ramdump.field_offset(
                'struct cpr3_controller',
                'use_hw_closed_loop'))
        cpr_allowed_sw = self.ramdump.read_bool(
            ctrl_addr + self.ramdump.field_offset(
                'struct cpr3_controller',
                'cpr_allowed_sw'))
        cpr_enabled = self.ramdump.read_bool(
            ctrl_addr + self.ramdump.field_offset(
                'struct cpr3_controller', 'cpr_enabled'))
        if supports_hw_closed_loop == 1:
            if cpr_allowed_sw == 0:
                cpr_mode = "open-loop"
            elif use_hw_closed_loop == 0:
                cpr_mode = "SW closed-loop"
            else:
                cpr_mode = "HW closed-loop"
        else:
            if cpr_allowed_sw == 0:
                cpr_mode = "open-loop"
            else:
                cpr_mode = "closed-loop"
        tmp = ""
        if cpr_controller_name is None:
            return
        tmp += "=" * 80 + "\n"
        tmp += 'CPR3 controller state: %s\n' % cpr_controller_name
        tmp += "=" * 80 + "\n"
        tmp += '%-30s = %s\n' % ("CPR mode", cpr_mode)
        tmp += '%-30s = %d\n' % ("CPR loop currently operating",
                                 cpr_enabled)
        self.output.append(tmp)
        tmp = ""
        self.get_apm_threshold(ctrl_addr)
        self.get_aging_info(ctrl_addr)
        self.dump_vdd_regulator(ctrl_addr)
        if cpr_allowed_sw == 1 and use_hw_closed_loop == 1:
            tmp = "* The actual voltage at the PMIC may be anywhere " \
                  "between the aggregated ceiling and floor voltage when"\
                  " using CPR HW closed-loop mode.\n"
            self.output.append(tmp)
            tmp = ""
        aggr_corner_addr = ctrl_addr + self.ramdump.field_offset(
            'struct cpr3_controller', 'aggr_corner')
        self.output.append("\nCPR aggregated voltages:\n")
        self.dump_cpr3_corner_info(aggr_corner_addr, 0, 0, 0)
        thread_addr = self.ramdump.read_word(
            ctrl_addr +
            self.ramdump.field_offset(
                'struct cpr3_controller', 'thread'))
        thread_count = self.ramdump.read_int(
            ctrl_addr +
            self.ramdump.field_offset(
                'struct cpr3_controller', 'thread_count'))
        size_thr = self.ramdump.sizeof('struct cpr3_thread')
        for i in range(thread_count):
            self.dump_cpr3_thread_state(thread_addr + i * size_thr)
        # print new line for each regulator struct
        tmp += '\n'
        self.output.append(tmp)

    def kryo_walker(self, kryo_addr):
        if kryo_addr == self.head:
            return

        retention_mode = self.ramdump.read_int(
            kryo_addr +
            self.ramdump.field_offset(
                'struct kryo_regulator', 'retention_mode'))
        mode = self.ramdump.read_int(
            kryo_addr + self.ramdump.field_offset('struct kryo_regulator',
                                                  'mode'))
        if mode == 0:
            mode = "BHS"
        else:
            mode = "LDO"

        if retention_mode == 0:
            retention_mode = "BHS"
        else:
            retention_mode = "LDO"

        volt = self.ramdump.read_int(kryo_addr + self.ramdump.field_offset(
            'struct kryo_regulator', 'volt'))
        retention_volt = self.ramdump.read_int(
            kryo_addr +
            self.ramdump.field_offset(
                'struct kryo_regulator',
                'retention_volt'))
        vreg_en = self.ramdump.read_bool(
            kryo_addr +
            self.ramdump.field_offset(
                'struct kryo_regulator',
                'vreg_en'))
        vref_func_step_volt = self.ramdump.read_int(
            kryo_addr +
            self.ramdump.field_offset(
                'struct kryo_regulator',
                'vref_func_step_volt'))
        vref_func_min_volt = self.ramdump.read_int(
            kryo_addr +
            self.ramdump.field_offset(
                'struct kryo_regulator',
                'vref_func_min_volt'))
        vref_func_max_volt = self.ramdump.read_int(
            kryo_addr + self.ramdump.field_offset(
                'struct kryo_regulator', 'vref_func_max_volt'))
        vref_ret_step_volt = self.ramdump.read_int(
            kryo_addr + self.ramdump.field_offset(
                'struct kryo_regulator', 'vref_ret_step_volt'))
        vref_ret_min_volt = self.ramdump.read_int(
            kryo_addr + self.ramdump.field_offset(
                'struct kryo_regulator', 'vref_ret_min_volt'))
        vref_ret_max_volt = self.ramdump.read_int(
            kryo_addr + self.ramdump.field_offset(
                'struct kryo_regulator', 'vref_ret_max_volt'))
        name_addr = self.ramdump.read_word(
            kryo_addr +
            self.ramdump.field_offset('struct kryo_regulator', 'name'))
        name = self.ramdump.read_cstring(name_addr, 48)
        tmp = ""
        tmp += "-" * 80 + "\n"
        tmp += "Regulator: %s\n" % name
        tmp += "-" * 80 + "\n"
        tmp += "%-30s = %d\n" % ("Enabled", vreg_en)
        tmp += "%-30s = %s\n" % ("Mode", mode)

        tmp += "%-30s = %d uV\n" % ("Voltage", volt)
        tmp += "%-30s = %s\n" % ("Retention Mode", retention_mode)

        tmp += "%-30s = %d uV\n" % ("Retention Voltage", retention_volt)
        tmp += "%-30s = %d uV\n" % ("Vref Functional Step Voltage",
                                    vref_func_step_volt)

        tmp += "%-30s = %d uV\n" % ("Vref Functional Min Voltage",
                                    vref_func_min_volt)

        tmp += "%-30s = %d uV\n" % ("Vref Functional Max Voltage",
                                    vref_func_max_volt)

        tmp += "%-30s = %d uV\n" % ("Vref Retention Step Voltage",
                                    vref_ret_step_volt)

        tmp += "%-30s = %d uV\n" % ("Vref Retention Min Voltage",
                                    vref_ret_min_volt)

        tmp += "%-30s = %d uV\n" % ("Vref Retention Max Voltage",
                                    vref_ret_max_volt)

        self.output.append(tmp)
        rdev_addr = self.ramdump.read_word(
            kryo_addr + self.ramdump.field_offset('struct kryo_regulator',
                                                  'rdev'))
        offset = self.ramdump.field_offset('struct regulator_dev',
                                           'consumer_list')
        self.dump_consumer(rdev_addr + offset)

    def dump_consumer(self, consumer_head):
        tmp = ""
        tmp += "\nConsumers:\n"
        tmp += "%-48s%-10s%-10s%-10s\n" % ("Device-Supply", "EN", "Min_Uv",
                                           "Max_Uv")
        self.output.append(tmp)
        node_offset = self.ramdump.field_offset('struct regulator', 'list')
        self.consumer_head = consumer_head
        c_w = linux_list.ListWalker(self.ramdump, consumer_head, node_offset)
        c_w.walk(consumer_head, self.consumer_walker)
        self.output.append("\n")

    def consumer_walker(self, reg_addr):
        if reg_addr + self.ramdump.field_offset('struct regulator', 'list') \
           == self.consumer_head:
            return
        min_uV = self.ramdump.read_int(
            reg_addr +
            self.ramdump.field_offset('struct regulator', 'min_uV'))
        max_uV = self.ramdump.read_int(
            reg_addr +
            self.ramdump.field_offset('struct regulator', 'max_uV'))
        enabled = self.ramdump.read_int(
            reg_addr + self.ramdump.field_offset('struct regulator',
                                                 'enabled'))
        if enabled == 1:
            enabled = 'Y'
        else:
            enabled = 'N'
        name_addr = self.ramdump.read_word(
            reg_addr +
            self.ramdump.field_offset('struct regulator', 'supply_name'))
        name = self.ramdump.read_cstring(name_addr, 64)
        tmp = "%-48s%-10s%-10d%-10d\n" % (name, enabled, min_uV, max_uV)
        self.output.append(tmp)

    def parse(self):
        self.output_file = self.ramdump.open_file('cpr3_info.txt')
        self.get_cpr()
        self.get_kryo()
        for i in self.output:
            self.output_file.write(i)
        print_out_str("--- Wrote the output to cpr3_info.txt")
        self.output_file.close()
