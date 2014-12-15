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

@register_parser('--clock-dump', 'Dump all the clocks in the system')
class ClockDumps(RamParser) :

    def __init__(self, *args):
        super(ClockDumps, self).__init__(*args)
        self.enabled_clocks = []
        self.disabled_clocks = []
        self.prepared_clocks = []
        self.head = ''

    def print_header(self, type, title):
        if type == 'CLK_PROVIDERS':
            self.output_file.write("--------------------------------------------\n")
            self.output_file.write("{0} from of_clk_providers list\n".format(title))
            self.output_file.write("--------------------------------------------\n")
            self.output_file.write("  {0:40} {1:21} {2:25} {3:10} {4:40}\n".format('CLOCK NAME', 'COUNT/PREPARE_COUNT', 'RATE', 'CUR_LEVEL', 'CLOCK STRUCTURE'))
        elif type == 'CLOCKS':
            self.output_file.write("----------------------------------\n")
            self.output_file.write("{0} from clocks list\n".format(title))
            self.output_file.write("----------------------------------\n")
            self.output_file.write("  {0:40} {1:25} {2:20} {3:21} {4:25} {5:10} {6:40}\n".format('CLOCK NAME', 'DEVID', 'CONID', 'COUNT/PREPARE_COUNT', 'RATE', 'CUR_LEVEL', 'CLOCK STRUCTURE'))

    def printclocks(self, type):
        if len(self.disabled_clocks):
            self.print_header(type, "Disabled Clocks")
            for clocks in self.disabled_clocks:
                self.output_file.write('D ' + clocks)

        if len(self.enabled_clocks):
            self.output_file.write("\n")
            self.print_header(type, "Enabled Clocks")
            for clocks in self.enabled_clocks:
                self.output_file.write('E ' + clocks)

        if len(self.prepared_clocks):
            self.output_file.write("\n")
            self.print_header(type, "Prepared Clocks")
            for clocks in self.prepared_clocks:
                self.output_file.write('P ' + clocks)

    def get_clocks(self):
        clocks = self.ramdump.addr_lookup('clocks')
        if clocks is None:
            self.output_file.write("NOTE: 'clocks' list not found to extract the clocks information")
            return

        head = self.ramdump.read_word(clocks, True)
        self.head = clocks
        node_offset = self.ramdump.field_offset('struct clk_lookup', 'node')
        clocks_walker = linux_list.ListWalker(self.ramdump, head, node_offset)
        clocks_walker.walk(head, self.clocks_walker)

    def clocks_walker(self, node):
        if node == self.head:
            return

        devid_address = node + self.ramdump.field_offset('struct clk_lookup', 'dev_id')
        devid = self.ramdump.read_cstring(self.ramdump.read_word(devid_address, True), 48)
        conid_address = node + self.ramdump.field_offset('struct clk_lookup', 'con_id')
        conid = self.ramdump.read_cstring(self.ramdump.read_word(conid_address, True), 48)

        clock_address = node + self.ramdump.field_offset('struct clk_lookup', 'clk')
        clk = self.ramdump.read_word(clock_address, True)
        dbg_name_address = clk + self.ramdump.field_offset('struct clk', 'dbg_name')
        dbg_name = self.ramdump.read_cstring(self.ramdump.read_word(dbg_name_address, True), 48)
        rate_address = clk + self.ramdump.field_offset('struct clk', 'rate')
        rate = self.ramdump.read_word(rate_address, True)
        count_address = clk + self.ramdump.field_offset('struct clk', 'count')
        count = self.ramdump.read_u32(count_address, True)
        prepare_count_address = clk + self.ramdump.field_offset('struct clk', 'prepare_count')
        prepare_count = self.ramdump.read_u32(prepare_count_address, True)
        vdd_class_address = clk + self.ramdump.field_offset('struct clk', 'vdd_class')
        vdd_class = self.ramdump.read_word(vdd_class_address, True)
        if vdd_class != 0:
            cur_level_address = vdd_class + self.ramdump.field_offset('struct clk_vdd_class', 'cur_level')
            cur_level = self.ramdump.read_word(cur_level_address, True)
        else:
            cur_level = "NULL"

        output = "{0:40} {1:<25} {2:20} {3:<2}/ {4:<17} {5:<25} {6:<10} v.v (struct clk *)0x{7:<20x}\n".format(
            dbg_name, devid, conid, count, prepare_count, rate, cur_level, clk)

        if count > 0:
            self.enabled_clocks.append(output)
        elif prepare_count > 0:
            self.prepared_clocks.append(output)
        else:
            self.disabled_clocks.append(output)

    def get_clk_providers(self):
        clocks = self.ramdump.addr_lookup('of_clk_providers')
        if clocks is None:
            self.output_file.write("NOTE: 'of_clk_providers' list not found to extract the clocks information")
            return

        self.enabled_clocks = []
        self.disabled_clocks = []
        self.prepared_clocks = []
        self.head = clocks

        head = self.ramdump.read_word(clocks, True)
        node_offset = self.ramdump.field_offset('struct clk_lookup', 'node')
        clk_providers_walker = linux_list.ListWalker(self.ramdump, head, node_offset)
        clk_providers_walker.walk(head, self.clk_providers_walker)

    def clk_providers_walker(self, node):
        if node == self.head:
            return

        data_address = node + self.ramdump.field_offset('struct of_clk_provider', 'data')
        node_address = node + self.ramdump.field_offset('struct of_clk_provider', 'node')
        data = self.ramdump.read_word(data_address, True)
        node = self.ramdump.read_word(node_address, True)
        table_address = data + self.ramdump.field_offset('struct of_msm_provider_data', 'table')
        size_address = data + self.ramdump.field_offset('struct of_msm_provider_data', 'size')
        table = self.ramdump.read_word(table_address, True)
        size = self.ramdump.read_word(size_address, True)

        counter = 0
        while counter < size:
            clock_address = table + self.ramdump.field_offset('struct clk_lookup', 'clk')
            clk = self.ramdump.read_word(clock_address, True)
            dbg_name_address = clk + self.ramdump.field_offset('struct clk', 'dbg_name')
            dbg_name = self.ramdump.read_cstring(self.ramdump.read_word(dbg_name_address, True), 48)
            rate_address = clk + self.ramdump.field_offset('struct clk', 'rate')
            rate = self.ramdump.read_word(rate_address, True)
            count_address = clk + self.ramdump.field_offset('struct clk', 'count')
            count = self.ramdump.read_u32(count_address, True)
            prepare_count_address = clk + self.ramdump.field_offset('struct clk', 'prepare_count')
            prepare_count = self.ramdump.read_u32(prepare_count_address, True)
            vdd_class_address = clk + self.ramdump.field_offset('struct clk', 'vdd_class')
            vdd_class = self.ramdump.read_word(vdd_class_address, True)
            if vdd_class != 0:
                cur_level_address = vdd_class + self.ramdump.field_offset('struct clk_vdd_class', 'cur_level')
                cur_level = self.ramdump.read_word(cur_level_address, True)
            else:
                cur_level = "NULL"

            output = "{0:40} {1:<2}/ {2:<17} {3:<25} {4:<10} v.v (struct clk *)0x{5:<20x}\n".format(dbg_name, count, prepare_count, rate, cur_level, clk)

            if count > 0:
                self.enabled_clocks.append(output)
            elif prepare_count > 0:
                self.prepared_clocks.append(output)
            else:
                self.disabled_clocks.append(output)

            counter = counter + 1
            table = table + self.ramdump.sizeof('struct clk_lookup')

    def parse(self):
        self.output_file = self.ramdump.open_file('ClockDumps.txt')

        self.get_clocks()
        self.printclocks('CLOCKS')
        self.get_clk_providers()
        self.printclocks('CLK_PROVIDERS')

        self.output_file.close()
        print_out_str("--- Wrote the output to ClockDumps.txt")
