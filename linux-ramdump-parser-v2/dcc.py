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

import struct
from print_out import print_out_str
from ramparse import VERSION

dcc_register_list = [
    'DCC_HW_VERSION',
    'DCC_HW_INFO',
    'DCC_CGC_CFG',
    'DCC_LL',
    'DCC_RAM_CFG',
    'DCC_CFG',
    'DCC_SW_CTL',
    'DCC_STATUS',
    'DCC_FETCH_ADDR',
    'DCC_SRAM_ADDR',
    'DCC_INT_ENABLE',
    'DCC_INT_STATUS',
    'DCC_QSB_CFG'
    ]

# DCC regs hash table
dcc_regs = {}

class DccRegDump():

    def __init__(self, start, end):
        self.start_addr = start
        self.end_addr = end

    def parse_all_regs(self, ram_dump):
        num_reg = len(dcc_register_list)
        if (self.start_addr + 4 * num_reg) > self.end_addr:
                return False

        for reg in dcc_register_list:
                dcc_regs[reg] = ram_dump.read_u32(self.start_addr, False)
                self.start_addr += 4
        return True

    def dump_all_regs(self, ram_dump):
        outfile = ram_dump.open_file('dcc_regs.txt')
        outfile.write('DCC registers:\n')
        for reg in dcc_register_list:
                outfile.write('{0} : 0x{1:08x}\n'.format(reg, dcc_regs[reg]))
        outfile.close()

class DccSramDump():
    def __init__(self, start, end):
        self.start_addr = start
        self.end_addr = end

    def dump_sram_img(self, ram_dump):
        if self.start_addr >= self.end_addr:
                return False

        rsz = self.end_addr - self.start_addr

        if dcc_regs.has_key('DCC_HW_INFO') == False \
                        or dcc_regs['DCC_HW_INFO'] == 0:
            print_out_str('DCC HW Info missing! Skipping sram dump...')
            return False

        if dcc_regs['DCC_CFG'] & 0x1:
            print_out_str('DCC is configured in CRC mode. Skipping sram dump ...')
            return False

        if dcc_regs['DCC_RAM_CFG'] == 0:
            print_out_str('No config found in DCC SRAM. Skipping sram dump ...')
            return False

        sramfile = ram_dump.open_file('sram.bin')
        for i in range(0, rsz):
            val = ram_dump.read_byte(self.start_addr + i, False)
            sramfile.write(struct.pack('<B', val))

        sramfile.close()

        return True
