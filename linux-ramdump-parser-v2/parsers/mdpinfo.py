# Copyright (c) 2016, The Linux Foundation. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and
# only version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.


from parser_util import register_parser, RamParser
from print_out import print_out_str
from linux_list import ListWalker
from ramdump import Struct


class MdssDbgBase(Struct):
    _struct_name = "struct mdss_debug_base"
    _fields = {
        'name': Struct.get_cstring,
        'base': Struct.get_pointer,
        'max_offset': Struct.get_u32,
        'dump_list': Struct.get_address,
        'reg_dump': Struct.get_pointer,
    }


class MdssDbgXlog(Struct):
    def get_dbgbase_arr(self, key):
        arr = self.get_array_ptrs(key)
        return [MdssDbgBase(self.ramdump, b) for b in arr]

    _struct_name = "struct mdss_dbg_xlog"
    _fields = {
        'blk_arr': get_dbgbase_arr,
    }


class RangeDumpNode(Struct):
    def get_offset(self, key):
        return Struct(self.ramdump, self.get_address(key),
                      struct_name="struct dump_offset",
                      fields={
                          'start': Struct.get_u32,
                          'end': Struct.get_u32,
                      })

    _struct_name = "struct range_dump_node"
    _fields = {
        'offset': get_offset,
        'range_name': Struct.get_cstring,
        'reg_dump': Struct.get_pointer,
    }


@register_parser('--print-mdpinfo', 'print mdp info')
class MDPinfo(RamParser):
    def __init__(self, *args):
        super(MDPinfo, self).__init__(*args)
        self.outfile = None

    def mdss_dump_reg(self, addr, length, reg_dump):
        if reg_dump == 0:
            return

        # Making length multiple of 16
        length = int((length + 15) / 16)

        # Print out registers
        for i in range(0, length):
            self.outfile.write('{0:x} : '.format(addr))
            for j in range(0, 4):
                read = reg_dump + (16 * i) + (4 * j)
                self.outfile.write('{0:#0{1}x} '
                                   .format(self.ramdump.read_u32(read), 10))

            self.outfile.write('\n')
            addr += 16

    def print_range(self, blk, node):
        rng = RangeDumpNode(self.ramdump, node)

        if (rng.offset.start > rng.offset.end) or (rng.offset.end == 0):
            print_out_str("Invalid offsets (%d, %d) for range: %s" %
                          (rng.offset.start, rng.offset.end, rng.range_name))
            return

        addr = blk.base + rng.offset.start

        self.outfile.write('{0}: base=0x{1:x} start=0x{2:x} end=0x{3:x}\n'
                           .format(rng.range_name, addr,
                                   rng.offset.start, rng.offset.end))
        self.outfile.write('start_addr:{0:x} end_addr:{1:x} reg_addr={2:x}\n'
                           .format(rng.offset.start, rng.offset.end, addr))

        # Calculating length
        length = min(blk.max_offset, rng.offset.end) - rng.offset.start

        self.mdss_dump_reg(addr, length, rng.reg_dump)

    def parse(self):
        mdss_dbg = MdssDbgXlog(self.ramdump, 'mdss_dbg_xlog')

        if mdss_dbg.is_empty():
            return

        for blk in mdss_dbg.blk_arr:
            if blk.is_empty():
                continue

            # Delays file creation until we have found a non-null array element
            if not self.outfile:
                self.outfile = self.ramdump.open_file('mdpinfo_out.txt')

            self.outfile.write('mdss_dump_reg_by_ranges:'
                               '=========%s DUMP=========\n' % blk.name)

            head_offset = self.ramdump.field_offset('struct range_dump_node',
                                                    'head')

            dump_list = ListWalker(self.ramdump, blk.dump_list, head_offset)
            if dump_list.is_empty():
                self.outfile.write('Ranges not found, '
                                   'will dump full registers\n')
                self.outfile.write('base:0x%x length:%d\n' %
                                   (blk.base, blk.max_offset))

                self.mdss_dump_reg(blk.base, blk.max_offset, blk.reg_dump)
            else:
                for node in dump_list:
                    self.print_range(blk, node)

        # Close the file only if it was created
        if self.outfile:
            self.outfile.close()
            self.outfile = None
