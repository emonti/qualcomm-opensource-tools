# Copyright (c) 2013-2014, The Linux Foundation. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and
# only version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

import re
import string

from print_out import print_out_str
from parser_util import register_parser, RamParser, cleanupString


@register_parser('--dmesg', 'Print the dmesg', shortopt='-d')
class Dmesg(RamParser):

    def __init__(self, *args):
        super(Dmesg, self).__init__(*args)
        self.wrap_cnt = 0

    def extract_dmesg_flat(self, ramdump):
        addr = ramdump.read_word(ramdump.addr_lookup('log_buf'))
        size = ramdump.read_word(ramdump.addr_lookup('log_buf_len'))
        dmesg = ramdump.read_physical(ramdump.virt_to_phys(addr), size)
        print_out_str(cleanupString(dmesg.decode('ascii', 'ignore')))

    def log_from_idx(self, ramdump, idx, logbuf):
        len_offset = ramdump.field_offset('struct log', 'len')

        msg = logbuf + idx
        msg_len = ramdump.read_word(msg + len_offset)
        if (msg_len == 0):
            return logbuf
        else:
            return msg

    def log_next(self, ramdump, idx, logbuf):
        len_offset = ramdump.field_offset('struct log', 'len')
        msg = idx

        msg_len = ramdump.read_halfword(msg + len_offset)
        if (msg_len == 0):
            self.wrap_cnt += 1
            return logbuf
        else:
            return idx + msg_len

    def extract_dmesg_binary(self, ramdump):
        first_idx_addr = ramdump.addr_lookup('log_first_idx')
        last_idx_addr = ramdump.addr_lookup('log_next_idx')
        logbuf_addr = ramdump.addr_lookup('log_buf')
        time_offset = ramdump.field_offset('struct log', 'ts_nsec')
        len_offset = ramdump.field_offset('struct log', 'len')
        text_len_offset = ramdump.field_offset('struct log', 'text_len')
        log_size = ramdump.sizeof('struct log')

        first_idx = ramdump.read_word(first_idx_addr)
        last_idx = ramdump.read_word(last_idx_addr)

        curr_idx = logbuf_addr + first_idx

        while curr_idx != logbuf_addr + last_idx and self.wrap_cnt < 2:
            timestamp = ramdump.read_dword(curr_idx + time_offset)
            text_len = ramdump.read_halfword(curr_idx + text_len_offset)
            text_str = ramdump.read_cstring(curr_idx + log_size, text_len)
            for partial in text_str.split('\n'):
                f = '[{0:>5}.{1:0>6d}] {2}'.format(
                    timestamp / 1000000000, (timestamp % 1000000000) / 1000, partial)
                print_out_str(f)
            curr_idx = self.log_next(ramdump, curr_idx, logbuf_addr)

    def parse(self):
        if re.search('3.7.\d', self.ramdump.version) is not None:
            self.extract_dmesg_binary(self.ramdump)
        elif re.search('3\.10\.\d', self.ramdump.version) is not None:
            self.extract_dmesg_binary(self.ramdump)
        else:
            self.extract_dmesg_flat(self.ramdump)
