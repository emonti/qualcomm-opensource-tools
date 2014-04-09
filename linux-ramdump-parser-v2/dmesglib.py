# Copyright (c) 2014, The Linux Foundation. All rights reserved.
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

from parser_util import cleanupString

class DmesgLib(object):

    def __init__(self, ramdump, outfile):
        self.ramdump = ramdump
        self.wrap_cnt = 0
        self.outfile = outfile

    def log_from_idx(self, idx, logbuf):
        len_offset = self.ramdump.field_offset('struct log', 'len')

        msg = logbuf + idx
        msg_len = self.ramdump.read_u16(msg + len_offset)
        if (msg_len == 0):
            return logbuf
        else:
            return msg

    def log_next(self, idx, logbuf):
        len_offset = self.ramdump.field_offset('struct log', 'len')
        msg = idx

        msg_len = self.ramdump.read_u16(msg + len_offset)
        if (msg_len == 0):
            self.wrap_cnt += 1
            return logbuf
        else:
            return idx + msg_len

    def extract_dmesg_flat(self):
        addr = self.ramdump.read_word(self.ramdump.addr_lookup('log_buf'))
        size = self.ramdump.read_word(self.ramdump.addr_lookup('log_buf_len'))
        dmesg = self.ramdump.read_physical(self.ramdump.virt_to_phys(addr), size)
        self.outfile.write(cleanupString(dmesg.decode('ascii', 'ignore')) + '\n')

    def extract_dmesg_binary(self):
        first_idx_addr = self.ramdump.addr_lookup('log_first_idx')
        last_idx_addr = self.ramdump.addr_lookup('log_next_idx')
        logbuf_addr = self.ramdump.read_word(self.ramdump.addr_lookup('log_buf'))
        time_offset = self.ramdump.field_offset('struct log', 'ts_nsec')
        len_offset = self.ramdump.field_offset('struct log', 'len')
        text_len_offset = self.ramdump.field_offset('struct log', 'text_len')
        log_size = self.ramdump.sizeof('struct log')

        first_idx = self.ramdump.read_u32(first_idx_addr)
        last_idx = self.ramdump.read_u32(last_idx_addr)

        curr_idx = logbuf_addr + first_idx

        while curr_idx != logbuf_addr + last_idx and self.wrap_cnt < 2:
            timestamp = self.ramdump.read_dword(curr_idx + time_offset)
            text_len = self.ramdump.read_u16(curr_idx + text_len_offset)
            text_str = self.ramdump.read_cstring(curr_idx + log_size, text_len)
            for partial in text_str.split('\n'):
                f = '[{0:>5}.{1:0>6d}] {2}\n'.format(
                    timestamp / 1000000000, (timestamp % 1000000000) / 1000, partial)
                self.outfile.write(f)
            curr_idx = self.log_next(curr_idx, logbuf_addr)

    def extract_dmesg(self):
        if re.search('3.7.\d', self.ramdump.version) is not None:
            self.extract_dmesg_binary()
        elif re.search('3\.10\.\d', self.ramdump.version) is not None:
            self.extract_dmesg_binary()
        else:
            self.extract_dmesg_flat()
