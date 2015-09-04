# Copyright (c) 2014-2015, The Linux Foundation. All rights reserved.
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

LOG_MAGIC = 0x5d7aefca

class DmesgLib(object):

    def __init__(self, ramdump, outfile):
        self.ramdump = ramdump
        self.wrap_cnt = 0
        self.outfile = outfile
        if (self.ramdump.sizeof('struct printk_log') is None):
           self.struct_name = 'struct log'
        else:
           self.struct_name = 'struct printk_log'

    def log_from_idx(self, idx, logbuf):
        len_offset = self.ramdump.field_offset(self.struct_name, 'len')

        msg = logbuf + idx
        msg_len = self.ramdump.read_u16(msg + len_offset)
        if (msg_len == 0):
            return logbuf
        else:
            return msg

    def log_next(self, idx, logbuf):
        len_offset = self.ramdump.field_offset(self.struct_name, 'len')
        msg = idx

        msg_len = self.ramdump.read_u16(msg + len_offset)
        if (msg_len == 0):
            self.wrap_cnt += 1
            return logbuf
        else:
            return idx + msg_len

    def verify_log_helper(self, msg, verbose):
        # return early if CONFIG_LOG_BUF_MAGIC is not defined
        log_align_addr = self.ramdump.address_of('__log_align')
        if (log_align_addr is None):
            return True

        len_offset = self.ramdump.field_offset(self.struct_name, 'len')
        text_offset = self.ramdump.field_offset(self.struct_name, 'text_len')
        dict_offset = self.ramdump.field_offset(self.struct_name, 'dict_len')
        magic_offset = self.ramdump.field_offset(self.struct_name, 'magic')
        msg_len = self.ramdump.read_u16(msg + len_offset)
        text_len = self.ramdump.read_u16(msg + text_offset)
        dict_len = self.ramdump.read_u16(msg + dict_offset)
        magic = self.ramdump.read_u32(msg + magic_offset)
        log_size = self.ramdump.sizeof(self.struct_name)
        log_align = self.ramdump.read_u32(log_align_addr)
        is_logwrap_marker = not bool(text_len | msg_len | dict_len)

        err = []
        if (magic != LOG_MAGIC):
            err.append('Bad Magic')

        computed_msg_len = (text_len + dict_len + log_size + log_align - 1) & ~(log_align - 1)
        if (not is_logwrap_marker and (msg_len != computed_msg_len)):
            err.append('Bad length')

        err = ' '.join(err)
        if (err):
            if (verbose):
                f = '--------- Corrupted Dmesg {} for record @ {:x} ---------\n'.format(err, msg)
                self.outfile.write(f)
                f = self.ramdump.hexdump(msg - 0x40, 0xC0)
                self.outfile.write(f)
            return False
        return True

    def verify_log(self, msg, logbuf_addr, last_idx):
        logbuf_size = self.ramdump.sizeof('__log_buf')
        log_size = self.ramdump.sizeof(self.struct_name)

        verbose = True
        while msg != logbuf_addr + last_idx:
            if (self.verify_log_helper(msg, verbose)):
                return msg
            verbose = False
            msg = msg + 0x4
            if (msg > logbuf_addr + logbuf_size - log_size):
                msg = logbuf_addr
                self.wrap_cnt += 1

        return logbuf_addr + last_idx

    def extract_dmesg_flat(self):
        addr = self.ramdump.read_word(self.ramdump.address_of('log_buf'))
        size = self.ramdump.read_word(self.ramdump.address_of('log_buf_len'))
        dmesg = self.ramdump.read_physical(self.ramdump.virt_to_phys(addr), size)
        self.outfile.write(cleanupString(dmesg.decode('ascii', 'ignore')) + '\n')

    def extract_dmesg_binary(self):
        first_idx_addr = self.ramdump.address_of('log_first_idx')
        last_idx_addr = self.ramdump.address_of('log_next_idx')
        logbuf_addr = self.ramdump.read_word(
            self.ramdump.address_of('log_buf'))
        time_offset = self.ramdump.field_offset(self.struct_name, 'ts_nsec')
        len_offset = self.ramdump.field_offset(self.struct_name, 'len')
        text_len_offset = self.ramdump.field_offset(self.struct_name, 'text_len')
        log_size = self.ramdump.sizeof(self.struct_name)

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
            curr_idx = self.verify_log(curr_idx, logbuf_addr, last_idx)

    def extract_dmesg(self):
        major, minor, patch = self.ramdump.kernel_version
        if (major, minor) >= (3, 7):
            self.extract_dmesg_binary()
            return
        self.extract_dmesg_flat()
