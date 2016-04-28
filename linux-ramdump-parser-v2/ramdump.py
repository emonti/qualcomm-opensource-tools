# Copyright (c) 2012-2015, The Linux Foundation. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and
# only version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

import sys
import re
import os
import struct
import gzip
import functools
import string
import random
import platform
import stat

from boards import get_supported_boards, get_supported_ids
from tempfile import NamedTemporaryFile

import gdbmi
from print_out import print_out_str
from mmu import Armv7MMU, Armv7LPAEMMU, Armv8MMU
import parser_util

FP = 11
SP = 13
LR = 14
PC = 15

# The smem code is very stable and unlikely to go away or be changed.
# Rather than go through the hassel of parsing the id through gdb,
# just hard code it

SMEM_HW_SW_BUILD_ID = 0x89
BUILD_ID_LENGTH = 32

first_mem_file_names = ['EBICS0.BIN',
                        'EBI1.BIN', 'DDRCS0.BIN', 'ebi1_cs0.bin', 'DDRCS0_0.BIN']
extra_mem_file_names = ['EBI1CS1.BIN', 'DDRCS1.BIN', 'ebi1_cs1.bin', 'DDRCS0_1.BIN', 'DDRCS1_0.BIN', 'DDRCS1_1.BIN']


class RamDump():

    class Unwinder ():

        class Stackframe ():

            def __init__(self, fp, sp, lr, pc):
                self.fp = fp
                self.sp = sp
                self.lr = lr
                self.pc = pc

        class UnwindCtrlBlock ():

            def __init__(self):
                self.vrs = 16 * [0]
                self.insn = 0
                self.entries = -1
                self.byte = -1
                self.index = 0

        def __init__(self, ramdump):
            start = ramdump.address_of('__start_unwind_idx')
            end = ramdump.address_of('__stop_unwind_idx')
            self.ramdump = ramdump
            if (start is None) or (end is None):
                if ramdump.arm64:
                    self.unwind_frame = self.unwind_frame_generic64
                else:
                    self.unwind_frame = self.unwind_frame_generic
                return None
            # addresses
            self.unwind_frame = self.unwind_frame_tables
            self.start_idx = start
            self.stop_idx = end
            self.unwind_table = []
            i = 0
            for addr in range(start, end, 8):
                r = ramdump.read_string(addr, '<II')
                if r is None:
                    break
                (a, b) = r
                self.unwind_table.append((a, b, start + 8 * i))
                i += 1

            ver = ramdump.version
            if re.search('3.0.\d', ver) is not None:
                self.search_idx = self.search_idx_3_0
            else:
                self.search_idx = self.search_idx_3_4
                # index into the table
                self.origin = self.unwind_find_origin()

        def unwind_find_origin(self):
            start = 0
            stop = len(self.unwind_table)
            while (start < stop):
                mid = start + ((stop - start) >> 1)
                if (self.unwind_table[mid][0] >= 0x40000000):
                    start = mid + 1
                else:
                    stop = mid
            return stop

        def unwind_frame_generic64(self, frame):
            fp = frame.fp
            low = frame.sp
            mask = (self.ramdump.thread_size) - 1
            high = (low + mask) & (~mask)

            # Ignore NON HLOS addresses and return from the function without
            # unwinding the frame pointer. HLOS addresses are expected to be
            # greater than or equal to page_offset. NON HLOS addresses have 1-1
            # virtual to physical mapping and may not have physical addresses
            # equal to or greater than page_offset anytime soon.
            if (fp < low or fp > high or fp & 0xf or fp < self.ramdump.page_offset):
                return

            frame.sp = fp + 0x10
            frame.fp = self.ramdump.read_word(fp)
            frame.pc = self.ramdump.read_word(fp + 8)
            return 0

        def unwind_frame_generic(self, frame):
            high = 0
            fp = frame.fp

            low = frame.sp
            mask = (self.ramdump.thread_size) - 1

            high = (low + mask) & (~mask)  # ALIGN(low, THREAD_SIZE)

            # /* check current frame pointer is within bounds */
            if (fp < (low + 12) or fp + 4 >= high):
                return -1

            fp_is_at = self.ramdump.read_word(frame.fp - 12)
            sp_is_at = self.ramdump.read_word(frame.fp - 8)
            pc_is_at = self.ramdump.read_word(frame.fp - 4)

            frame.fp = fp_is_at
            frame.sp = sp_is_at
            frame.pc = pc_is_at

            return 0

        def walk_stackframe_generic(self, frame):
            while True:
                symname = self.ramdump.addr_to_symbol(frame.pc)
                print_out_str(symname)

                ret = self.unwind_frame_generic(frame)
                if ret < 0:
                    break

        def unwind_backtrace_generic(self, sp, fp, pc):
            frame = self.Stackframe()
            frame.fp = fp
            frame.pc = pc
            frame.sp = sp
            walk_stackframe_generic(frame)

        def search_idx_3_4(self, addr):
            start = 0
            stop = len(self.unwind_table)
            orig = addr

            if (addr < self.start_idx):
                stop = self.origin
            else:
                start = self.origin

            if (start >= stop):
                return None

            addr = (addr - self.unwind_table[start][2]) & 0x7fffffff

            while (start < (stop - 1)):
                mid = start + ((stop - start) >> 1)

                dif = (self.unwind_table[mid][2]
                       - self.unwind_table[start][2])
                if ((addr - dif) < self.unwind_table[mid][0]):
                    stop = mid
                else:
                    addr = addr - dif
                    start = mid

            if self.unwind_table[start][0] <= addr:
                return self.unwind_table[start]
            else:
                return None

        def search_idx_3_0(self, addr):
            first = 0
            last = len(self.unwind_table)
            while (first < last - 1):
                mid = first + ((last - first + 1) >> 1)
                if (addr < self.unwind_table[mid][0]):
                    last = mid
                else:
                    first = mid

            return self.unwind_table[first]

        def unwind_get_byte(self, ctrl):

            if (ctrl.entries <= 0):
                print_out_str('unwind: Corrupt unwind table')
                return 0

            val = self.ramdump.read_word(ctrl.insn)

            ret = (val >> (ctrl.byte * 8)) & 0xff

            if (ctrl.byte == 0):
                ctrl.insn += 4
                ctrl.entries -= 1
                ctrl.byte = 3
            else:
                ctrl.byte -= 1

            return ret

        def unwind_exec_insn(self, ctrl):
            insn = self.unwind_get_byte(ctrl)

            if ((insn & 0xc0) == 0x00):
                ctrl.vrs[SP] += ((insn & 0x3f) << 2) + 4
            elif ((insn & 0xc0) == 0x40):
                ctrl.vrs[SP] -= ((insn & 0x3f) << 2) + 4
            elif ((insn & 0xf0) == 0x80):
                vsp = ctrl.vrs[SP]
                reg = 4

                insn = (insn << 8) | self.unwind_get_byte(ctrl)
                mask = insn & 0x0fff
                if (mask == 0):
                    print_out_str("unwind: 'Refuse to unwind' instruction")
                    return -1

                # pop R4-R15 according to mask */
                load_sp = mask & (1 << (13 - 4))
                while (mask):
                    if (mask & 1):
                        ctrl.vrs[reg] = self.ramdump.read_word(vsp)
                        if ctrl.vrs[reg] is None:
                            return -1
                        vsp += 4
                    mask >>= 1
                    reg += 1
                if not load_sp:
                    ctrl.vrs[SP] = vsp

            elif ((insn & 0xf0) == 0x90 and (insn & 0x0d) != 0x0d):
                ctrl.vrs[SP] = ctrl.vrs[insn & 0x0f]
            elif ((insn & 0xf0) == 0xa0):
                vsp = ctrl.vrs[SP]
                a = list(range(4, 4 + (insn & 7)))
                a.append(4 + (insn & 7))
                # pop R4-R[4+bbb] */
                for reg in (a):
                    ctrl.vrs[reg] = self.ramdump.read_word(vsp)
                    if ctrl.vrs[reg] is None:
                        return -1
                    vsp += 4
                if (insn & 0x80):
                    ctrl.vrs[14] = self.ramdump.read_word(vsp)
                    if ctrl.vrs[14] is None:
                        return -1
                    vsp += 4
                ctrl.vrs[SP] = vsp
            elif (insn == 0xb0):
                if (ctrl.vrs[PC] == 0):
                    ctrl.vrs[PC] = ctrl.vrs[LR]
                ctrl.entries = 0
            elif (insn == 0xb1):
                mask = self.unwind_get_byte(ctrl)
                vsp = ctrl.vrs[SP]
                reg = 0

                if (mask == 0 or mask & 0xf0):
                    print_out_str('unwind: Spare encoding')
                    return -1

                # pop R0-R3 according to mask
                while mask:
                    if (mask & 1):
                        ctrl.vrs[reg] = self.ramdump.read_word(vsp)
                        if ctrl.vrs[reg] is None:
                            return -1
                        vsp += 4
                    mask >>= 1
                    reg += 1
                ctrl.vrs[SP] = vsp
            elif (insn == 0xb2):
                uleb128 = self.unwind_get_byte(ctrl)
                ctrl.vrs[SP] += 0x204 + (uleb128 << 2)
            else:
                print_out_str('unwind: Unhandled instruction')
                return -1

            return 0

        def prel31_to_addr(self, addr):
            value = self.ramdump.read_word(addr)
            # offset = (value << 1) >> 1
            # C wants this sign extended. Python doesn't do that.
            # Sign extend manually.
            if (value & 0x40000000):
                offset = value | 0x80000000
            else:
                offset = value

            # This addition relies on integer overflow
            # Emulate this behavior
            temp = addr + offset
            return (temp & 0xffffffff) + ((temp >> 32) & 0xffffffff)

        def unwind_frame_tables(self, frame):
            low = frame.sp
            high = ((low + (self.ramdump.thread_size - 1)) & \
                ~(self.ramdump.thread_size - 1)) + self.ramdump.thread_size
            idx = self.search_idx(frame.pc)

            if (idx is None):
                return -1

            ctrl = self.UnwindCtrlBlock()
            ctrl.vrs[FP] = frame.fp
            ctrl.vrs[SP] = frame.sp
            ctrl.vrs[LR] = frame.lr
            ctrl.vrs[PC] = 0

            if (idx[1] == 1):
                return -1

            elif ((idx[1] & 0x80000000) == 0):
                ctrl.insn = self.prel31_to_addr(idx[2] + 4)

            elif (idx[1] & 0xff000000) == 0x80000000:
                ctrl.insn = idx[2] + 4
            else:
                print_out_str('not supported')
                return -1

            val = self.ramdump.read_word(ctrl.insn)

            if ((val & 0xff000000) == 0x80000000):
                ctrl.byte = 2
                ctrl.entries = 1
            elif ((val & 0xff000000) == 0x81000000):
                ctrl.byte = 1
                ctrl.entries = 1 + ((val & 0x00ff0000) >> 16)
            else:
                return -1

            while (ctrl.entries > 0):
                urc = self.unwind_exec_insn(ctrl)
                if (urc < 0):
                    return urc
                if (ctrl.vrs[SP] < low or ctrl.vrs[SP] >= high):
                    return -1

            if (ctrl.vrs[PC] == 0):
                ctrl.vrs[PC] = ctrl.vrs[LR]

            # check for infinite loop */
            if (frame.pc == ctrl.vrs[PC]):
                return -1

            frame.fp = ctrl.vrs[FP]
            frame.sp = ctrl.vrs[SP]
            frame.lr = ctrl.vrs[LR]
            frame.pc = ctrl.vrs[PC]

            return 0

        def unwind_backtrace(self, sp, fp, pc, lr, extra_str='',
                             out_file=None):
            offset = 0
            frame = self.Stackframe(fp, sp, lr, pc)
            frame.fp = fp
            frame.sp = sp
            frame.lr = lr
            frame.pc = pc

            while True:
                where = frame.pc
                offset = 0

                if frame.pc is None:
                    break

                r = self.ramdump.unwind_lookup(frame.pc)
                if r is None:
                    symname = 'UNKNOWN'
                    offset = 0x0
                else:
                    symname, offset = r
                pstring = (
                    extra_str + '[<{0:x}>] {1}+0x{2:x}'.format(frame.pc, symname, offset))
                if out_file:
                    out_file.write(pstring + '\n')
                else:
                    print_out_str(pstring)

                urc = self.unwind_frame(frame)
                if urc < 0:
                    break

    def __init__(self, options, nm_path, gdb_path, objdump_path):
        self.ebi_files = []
        self.phys_offset = None
        self.tz_start = 0
        self.ebi_start = 0
        self.cpu_type = None
        self.hw_id = options.force_hardware or None
        self.hw_version = options.force_hardware_version or None
        self.offset_table = []
        self.vmlinux = options.vmlinux
        self.nm_path = nm_path
        self.gdb_path = gdb_path
        self.objdump_path = objdump_path
        self.outdir = options.outdir
        self.imem_fname = None
        self.gdbmi = gdbmi.GdbMI(self.gdb_path, self.vmlinux)
        self.gdbmi.open()
        self.arm64 = options.arm64
        self.page_offset = 0xc0000000
        self.thread_size = 8192
        self.qtf_path = options.qtf_path
        self.qtf = options.qtf
        self.dcc = False
        self.t32_host_system = options.t32_host_system or platform.system()
        self.ipc_log_test = options.ipc_test
        self.ipc_log_skip = options.ipc_skip
        self.ipc_log_debug = options.ipc_debug
        self.ipc_log_help = options.ipc_help
        self.use_stdout = options.stdout
        self.kernel_version = (0, 0, 0)
        if options.ram_addr is not None:
            # TODO sanity check to make sure the memory regions don't overlap
            for file_path, start, end in options.ram_addr:
                fd = open(file_path, 'rb')
                if not fd:
                    print_out_str(
                        'Could not open {0}. Will not be part of dump'.format(file_path))
                    continue
                self.ebi_files.append((fd, start, end, file_path))
        else:
            if not self.auto_parse(options.autodump):
                return None
        if self.ebi_start == 0:
            self.ebi_start = self.ebi_files[0][1]
        if self.phys_offset is None:
            self.get_hw_id()
        if options.phys_offset is not None:
            print_out_str(
                '[!!!] Phys offset was set to {0:x}'.format(\
                    options.phys_offset))
            self.phys_offset = options.phys_offset
        self.lookup_table = []
        self.config = []
        self.config_dict = {}
        if self.arm64:
            self.page_offset = 0xffffffc000000000
            self.thread_size = 16384
        if options.page_offset is not None:
            print_out_str(
                '[!!!] Page offset was set to {0:x}'.format(page_offset))
            self.page_offset = options.page_offset
        self.setup_symbol_tables()

        # The address of swapper_pg_dir can be used to determine
        # whether or not we're running with LPAE enabled since an
        # extra 4k is needed for LPAE. If it's 0x5000 below
        # PAGE_OFFSET + TEXT_OFFSET then we know we're using LPAE. For
        # non-LPAE it should be 0x4000 below PAGE_OFFSET + TEXT_OFFSET
        swapper_pg_dir = self.address_of('swapper_pg_dir')
        if swapper_pg_dir is None:
            print_out_str('!!! Could not get the swapper page directory!')
            print_out_str(
                '!!! Your vmlinux is probably wrong for these dumps')
            print_out_str('!!! Exiting now')
            sys.exit(1)
        self.swapper_pg_dir_addr =  swapper_pg_dir - self.page_offset
        self.kernel_text_offset = self.address_of('stext') - self.page_offset
        pg_dir_size = self.kernel_text_offset - self.swapper_pg_dir_addr
        if self.arm64:
            print_out_str('Using 64bit MMU')
            self.mmu = Armv8MMU(self)
        elif pg_dir_size == 0x4000:
            print_out_str('Using non-LPAE MMU')
            self.mmu = Armv7MMU(self)
        elif pg_dir_size == 0x5000:
            print_out_str('Using LPAE MMU')
            text_offset = 0x8000
            pg_dir_size = 0x5000    # 0x4000 for non-LPAE
            swapper_pg_dir_addr = self.phys_offset + text_offset - pg_dir_size

            # We deduce ttbr1 and ttbcr.t1sz based on the value of
            # PAGE_OFFSET. This is based on v7_ttb_setup in
            # arch/arm/mm/proc-v7-3level.S:

            # * TTBR0/TTBR1 split (PAGE_OFFSET):
            # *   0x40000000: T0SZ = 2, T1SZ = 0 (not used)
            # *   0x80000000: T0SZ = 0, T1SZ = 1
            # *   0xc0000000: T0SZ = 0, T1SZ = 2
            if self.page_offset == 0x40000000:
                t1sz = 0
            elif self.page_offset == 0x80000000:
                t1sz = 1
            elif self.page_offset == 0xc0000000:
                t1sz = 2
                # need to fixup ttbr1 since we'll be skipping the
                # first-level lookup (see v7_ttb_setup):
                # /* PAGE_OFFSET == 0xc0000000, T1SZ == 2 */
                # add      \ttbr1, \ttbr1, #4096 * (1 + 3) @ only L2 used, skip
                # pgd+3*pmd
                swapper_pg_dir_addr += (4096 * (1 + 3))
            else:
                raise Exception(
                    'Invalid phys_offset for page_table_walk: 0x%x'
                    % self.page_offset)
            self.mmu = Armv7LPAEMMU(self, swapper_pg_dir_addr, t1sz)
        else:
            print_out_str(
                "!!! Couldn't determine whether or not we're using LPAE!")
            print_out_str(
                '!!! This is a BUG in the parser and should be reported.')
            sys.exit(1)

        if not self.get_version():
            print_out_str('!!! Could not get the Linux version!')
            print_out_str(
                '!!! Your vmlinux is probably wrong for these dumps')
            print_out_str('!!! Exiting now')
            sys.exit(1)
        if not self.get_config():
            print_out_str('!!! Could not get saved configuration')
            print_out_str(
                '!!! This is really bad and probably indicates RAM corruption')
            print_out_str('!!! Some features may be disabled!')
        self.unwind = self.Unwinder(self)

    def __del__(self):
        self.gdbmi.close()

    def open_file(self, file_name, mode='wb'):
        file_path = os.path.join(self.outdir, file_name)
        f = None
        try:
            f = open(file_path, mode)
        except:
            print_out_str('Could not open path {0}'.format(file_path))
            print_out_str('Do you have write/read permissions on the path?')
            sys.exit(1)
        return f

    def get_config(self):
        kconfig_addr = self.address_of('kernel_config_data')
        if kconfig_addr is None:
            return
        kconfig_size = self.sizeof('kernel_config_data')
        # size includes magic, offset from it
        kconfig_size = kconfig_size - 16 - 1
        zconfig = NamedTemporaryFile(mode='wb', delete=False)
        # kconfig data starts with magic 8 byte string, go past that
        s = self.read_cstring(kconfig_addr, 8)
        if s != 'IKCFG_ST':
            return
        kconfig_addr = kconfig_addr + 8
        for i in range(0, kconfig_size):
            val = self.read_byte(kconfig_addr + i)
            zconfig.write(struct.pack('<B', val))

        zconfig.close()
        zconfig_in = gzip.open(zconfig.name, 'rb')
        try:
            t = zconfig_in.readlines()
        except:
            return False
        zconfig_in.close()
        os.remove(zconfig.name)
        for l in t:
            self.config.append(l.rstrip().decode('ascii', 'ignore'))
            if not l.startswith('#') and l.strip() != '':
                cfg, val = l.split('=')
                self.config_dict[cfg] = val.strip()
        return True

    def get_config_val(self, config):
        return self.config_dict.get(config)

    def is_config_defined(self, config):
        s = config + '=y'
        return s in self.config

    def get_version(self):
        banner_addr = self.address_of('linux_banner')
        if banner_addr is not None:
            # Don't try virt to phys yet, compute manually
            banner_addr = banner_addr - self.page_offset + self.phys_offset
            b = self.read_cstring(banner_addr, 256, False)
            if b is None:
                print_out_str('!!! Could not read banner address!')
                return False
            v = re.search('Linux version (\d{0,2}\.\d{0,2}\.\d{0,2})', b)
            if v is None:
                print_out_str('!!! Could not match version! {0}'.format(b))
                return False
            self.version = v.group(1)
            match = re.search('(\d+)\.(\d+)\.(\d+)', self.version)
            if match is not None:
                self.kernel_version = tuple(map(int, match.groups()))
            else:
                print_out_str('!!! Could not extract version info! {0}'.format(self.version))

            print_out_str('Linux Banner: ' + b.rstrip())
            print_out_str('version = {0}'.format(self.version))
            return True
        else:
            print_out_str('!!! Could not lookup banner address')
            return False

    def print_command_line(self):
        command_addr = self.address_of('saved_command_line')
        if command_addr is not None:
            command_addr = self.read_word(command_addr)
            b = self.read_cstring(command_addr, 2048)
            if b is None:
                print_out_str('!!! could not read saved command line address')
                return False
            print_out_str('Command Line: ' + b)
            return True
        else:
            print_out_str('!!! Could not lookup saved command line address')
            return False

    def get_ddr_base_addr(self, file_path):
        if os.path.exists(os.path.join(file_path, 'load.cmm')):
            with open (os.path.join(file_path, 'load.cmm'), "r") as myfile:
                for line in myfile.readlines():
                    words = line.split()
                    if words[0] == "d.load.binary" and words[1].startswith("DDRCS"):
                        if words[2][0:2].lower() == '0x':
                            return int(words[2], 16)
        elif os.path.exists(os.path.join(file_path, 'dump_info.txt')):
            with open (os.path.join(file_path, 'dump_info.txt'), "r") as myfile:
                for line in myfile.readlines():
                    words = line.split()
                    if words[-1].startswith("DDRCS"):
                        if words[1][0:2].lower() == '0x':
                            return int(words[1], 16)

    def auto_parse(self, file_path):
        first_mem_path = None

        for f in first_mem_file_names:
            test_path = file_path + '/' + f
            if os.path.exists(test_path):
                first_mem_path = test_path
                break

        if first_mem_path is None:
            print_out_str('!!! Could not open a memory file. I give up')
            sys.exit(1)

        first_mem = open(first_mem_path, 'rb')
        # put some dummy data in for now
        self.ebi_files = [(first_mem, 0, 0xffff0000, first_mem_path)]
        if not self.get_hw_id(add_offset=False):
            return False

        base_addr = self.get_ddr_base_addr(file_path)
        if base_addr is not None:
            self.ebi_start = base_addr
            self.phys_offset = base_addr
        else:
            print_out_str('!!! WARNING !!! Using Static DDR Base Addresses.')

        first_mem_end = self.ebi_start + os.path.getsize(first_mem_path) - 1
        self.ebi_files = [
            (first_mem, self.ebi_start, first_mem_end, first_mem_path)]
        print_out_str(
            'Adding {0} {1:x}--{2:x}'.format(first_mem_path, self.ebi_start, first_mem_end))
        self.ebi_start = self.ebi_start + os.path.getsize(first_mem_path)

        for f in extra_mem_file_names:
            extra_path = file_path + '/' + f

            if os.path.exists(extra_path):
                extra = open(extra_path, 'rb')
                extra_start = self.ebi_start
                extra_end = extra_start + os.path.getsize(extra_path) - 1
                self.ebi_start = extra_end + 1
                print_out_str(
                    'Adding {0} {1:x}--{2:x}'.format(extra_path, extra_start, extra_end))
                self.ebi_files.append(
                    (extra, extra_start, extra_end, extra_path))

        if self.imem_fname is not None:
            imemc_path = file_path + '/' + self.imem_fname
            if os.path.exists(imemc_path):
                imemc = open(imemc_path, 'rb')
                imemc_start = self.tz_start
                imemc_end = imemc_start + os.path.getsize(imemc_path) - 1
                print_out_str(
                    'Adding {0} {1:x}--{2:x}'.format(imemc_path, imemc_start, imemc_end))
                self.ebi_files.append(
                    (imemc, imemc_start, imemc_end, imemc_path))
        return True

    def create_t32_launcher(self):
        out_path = self.outdir

        t32_host_system = self.t32_host_system or platform.system()

        launch_config = open(out_path + '/t32_config.t32', 'wb')
        launch_config.write('OS=\n')
        launch_config.write('ID=T32_1000002\n')
        if t32_host_system == 'Windows':
            launch_config.write('TMP=C:\\TEMP\n')
            launch_config.write('SYS=C:\\T32\n')
            launch_config.write('HELP=C:\\T32\\pdf\n')
        else:
            launch_config.write('TMP=/tmp\n')
            launch_config.write('SYS=/opt/t32\n')
            launch_config.write('HELP=/opt/t32/pdf\n')
        launch_config.write('\n')
        launch_config.write('PBI=SIM\n')
        launch_config.write('\n')
        launch_config.write('SCREEN=\n')
        launch_config.write('FONT=SMALL\n')
        launch_config.write('HEADER=Trace32-ScorpionSimulator\n')
        launch_config.write('\n')
        if t32_host_system == 'Windows':
            launch_config.write('PRINTER=WINDOWS\n')
            launch_config.write('\n')
        launch_config.write('RCL=NETASSIST\n')
        launch_config.write('PACKLEN=1024\n')
        launch_config.write('PORT=%d\n' % random.randint(20000, 30000))
        launch_config.write('\n')

        launch_config.close()

        startup_script = open(out_path + '/t32_startup_script.cmm', 'wb')

        startup_script.write(('title \"' + out_path + '\"\n').encode('ascii', 'ignore'))

        is_cortex_a53 = self.hw_id == 8916 or self.hw_id == 8939 or self.hw_id == 8936

        if self.arm64 and is_cortex_a53:
            startup_script.write('sys.cpu CORTEXA53\n'.encode('ascii', 'ignore'))
        else:
            startup_script.write('sys.cpu {0}\n'.format(self.cpu_type).encode('ascii', 'ignore'))
        startup_script.write('sys.up\n'.encode('ascii', 'ignore'))

        for ram in self.ebi_files:
            ebi_path = os.path.abspath(ram[3])
            startup_script.write('data.load.binary {0} 0x{1:x}\n'.format(
                ebi_path, ram[1]).encode('ascii', 'ignore'))
        if self.arm64:
            startup_script.write('Register.Set NS 1\n'.encode('ascii', 'ignore'))
            startup_script.write('Data.Set SPR:0x30201 %Quad 0x{0:x}\n'.format(self.swapper_pg_dir_addr + self.phys_offset).encode('ascii', 'ignore'))

            if is_cortex_a53:
                startup_script.write('Data.Set SPR:0x30202 %Quad 0x00000012B5193519\n'.encode('ascii', 'ignore'))
                startup_script.write('Data.Set SPR:0x30A20 %Quad 0x000000FF440C0400\n'.encode('ascii', 'ignore'))
                startup_script.write('Data.Set SPR:0x30A30 %Quad 0x0000000000000000\n'.encode('ascii', 'ignore'))
                startup_script.write('Data.Set SPR:0x30100 %Quad 0x0000000034D5D91D\n'.encode('ascii', 'ignore'))
            else:
                startup_script.write('Data.Set SPR:0x30202 %Quad 0x00000032B5193519\n'.encode('ascii', 'ignore'))
                startup_script.write('Data.Set SPR:0x30A20 %Quad 0x000000FF440C0400\n'.encode('ascii', 'ignore'))
                startup_script.write('Data.Set SPR:0x30A30 %Quad 0x0000000000000000\n'.encode('ascii', 'ignore'))
                startup_script.write('Data.Set SPR:0x30100 %Quad 0x0000000004C5D93D\n'.encode('ascii', 'ignore'))

            startup_script.write('Register.Set CPSR 0x3C5\n'.encode('ascii', 'ignore'))
            startup_script.write('MMU.Delete\n'.encode('ascii', 'ignore'))
            startup_script.write('MMU.SCAN PT 0xFFFFFF8000000000--0xFFFFFFFFFFFFFFFF\n'.encode('ascii', 'ignore'))
            startup_script.write('mmu.on\n'.encode('ascii', 'ignore'))
            startup_script.write('mmu.pt.list 0xffffff8000000000\n'.encode('ascii', 'ignore'))
        else:
            startup_script.write(
                'PER.S.F C15:0x2 %L 0x{0:x}\n'.format(self.mmu.ttbr).encode('ascii', 'ignore'))
            if isinstance(self.mmu, Armv7LPAEMMU):
                # TTBR1. This gets setup once and never change again even if TTBR0
                # changes
                startup_script.write('PER.S.F C15:0x102 %L 0x{0:x}\n'.format(
                    self.mmu.ttbr + 0x4000).encode('ascii', 'ignore'))
                # TTBCR with EAE and T1SZ set approprately
                startup_script.write(
                    'PER.S.F C15:0x202 %L 0x80030000\n'.encode('ascii', 'ignore'))
            startup_script.write('mmu.on\n'.encode('ascii', 'ignore'))
            startup_script.write('mmu.scan\n'.encode('ascii', 'ignore'))
        startup_script.write(
            ('data.load.elf ' + os.path.abspath(self.vmlinux) + ' /nocode\n').encode('ascii', 'ignore'))

        if t32_host_system == 'Windows':
            if self.arm64:
                startup_script.write(
                     'task.config C:\\T32\\demo\\arm64\\kernel\\linux\\linux-3.x\\linux3.t32\n'.encode('ascii', 'ignore'))
                startup_script.write(
                     'menu.reprogram C:\\T32\\demo\\arm64\\kernel\\linux\\linux-3.x\\linux.men\n'.encode('ascii', 'ignore'))
            else:
                startup_script.write(
                    'task.config c:\\t32\\demo\\arm\\kernel\\linux\\linux.t32\n'.encode('ascii', 'ignore'))
                startup_script.write(
                    'menu.reprogram c:\\t32\\demo\\arm\\kernel\\linux\\linux.men\n'.encode('ascii', 'ignore'))
        else:
            if self.arm64:
                startup_script.write(
                    'task.config /opt/t32/demo/arm64/kernel/linux/linux-3.x/linux3.t32\n'.encode('ascii', 'ignore'))
                startup_script.write(
                    'menu.reprogram /opt/t32/demo/arm64/kernel/linux/linux-3.x/linux.men\n'.encode('ascii', 'ignore'))
            else:
                startup_script.write(
                    'task.config /opt/t32/demo/arm/kernel/linux/linux.t32\n'.encode('ascii', 'ignore'))
                startup_script.write(
                    'menu.reprogram /opt/t32/demo/arm/kernel/linux/linux.men\n'.encode('ascii', 'ignore'))

        startup_script.write('task.dtask\n'.encode('ascii', 'ignore'))
        startup_script.write(
            'v.v  %ASCII %STRING linux_banner\n'.encode('ascii', 'ignore'))
        if os.path.exists(out_path + '/regs_panic.cmm'):
            startup_script.write(
                'do {0}\n'.format(out_path + '/regs_panic.cmm').encode('ascii', 'ignore'))
        elif os.path.exists(out_path + '/core0_regs.cmm'):
            startup_script.write(
                'do {0}\n'.format(out_path + '/core0_regs.cmm').encode('ascii', 'ignore'))
        startup_script.close()

        if t32_host_system == 'Windows':
            t32_bat = open(out_path + '/launch_t32.bat', 'wb')
            if self.arm64:
                t32_binary = 'C:\\T32\\bin\\windows64\\t32MARM64.exe'
            elif is_cortex_a53:
                t32_binary = 'C:\\T32\\bin\\windows64\\t32MARM.exe'
            else:
                t32_binary = 'c:\\t32\\t32MARM.exe'
            t32_bat.write(('start '+ t32_binary + ' -c ' + out_path + '/t32_config.t32, ' +
                          out_path + '/t32_startup_script.cmm').encode('ascii', 'ignore'))
        else:
            t32_bat = open(out_path + '/launch_t32.sh', 'wb')
            if t32_host_system == 'Darwin':
                t32_bin_path = 'macosx64'
            else:
                t32_bin_path = 'pc_linux64'

            if self.arm64:
                t32_binary = 't32marm64-qt'
            elif is_cortex_a53:
                t32_binary = 't32marm-qt'
            else:
                t32_binary = 't32marm-qt'

            t32_bat.write('#!/bin/sh\n\n')
            t32_bat.write('cd $(dirname $0)\n')
            t32_bat.write('/opt/t32/bin/%s/%s -c t32_config.t32, t32_startup_script.cmm &\n' % (t32_bin_path, t32_binary))
            os.chmod(out_path + '/launch_t32.sh', stat.S_IRWXU)

        t32_bat.close()
        print_out_str(
            '--- Created a T32 Simulator launcher (run {0}/launch_t32.bat)'.format(out_path))

    def read_tz_offset(self):
        if self.tz_addr == 0:
            print_out_str(
                'No TZ address was given, cannot read the magic value!')
            return None
        else:
            return self.read_word(self.tz_addr, False)

    def get_hw_id(self, add_offset=True):
        socinfo_format = -1
        socinfo_id = -1
        socinfo_version = 0
        socinfo_build_id = 'DUMMY'
        chosen_board = None

        boards = get_supported_boards()

        if (self.hw_id is None):
            heap_toc_offset = self.field_offset('struct smem_shared', 'heap_toc')
            if heap_toc_offset is None:
                print_out_str(
                    '!!!! Could not get a necessary offset for auto detection!')
                print_out_str(
                    '!!!! Please check the gdb path which is used for offsets!')
                print_out_str('!!!! Also check that the vmlinux is not stripped')
                print_out_str('!!!! Exiting...')
                sys.exit(1)

            smem_heap_entry_size = self.sizeof('struct smem_heap_entry')
            offset_offset = self.field_offset('struct smem_heap_entry', 'offset')
            for board in boards:
                socinfo_start_addr = board.smem_addr + heap_toc_offset + smem_heap_entry_size * SMEM_HW_SW_BUILD_ID + offset_offset
                if add_offset:
                    socinfo_start_addr += board.ram_start
                soc_start = self.read_int(socinfo_start_addr, False)
                if soc_start is None:
                    continue

                socinfo_start = board.smem_addr + soc_start
                if add_offset:
                    socinfo_start += board.ram_start

                socinfo_id = self.read_int(socinfo_start + 4, False)
                if socinfo_id != board.socid:
                    continue

                socinfo_format = self.read_int(socinfo_start, False)
                socinfo_version = self.read_int(socinfo_start + 8, False)
                socinfo_build_id = self.read_cstring(
                    socinfo_start + 12, BUILD_ID_LENGTH, virtual=False)

                chosen_board = board
                break

            if chosen_board is None:
                print_out_str('!!!! Could not find hardware')
                print_out_str("!!!! The SMEM didn't match anything")
                print_out_str(
                    '!!!! You can use --force-hardware to use a specific set of values')
                sys.exit(1)

        else:
            for board in boards:
                if self.hw_id == board.board_num:
                    print_out_str(
                        '!!! Hardware id found! The socinfo values given are bogus')
                    print_out_str('!!! Proceed with caution!')
                    chosen_board = board
                    break
            if chosen_board is None:
                print_out_str(
                    '!!! A bogus hardware id was specified: {0}'.format(self.hw_id))
                print_out_str('!!! Supported ids:')
                for b in get_supported_ids():
                    print_out_str('    {0}'.format(b))
                sys.exit(1)

        print_out_str('\nHardware match: {0}'.format(board.board_num))
        print_out_str('Socinfo id = {0}, version {1:x}.{2:x}'.format(
            socinfo_id, socinfo_version >> 16, socinfo_version & 0xFFFF))
        print_out_str('Socinfo build = {0}'.format(socinfo_build_id))
        print_out_str(
            'Now setting phys_offset to {0:x}'.format(board.phys_offset))
        if board.wdog_addr is not None:
            print_out_str(
            'TZ address: {0:x}'.format(board.wdog_addr))
        self.phys_offset = board.phys_offset
        self.tz_addr = board.wdog_addr
        self.ebi_start = board.ram_start
        self.tz_start = board.imem_start
        self.hw_id = board.board_num
        self.cpu_type = board.cpu
        self.imem_fname = board.imem_file_name
        return True

    def resolve_virt(self, virt_or_name):
        """Takes a virtual address or variable name, returns a virtual
        address
        """
        if not isinstance(virt_or_name, basestring):
            return virt_or_name
        return self.address_of(virt_or_name)

    def virt_to_phys(self, virt_or_name):
        """Does a virtual-to-physical address lookup of the virtual address or
        variable name."""
        return self.mmu.virt_to_phys(self.resolve_virt(virt_or_name))

    def setup_symbol_tables(self):
        stream = os.popen(self.nm_path + ' -n ' + self.vmlinux)
        symbols = stream.readlines()
        for line in symbols:
            s = line.split(' ')
            if len(s) == 3:
                self.lookup_table.append((int(s[0], 16), s[2].rstrip()))
        stream.close()

    def address_of(self, symbol):
        try:
            return self.gdbmi.address_of(symbol)
        except gdbmi.GdbMIException:
            pass

    def symbol_at(self, addr):
        try:
            return self.gdbmi.symbol_at(addr)
        except gdbmi.GdbMIException:
            pass

    def sizeof(self, the_type):
        try:
            return self.gdbmi.sizeof(the_type)
        except gdbmi.GdbMIException:
            pass

    def array_index(self, addr, the_type, index):
        """Index into the array of type `the_type' located at `addr'.

        I.e.:

            Given:

                int my_arr[3];
                my_arr[2] = 42;


            The following:

                my_arr_addr = dump.address_of("my_arr")
                dump.read_word(dump.array_index(my_arr_addr, "int", 2))

        will return 42.

        """
        offset = self.gdbmi.sizeof(the_type) * index
        return addr + offset

    def field_offset(self, the_type, field):
        try:
            return self.gdbmi.field_offset(the_type, field)
        except gdbmi.GdbMIException:
            pass

    def container_of(self, ptr, the_type, member):
        try:
            return self.gdbmi.container_of(ptr, the_type, member)
        except gdbmi.GdbMIException:
            pass

    def sibling_field_addr(self, ptr, parent_type, member, sibling):
        try:
            return self.gdbmi.sibling_field_addr(ptr, parent_type, member, sibling)
        except gdbmi.GdbMIException:
            pass

    def unwind_lookup(self, addr, symbol_size=0):
        if (addr is None):
            return ('(Invalid address)', 0x0)

        # modules are not supported so just print out an address
        # instead of a confusing symbol
        if (addr < self.page_offset):
            return ('(No symbol for address {0:x})'.format(addr), 0x0)

        low = 0
        high = len(self.lookup_table)
        # Python now complains about division producing floats
        mid = (low + high) >> 1
        premid = 0

        while(not(addr >= self.lookup_table[mid][0] and addr < self.lookup_table[mid + 1][0])):

            if(addr < self.lookup_table[mid][0]):
                high = mid - 1

            if(addr > self.lookup_table[mid][0]):
                low = mid + 1

            mid = (high + low) >> 1

            if(mid == premid):
                return None
            if (mid + 1) >= len(self.lookup_table) or mid < 0:
                return None

            premid = mid

        if symbol_size == 0:
            return (self.lookup_table[mid][1], addr - self.lookup_table[mid][0])
        else:
            return (self.lookup_table[mid][1], self.lookup_table[mid + 1][0] - self.lookup_table[mid][0])

    def read_physical(self, addr, length):
        ebi = (-1, -1, -1)
        for a in self.ebi_files:
            fd, start, end, path = a
            if addr >= start and addr <= end:
                ebi = a
                break
        if ebi[0] is -1:
            return None
        offset = addr - ebi[1]
        ebi[0].seek(offset)
        a = ebi[0].read(length)
        return a

    def read_dword(self, addr_or_name, virtual=True, cpu=None):
        s = self.read_string(addr_or_name, '<Q', virtual, cpu)
        return s[0] if s is not None else None

    def read_word(self, addr_or_name, virtual=True, cpu=None):
        """returns a word size (pointer) read from ramdump"""
        if self.arm64:
            s = self.read_string(addr_or_name, '<Q', virtual, cpu)
        else:
            s = self.read_string(addr_or_name, '<I', virtual, cpu)
        return s[0] if s is not None else None

    def read_halfword(self, addr_or_name, virtual=True, cpu=None):
        """returns a value corresponding to half the word size"""
        if self.arm64:
            s = self.read_string(addr_or_name, '<I', virtual, cpu)
        else:
            s = self.read_string(addr_or_name, '<H', virtual, cpu)
        return s[0] if s is not None else None

    def read_byte(self, addr_or_name, virtual=True, cpu=None):
        s = self.read_string(addr_or_name, '<B', virtual, cpu)
        return s[0] if s is not None else None

    def read_bool(self, addr_or_name, virtual=True, cpu=None):
        s = self.read_string(addr_or_name, '<?', virtual, cpu)
        return s[0] if s is not None else None

    def read_u64(self, addr_or_name, virtual=True, cpu=None):
        """returns a value guaranteed to be 64 bits"""
        s = self.read_string(addr_or_name, '<Q', virtual, cpu)
        return s[0] if s is not None else None

    def read_s32(self, addr_or_name, virtual=True, cpu=None):
        """returns a value guaranteed to be 32 bits"""
        s = self.read_string(addr_or_name, '<i', virtual, cpu)
        return s[0] if s is not None else None

    def read_u32(self, addr_or_name, virtual=True, cpu=None):
        """returns a value guaranteed to be 32 bits"""
        s = self.read_string(addr_or_name, '<I', virtual, cpu)
        return s[0] if s is not None else None

    def read_int(self, addr_or_name, virtual=True,  cpu=None):
        """Alias for `read_u32'"""
        return self.read_u32(addr_or_name, virtual, cpu)

    def read_u16(self, addr_or_name, virtual=True, cpu=None):
        """returns a value guaranteed to be 16 bits"""
        s = self.read_string(addr_or_name, '<H', virtual, cpu)
        return s[0] if s is not None else None

    def read_pointer(self, addr_or_name, virtual=True, cpu=None):
        """Reads `addr_or_name' as a pointer variable.

        The read length is either 32-bit or 64-bit depending on the
        architecture.  This returns the *value* of the pointer variable
        (i.e. the address it contains), not the data it points to.
        """
        fn = self.read_u32 if self.sizeof('void *') == 4 else self.read_u64
        return fn(addr_or_name, virtual, cpu)

    def read_structure_field(self, addr_or_name, struct_name, field):
        """reads a 4 or 8 byte field from a structure"""
        size = self.sizeof("(({0} *)0)->{1}".format(struct_name, field))
        virt = self.resolve_virt(addr_or_name)
        if size == 4:
            return self.read_u32(virt + self.field_offset(struct_name,
                                                                  field))
        if size == 8:
            return self.read_u64(virt + self.field_offset(struct_name,
                                                                  field))
        return None

    def read_structure_cstring(self, addr_or_name, struct_name, field,
                               max_length=100):
        """reads a C string from a structure field.  The C string field will be
        dereferenced before reading, so it should be a `char *', not a
        `char []'.
        """
        virt = self.resolve_virt(addr_or_name)
        cstring_addr = virt + self.field_offset(struct_name, field)
        return self.read_cstring(self.read_pointer(cstring_addr), max_length)

    def read_cstring(self, addr_or_name, max_length=100, virtual=True,
                     cpu=None):
        addr = addr_or_name
        if virtual:
            if cpu is not None:
                pcpu_offset = self.per_cpu_offset(cpu)
                addr_or_name = self.resolve_virt(addr_or_name)
                addr_or_name += pcpu_offset + self.per_cpu_offset(cpu)
            addr = self.virt_to_phys(addr_or_name)
        s = self.read_physical(addr, max_length)
        if s is not None:
            a = s.decode('ascii', 'ignore')
            return a.split('\0')[0]
        else:
            return s

    def read_string(self, addr_or_name, format_string, virtual=True, cpu=None):
        """Reads data using a format string.

        Reads data from addr_or_name using format_string (which should be a
        struct.unpack format).

        Returns the tuple returned by struct.unpack.
        """
        addr = addr_or_name
        per_cpu_string = ''
        if virtual:
            if cpu is not None:
                pcpu_offset = self.per_cpu_offset(cpu)
                addr_or_name = self.resolve_virt(addr_or_name)
                addr_or_name += pcpu_offset
                per_cpu_string = ' with per-cpu offset of ' + hex(pcpu_offset)
            addr = self.virt_to_phys(addr_or_name)
        s = self.read_physical(addr, struct.calcsize(format_string))
        if (s is None) or (s == ''):
            return None
        return struct.unpack(format_string, s)

    def hexdump(self, addr_or_name, length, virtual=True, file_object=None):
        """Returns a string with a hexdump (in the format of `xxd').

        `length' is in bytes.

        Example (intentionally not in doctest format since it would require
        a specific dump to be loaded to pass as a doctest):

        >>> print(dump.hexdump('linux_banner', 0x80))
        ffffffc000c610a8: 4c69 6e75 7820 7665 7273 696f 6e20 332e  Linux version 3.
        ffffffc000c610b8: 3138 2e32 302d 6761 3762 3238 6539 2d31  18.20-ga7b28e9-1
        ffffffc000c610c8: 3333 3830 2d67 3036 3032 6531 3020 286c  3380-g0602e10 (l
        ffffffc000c610d8: 6e78 6275 696c 6440 6162 6169 7431 3532  nxbuild@abait152
        ffffffc000c610e8: 2d73 642d 6c6e 7829 2028 6763 6320 7665  -sd-lnx) (gcc ve
        ffffffc000c610f8: 7273 696f 6e20 342e 392e 782d 676f 6f67  rsion 4.9.x-goog
        ffffffc000c61108: 6c65 2032 3031 3430 3832 3720 2870 7265  le 20140827 (pre
        ffffffc000c61118: 7265 6c65 6173 6529 2028 4743 4329 2029  release) (GCC) )
        """
        import StringIO
        sio = StringIO.StringIO()
        address = self.resolve_virt(addr_or_name)
        parser_util.xxd(
            address,
            [self.read_byte(address + i, virtual=virtual) or 0
             for i in xrange(length)],
            file_object=sio)
        ret = sio.getvalue()
        sio.close()
        return ret

    def per_cpu_offset(self, cpu):
        per_cpu_offset_addr = self.address_of('__per_cpu_offset')
        if per_cpu_offset_addr is None:
            return 0
        per_cpu_offset_addr_indexed = self.array_index(
            per_cpu_offset_addr, 'unsigned long', cpu)
        return self.read_word(per_cpu_offset_addr_indexed)

    def get_num_cpus(self):
        cpu_present_bits_addr = self.address_of('cpu_present_bits')
        cpu_present_bits = self.read_word(cpu_present_bits_addr)
        return bin(cpu_present_bits).count('1')

    def iter_cpus(self):
        return xrange(self.get_num_cpus())

    def thread_saved_field_common_32(self, task, reg_offset):
        thread_info = self.read_word(task + self.field_offset('struct task_struct', 'stack'))
        cpu_context_offset = self.field_offset('struct thread_info', 'cpu_context')
        val = self.read_word(thread_info + cpu_context_offset + reg_offset)
        return val

    def thread_saved_field_common_64(self, task, reg_offset):
        thread_offset = self.field_offset('struct task_struct', 'thread')
        cpu_context_offset = self.field_offset('struct thread_struct', 'cpu_context')
        val = self.read_word(task + thread_offset + cpu_context_offset + reg_offset)
        return val

    def thread_saved_pc(self, task):
        if self.arm64:
            return self.thread_saved_field_common_64(task, self.field_offset('struct cpu_context', 'pc'))
        else:
            return self.thread_saved_field_common_32(task, self.field_offset('struct cpu_context_save', 'pc'))

    def thread_saved_sp(self, task):
        if self.arm64:
            return self.thread_saved_field_common_64(task, self.field_offset('struct cpu_context', 'sp'))
        else:
            return self.thread_saved_field_common_32(task, self.field_offset('struct cpu_context_save', 'sp'))

    def thread_saved_fp(self, task):
        if self.arm64:
            return self.thread_saved_field_common_64(task, self.field_offset('struct cpu_context', 'fp'))
        else:
            return self.thread_saved_field_common_32(task, self.field_offset('struct cpu_context_save', 'fp'))
