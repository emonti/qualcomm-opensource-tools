# Copyright (c) 2012-2013, The Linux Foundation. All rights reserved.
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
from tempfile import NamedTemporaryFile

import gdbmi
from print_out import print_out_str
from mmu import Armv7MMU, Armv7LPAEMMU

FP = 11
SP = 13
LR = 14
PC = 15
THREAD_SIZE = 8192

HARDWARE_ID_IDX = 0
MEMORY_START_IDX = 1
PHYS_OFFSET_IDX = 2
WATCHDOG_BARK_OFFSET_IDX = 3
IMEM_START_IDX = 4
CPU_TYPE = 5
IMEM_FILENAME = 6
VERSION_COMPARE = 7

smem_offsets = [
    0,  # 8960/9x15 family and earlier
    0x0FA00000,  # 8974
    0x00100000,
    0x0D900000,  # 8610
    0x01100000,  # 9635
]

hw_ids = [
    (8660, 0x40000000, 0x40200000, 0x2a05f658,
     0x2a05f000, 'SCORPION', 'IMEM_C.BIN', None),
    (8960, 0x80000000, 0x80200000, 0x2a03f658,
     0x2a03f000, 'KRAIT',    'IMEM_C.BIN', None),
    (8064, 0x80000000, 0x80200000, 0x2a03f658,
     0x2a03f000, 'KRAIT',    'IMEM_C.BIN', None),
    (9615, 0x40000000, 0x40800000, 0x0,
     0x0,        'CORTEXA5', None,         None),
    (8974, 0x0,        0x0,        0xfe805658,
     0xfe800000, 'KRAIT',    'OCIMEM.BIN', None),
    (9625, 0x0,        0x00200000, 0xfc42b658,
     0xfc428000, 'CORTEXA5', 'MSGRAM.BIN', 1),
    (9625, 0x0,        0x00200000, 0xfe805658,
     0xfe800000, 'CORTEXA5', 'OCIMEM.BIN', 2),
    (8625, 0x0,        0x00200000, 0x0,
     0x0,        'SCORPION',  None,        None),
    (8226, 0x0,        0x00000000, 0xfe805658,
     0xfe800000, 'CORTEXA7', 'OCIMEM.BIN', None),
    (8610, 0x0,        0x00000000, 0xfe805658,
     0xfe800000, 'CORTEXA7', 'OCIMEM.BIN', None),
    (8084, 0x0,        0x0,        0xfe805658,
     0xfe800000, 'KRAIT',    'OCIMEM.BIN', None),
    (9635, 0x0,        0x00000000, 0xfe805658,
     0xfe800000, 'CORTEXA7', 'OCIMEM.BIN', None),
    (8092, 0x0,        0x0,        0xfe805658,
     0xfe800000, 'KRAIT',    'OCIMEM.BIN', None),
]

MSM_CPU_UNKNOWN = 0
MSM_CPU_7X01 = -1
MSM_CPU_7X25 = -1
MSM_CPU_7X27 = -1
MSM_CPU_8X50 = -1
MSM_CPU_8X50A = -1
MSM_CPU_7X30 = -1
MSM_CPU_8X55 = -1
MSM_CPU_8X60 = 8660
MSM_CPU_8960 = 8960
MSM_CPU_8960AB = 8960
MSM_CPU_7X27A = 8625
FSM_CPU_9XXX = -1
MSM_CPU_7X25A = 8625
MSM_CPU_7X25AA = 8625
MSM_CPU_7X25AB = 8625
MSM_CPU_8064 = 8064
MSM_CPU_8064AB = 8064
MSM_CPU_8930 = 8960
MSM_CPU_8930AA = 8960
MSM_CPU_8930AB = 8960
MSM_CPU_7X27AA = -1
MSM_CPU_9615 = 9615
MSM_CPU_8974 = 8974
MSM_CPU_8974PRO_AA = 8974
MSM_CPU_8974PRO_AB = 8974
MSM_CPU_8974PRO_AC = 8974
MSM_CPU_8627 = 8960
MSM_CPU_8625 = 9615
MSM_CPU_9625 = 9625
MSM_CPU_8226 = 8226
MSM_CPU_8610 = 8610
MSM_CPU_8084 = 8084
MSM_CPU_KRYPTON = 9635
MSM_CPU_8092 = 8092

    # id, cpu, cpuname
cpu_of_id = [
    # 7x01 IDs
    (1,  MSM_CPU_7X01, 'MSM_CPU_7X01'),
    (16, MSM_CPU_7X01, 'MSM_CPU_7X01'),
    (17, MSM_CPU_7X01, 'MSM_CPU_7X01'),
    (18, MSM_CPU_7X01, 'MSM_CPU_7X01'),
    (19, MSM_CPU_7X01, 'MSM_CPU_7X01'),
    (23, MSM_CPU_7X01, 'MSM_CPU_7X01'),
    (25, MSM_CPU_7X01, 'MSM_CPU_7X01'),
    (26, MSM_CPU_7X01, 'MSM_CPU_7X01'),
    (32, MSM_CPU_7X01, 'MSM_CPU_7X01'),
    (33, MSM_CPU_7X01, 'MSM_CPU_7X01'),
    (34, MSM_CPU_7X01, 'MSM_CPU_7X01'),
    (35, MSM_CPU_7X01, 'MSM_CPU_7X01'),

    # 7x25 IDs
    (20, MSM_CPU_7X25, 'MSM_CPU_7X25'),
    (21, MSM_CPU_7X25, 'MSM_CPU_7X25'),  # 7225
    (24, MSM_CPU_7X25, 'MSM_CPU_7X25'),  # 7525
    (27, MSM_CPU_7X25, 'MSM_CPU_7X25'),  # 7625
    (39, MSM_CPU_7X25, 'MSM_CPU_7X25'),
    (40, MSM_CPU_7X25, 'MSM_CPU_7X25'),
    (41, MSM_CPU_7X25, 'MSM_CPU_7X25'),
    (42, MSM_CPU_7X25, 'MSM_CPU_7X25'),
    (62, MSM_CPU_7X25, 'MSM_CPU_7X25'),  # 7625-1
    (63, MSM_CPU_7X25, 'MSM_CPU_7X25'),  # 7225-1
    (66, MSM_CPU_7X25, 'MSM_CPU_7X25'),  # 7225-2


    # 7x27 IDs
    (43, MSM_CPU_7X27, 'MSM_CPU_7X27'),
    (44, MSM_CPU_7X27, 'MSM_CPU_7X27'),
    (61, MSM_CPU_7X27, 'MSM_CPU_7X27'),
    (67, MSM_CPU_7X27, 'MSM_CPU_7X27'),  # 7227-1
    (68, MSM_CPU_7X27, 'MSM_CPU_7X27'),  # 7627-1
    (69, MSM_CPU_7X27, 'MSM_CPU_7X27'),  # 7627-2


    # 8x50 IDs
    (30, MSM_CPU_8X50, 'MSM_CPU_8X50'),
    (36, MSM_CPU_8X50, 'MSM_CPU_8X50'),
    (37, MSM_CPU_8X50, 'MSM_CPU_8X50'),
    (38, MSM_CPU_8X50, 'MSM_CPU_8X50'),

    # 7x30 IDs
    (59, MSM_CPU_7X30, 'MSM_CPU_7X30'),
    (60, MSM_CPU_7X30, 'MSM_CPU_7X30'),

    # 8x55 IDs
    (74, MSM_CPU_8X55, 'MSM_CPU_8X55'),
    (75, MSM_CPU_8X55, 'MSM_CPU_8X55'),
    (85, MSM_CPU_8X55, 'MSM_CPU_8X55'),

    # 8x60 IDs
    (70, MSM_CPU_8X60, 'MSM_CPU_8X60'),
    (71, MSM_CPU_8X60, 'MSM_CPU_8X60'),
    (86, MSM_CPU_8X60, 'MSM_CPU_8X60'),

    # 8960 IDs
    (87, MSM_CPU_8960, 'MSM_CPU_8960'),

    # 7x25A IDs
    (88, MSM_CPU_7X25A, 'MSM_CPU_7X25A'),
    (89, MSM_CPU_7X25A, 'MSM_CPU_7X25A'),
    (96, MSM_CPU_7X25A, 'MSM_CPU_7X25A'),

    # 7x27A IDs
    (90, MSM_CPU_7X27A, 'MSM_CPU_7X27A'),
    (91, MSM_CPU_7X27A, 'MSM_CPU_7X27A'),
    (92, MSM_CPU_7X27A, 'MSM_CPU_7X27A'),
    (97, MSM_CPU_7X27A, 'MSM_CPU_7X27A'),

    # FSM9xxx ID
    (94, FSM_CPU_9XXX, 'FSM_CPU_9XXX'),
    (95, FSM_CPU_9XXX, 'FSM_CPU_9XXX'),

    #  7x25AA ID
    (98, MSM_CPU_7X25AA, 'MSM_CPU_7X25AA'),
    (99, MSM_CPU_7X25AA, 'MSM_CPU_7X25AA'),
    (100, MSM_CPU_7X25AA, 'MSM_CPU_7X25AA'),

    #  7x27AA ID
    (101, MSM_CPU_7X27AA, 'MSM_CPU_7X27AA'),
    (102, MSM_CPU_7X27AA, 'MSM_CPU_7X27AA'),
    (103, MSM_CPU_7X27AA, 'MSM_CPU_7X27AA'),

    # 9x15 ID
    (104, MSM_CPU_9615, 'MSM_CPU_9615'),
    (105, MSM_CPU_9615, 'MSM_CPU_9615'),
    (106, MSM_CPU_9615, 'MSM_CPU_9615'),
    (107, MSM_CPU_9615, 'MSM_CPU_9615'),

    # 8064 IDs
    (109, MSM_CPU_8064, 'MSM_CPU_8064'),
    (130, MSM_CPU_8064, 'MSM_CPU_8064'),

    # 8930 IDs
    (116, MSM_CPU_8930, 'MSM_CPU_8930'),
    (117, MSM_CPU_8930, 'MSM_CPU_8930'),
    (118, MSM_CPU_8930, 'MSM_CPU_8930'),
    (119, MSM_CPU_8930, 'MSM_CPU_8930'),

    # 8627 IDs
    (120, MSM_CPU_8627, 'MSM_CPU_8627'),
    (121, MSM_CPU_8627, 'MSM_CPU_8627'),

    # 8660A ID
    (122, MSM_CPU_8960, 'MSM_CPU_8960'),

    # 8260A ID
    (123, MSM_CPU_8960, '8260A'),

    # 8060A ID
    (124, MSM_CPU_8960, '8060A'),

    # Copper IDs
    (126, MSM_CPU_8974, 'MSM_CPU_8974'),
    (184, MSM_CPU_8974, 'MSM_CPU_8974'),
    (185, MSM_CPU_8974, 'MSM_CPU_8974'),
    (186, MSM_CPU_8974, 'MSM_CPU_8974'),

    # 8974 PRO AA IDs
    (208, MSM_CPU_8974PRO_AA, 'MSM_CPU_8974PRO_AA'),
    (211, MSM_CPU_8974PRO_AA, 'MSM_CPU_8974PRO_AA'),
    (214, MSM_CPU_8974PRO_AA, 'MSM_CPU_8974PRO_AA'),
    (217, MSM_CPU_8974PRO_AA, 'MSM_CPU_8974PRO_AA'),

    # 8974 PRO AB IDs
    (209, MSM_CPU_8974PRO_AB, 'MSM_CPU_8974PRO_AB'),
    (212, MSM_CPU_8974PRO_AB, 'MSM_CPU_8974PRO_AB'),
    (215, MSM_CPU_8974PRO_AB, 'MSM_CPU_8974PRO_AB'),
    (218, MSM_CPU_8974PRO_AB, 'MSM_CPU_8974PRO_AB'),

    # 8974 PRO AC IDs
    (194, MSM_CPU_8974PRO_AC, 'MSM_CPU_8974PRO_AC'),
    (210, MSM_CPU_8974PRO_AC, 'MSM_CPU_8974PRO_AC'),
    (213, MSM_CPU_8974PRO_AC, 'MSM_CPU_8974PRO_AC'),
    (216, MSM_CPU_8974PRO_AC, 'MSM_CPU_8974PRO_AC'),

    # 8625 IDs
    (127, MSM_CPU_8625, 'MSM_CPU_8625'),
    (128, MSM_CPU_8625, 'MSM_CPU_8625'),
    (129, MSM_CPU_8625, 'MSM_CPU_8625'),

    # 8064 MPQ ID */
    (130, MSM_CPU_8064, 'MSM_CPU_8064'),

    # 7x25AB IDs
    (131, MSM_CPU_7X25AB, 'MSM_CPU_7X25AB'),
    (132, MSM_CPU_7X25AB, 'MSM_CPU_7X25AB'),
    (133, MSM_CPU_7X25AB, 'MSM_CPU_7X25AB'),
    (135, MSM_CPU_7X25AB, 'MSM_CPU_7X25AB'),

    # 9625 IDs
    (134, MSM_CPU_9625, 'MSM_CPU_9625'),
    (148, MSM_CPU_9625, 'MSM_CPU_9625'),
    (149, MSM_CPU_9625, 'MSM_CPU_9625'),
    (150, MSM_CPU_9625, 'MSM_CPU_9625'),
    (151, MSM_CPU_9625, 'MSM_CPU_9625'),
    (152, MSM_CPU_9625, 'MSM_CPU_9625'),
    (173, MSM_CPU_9625, 'MSM_CPU_9625'),
    (174, MSM_CPU_9625, 'MSM_CPU_9625'),
    (175, MSM_CPU_9625, 'MSM_CPU_9625'),

    # 8960AB IDs
    (138, MSM_CPU_8960AB, 'MSM_CPU_8960AB'),
    (139, MSM_CPU_8960AB, 'MSM_CPU_8960AB'),
    (140, MSM_CPU_8960AB, 'MSM_CPU_8960AB'),
    (141, MSM_CPU_8960AB, 'MSM_CPU_8960AB'),

    # 8930AA IDs
    (142, MSM_CPU_8930AA, 'MSM_CPU_8930AA'),
    (143, MSM_CPU_8930AA, 'MSM_CPU_8930AA'),
    (144, MSM_CPU_8930AA, 'MSM_CPU_8930AA'),

    # 8226 IDx
    (145, MSM_CPU_8226, 'MSM_CPU_8226'),
    (158, MSM_CPU_8226, 'MSM_CPU_8226'),
    (159, MSM_CPU_8226, 'MSM_CPU_8226'),
    (198, MSM_CPU_8226, 'MSM_CPU_8226'),
    (199, MSM_CPU_8226, 'MSM_CPU_8226'),
    (200, MSM_CPU_8226, 'MSM_CPU_8226'),
    (205, MSM_CPU_8226, 'MSM_CPU_8226'),
    (219, MSM_CPU_8226, 'MSM_CPU_8226'),
    (220, MSM_CPU_8226, 'MSM_CPU_8226'),
    (221, MSM_CPU_8226, 'MSM_CPU_8226'),
    (222, MSM_CPU_8226, 'MSM_CPU_8226'),
    (223, MSM_CPU_8226, 'MSM_CPU_8226'),
    (224, MSM_CPU_8226, 'MSM_CPU_8226'),

    # 8610 IDx
    (147, MSM_CPU_8610, 'MSM_CPU_8610'),
    (161, MSM_CPU_8610, 'MSM_CPU_8610'),
    (162, MSM_CPU_8610, 'MSM_CPU_8610'),
    (163, MSM_CPU_8610, 'MSM_CPU_8610'),
    (164, MSM_CPU_8610, 'MSM_CPU_8610'),
    (165, MSM_CPU_8610, 'MSM_CPU_8610'),
    (166, MSM_CPU_8610, 'MSM_CPU_8610'),

    # 8064AB IDs
    (153, MSM_CPU_8064AB, 'MSM_CPU_8064AB'),

    # 8930AB IDs
    (154, MSM_CPU_8930AB, 'MSM_CPU_8930AB'),
    (155, MSM_CPU_8930AB, 'MSM_CPU_8930AB'),
    (156, MSM_CPU_8930AB, 'MSM_CPU_8930AB'),
    (157, MSM_CPU_8930AB, 'MSM_CPU_8930AB'),

    (160, MSM_CPU_8930AA, 'MSM_CPU_8930AA'),

    # 8084 IDs
    (178, MSM_CPU_8084, 'MSM_CPU_8084'),

    # 9635 IDs
    (187, MSM_CPU_KRYPTON, 'MSM_CPU_KRYPTON'),
    (227, MSM_CPU_KRYPTON, 'MSM_CPU_KRYPTON'),
    (228, MSM_CPU_KRYPTON, 'MSM_CPU_KRYPTON'),
    (229, MSM_CPU_KRYPTON, 'MSM_CPU_KRYPTON'),
    (230, MSM_CPU_KRYPTON, 'MSM_CPU_KRYPTON'),
    (231, MSM_CPU_KRYPTON, 'MSM_CPU_KRYPTON'),

    (146, MSM_CPU_8092, 'MSM_CPU_8092'),

    # Uninitialized IDs are not known to run Linux.
    # MSM_CPU_UNKNOWN is set to 0 to ensure these IDs are
    # considered as unknown CPU.
]

socinfo_v1 = functools.reduce(lambda x, y: x + y, [
    'I',  # format
    'I',  # id
    'I',  # version
])

launch_config_str = 'OS=\nID=T32_1000002\nTMP=C:\\TEMP\nSYS=C:\\T32\nHELP=C:\\T32\\pdf\n\nPBI=SIM\nSCREEN=\nFONT=SMALL\nHEADER=Trace32-ScorpionSimulator\nPRINTER=WINDOWS'

# The smem code is very stable and unlikely to go away or be changed.
# Rather than go through the hassel of parsing the id through gdb,
# just hard code it

SMEM_HW_SW_BUILD_ID = 0x89
BUILD_ID_LENGTH = 32

first_mem_file_names = ['EBICS0.BIN',
                        'EBI1.BIN', 'DDRCS0.BIN', 'ebi1_cs0.bin', 'DDRCS0_0.BIN']
extra_mem_file_names = ['EBI1CS1.BIN', 'DDRCS1.BIN', 'ebi1_cs1.bin', 'DDRCS0_1.BIN']


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
            start = ramdump.addr_lookup('__start_unwind_idx')
            end = ramdump.addr_lookup('__stop_unwind_idx')
            if (start is None) or (end is None):
                print_out_str('!!! Could not lookup unwinding information')
                return None
            # addresses
            self.start_idx = start
            self.stop_idx = end
            self.unwind_table = []
            self.ramdump = ramdump
            i = 0
            for addr in range(start, end, 8):
                (a, b) = ramdump.read_string(addr, '<II')
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

        def unwind_frame_generic(self, frame):
            high = 0
            fp = frame.fp

            low = frame.sp
            mask = (THREAD_SIZE) - 1

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

        def unwind_exec_insn(self, ctrl, trace=False):
            insn = self.unwind_get_byte(ctrl)

            if ((insn & 0xc0) == 0x00):
                ctrl.vrs[SP] += ((insn & 0x3f) << 2) + 4
                if trace:
                    print_out_str(
                        '    add {0} to stack'.format(((insn & 0x3f) << 2) + 4))
            elif ((insn & 0xc0) == 0x40):
                ctrl.vrs[SP] -= ((insn & 0x3f) << 2) + 4
                if trace:
                    print_out_str(
                        '    subtract {0} from stack'.format(((insn & 0x3f) << 2) + 4))
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
                        if trace:
                            print_out_str(
                                '    pop r{0} from stack'.format(reg))
                        if ctrl.vrs[reg] is None:
                            return -1
                        vsp += 4
                    mask >>= 1
                    reg += 1
                if not load_sp:
                    ctrl.vrs[SP] = vsp

            elif ((insn & 0xf0) == 0x90 and (insn & 0x0d) != 0x0d):
                if trace:
                    print_out_str(
                        '    set SP with the value from {0}'.format(insn & 0x0f))
                ctrl.vrs[SP] = ctrl.vrs[insn & 0x0f]
            elif ((insn & 0xf0) == 0xa0):
                vsp = ctrl.vrs[SP]
                a = list(range(4, 4 + (insn & 7)))
                a.append(4 + (insn & 7))
                # pop R4-R[4+bbb] */
                for reg in (a):
                    ctrl.vrs[reg] = self.ramdump.read_word(vsp)
                    if trace:
                        print_out_str('    pop r{0} from stack'.format(reg))

                    if ctrl.vrs[reg] is None:
                        return -1
                    vsp += 4
                if (insn & 0x80):
                    if trace:
                        print_out_str('    set LR from the stack')
                    ctrl.vrs[14] = self.ramdump.read_word(vsp)
                    if ctrl.vrs[14] is None:
                        return -1
                    vsp += 4
                ctrl.vrs[SP] = vsp
            elif (insn == 0xb0):
                if trace:
                    print_out_str('    set pc = lr')
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
                        if trace:
                            print_out_str(
                                '    pop r{0} from stack'.format(reg))
                        if ctrl.vrs[reg] is None:
                            return -1
                        vsp += 4
                    mask >>= 1
                    reg += 1
                ctrl.vrs[SP] = vsp
            elif (insn == 0xb2):
                uleb128 = self.unwind_get_byte(ctrl)
                if trace:
                    print_out_str(
                        '    Adjust sp by {0}'.format(0x204 + (uleb128 << 2)))

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

        def unwind_frame(self, frame, trace=False):
            low = frame.sp
            high = ((low + (THREAD_SIZE - 1)) & ~(THREAD_SIZE - 1)) + \
                THREAD_SIZE
            idx = self.search_idx(frame.pc)

            if (idx is None):
                if trace:
                    print_out_str("can't find %x" % frame.pc)
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
                urc = self.unwind_exec_insn(ctrl, trace)
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

        def unwind_backtrace(self, sp, fp, pc, lr, extra_str='', out_file=None, trace=False):
            offset = 0
            frame = self.Stackframe(fp, sp, lr, pc)
            frame.fp = fp
            frame.sp = sp
            frame.lr = lr
            frame.pc = pc

            while True:
                where = frame.pc
                offset = 0

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

                urc = self.unwind_frame(frame, trace)
                if urc < 0:
                    break

    def __init__(self, vmlinux_path, nm_path, gdb_path, ebi, file_path, phys_offset, outdir, hw_id=None, hw_version=None):
        self.ebi_files = []
        self.phys_offset = None
        self.tz_start = 0
        self.ebi_start = 0
        self.cpu_type = None
        self.hw_id = hw_id
        self.hw_version = hw_version
        self.offset_table = []
        self.vmlinux = vmlinux_path
        self.nm_path = nm_path
        self.gdb_path = gdb_path
        self.outdir = outdir
        self.imem_fname = None
        self.gdbmi = gdbmi.GdbMI(self.gdb_path, self.vmlinux)
        self.gdbmi.open()
        if ebi is not None:
            # TODO sanity check to make sure the memory regions don't overlap
            for file_path, start, end in ebi:
                fd = open(file_path, 'rb')
                if not fd:
                    print_out_str(
                        'Could not open {0}. Will not be part of dump'.format(file_path))
                    continue
                self.ebi_files.append((fd, start, end, file_path))
        else:
            if not self.auto_parse(file_path):
                return None
        if self.ebi_start == 0:
            self.ebi_start = self.ebi_files[0][1]
        if self.phys_offset is None:
            self.get_hw_id()
        if phys_offset is not None:
            print_out_str(
                '[!!!] Phys offset was set to {0:x}'.format(phys_offset))
            self.phys_offset = phys_offset
        self.lookup_table = []
        self.page_offset = 0xc0000000
        self.config = []
        self.setup_symbol_tables()

        # The address of swapper_pg_dir can be used to determine
        # whether or not we're running with LPAE enabled since an
        # extra 4k is needed for LPAE. If it's 0x5000 below
        # PAGE_OFFSET + TEXT_OFFSET then we know we're using LPAE. For
        # non-LPAE it should be 0x4000 below PAGE_OFFSET + TEXT_OFFSET
        swapper_pg_dir_addr = self.addr_lookup('swapper_pg_dir')
        kernel_text_offset = 0x8000
        pg_dir_size = kernel_text_offset - \
            (swapper_pg_dir_addr - self.page_offset)
        if pg_dir_size == 0x4000:
            print_out_str('Using non-LPAE MMU')
            self.mmu = Armv7MMU(self)
        elif pg_dir_size == 0x5000:
            print_out_str('Using LPAE MMU')
            self.mmu = Armv7LPAEMMU(self)
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
        kconfig_addr = self.addr_lookup('kernel_config_data')
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
        return True

    def is_config_defined(self, config):
        s = config + '=y'
        return s in self.config

    def get_version(self):
        banner_addr = self.addr_lookup('linux_banner')
        if banner_addr is not None:
            # Don't try virt to phys yet, compute manually
            banner_addr = banner_addr - 0xc0000000 + self.phys_offset
            b = self.read_cstring(banner_addr, 256, False)
            if b is None:
                print_out_str('!!! Could not read banner address!')
                return False
            v = re.search('Linux version (\d{0,2}\.\d{0,2}\.\d{0,2})', b)
            if v is None:
                print_out_str('!!! Could not match version! {0}'.format(b))
                return False
            self.version = v.group(1)
            print_out_str('Linux Banner: ' + b.rstrip())
            print_out_str('version = {0}'.format(self.version))
            return True
        else:
            print_out_str('!!! Could not lookup banner address')
            return False

    def print_command_line(self):
        command_addr = self.addr_lookup('saved_command_line')
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
        if not self.get_hw_id():
            return False
        first_mem_end = self.ebi_start + os.path.getsize(first_mem_path) - 1
        self.ebi_files = [
            (first_mem, self.ebi_start, first_mem_end, first_mem_path)]
        print_out_str(
            'Adding {0} {1:x}--{2:x}'.format(first_mem_path, self.ebi_start, first_mem_end))

        for f in extra_mem_file_names:
            extra_path = file_path + '/' + f

            if os.path.exists(extra_path):
                extra = open(extra_path, 'rb')
                extra_start = self.ebi_start + os.path.getsize(first_mem_path)
                extra_end = extra_start + os.path.getsize(extra_path) - 1
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

    # TODO support linux launcher, for when linux T32 actually happens
    def create_t32_launcher(self):
        out_path = self.outdir
        launch_config = open(out_path + '/t32_config.t32', 'wb')
        launch_config.write(launch_config_str.encode('ascii', 'ignore'))
        launch_config.close()

        startup_script = open(out_path + '/t32_startup_script.cmm', 'wb')

        startup_script.write(
            'sys.cpu {0}\n'.format(self.cpu_type).encode('ascii', 'ignore'))
        startup_script.write('sys.up\n'.encode('ascii', 'ignore'))

        for ram in self.ebi_files:
            ebi_path = os.path.abspath(ram[3])
            startup_script.write('data.load.binary {0} 0x{1:x}\n'.format(
                ebi_path, ram[1]).encode('ascii', 'ignore'))
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
        startup_script.write(
            'task.config c:\\t32\\demo\\arm\\kernel\\linux\\linux.t32\n'.encode('ascii', 'ignore'))
        startup_script.write(
            'menu.reprogram c:\\t32\\demo\\arm\\kernel\\linux\\linux.men\n'.encode('ascii', 'ignore'))
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

        t32_bat = open(out_path + '/launch_t32.bat', 'wb')
        t32_bat.write(('start c:\\t32\\t32MARM.exe -c ' + out_path + '/t32_config.t32, ' +
                      out_path + '/t32_startup_script.cmm').encode('ascii', 'ignore'))
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

    def find_hw_id(self, socinfo_id, version):
        if self.hw_version is not None:
            version = self.hw_version
        for cpuid in cpu_of_id:
            if socinfo_id == cpuid[0]:
                for hwid in hw_ids:
                    if cpuid[1] == hwid[HARDWARE_ID_IDX]:
                        if hwid[VERSION_COMPARE] is not None and hwid[VERSION_COMPARE] != version:
                            continue

                        return hwid
        return None

    def get_hw_id(self):
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
        socinfo_format = -1
        socinfo_id = -1
        socinfo_version = 0
        socinfo_build_id = 'DUMMY'
        hwid = None

        if (self.hw_id is None):
            for smem_offset in smem_offsets:
                socinfo_start_addr = self.ebi_files[0][
                    1] + smem_offset + heap_toc_offset + smem_heap_entry_size * SMEM_HW_SW_BUILD_ID + offset_offset
                soc_start = self.read_word(socinfo_start_addr, False)
                if soc_start is None:
                    continue

                socinfo_start = self.ebi_files[0][1] + smem_offset + soc_start

                socinfo_format = self.read_word(socinfo_start, False)
                socinfo_id = self.read_word(socinfo_start + 4, False)
                socinfo_version = self.read_word(socinfo_start + 8, False)
                socinfo_build_id = self.read_cstring(
                    socinfo_start + 12, BUILD_ID_LENGTH, False)

                if socinfo_id is not None and socinfo_version is not None:
                    hwid = self.find_hw_id(socinfo_id, socinfo_version >> 16)
                if (hwid is not None):
                    break
            if (hwid is None):
                print_out_str('!!!! Could not find hardware')
                print_out_str("!!!! The SMEM didn't match anything")
                print_out_str(
                    '!!!! You can use --force-hardware to use a specific set of values')
                sys.exit(1)

        else:
            hwid = None
            for a in hw_ids:
                if self.hw_id == a[HARDWARE_ID_IDX] and self.hw_version == a[VERSION_COMPARE]:
                    print_out_str(
                        '!!! Hardware id found! The socinfo values given are bogus')
                    print_out_str('!!! Proceed with caution!')
                    hwid = a
                    break
            if hwid is None:
                print_out_str(
                    '!!! A bogus hardware id was specified: {0}'.format(self.hw_id))
                print_out_str(
                    '!!! Try passing one of these to --force-hardware.')
                print_out_str(
                    '!!! If a version is specified, pass the version with --force-version')
                for a in hw_ids:
                    if a[VERSION_COMPARE] is not None:
                        v = 'v{0}'.format(a[VERSION_COMPARE])
                    else:
                        v = ''
                    print_out_str(
                        '!!!    {0}{1}'.format(a[HARDWARE_ID_IDX], v))
                sys.exit(1)

        print_out_str('\nHardware match: {0}'.format(hwid[HARDWARE_ID_IDX]))
        print_out_str('Socinfo id = {0}, version {1:x}.{2:x}'.format(
            socinfo_id, socinfo_version >> 16, socinfo_version & 0xFFFF))
        print_out_str('Socinfo build = {0}'.format(socinfo_build_id))
        print_out_str(
            'Now setting phys_offset to {0:x}'.format(hwid[PHYS_OFFSET_IDX]))
        print_out_str(
            'TZ address: {0:x}'.format(hwid[WATCHDOG_BARK_OFFSET_IDX]))
        self.phys_offset = hwid[PHYS_OFFSET_IDX]
        self.tz_addr = hwid[WATCHDOG_BARK_OFFSET_IDX]
        self.ebi_start = hwid[MEMORY_START_IDX]
        self.tz_start = hwid[IMEM_START_IDX]
        self.hw_id = hwid[HARDWARE_ID_IDX]
        self.cpu_type = hwid[CPU_TYPE]
        self.imem_fname = hwid[IMEM_FILENAME]
        return True

    def virt_to_phys(self, virt):
        return self.mmu.virt_to_phys(virt)

    def setup_symbol_tables(self):
        stream = os.popen(self.nm_path + ' -n ' + self.vmlinux)
        symbols = stream.readlines()
        for line in symbols:
            s = line.split(' ')
            if len(s) == 3:
                self.lookup_table.append((int(s[0], 16), s[2].rstrip()))
        stream.close()

    def addr_lookup(self, symbol):
        try:
            return self.gdbmi.address_of(symbol)
        except gdbmi.GdbMIException:
            pass

    def symbol_lookup(self, addr):
        try:
            return self.gdbmi.symbol_at(addr).symbol
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

                my_arr_addr = dump.addr_lookup("my_arr")
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

    def read_physical(self, addr, length, trace=False):
        ebi = (-1, -1, -1)
        for a in self.ebi_files:
            fd, start, end, path = a
            if addr >= start and addr <= end:
                ebi = a
                break
        if ebi[0] is -1:
            return None
        if trace:
            print_out_str('reading from {0}'.format(ebi[0]))
            print_out_str('start = {0:x}'.format(ebi[1]))
            print_out_str('end = {0:x}'.format(ebi[2]))
            print_out_str('length = {0:x}'.format(length))
        offset = addr - ebi[1]
        if trace:
            print_out_str('offset = {0:x}'.format(offset))
        ebi[0].seek(offset)
        a = ebi[0].read(length)
        if trace:
            print_out_str('result = {0}'.format(a))
            print_out_str('lenght = {0}'.format(len(a)))
        return a

    def read_dword(self, address, virtual=True, trace=False, cpu=None):
        if trace:
            print_out_str('reading {0:x}'.format(address))
        s = self.read_string(address, '<Q', virtual, trace, cpu)
        if s is None:
            return None
        else:
            return s[0]

    # returns the 4 bytes read from the specified virtual address
    # return None on error
    def read_word(self, address, virtual=True, trace=False, cpu=None):
        if trace:
            print_out_str('reading {0:x}'.format(address))
        s = self.read_string(address, '<I', virtual, trace, cpu)
        if s is None:
            return None
        else:
            return s[0]

    def read_halfword(self, address, virtual=True, trace=False, cpu=None):
        if trace:
            print_out_str('reading {0:x}'.format(address))
        s = self.read_string(address, '<H', virtual, trace, cpu)
        if s is None:
            return None
        else:
            return s[0]

    def read_byte(self, address, virtual=True, trace=False, cpu=None):
        if trace:
            print_out_str('reading {0:x}'.format(address))
        s = self.read_string(address, '<B', virtual, trace, cpu)
        if s is None:
            return None
        else:
            return s[0]

    def read_cstring(self, address, max_length, virtual=True, cpu=None):
        addr = address
        if virtual:
            if cpu is not None:
                address += pcpu_offset + self.per_cpu_offset(cpu)
            addr = self.virt_to_phys(address)
        s = self.read_physical(addr, max_length)
        if s is not None:
            a = s.decode('ascii', 'ignore')
            return a.split('\0')[0]
        else:
            return s

    # returns a tuple of the result from reading from the specified fromat string
    # return None on failure
    def read_string(self, address, format_string, virtual=True, trace=False, cpu=None):
        addr = address
        per_cpu_string = ''
        if virtual:
            if cpu is not None:
                pcpu_offset = self.per_cpu_offset(cpu)
                address += pcpu_offset
                per_cpu_string = ' with per-cpu offset of ' + hex(pcpu_offset)
            addr = self.virt_to_phys(address)
        if trace:
            print_out_str('reading from phys {0:x}{1}'.format(addr,
                                                              per_cpu_string))
        s = self.read_physical(addr, struct.calcsize(format_string), trace)
        if (s is None) or (s == ''):
            if trace:
                print_out_str(
                    'address {0:x} failed hard core (v {1} t{2})'.format(addr, virtual, trace))
            return None
        return struct.unpack(format_string, s)

    def per_cpu_offset(self, cpu):
        per_cpu_offset_addr = self.addr_lookup('__per_cpu_offset')
        if per_cpu_offset_addr is None:
            return 0
        per_cpu_offset_addr_indexed = self.array_index(
            per_cpu_offset_addr, 'unsigned long', cpu)
        return self.read_word(per_cpu_offset_addr_indexed)

    def get_num_cpus(self):
        cpu_present_bits_addr = self.addr_lookup('cpu_present_bits')
        cpu_present_bits = self.read_word(cpu_present_bits_addr)
        return bin(cpu_present_bits).count('1')

    def iter_cpus(self):
        return xrange(self.get_num_cpus())
