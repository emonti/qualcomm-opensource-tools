# Copyright (c) 2012-2014, The Linux Foundation. All rights reserved.
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
import re
from print_out import print_out_str

# (name from tz dump, corresponding T32 register, whether or not to print_out_str (the function name))
sysdbg_cpu64_register_names_default = [
    ('x0', 'x0', False),
    ('x1', 'x1', False),
    ('x2', 'x2', False),
    ('x3', 'x3', False),
    ('x4', 'x4', False),
    ('x5', 'x5', False),
    ('x6', 'x6', False),
    ('x7', 'x7', False),
    ('x8', 'x8', False),
    ('x9', 'x9', False),
    ('x10', 'x10', False),
    ('x11', 'x11', False),
    ('x12', 'x12', False),
    ('x13', 'x13', False),
    ('x14', 'x14', False),
    ('x15', 'x15', False),
    ('x16', 'x16', False),
    ('x17', 'x17', False),
    ('x18', 'x18', False),
    ('x19', 'x19', False),
    ('x20', 'x20', False),
    ('x21', 'x21', False),
    ('x22', 'x22', False),
    ('x23', 'x23', False),
    ('x24', 'x24', False),
    ('x25', 'x25', False),
    ('x26', 'x26', False),
    ('x27', 'x27', False),
    ('x28', 'x28', False),
    ('x29', 'x29', False),
    ('x30', 'x30', True),
    ('pc', 'pc', True),
    ('currentEL', None, False),
    ('sp_el3', 'sp_el3', False),
    ('elr_el3', 'elr_el3', True),
    ('spsr_el3', 'spsr_el3', False),
    ('sp_el2', 'sp_el2', False),
    ('elr_el2', 'elr_el2', True),
    ('spsr_el2', 'spsr_el2', False),
    ('sp_el1', 'sp_el1', False),
    ('elr_el1', 'elr_el1', True),
    ('spsr_el1', 'spsr_el1', False),
    ('sp_el0', 'sp_el0', False),
    ('__reserved1', '__reserved1', False),
    ('__reserved2', '__reserved2', False),
    ('__reserved3', '__reserved3', False),
    ('__reserved4', '__reserved4', False),
]

sysdbg_cpu64_ctxt_regs_type_default = ''.join([
    'Q',  # x0
    'Q',  # x1
    'Q',  # x2
    'Q',  # x3
    'Q',  # x4
    'Q',  # x5
    'Q',  # x6
    'Q',  # x7
    'Q',  # x8
    'Q',  # x9
    'Q',  # x10
    'Q',  # x11
    'Q',  # x12
    'Q',  # x13
    'Q',  # x14
    'Q',  # x15
    'Q',  # x16
    'Q',  # x17
    'Q',  # x18
    'Q',  # x19
    'Q',  # x20
    'Q',  # x21
    'Q',  # x22
    'Q',  # x23
    'Q',  # x24
    'Q',  # x25
    'Q',  # x26
    'Q',  # x27
    'Q',  # x28
    'Q',  # x29
    'Q',  # x30
    'Q',  # pc
    'Q',  # currentEL
    'Q',  # sp_el3
    'Q',  # elr_el3
    'Q',  # spsr_el3
    'Q',  # sp_el2
    'Q',  # elr_el2
    'Q',  # spsr_el2
    'Q',  # sp_el1
    'Q',  # elr_el1
    'Q',  # spsr_el1
    'Q',  # sp_el0
    'Q',  # __reserved1
    'Q',  # __reserved2
    'Q',  # __reserved3
    'Q',  # __reserved4
])

sysdbg_cpu32_register_names_default = [
    ('r0', 'r0', False),
    ('r1', 'r1', False),
    ('r2', 'r2', False),
    ('r3', 'r3', False),
    ('r4', 'r4', False),
    ('r5', 'r5', False),
    ('r6', 'r6', False),
    ('r7', 'r7', False),
    ('r8', 'r8', False),
    ('r9', 'r9', False),
    ('r10', 'r10', False),
    ('r11', 'r11', False),
    ('r12', 'r12', False),
    ('r13_usr', 'r13_usr', False),
    ('r14_usr', 'r14_usr', False),
    ('r13_hyp', 'r13_hyp', False),
    ('r14_irq', 'r14_irq', True),
    ('r13_irq', 'r13_irq', False),
    ('r14_svc', 'r14_svc', True),
    ('r13_svc', 'r13_svc', False),
    ('r14_abt', 'r14_abt', True),
    ('r13_abt', 'r13_abt', False),
    ('r14_und', 'r14_und', True),
    ('r13_und', 'r13_und', False),
    ('r8_fiq', 'r8_fiq', False),
    ('r9_fiq', 'r9_fiq', False),
    ('r10_fiq', 'r10_fiq', False),
    ('r11_fiq', 'r11_fiq', False),
    ('r12_fiq', 'r12_fiq', False),
    ('r13_fiq', 'r13_fiq', False),
    ('r14_fiq', 'r14_fiq', True),
    ('pc', 'pc', True),
    ('cpsr', 'cpsr', False),
    ('r13_mon', 'r13_mon', False),
    ('r14_mon', 'r14_mon', True),
    ('r14_hyp', 'elr_hyp', True),
    ('_reserved', '_reserved', False),
    ('__reserved1', '__reserved1', False),
    ('__reserved2', '__reserved2', False),
    ('__reserved3', '__reserved3', False),
    ('__reserved4', '__reserved4', False),
]

sysdbg_cpu32_ctxt_regs_type_default = ''.join([
    'Q',  # r0
    'Q',  # r1
    'Q',  # r2
    'Q',  # r3
    'Q',  # r4
    'Q',  # r5
    'Q',  # r6
    'Q',  # r7
    'Q',  # r8
    'Q',  # r9
    'Q',  # r10
    'Q',  # r11
    'Q',  # r12
    'Q',  # r13_usr
    'Q',  # r14_usr
    'Q',  # r13_hyp
    'Q',  # r14_irq
    'Q',  # r13_irq
    'Q',  # r14_svc
    'Q',  # r13_svc
    'Q',  # r14_abt
    'Q',  # r13_abt
    'Q',  # r14_und
    'Q',  # r13_und
    'Q',  # r8_fiq
    'Q',  # r9_fiq
    'Q',  # r10_fiq
    'Q',  # r11_fiq
    'Q',  # r12_fiq
    'Q',  # r13_fiq
    'Q',  # r14_fiq
    'Q',  # pc
    'Q',  # cpsr
    'Q',  # r13_mon
    'Q',  # r14_mon
    'Q',  # r14_hyp
    'Q',  # _reserved
    'Q',  # __reserved1
    'Q',  # __reserved2
    'Q',  # __reserved3
    'Q',  # __reserved4
])

sysdbg_cpu64_register_names_v1_3 = [
    ('x0', 'x0', False),
    ('x1', 'x1', False),
    ('x2', 'x2', False),
    ('x3', 'x3', False),
    ('x4', 'x4', False),
    ('x5', 'x5', False),
    ('x6', 'x6', False),
    ('x7', 'x7', False),
    ('x8', 'x8', False),
    ('x9', 'x9', False),
    ('x10', 'x10', False),
    ('x11', 'x11', False),
    ('x12', 'x12', False),
    ('x13', 'x13', False),
    ('x14', 'x14', False),
    ('x15', 'x15', False),
    ('x16', 'x16', False),
    ('x17', 'x17', False),
    ('x18', 'x18', False),
    ('x19', 'x19', False),
    ('x20', 'x20', False),
    ('x21', 'x21', False),
    ('x22', 'x22', False),
    ('x23', 'x23', False),
    ('x24', 'x24', False),
    ('x25', 'x25', False),
    ('x26', 'x26', False),
    ('x27', 'x27', False),
    ('x28', 'x28', False),
    ('x29', 'x29', False),
    ('x30', 'x30', True),
    ('pc', 'pc', True),
    ('currentEL', None, False),
    ('sp_el3', 'sp_el3', False),
    ('elr_el3', 'elr_el3', True),
    ('spsr_el3', 'spsr_el3', False),
    ('sp_el2', 'sp_el2', False),
    ('elr_el2', 'elr_el2', True),
    ('spsr_el2', 'spsr_el2', False),
    ('sp_el1', 'sp_el1', False),
    ('elr_el1', 'elr_el1', True),
    ('spsr_el1', 'spsr_el1', False),
    ('sp_el0', 'sp_el0', False),
    ('cpumerrsr_el1', None, False),
    ('l2merrsr_el1',  None, False),
    ('__reserved1', '__reserved1', False),
    ('__reserved2', '__reserved2', False),
]

sysdbg_cpu64_ctxt_regs_type_v1_3 = ''.join([
    'Q',  # x0
    'Q',  # x1
    'Q',  # x2
    'Q',  # x3
    'Q',  # x4
    'Q',  # x5
    'Q',  # x6
    'Q',  # x7
    'Q',  # x8
    'Q',  # x9
    'Q',  # x10
    'Q',  # x11
    'Q',  # x12
    'Q',  # x13
    'Q',  # x14
    'Q',  # x15
    'Q',  # x16
    'Q',  # x17
    'Q',  # x18
    'Q',  # x19
    'Q',  # x20
    'Q',  # x21
    'Q',  # x22
    'Q',  # x23
    'Q',  # x24
    'Q',  # x25
    'Q',  # x26
    'Q',  # x27
    'Q',  # x28
    'Q',  # x29
    'Q',  # x30
    'Q',  # pc
    'Q',  # currentEL
    'Q',  # sp_el3
    'Q',  # elr_el3
    'Q',  # spsr_el3
    'Q',  # sp_el2
    'Q',  # elr_el2
    'Q',  # spsr_el2
    'Q',  # sp_el1
    'Q',  # elr_el1
    'Q',  # spsr_el1
    'Q',  # sp_el0
    'Q',  # cpumerrsr_el1
    'Q',  # l2merrsr_el1
    'Q',  # __reserved1
    'Q',  # __reserved2
])

cpu_name = (
    'Invalid',
    'A53',
    'A57',
    'Hydra',
)

sysdbg_cpu64_register_names = {}
sysdbg_cpu64_ctxt_regs_type = {}
sysdbg_cpu32_register_names = {}
sysdbg_cpu32_ctxt_regs_type = {}

sysdbg_cpu64_register_names['default'] = sysdbg_cpu64_register_names_default
sysdbg_cpu64_ctxt_regs_type['default'] = sysdbg_cpu64_ctxt_regs_type_default
sysdbg_cpu32_register_names['default'] = sysdbg_cpu32_register_names_default
sysdbg_cpu32_ctxt_regs_type['default'] = sysdbg_cpu32_ctxt_regs_type_default

# Version 1.3
sysdbg_cpu64_register_names['1.3'] = sysdbg_cpu64_register_names_v1_3
sysdbg_cpu64_ctxt_regs_type['1.3'] = sysdbg_cpu64_ctxt_regs_type_v1_3

class TZCpuCtx_v2():

    def __init__(self, version, regs_t, ramdump):
        i = 0
        self.regs = {}
        self.version = version
        if ramdump.arm64:
            register_name = sysdbg_cpu64_register_names[self.version]
        else:
            register_name = sysdbg_cpu32_register_names[self.version]

        for r in regs_t:
            self.regs[register_name[i][0]] = r
            i += 1

    def print_regs(self, outfile, ramdump):
        if ramdump.arm64:
            register_names = sysdbg_cpu64_register_names[self.version]
        else:
            register_names = sysdbg_cpu32_register_names[self.version]
        for reg_name, t32_name, print_pc in register_names:
            if re.match('(.*)reserved(.*)', reg_name):
                continue
            if print_pc:
                a = ramdump.unwind_lookup(self.regs[reg_name])
                if a is not None:
                    symname, offset = ramdump.unwind_lookup(
                        self.regs[reg_name])
                    pc_string = '[{0}+0x{1:x}]'.format(symname, offset)
                else:
                    pc_string = None
            else:
                pc_string = None
            if pc_string is not None:
                print_out_str('   {0:8} = 0x{1:016x} {2}'.format(
                    reg_name, self.regs[reg_name], pc_string))
            else:
                print_out_str('   {0:8} = 0x{1:016x}'.format(
                    reg_name, self.regs[reg_name]))
            if t32_name is not None:
                outfile.write(
                    'r.s {0} 0x{1:x}\n'.format(t32_name, self.regs[reg_name]))

class TZRegDump_v2():

    def __init__(self):
        self.core_regs = None
        self.sec_regs = None
        self.version = 0
        self.start_addr = 0
        self.end_addr = 0
        self.core = 0
	self.status = []

    def dump_all_regs(self, ram_dump):
        coren_regs = ram_dump.open_file('core{0}_regs.cmm'.format(self.core))

        print_out_str('core{0} regs:'.format(self.core))
        self.core_regs.print_regs(coren_regs, ram_dump)
        coren_regs.close()

        secure_regs = ram_dump.open_file('secure_world_core{0}_regs.cmm'.format(self.core))
        print_out_str('\n=============== secure contex ===========')
        self.sec_regs.print_regs(secure_regs, ram_dump)
        print_out_str('============ end secure context ===========')
        secure_regs.close()

    def dump_core_pc(self, ram_dump):
        pc = self.core_regs.regs['pc']
        if ram_dump.arm64:
            lr = self.core_regs.regs['x30']
            bt = self.core_regs.regs['sp_el1']
            fp = self.core_regs.regs['x29']
        else:
            lr = self.core_regs.regs['r14_svc']
            bt = self.core_regs.regs['r13_svc']
            fp = self.core_regs.regs['r11']

        a = ram_dump.unwind_lookup(pc)
        if a is not None:
            symname, offset = a
        else:
            symname = 'UNKNOWN'
            offset = 0
        print_out_str(
            'Core {3} PC: {0}+{1:x} <{2:x}>'.format(symname, offset, pc, self.core))
        a = ram_dump.unwind_lookup(lr)
        if a is not None:
            symname, offset = a
        else:
            symname = 'UNKNOWN'
            offset = 0
        print_out_str(
            'Core {3} LR: {0}+{1:x} <{2:x}>'.format(symname, offset, lr, self.core))
        print_out_str('')
        ram_dump.unwind.unwind_backtrace(bt, fp, pc, lr, '')
        print_out_str('')

    def init_regs(self, version, start_addr, end_addr, core, ram_dump):
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.core = core

        self.version = '{0}.{1}'.format(version >> 4, version & 0xF)
        if ram_dump.arm64:
            register_names = sysdbg_cpu64_register_names
        else:
            register_names = sysdbg_cpu32_register_names

        if self.version not in register_names:
            self.version = 'default'

        # uint32 status[4]; -- status fields
        # sdi_cpu_ctxt_regs_type cpu_regs; -- ctxt for all cpus
        # sdi_cpu_ctxt_regs_type __reserved3; -- secure ctxt
        for i in range(0, 4):
            self.status.append(ram_dump.read_u32(self.start_addr, False))
            self.start_addr += 4

        if ram_dump.arm64:
            sc_regs = ram_dump.read_string(
                self.start_addr, sysdbg_cpu64_ctxt_regs_type[self.version], False)
            self.start_addr += struct.calcsize(sysdbg_cpu64_ctxt_regs_type[self.version])
            sc_secure = ram_dump.read_string(
               self.start_addr, sysdbg_cpu64_ctxt_regs_type[self.version] , False)
            self.start_addr += struct.calcsize(sysdbg_cpu64_ctxt_regs_type[self.version])
        else:
            sc_regs = ram_dump.read_string(
                self.start_addr, sysdbg_cpu32_ctxt_regs_type[self.version], False)
            self.start_addr += struct.calcsize(sysdbg_cpu32_ctxt_regs_type[self.version])
            sc_secure = ram_dump.read_string(
                self.start_addr, sysdbg_cpu32_ctxt_regs_type[self.version] , False)
            self.start_addr += struct.calcsize(sysdbg_cpu32_ctxt_regs_type[self.version])

        self.core_regs = TZCpuCtx_v2(self.version, sc_regs, ram_dump)
        self.sec_regs = TZCpuCtx_v2(self.version, sc_secure, ram_dump)
        return True
