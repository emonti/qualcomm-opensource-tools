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

import struct
import re
from print_out import print_out_str
from bitops import is_set

# name from tz dump, corresponding T32 register, whether or not to
# print_out_str (the function name)
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

sysdbg_cpu64_register_names_v1_4 = [
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
    ('cpu_state_0', 'cpu_state_0', False),
    ('cpu_state_1', 'cpu_state_1', False),
    ('cpu_state_3', 'cpu_state_3', False),
    ('cpu_state_4', 'cpu_state_4', False),
    ('cpu_state_5', 'cpu_state_5', False),
    ('__reserved1', '__reserved1', False),
    ('__reserved2', '__reserved2', False),
    ('__reserved3', '__reserved3', False),
    ('__reserved4', '__reserved4', False),
]

sysdbg_cpu64_ctxt_regs_type_v1_4 = ''.join([
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
    'Q',  # cpu_state_0
    'Q',  # cpu_state_1
    'Q',  # cpu_state_3
    'Q',  # cpu_state_4
    'Q',  # cpu_state_5
    'Q',  # __reserved1
    'Q',  # __reserved2
    'Q',  # __reserved3
    'Q',  # __reserved4
])

sysdbg_neon128_register_names_v1_4 = [
    ('q0-lower', 'v0-lower', False),
    ('q0-upper', 'v0-upper', False),
    ('q1-lower', 'v1-lower', False),
    ('q1-upper', 'v1-upper', False),
    ('q2-lower', 'v2-lower', False),
    ('q2-upper', 'v2-upper', False),
    ('q3-lower', 'v3-lower', False),
    ('q3-upper', 'v3-upper', False),
    ('q4-lower', 'v4-lower', False),
    ('q4-upper', 'v4-upper', False),
    ('q5-lower', 'v5-lower', False),
    ('q5-upper', 'v5-upper', False),
    ('q6-lower', 'v6-lower', False),
    ('q6-upper', 'v6-upper', False),
    ('q7-lower', 'v7-lower', False),
    ('q7-upper', 'v7-upper', False),
    ('q8-lower', 'v8-lower', False),
    ('q8-upper', 'v8-upper', False),
    ('q9-lower', 'v9-lower', False),
    ('q9-upper', 'v9-upper', False),
    ('q10-lower', 'v10-lower', False),
    ('q10-upper', 'v10-upper', False),
    ('q11-lower', 'v11-lower', False),
    ('q11-upper', 'v11-upper', False),
    ('q12-lower', 'v12-lower', False),
    ('q12-upper', 'v12-upper', False),
    ('q13-lower', 'v13-lower', False),
    ('q13-upper', 'v13-upper', False),
    ('q14-lower', 'v14-lower', False),
    ('q14-upper', 'v14-upper', False),
    ('q15-lower', 'v15-lower', False),
    ('q15-upper', 'v15-upper', False),
    ('q16-lower', 'v16-lower', False),
    ('q16-upper', 'v16-upper', False),
    ('q17-lower', 'v17-lower', False),
    ('q17-upper', 'v17-upper', False),
    ('q18-lower', 'v18-lower', False),
    ('q18-upper', 'v18-upper', False),
    ('q19-lower', 'v19-lower', False),
    ('q19-upper', 'v19-upper', False),
    ('q20-lower', 'v20-lower', False),
    ('q20-upper', 'v20-upper', False),
    ('q21-lower', 'v21-lower', False),
    ('q21-upper', 'v21-upper', False),
    ('q22-lower', 'v22-lower', False),
    ('q22-upper', 'v22-upper', False),
    ('q23-lower', 'v23-lower', False),
    ('q23-upper', 'v23-upper', False),
    ('q24-lower', 'v24-lower', False),
    ('q24-upper', 'v24-upper', False),
    ('q25-lower', 'v25-lower', False),
    ('q25-upper', 'v25-upper', False),
    ('q26-lower', 'v26-lower', False),
    ('q26-upper', 'v26-upper', False),
    ('q27-lower', 'v27-lower', False),
    ('q27-upper', 'v27-upper', False),
    ('q28-lower', 'v28-lower', False),
    ('q28-upper', 'v28-upper', False),
    ('q29-lower', 'v29-lower', False),
    ('q29-upper', 'v29-upper', False),
    ('q30-lower', 'v30-lower', False),
    ('q30-upper', 'v30-upper', False),
    ('q31-lower', 'v31-lower', False),
    ('q31-upper', 'v31-upper', False),
]

sysdbg_neon128_register_type_v1_4 = ''.join([
    'Q',  # q0-lower
    'Q',  # q0-upper
    'Q',  # q1-lower
    'Q',  # q1-upper
    'Q',  # q2-lower
    'Q',  # q2-upper
    'Q',  # q3-lower
    'Q',  # q3-upper
    'Q',  # q4-lower
    'Q',  # q4-upper
    'Q',  # q5-lower
    'Q',  # q5-upper
    'Q',  # q6-lower
    'Q',  # q6-upper
    'Q',  # q7-lower
    'Q',  # q7-upper
    'Q',  # q8-lower
    'Q',  # q8-upper
    'Q',  # q9-lower
    'Q',  # q9-upper
    'Q',  # q10-lower
    'Q',  # q10-upper
    'Q',  # q11-lower
    'Q',  # q11-upper
    'Q',  # q12-lower
    'Q',  # q12-upper
    'Q',  # q13-lower
    'Q',  # q13-upper
    'Q',  # q14-lower
    'Q',  # q14-upper
    'Q',  # q15-lower
    'Q',  # q15-upper
    'Q',  # q16-lower
    'Q',  # q16-upper
    'Q',  # q17-lower
    'Q',  # q17-upper
    'Q',  # q18-lower
    'Q',  # q18-upper
    'Q',  # q19-lower
    'Q',  # q19-upper
    'Q',  # q20-lower
    'Q',  # q20-upper
    'Q',  # q21-lower
    'Q',  # q21-upper
    'Q',  # q22-lower
    'Q',  # q22-upper
    'Q',  # q23-lower
    'Q',  # q23-upper
    'Q',  # q24-lower
    'Q',  # q24-upper
    'Q',  # q25-lower
    'Q',  # q25-upper
    'Q',  # q26-lower
    'Q',  # q26-upper
    'Q',  # q27-lower
    'Q',  # q27-upper
    'Q',  # q28-lower
    'Q',  # q28-upper
    'Q',  # q29-lower
    'Q',  # q29-upper
    'Q',  # q30-lower
    'Q',  # q30-upper
    'Q',  # q31-lower
    'Q',  # q31-upper
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

# Version 1.4
sysdbg_cpu64_register_names['1.4'] = sysdbg_cpu64_register_names_v1_4
sysdbg_cpu64_ctxt_regs_type['1.4'] = sysdbg_cpu64_ctxt_regs_type_v1_4


class NeonCtxType():

    def __init__(self, regs_t, ramdump):
        i = 0
        self.regs = {}

        if ramdump.arm64 is None:
            return

        register_name = sysdbg_neon128_register_names_v1_4
        for r in regs_t:
            self.regs[register_name[i][0]] = r
            i += 1


class TZCpuCtx_v2():

    def compute_pc(self, neon_regs):
        pstate = self.regs['cpu_state_1']
        cpu_state_3 = self.regs['cpu_state_3']
        cpu_state_5 = self.regs['cpu_state_5']
        pc = self.regs['pc']

        # AArch32 Mode
        if is_set(pstate, 4):
            val = pstate & 0xF
            if val == 0x0 and is_set(cpu_state_3, 14):
                self.regs['pc'] = self.regs['x14']
            elif val == 0x1 and is_set(cpu_state_3, 30):
                self.regs['pc'] = self.regs['x30']
            elif val == 0x2 and is_set(cpu_state_3, 16):
                self.regs['pc'] = self.regs['x16']
            elif val == 0x3 and is_set(cpu_state_3, 18):
                self.regs['pc'] = self.regs['x18']
            elif val == 0x7 and is_set(cpu_state_3, 20):
                self.regs['pc'] = self.regs['x20']
            elif val == 0xB and is_set(cpu_state_3, 22):
                self.regs['pc'] = self.regs['x22']
            elif val == 0x6 and is_set(cpu_state_5, 31):
                self.regs['pc'] = neon_regs['q31-upper']
            elif val == 0xA:
                self.regs['pc'] = self.regs['elr_el2']
            elif val == 0xF and is_set(cpu_state_3, 14):
                self.regs['pc'] = self.regs['x14']
            else:
                print_out_str('!!! AArch32 PC Approximation Logic Failed!')
        # AArch64 Mode
        else:
            if is_set(cpu_state_3, 30):
                self.regs['pc'] = self.regs['x30']
            else:
                val = (pstate >> 2) & 0x3
                if val == 0x0:
                    self.regs['pc'] = self.regs['elr_el1']
                elif val == 0x1:
                    self.regs['pc'] = self.regs['elr_el1']
                elif val == 0x2:
                    self.regs['pc'] = self.regs['elr_el2']
                elif val == 0x3:
                    self.regs['pc'] = self.regs['elr_el3']
                else:
                    print_out_str('!!! AArch64 PC Approximation Logic Failed!')

        if pc and pc != self.regs['pc']:
            print_out_str(
                '!!! PC computed by SDI {0} and Parser {1} are different!'
                .format(hex(pc), hex(self.regs['pc'])))

    def __init__(self, version, regs_t, neon_regs, ramdump):
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

        if self.version == '1.4' and self.regs['cpu_state_0'] == 0x1:
            print_out_str(
                '!!! PC is invalid, applying "PC Approximation Logic"!')
            self.compute_pc(neon_regs)

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
                if reg_name.startswith('cpu_state_'):
                    continue
                outfile.write(
                    'r.s {0} 0x{1:x}\n'.format(t32_name, self.regs[reg_name]))


class TZRegDump_v2():

    def __init__(self):
        self.core_regs = None
        self.sec_regs = None
        self.neon_regs = {}
        self.version = 0
        self.start_addr = 0
        self.end_addr = 0
        self.core = 0
        self.status = []
        self.neon_fields = []

    def dump_all_regs(self, ram_dump):
        coren_regs = ram_dump.open_file('core{0}_regs.cmm'.format(self.core))

        print_out_str('core{0} regs:'.format(self.core))
        self.core_regs.print_regs(coren_regs, ram_dump)
        coren_regs.close()

        secure_regs = ram_dump.open_file(
            'secure_world_core{0}_regs.cmm'.format(self.core))
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
            'Core {3} PC: {0}+{1:x} <{2:x}>'.format(symname, offset,
                                                    pc, self.core))
        a = ram_dump.unwind_lookup(lr)
        if a is not None:
            symname, offset = a
        else:
            symname = 'UNKNOWN'
            offset = 0
        print_out_str(
            'Core {3} LR: {0}+{1:x} <{2:x}>'.format(symname, offset,
                                                    lr, self.core))
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
                self.start_addr,
                sysdbg_cpu64_ctxt_regs_type[self.version],
                False)
            self.start_addr += struct.calcsize(
                sysdbg_cpu64_ctxt_regs_type[self.version])
            sc_secure = ram_dump.read_string(
                self.start_addr,
                sysdbg_cpu64_ctxt_regs_type[self.version],
                False)
            self.start_addr += struct.calcsize(
                sysdbg_cpu64_ctxt_regs_type[self.version])

            if self.version == '1.4':
                for i in range(0, 3):
                    self.neon_fields.append(ram_dump.read_u32(
                                            self.start_addr, False))
                    self.start_addr += 4

                neon_ctx_regs = ram_dump.read_string(
                    self.start_addr,
                    sysdbg_neon128_register_type_v1_4,
                    False)
                self.start_addr += struct.calcsize(
                    sysdbg_neon128_register_type_v1_4)

                neon = NeonCtxType(neon_ctx_regs, ram_dump)
                self.neon_regs = neon.regs
        else:
            sc_regs = ram_dump.read_string(
                self.start_addr,
                sysdbg_cpu32_ctxt_regs_type[self.version],
                False)
            self.start_addr += struct.calcsize(
                sysdbg_cpu32_ctxt_regs_type[self.version])
            sc_secure = ram_dump.read_string(
                self.start_addr,
                sysdbg_cpu32_ctxt_regs_type[self.version],
                False)
            self.start_addr += struct.calcsize(
                sysdbg_cpu32_ctxt_regs_type[self.version])

        self.core_regs = TZCpuCtx_v2(self.version, sc_regs,
                                     self.neon_regs, ram_dump)
        self.sec_regs = TZCpuCtx_v2(self.version, sc_secure,
                                    self.neon_regs, ram_dump)
        return True
