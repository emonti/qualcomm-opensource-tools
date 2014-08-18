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

import string
from print_out import print_out_str
from parser_util import register_parser, RamParser, cleanupString

def find_panic(ramdump, addr_stack, thread_task_name):
    if ramdump.arm64:
        stack_size = 0x4000
        increment = 8
    else:
        stack_size = 0x2000
        increment = 4
    for i in range(addr_stack, addr_stack + stack_size, increment):
        if ramdump.arm64:
            pc = ramdump.read_word(i + 8) - 4
            fp = ramdump.read_word(i)
            spx = i + 16
            lr = 0
        else:
            pc = ramdump.read_word(i)
            lr = ramdump.read_word(i + 4)
            spx = i + 4
            fp = 0
        l = ramdump.unwind_lookup(pc)
        if l is not None:
            s, offset = l
            if s == 'panic':
                print_out_str('Faulting process found! Name {0})'.format(thread_task_name))
                ramdump.unwind.unwind_backtrace(spx, fp, pc, lr, '')
                regspanic = ramdump.open_file('regs_panic.cmm')
                if ramdump.arm64:
                    regspanic.write('r.s pc 0x{0:x}\n'.format(pc))
                    regspanic.write('r.s sp 0x{0:x}\n'.format(spx))
                else:
                    regspanic.write('r.s pc 0x{0:x}\n'.format(pc))
                    regspanic.write('r.s r13 0x{0:x}\n'.format(i + 4))
                regspanic.close()
                return True
    return False


def dump_thread_group(ramdump, thread_group, task_out, check_for_panic=0):
    offset_thread_group = ramdump.field_offset(
        'struct task_struct', 'thread_group')
    offset_comm = ramdump.field_offset('struct task_struct', 'comm')
    offset_pid = ramdump.field_offset('struct task_struct', 'pid')
    offset_stack = ramdump.field_offset('struct task_struct', 'stack')
    offset_state = ramdump.field_offset('struct task_struct', 'state')
    offset_exit_state = ramdump.field_offset(
        'struct task_struct', 'exit_state')
    offset_cpu = ramdump.field_offset('struct thread_info', 'cpu')
    orig_thread_group = thread_group
    first = 0
    seen_threads = []
    while True:
        next_thread_start = thread_group - offset_thread_group
        next_thread_comm = next_thread_start + offset_comm
        next_thread_pid = next_thread_start + offset_pid
        next_thread_stack = next_thread_start + offset_stack
        next_thread_state = next_thread_start + offset_state
        next_thread_exit_state = next_thread_start + offset_exit_state
        thread_task_name = cleanupString(
            ramdump.read_cstring(next_thread_comm, 16))
        if thread_task_name is None:
            return
        thread_task_pid = ramdump.read_int(next_thread_pid)
        if thread_task_pid is None:
            return
        task_state = ramdump.read_word(next_thread_state)
        if task_state is None:
            return
        task_exit_state = ramdump.read_int(next_thread_exit_state)
        if task_exit_state is None:
            return
        addr_stack = ramdump.read_word(next_thread_stack)
        if addr_stack is None:
            return
        threadinfo = addr_stack
        if threadinfo is None:
            return
        if not check_for_panic:
            if not first:
                task_out.write('Process: {0}, cpu: {1} pid: {2} start: 0x{3:x}\n'.format(
                    thread_task_name, ramdump.read_int(threadinfo + offset_cpu), thread_task_pid, next_thread_start))
                task_out.write(
                    '=====================================================\n')
                first = 1
            task_out.write('    Task name: {0} pid: {1} cpu: {2}\n    state: 0x{3:x} exit_state: 0x{4:x} stack base: 0x{5:x}\n'.format(
                thread_task_name, thread_task_pid, ramdump.read_int(threadinfo + offset_cpu), task_state, task_exit_state, addr_stack))
            task_out.write('    Stack:\n')
            ramdump.unwind.unwind_backtrace(
                 ramdump.thread_saved_sp(next_thread_start),
                 ramdump.thread_saved_fp(next_thread_start),
                 ramdump.thread_saved_pc(next_thread_start),
                 0, '    ', task_out)
            task_out.write(
                '=======================================================\n')
        else:
            find_panic(ramdump, addr_stack, thread_task_name)

        next_thr = ramdump.read_word(thread_group)
        if (next_thr == thread_group) and (next_thr != orig_thread_group):
            if not check_for_panic:
                task_out.write(
                    '!!!! Cycle in thread group! The list is corrupt!\n')
            break
        if (next_thr in seen_threads):
            break

        seen_threads.append(next_thr)
        thread_group = next_thr
        if thread_group == orig_thread_group:
            break


def do_dump_stacks(ramdump, check_for_panic=0):
    offset_tasks = ramdump.field_offset('struct task_struct', 'tasks')
    offset_comm = ramdump.field_offset('struct task_struct', 'comm')
    offset_stack = ramdump.field_offset('struct task_struct', 'stack')
    offset_thread_group = ramdump.field_offset(
        'struct task_struct', 'thread_group')
    offset_pid = ramdump.field_offset('struct task_struct', 'pid')
    offset_state = ramdump.field_offset('struct task_struct', 'state')
    offset_exit_state = ramdump.field_offset(
        'struct task_struct', 'exit_state')
    init_addr = ramdump.addr_lookup('init_task')
    init_next_task = init_addr + offset_tasks
    orig_init_next_task = init_next_task
    init_thread_group = init_addr + offset_thread_group
    seen_tasks = []
    if check_for_panic == 0:
        task_out = ramdump.open_file('tasks.txt')
    else:
        task_out = None
    while True:
        dump_thread_group(ramdump, init_thread_group,
                          task_out, check_for_panic)
        next_task = ramdump.read_word(init_next_task)
        if next_task is None:
            return

        if (next_task == init_next_task) and (next_task != orig_init_next_task):
            if not check_for_panic:
                task_out.write(
                    '!!!! Cycle in task list! The list is corrupt!\n')
            break

        if (next_task in seen_tasks):
            break

        seen_tasks.append(next_task)

        init_next_task = next_task
        init_thread_group = init_next_task - offset_tasks + offset_thread_group
        if init_next_task == orig_init_next_task:
            break
    if check_for_panic == 0:
        task_out.close()
        print_out_str('---wrote tasks to tasks.txt')


@register_parser('--print-tasks', 'Print all the task information', shortopt='-t')
class DumpTasks(RamParser):

    def parse(self):
        do_dump_stacks(self.ramdump, 0)


@register_parser('--check-for-panic', 'Check if a kernel panic occured', shortopt='-p')
class CheckForPanic(RamParser):

    def parse(self):
        addr = self.ramdump.addr_lookup('in_panic')

        result = self.ramdump.read_word(addr)

        if result == 1:
            print_out_str('-------------------------------------------------')
            print_out_str('[!] KERNEL PANIC detected!')
            print_out_str('-------------------------------------------------')
            do_dump_stacks(self.ramdump, 1)
        else:
            print_out_str('No kernel panic detected')
