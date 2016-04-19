# Copyright (c) 2016 The Linux Foundation. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and
# only version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

from print_out import print_out_str
from parser_util import register_parser, RamParser, cleanupString


def do_dump_process_memory(ramdump):
    vmstat_names = [
        "NR_FREE_PAGES", "NR_SLAB_RECLAIMABLE",
        "NR_SLAB_UNRECLAIMABLE", "NR_SHMEM"]
    vmstat_data = {}
    vmstats_addr = ramdump.address_of('vm_stat')
    for x in vmstat_names:
        i = ramdump.gdbmi.get_value_of(x)
        vmstat_data[x] = ramdump.read_word(
                ramdump.array_index(vmstats_addr, 'atomic_long_t', i))
    total_mem = ramdump.read_word('totalram_pages') * 4
    offset_tasks = ramdump.field_offset('struct task_struct', 'tasks')
    offset_comm = ramdump.field_offset('struct task_struct', 'comm')
    offset_signal = ramdump.field_offset('struct task_struct', 'signal')
    offset_adj = ramdump.field_offset('struct signal_struct', 'oom_score_adj')
    offset_thread_group = ramdump.field_offset(
        'struct task_struct', 'thread_group')
    offset_pid = ramdump.field_offset('struct task_struct', 'pid')
    init_addr = ramdump.address_of('init_task')
    init_next_task = init_addr + offset_tasks
    orig_init_next_task = init_next_task
    init_thread_group = init_addr + offset_thread_group
    seen_tasks = set()
    task_info = []
    offset_thread_group = ramdump.field_offset(
        'struct task_struct', 'thread_group')
    memory_file = ramdump.open_file('memory.txt')
    total_slab = (
        vmstat_data["NR_SLAB_RECLAIMABLE"] +
        vmstat_data["NR_SLAB_UNRECLAIMABLE"]) * 4
    memory_file.write('Total RAM: {0:,}kB\n'.format(total_mem))
    memory_file.write('Total free memory: {0:,}kB({1:.1f}%)\n'.format(
        vmstat_data["NR_FREE_PAGES"] * 4,
        (100.0 * vmstat_data["NR_FREE_PAGES"] * 4) / total_mem))
    memory_file.write('Slab reclaimable: {0:,}kB({1:.1f}%)\n'.format(
        vmstat_data["NR_SLAB_RECLAIMABLE"] * 4,
        (100.0 * vmstat_data["NR_SLAB_RECLAIMABLE"] * 4) / total_mem))
    memory_file.write('Slab unreclaimable: {0:,}kB({1:.1f}%)\n'.format(
        vmstat_data["NR_SLAB_UNRECLAIMABLE"] * 4,
        (100.0 * vmstat_data["NR_SLAB_UNRECLAIMABLE"] * 4) / total_mem))
    memory_file.write('Total Slab memory: {0:,}kB({1:.1f}%)\n'.format(
        total_slab, (100.0 * total_slab) / total_mem))
    memory_file.write('Total SHMEM: {0:,}kB({1:.1f}%)\n\n'.format(
        vmstat_data["NR_SHMEM"] * 4,
        (100.0 * vmstat_data["NR_SHMEM"] * 4) / total_mem))
    while True:
        task_struct = init_thread_group - offset_thread_group
        next_thread_comm = task_struct + offset_comm
        thread_task_name = cleanupString(
            ramdump.read_cstring(next_thread_comm, 16))
        next_thread_pid = task_struct + offset_pid
        thread_task_pid = ramdump.read_int(next_thread_pid)
        signal_struct = ramdump.read_word(task_struct + offset_signal)
        adj = ramdump.read_u16(signal_struct + offset_adj)
        if adj & 0x8000:
            adj = adj - 0x10000
        rss = get_rss(ramdump, task_struct) * 4
        if rss != 0:
            task_info.append([thread_task_name, thread_task_pid, rss, adj])
        next_task = ramdump.read_word(init_next_task)
        if next_task is None:
            break

        if (next_task == init_next_task and
                next_task != orig_init_next_task):
            break

        if next_task in seen_tasks:
            break

        seen_tasks.add(next_task)
        init_next_task = next_task
        init_thread_group = init_next_task - offset_tasks + offset_thread_group
        if init_next_task == orig_init_next_task:
            break

    task_info = sorted(task_info, key=lambda l: l[2], reverse=True)
    str = '{0:<17s}{1:>8s}{2:>17s}{3:>8}\n'.format(
        'Task name', 'PID', 'RSS in kB', 'ADJ')
    memory_file.write(str)
    for item in task_info:
        str = '{0:<17s}{1:8d}{2:13,d}({3:2.1f}%) {4:6}\n'.format(
            item[0], item[1], item[2], (100.0 * item[2]) / total_mem, item[3])
        memory_file.write(str)
    memory_file.close()
    print_out_str('---wrote meminfo to memory.txt')


def get_rss(ramdump, task_struct):
    offset_mm = ramdump.field_offset('struct task_struct', 'mm')
    offset_rss_stat = ramdump.field_offset('struct mm_struct', 'rss_stat')
    offset_rss = ramdump.field_offset('struct mm_rss_stat', 'count')
    offset_anon_rss = ramdump.field_offset('struct mm_rss_stat', 'count[1]')
    offset_file_rss = ramdump.field_offset('struct mm_rss_stat', 'count[2]')
    mm_struct = ramdump.read_word(task_struct + offset_mm)
    if mm_struct == 0:
        return 0
    anon_rss = ramdump.read_word(mm_struct + offset_rss_stat + offset_anon_rss)
    rss = ramdump.read_word(mm_struct + offset_rss_stat + offset_rss)
    file_rss = ramdump.read_word(mm_struct + offset_rss_stat + offset_file_rss)
    # Ignore negative RSS values
    if anon_rss > 0x80000000:
        anon_rss = 0
    if rss > 0x80000000:
        rss = 0
    if file_rss > 0x80000000:
        file_rss = 0
    total_rss = rss + anon_rss + file_rss
    return total_rss


@register_parser('--print-memory-info', 'Print memory usage info')
class DumpProcessMemory(RamParser):

    def parse(self):
        do_dump_process_memory(self.ramdump)
