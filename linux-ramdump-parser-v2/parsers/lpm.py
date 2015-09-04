# Copyright (c) 2015, The Linux Foundation. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and
# only version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

import linux_list
from parser_util import register_parser, RamParser
from operator import itemgetter

@register_parser('--lpm', 'Parse LPM Driver info')
class lpm(RamParser):
    def __init__(self, *args):
        super(lpm, self).__init__(*args)
        self.head = ''
        self.output = []
        self.clusters = []
        self.cpu_possible_bits = None
        self.cpu_online_bits = None
        self.lpm_debug = []

    def get_bits(self):
        bits_addr = self.ramdump.address_of('cpu_possible_bits')
        if bits_addr is None:
                self.output.append("NOTE: 'cpu_possible_bits' not found")
                return

        self.cpu_possible_bits = self.ramdump.read_int(bits_addr)
        cpus = bin(self.cpu_possible_bits).count('1')
        self.output.append("{}\n".format('Available CPUs'))
        for i in range(0, cpus):
                self.output.append("{:10}{}:{}\n".format("", "CPU", i))
        self.output.append("\n")

        bits_addr = self.ramdump.address_of('cpu_online_bits')
        if bits_addr is None:
                self.output.append("NOTE: 'cpu_online_bits' not found")
                return

        self.cpu_online_bits = self.ramdump.read_int(bits_addr)
        cpus = bin(self.cpu_online_bits).count('1')
        self.output.append("{}\n".format('Online CPUs'))
        for i in range(0, cpus):
                self.output.append("{:10}{}:{}\n".format("", "CPU", i))
        self.output.append("{}{}{}".format("\n", "-" * 81, "\n"))

    def get_cluster_level_info(self, lpm_cluster):
        offset = self.ramdump.field_offset('struct lpm_cluster', 'nlevels')
        nlevels = self.ramdump.read_int(lpm_cluster + offset)
        self.output.append("{:20}:{}\n".format("number of levels", nlevels))

        offset = self.ramdump.field_offset('struct lpm_cluster', 'min_child_level')
        node = self.ramdump.read_int(lpm_cluster + offset)
        self.output.append("{:20}:{}\n".format("min child level", node))

        offset = self.ramdump.field_offset('struct lpm_cluster', 'default_level')
        node = self.ramdump.read_int(lpm_cluster + offset)
        self.output.append("{:20}:{}\n".format("default level", node))

        offset = self.ramdump.field_offset('struct lpm_cluster', 'last_level')
        node = self.ramdump.read_int(lpm_cluster + offset)
        self.output.append("{:20}:{}\n".format("last_level", node))

        offset = self.ramdump.field_offset('struct lpm_cluster', 'levels')
        levels = lpm_cluster + offset
        self.output.append("\n")

        cluster_level_size = self.ramdump.sizeof('struct lpm_cluster_level')

        for i in xrange(nlevels):
                # ToDo: Need a better way to arrive at the next level info.
                level = levels + (i * cluster_level_size)

                offset = self.ramdump.field_offset('struct lpm_cluster_level', 'mode')
                addr = self.ramdump.read_word(level + offset, True)
                node = self.ramdump.read_int(addr)
                self.output.append("{:20}:{}\n".format("level mode", node))

                offset = self.ramdump.field_offset('struct lpm_cluster_level', 'level_name')
                addr = self.ramdump.read_word(level + offset, True)
                name = self.ramdump.read_cstring(addr, 48)
                self.output.append("{:20}:{}\n".format("level name", name))

                offset = self.ramdump.field_offset('struct lpm_cluster_level', 'min_child_level')
                addr = level + offset
                node = self.ramdump.read_int(addr)
                self.output.append("{:20}:{}\n".format("min child level", node))

                offset = self.ramdump.field_offset('struct lpm_cluster_level', 'num_cpu_votes')
                addr = level + offset
                node = self.ramdump.read_int(addr)
                self.output.append("{:20}:{}({})\n".format("num cpu votes", hex(node).rstrip("L"), bin(node).lstrip("0b")))

                offset = self.ramdump.field_offset('struct lpm_cluster_level', 'available')
                addr = level + offset

                offset = self.ramdump.field_offset('struct lpm_level_avail', 'idle_enabled')
                node = self.ramdump.read_bool(addr + offset)
                self.output.append("{:20}:{}\n".format("idle_enabled", node))

                offset = self.ramdump.field_offset('struct lpm_level_avail', 'suspend_enabled')
                node = self.ramdump.read_bool(addr + offset)
                self.output.append("{:20}:{}\n".format("suspend_enabled", node))
                self.output.append("\n")

    def get_cluster_info(self, lpm_cluster):
        offset = self.ramdump.field_offset('struct lpm_cluster', 'cluster_name')
        addr = self.ramdump.read_word(lpm_cluster + offset, True)
        node = self.ramdump.read_cstring(addr, 48)
        self.output.append("{:20}:{}\n".format("Cluster Name", node))

        offset = self.ramdump.field_offset('struct lpm_cluster', 'child_cpus')
        node = self.ramdump.read_int(lpm_cluster + offset)
        self.output.append("{:20}:{}({})\n".format("child_cpus", hex(node).rstrip("L"), bin(node).lstrip("0b")))

        offset = self.ramdump.field_offset('struct lpm_cluster', 'num_childs_in_sync')
        node = self.ramdump.read_int(lpm_cluster + offset)
        self.output.append("{:20}:{}({})\n".format("num_childs_in_sync", hex(node).rstrip("L"), bin(node).lstrip("0b")))
        self.output.append("\n")

    def lpm_walker(self, lpm_cluster):
        if lpm_cluster == self.head:
                return
        self.clusters.append(lpm_cluster)

    def get_clusters(self):
        lpm_root_node = self.ramdump.read_word(
            self.ramdump.address_of('lpm_root_node'), True)
        if lpm_root_node is None:
                self.output_file.write("NOTE: 'lpm_root_node' not found\n")
                return

        self.clusters.append(lpm_root_node)

        offset = self.ramdump.field_offset('struct lpm_cluster', 'child')
        lpm_cluster = self.ramdump.read_word(lpm_root_node + offset, True)
        self.head = lpm_root_node + offset

        offset = self.ramdump.field_offset('struct lpm_cluster', 'list')
        lpm_walker = linux_list.ListWalker(self.ramdump, lpm_cluster, offset)
        lpm_walker.walk(lpm_cluster, self.lpm_walker)

    def get_cpu_level_info(self, cpu_cluster_base, cpu):
        self.output.append("{:20}:{}\n".format("CPU", cpu))

        cpu_cluster = self.ramdump.read_word(cpu_cluster_base, cpu=cpu)
        offset = self.ramdump.field_offset('struct lpm_cluster', 'cpu')
        cpu_level = self.ramdump.read_word(cpu_cluster + offset, True)

        offset = self.ramdump.field_offset('struct lpm_cpu', 'nlevels')
        nlevels = self.ramdump.read_int(cpu_level + offset, True)
        self.output.append("{:20}:{}\n".format("number of levels", nlevels))

        offset = self.ramdump.field_offset('struct lpm_cpu', 'levels')
        levels = cpu_level + offset

        self.output.append("\n")

        cpu_level_available = self.ramdump.address_of('cpu_level_available')
        if cpu_level_available is None:
                self.output.append("NOTE: 'cpu_level_available' not found\n")
                return
        cpu_level_available = cpu_level_available + self.ramdump.sizeof('long') * cpu
        cpu_level_available = self.ramdump.read_word(cpu_level_available, True)

        for i in range(0, nlevels):
                level = levels + (i * self.ramdump.sizeof('struct lpm_cpu_level'))

                offset = self.ramdump.field_offset('struct lpm_cpu_level', 'name')
                addr = self.ramdump.read_word(level + offset, True)
                node = self.ramdump.read_cstring(addr, 48)
                self.output.append("{:20}:{}\n".format("level name", node))

                offset = self.ramdump.field_offset('struct lpm_cpu_level', 'mode')
                node = self.ramdump.read_int(level + offset, True)
                self.output.append("{:20}:{}\n".format("level mode", node))

                level_available = cpu_level_available + i * self.ramdump.sizeof('struct lpm_level_avail')
                offset = self.ramdump.field_offset('struct lpm_level_avail', 'idle_enabled')
                node = self.ramdump.read_bool(level_available + offset)
                self.output.append("{:20}:{}\n".format("idle enabled", node))

                offset = self.ramdump.field_offset('struct lpm_level_avail', 'suspend_enabled')
                node = self.ramdump.read_bool(level_available + offset, True)
                self.output.append("{:20}:{}\n".format("suspend enabled", node))

                self.output.append("\n")

        self.output.append("{}{}".format("-" * 81, "\n"))

    def get_lpm(self):
        self.get_clusters()
        for i in self.clusters:
                self.get_cluster_info(i)
                self.get_cluster_level_info(i)
                self.output.append("{}{}".format("-" * 81, "\n"))

        cpu_cluster_base = self.ramdump.address_of('cpu_cluster')
        if cpu_cluster_base is None:
                self.output.append("NOTE: 'cpu_cluster' not found\n")
                return

        cpus = bin(self.cpu_possible_bits).count('1')
        for i in range(0, cpus):
                self.get_cpu_level_info(cpu_cluster_base, i)

    def get_time_stats(self, tstats, nlevels):
        for i in range(nlevels):
                lstats = tstats + i * self.ramdump.sizeof('struct level_stats')

                offset = self.ramdump.field_offset('struct level_stats', 'name')
                addr = self.ramdump.read_word(lstats + offset, True)
                self.output.append("{:20}:{}\n".format("lpm name", self.ramdump.read_cstring(addr + offset, 48)))

                offset = self.ramdump.field_offset('struct level_stats', 'success_count')
                self.output.append("{:20}:{}\n".format("success_count", self.ramdump.read_int(lstats + offset, True)))

                offset = self.ramdump.field_offset('struct level_stats', 'failed_count')
                self.output.append("{:20}:{}\n".format("failed_count", self.ramdump.read_int(lstats + offset, True)))

                self.output.append("\n")

    def get_cluster_stats(self, cluster):
        offset = self.ramdump.field_offset('struct lpm_cluster', 'stats')
        stats = self.ramdump.read_word(cluster + offset, True)

        offset = self.ramdump.field_offset('struct lpm_stats', 'name')
        self.output.append("{} {}\n\n".format(self.ramdump.read_cstring(stats + offset, 48), "lpm stats"))

        offset = self.ramdump.field_offset('struct lpm_stats', 'num_levels')
        nlevels = self.ramdump.read_int(stats + offset, True)

        offset = self.ramdump.field_offset('struct lpm_stats', 'time_stats')
        tstats = self.ramdump.read_word(stats + offset, True)

        self.get_time_stats(tstats, nlevels)
        self.output.append("{}{}".format("-" * 81, "\n"))

    def get_cpu_stats(self, cpu_stats_base, cpu):
        stats = cpu_stats_base + self.ramdump.per_cpu_offset(cpu)

        offset = self.ramdump.field_offset('struct lpm_stats', 'name')
        self.output.append("{} {}\n\n".format(self.ramdump.read_cstring(stats + offset, 48), "lpm stats"))

        offset = self.ramdump.field_offset('struct lpm_stats', 'num_levels')
        nlevels = self.ramdump.read_int(stats + offset, True)

        offset = self.ramdump.field_offset('struct lpm_stats', 'time_stats')
        tstats = self.ramdump.read_word(stats + offset, True)

        self.get_time_stats(tstats, nlevels)
        self.output.append("{}{}".format("-" * 81, "\n"))

    def get_stats(self):
        for i in self.clusters:
                self.get_cluster_stats(i)

        cpu_stats_base = self.ramdump.address_of('cpu_stats')
        if cpu_stats_base is None:
                self.output.append("NOTE: 'cpu_stats' not found\n")
                return

        cpus = bin(self.cpu_possible_bits).count('1')
        for i in range(0, cpus):
                self.get_cpu_stats(cpu_stats_base, i)

    def get_debug_phys(self):
        lpm_debug_phys = self.ramdump.address_of('lpm_debug_phys')
        if lpm_debug_phys is None:
                self.output.append("NOTE: 'lpm_debug data' not found\n")
                return
        lpm_debug_phys = self.ramdump.read_word(lpm_debug_phys, True)

        for i in range(0, 256):
                debug = []

                addr = lpm_debug_phys + i * self.ramdump.sizeof('struct lpm_debug')

                offset = self.ramdump.field_offset('struct lpm_debug', 'time')
                time = self.ramdump.read_word(addr + offset, False)
                debug.append(time)

                offset = self.ramdump.field_offset('struct lpm_debug', 'evt')
                evt = self.ramdump.read_int(addr + offset, False)
                debug.append(evt)

                offset = self.ramdump.field_offset('struct lpm_debug', 'cpu')
                cpu = self.ramdump.read_int(addr + offset, False)
                debug.append(cpu)

                offset = self.ramdump.field_offset('struct lpm_debug', 'arg1')
                arg1 = self.ramdump.read_int(addr + offset, False)
                debug.append(arg1)

                offset = self.ramdump.field_offset('struct lpm_debug', 'arg2')
                arg2 = self.ramdump.read_int(addr + offset, False)
                debug.append(arg2)

                offset = self.ramdump.field_offset('struct lpm_debug', 'arg3')
                arg3 = self.ramdump.read_int(addr + offset, False)
                debug.append(arg3)

                offset = self.ramdump.field_offset('struct lpm_debug', 'arg4')
                arg4 = self.ramdump.read_int(addr + offset, False)
                debug.append(arg4)

                self.lpm_debug.append(debug)

    def print_debug_phys(self):
        debug = []
        lpm_debug = []

        self.output.append("\n")
        self.output.append("{:16}".format("TimeStamp"))
        self.output.append("{:8} {:8} {:8} ".format("Event", "CPU", "arg1"))
        self.output.append("{:16}{:16}{:16}\n".format("arg2", "arg3", "arg4"))
        self.output.append("{}{}".format("-" * 81, "\n"))

        lpm_debug = sorted(self.lpm_debug, key=itemgetter(0))

        for i in range(len(lpm_debug)):
                debug = lpm_debug[i]
                for j in range(len(debug)):
                        if j == 0 or j > 3:
                                self.output.append("{:16}".format(hex(debug[j]).rstrip("L")))
                        else:
                                self.output.append("{}{:8}".format(debug[j], ""))

                self.output.append("\n")

    def parse(self):
        self.output_file = self.ramdump.open_file('lpm.txt')
        self.get_bits()
        self.get_lpm()
        self.get_stats()
        self.get_debug_phys()
        self.print_debug_phys()
        for i in self.output:
                self.output_file.write(i)
        self.output_file.close()
