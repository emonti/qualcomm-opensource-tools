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

import re

from mm import page_address, pfn_to_page
from print_out import print_out_str
from parser_util import register_parser, RamParser


@register_parser('--slabinfo', 'print information about slabs', optional=True)
class Slabinfo(RamParser):

    def get_free_pointer(self, ramdump, s, obj):
        # just like validate_slab_slab!
        slab_offset_offset = self.ramdump.field_offset(
            'struct kmem_cache', 'offset')
        slab_offset = self.ramdump.read_word(s + slab_offset_offset)
        return self.ramdump.read_word(obj + slab_offset)

    def slab_index(self, ramdump, p, addr, slab):
        slab_size_offset = self.ramdump.field_offset(
            'struct kmem_cache', 'size')
        slab_size = self.ramdump.read_int(slab + slab_size_offset)
        if slab_size is None:
            return -1
        return (p - addr) / slab_size

    def get_map(self, ramdump, slab, page, bitarray):
        freelist_offset = self.ramdump.field_offset('struct page', 'freelist')
        freelist = self.ramdump.read_word(page + freelist_offset)
        p = freelist
        addr = page_address(self.ramdump, page)
        seen = []
        if addr is None:
            return
        while p != 0 and p is not None and p not in seen:
            idx = self.slab_index(self.ramdump, p, addr, slab)
            if idx >= len(bitarray) or idx < 0:
                return
            bitarray[idx] = 1
            seen.append(p)
            p = self.get_free_pointer(self.ramdump, slab, p)

    def get_track(self, ramdump, slab, obj, track_type):
        track_size = self.ramdump.sizeof('struct track')
        slab_offset_offset = self.ramdump.field_offset(
            'struct kmem_cache', 'offset')
        slab_inuse_offset = self.ramdump.field_offset(
            'struct kmem_cache', 'inuse')
        slab_offset = self.ramdump.read_int(slab + slab_offset_offset)
        slab_inuse = self.ramdump.read_int(slab + slab_inuse_offset)
        if slab_offset != 0:
            p = obj + slab_offset + self.ramdump.sizeof("void *")
        else:
            p = obj + slab_inuse
        return p + track_type * track_size

    def print_track(self, ramdump, slab, obj, track_type, out_file):
        p = self.get_track(self.ramdump, slab, obj, track_type)
        track_addrs_offset = self.ramdump.field_offset('struct track', 'addrs')
        start = p + track_addrs_offset
        pointer_size = self.ramdump.sizeof("unsigned long")
        if track_type == 0:
            out_file.write('   ALLOC STACK\n')
        else:
            out_file.write('   FREE STACK\n')
        for i in range(0, 16):
            a = self.ramdump.read_word(start + pointer_size * i)
            if a == 0:
                break
            look = self.ramdump.unwind_lookup(a)
            if look is None:
                return
            symname, offset = look
            out_file.write(
                '      [<{0:x}>] {1}+0x{2:x}\n'.format(a, symname, offset))
        out_file.write('\n')

    def get_nobjects(self, ramdump, page):
        if re.search('3\.0\.\d', self.ramdump.version) is not None:
            n_objects_offset = self.ramdump.field_offset(
                'struct page', 'objects')
            n_objects = self.ramdump.read_halfword(page + n_objects_offset)
            return n_objects
        else:
            # The objects field is now a bit field. This confuses GDB as it thinks the
            # offset is always 0. Work around this for now
            map_count_offset = self.ramdump.field_offset(
                'struct page', '_mapcount')
            count = self.ramdump.read_int(page + map_count_offset)
            if count is None:
                return None
            n_objects = (count >> 16) & 0xFFFF
            return n_objects

    def print_slab(self, ramdump, slab_start, slab, page, out_file):
        p = slab_start
        if page is None:
            return
        n_objects = self.get_nobjects(self.ramdump, page)
        if n_objects is None:
            return
        slab_size_offset = self.ramdump.field_offset(
            'struct kmem_cache', 'size')
        slab_size = self.ramdump.read_int(slab + slab_size_offset)
        if slab_size is None:
            return
        slab_max_offset = self.ramdump.field_offset('struct kmem_cache', 'max')
        slab_max = self.ramdump.read_word(slab + slab_max_offset)
        if slab_max is None:
            return
        bitarray = [0] * slab_max
        addr = page_address(self.ramdump, page)
        self.get_map(self.ramdump, slab, page, bitarray)
        while p < slab_start + n_objects * slab_size:
            idx = self.slab_index(self.ramdump, p, addr, slab)
            bitidx = self.slab_index(self.ramdump, p, addr, slab)
            if bitidx >= len(bitarray) or bitidx < 0:
                return
            if bitarray[bitidx] == 1:
                out_file.write(
                    '   Object {0:x}-{1:x} FREE\n'.format(p, p + slab_size))
            else:
                out_file.write(
                    '   Object {0:x}-{1:x} ALLOCATED\n'.format(p, p + slab_size))
            if self.ramdump.is_config_defined('CONFIG_SLUB_DEBUG_ON'):
                self.print_track(self.ramdump, slab, p, 0, out_file)
                self.print_track(self.ramdump, slab, p, 1, out_file)
            p = p + slab_size

    def print_slab_page_info(self, ramdump, slab, slab_node, start, out_file):
        page = self.ramdump.read_word(start)
        seen = []
        if page == 0:
            return
        slab_lru_offset = self.ramdump.field_offset('struct page', 'lru')
        page_flags_offset = self.ramdump.field_offset('struct page', 'flags')
        slab_node_offset = self.ramdump.field_offset(
            'struct kmem_cache', 'size')
        max_pfn_addr = self.ramdump.addr_lookup('max_pfn')
        max_pfn = self.ramdump.read_word(max_pfn_addr)
        max_page = pfn_to_page(ramdump, max_pfn)
        while page != start:
            if page is None:
                return
            if page in seen:
               return
            if page > max_page:
               return
            seen.append(page)
            page = page - slab_lru_offset
            page_flags = self.ramdump.read_word(page + page_flags_offset)
            page_addr = page_address(self.ramdump, page)
            self.print_slab(self.ramdump, page_addr, slab, page, out_file)
            page = self.ramdump.read_word(page + slab_lru_offset)

    def print_per_cpu_slab_info(self, ramdump, slab, slab_node, start, out_file):
        page = self.ramdump.read_word(start)
        if page == 0:
            return
        page_flags_offset = self.ramdump.field_offset('struct page', 'flags')
        if page is None:
            return
        page_flags = self.ramdump.read_word(page + page_flags_offset)
        page_addr = page_address(self.ramdump, page)
        self.print_slab(self.ramdump, page_addr, slab, page, out_file)

    # based on validate_slab_cache. Currently assuming there is only one numa node
    # in the system because the code to do that correctly is a big pain. This will
    # need to be changed if we ever do NUMA properly.
    def parse(self):
        slab_out = self.ramdump.open_file('slabs.txt')
        original_slab = self.ramdump.addr_lookup('slab_caches')
        per_cpu_offset = self.ramdump.addr_lookup('__per_cpu_offset')
        cpu_present_bits_addr = self.ramdump.addr_lookup('cpu_present_bits')
        cpu_present_bits = self.ramdump.read_word(cpu_present_bits_addr)
        cpus = bin(cpu_present_bits).count('1')
        slab_list_offset = self.ramdump.field_offset(
            'struct kmem_cache', 'list')
        slab_name_offset = self.ramdump.field_offset(
            'struct kmem_cache', 'name')
        slab_node_offset = self.ramdump.field_offset(
            'struct kmem_cache', 'node')
        cpu_cache_page_offset = self.ramdump.field_offset(
            'struct kmem_cache_cpu', 'page')
        cpu_slab_offset = self.ramdump.field_offset(
            'struct kmem_cache', 'cpu_slab')
        slab_partial_offset = self.ramdump.field_offset(
            'struct kmem_cache_node', 'partial')
        slab = self.ramdump.read_word(original_slab)
        while slab != original_slab:
            slab = slab - slab_list_offset
            slab_name_addr = self.ramdump.read_word(slab + slab_name_offset)
            # actually an array but again, no numa
            slab_node_addr = self.ramdump.read_word(slab + slab_node_offset)
            slab_node = self.ramdump.read_word(slab_node_addr)
            slab_name = self.ramdump.read_cstring(slab_name_addr, 48)
            cpu_slab_addr = self.ramdump.read_word(slab + cpu_slab_offset)
            print_out_str('Parsing slab {0}'.format(slab_name))
            slab_out.write(
                '{0:x} slab {1} {2:x}\n'.format(slab, slab_name, slab_node_addr))
            self.print_slab_page_info(
                self.ramdump, slab, slab_node, slab_node_addr + slab_partial_offset, slab_out)
            if self.ramdump.is_config_defined('CONFIG_SLUB_DEBUG'):
               slab_full_offset = self.ramdump.field_offset(
                    'struct kmem_cache_node', 'full')
               self.print_slab_page_info(
                    self.ramdump, slab, slab_node, slab_node_addr + slab_full_offset, slab_out)

            for i in range(0, cpus):
                cpu_slabn_addr = self.ramdump.read_word(cpu_slab_addr, cpu=i)
                self.print_per_cpu_slab_info(
                    self.ramdump, slab, slab_node, cpu_slabn_addr + cpu_cache_page_offset, slab_out)

            slab = self.ramdump.read_word(slab + slab_list_offset)
        print_out_str('---wrote slab information to slabs.txt')
