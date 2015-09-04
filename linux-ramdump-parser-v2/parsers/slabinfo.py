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

import re

from mm import page_address, pfn_to_page
from print_out import print_out_str
from parser_util import register_parser, RamParser

SLAB_RED_ZONE = 0x400
SLAB_POISON = 0x800
SLAB_STORE_USER = 0x10000
OBJECT_POISON = 0x80000000

SLUB_RED_INACTIVE = 0xbb
SLUB_RED_ACTIVE = 0xcc
POISON_INUSE = 0x5a
POISON_FREE = 0x6b
POISON_END = 0xa5

class kmem_cache(object):
    def __init__(self, ramdump, addr):
        self.valid = False

        offset = ramdump.field_offset(
            'struct kmem_cache', 'flags')
        self.flags = ramdump.read_word(addr + offset)
        if self.flags is None:
            return

        offset = ramdump.field_offset(
            'struct kmem_cache', 'size')
        self.size = ramdump.read_int(addr + offset)
        if self.size is None:
            return

        offset = ramdump.field_offset(
            'struct kmem_cache', 'object_size')
        self.object_size = ramdump.read_int(addr + offset)
        if self.object_size is None:
            return

        offset = ramdump.field_offset(
            'struct kmem_cache', 'offset')
        self.offset = ramdump.read_int(addr + offset)
        if self.offset is None:
            return

        offset = ramdump.field_offset(
            'struct kmem_cache', 'max')
        self.max = ramdump.read_word(addr + offset)
        if self.max is None:
            return

        offset = ramdump.field_offset(
            'struct kmem_cache', 'inuse')
        self.inuse = ramdump.read_int(addr + offset)
        if self.inuse is None:
            return

        self.addr = addr
        self.valid = True

@register_parser('--slabinfo', 'print information about slabs', optional=True)
class Slabinfo(RamParser):

    def get_free_pointer(self, ramdump, s, obj):
        # just like validate_slab_slab!
        return self.ramdump.read_word(obj + s.offset)

    def slab_index(self, ramdump, p, addr, slab):
        return (p - addr) / slab.size

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

    def print_section(self, text, addr, length, out_file):
        out_file.write('{}\n'.format(text))
        output = self.ramdump.hexdump(addr, length)
        out_file.write(output)

    def print_trailer(self, s, page, p, out_file):
        addr = page_address(self.ramdump, page)

        if self.ramdump.is_config_defined('CONFIG_SLUB_DEBUG_ON'):
            self.print_track(self.ramdump, s.addr, p, 0, out_file)
            self.print_track(self.ramdump, s.addr, p, 1, out_file)

        out_file.write('INFO: Object 0x{:x} @offset=0x{:x} fp=0x{:x}\n\n'.format(
            p, p - addr, self.get_free_pointer(self.ramdump, s, p)))

        if (p > addr + 16):
            self.print_section('Bytes b4 ', p - 16, 16, out_file)

        self.print_section('Object ', p, min(s.object_size, 4096), out_file)
        if (s.flags & SLAB_RED_ZONE):
            self.print_section('Redzone ', p + s.object_size,
                s.inuse - s.object_size, out_file)

        if (s.offset):
            off = s.offset + self.ramdump.sizeof('void *')
        else:
            off = s.inuse

        if (s.flags & SLAB_STORE_USER):
            off += 2 * self.ramdump.sizeof('struct track')

        if (off != s.size):
            # Beginning of the filler is the free pointer
            self.print_section('Padding ', p + off, s.size - off, out_file)

    def memchr_inv(self, addr, value, size):
        data = self.read_byte_array(addr, size)
        if data is None:
            return 0
        for i in range(len(data)):
            if data[i] != value:
                return i + addr
        return 0

    def check_bytes_and_report(self, s, page, object, what, start,
             value, bytes, out_file):
        fault = self.memchr_inv(start, value, bytes)
        if (not fault):
            return True

        end = start + bytes
        while (end > fault and (self.read_byte_array(end - 1, 1)[0]) == value):
            end -= 1

        out_file.write('{0} overwritten\n'.format(what))
        out_file.write('INFO: 0x{:x}-0x{:x}. First byte 0x{:x} instead of 0x{:x}\n'.format(
            fault, end - 1, self.ramdump.read_byte(fault), value))

        self.print_trailer(s, page, object, out_file)
        return False

    def check_pad_bytes(self, s, page, p, out_file):
        off = s.inuse

        if (s.offset):
            # Freepointer is placed after the object
            off += self.ramdump.sizeof('void *')

        if (s.flags & SLAB_STORE_USER):
            # We also have user information there
            off += 2 * self.ramdump.sizeof('struct track')

        if (s.size == off):
            return True

        return self.check_bytes_and_report(s, page, p, 'Object padding',
            p + off, POISON_INUSE, s.size - off, out_file)

    def check_object(self, s, page, object, val, out_file):
        p = object
        endobject = object + s.object_size

        if (s.flags & SLAB_RED_ZONE):
            if (not self.check_bytes_and_report(s, page, object, 'Redzone',
                endobject, val, s.inuse - s.object_size, out_file)):
                return
        else:
            if ((s.flags & SLAB_POISON) and s.object_size < s.inuse):
                self.check_bytes_and_report(s, page, p, 'Alignment padding',
                    endobject, POISON_INUSE,
                    s.inuse - s.object_size, out_file)

        if (s.flags & SLAB_POISON):
            if (val != SLUB_RED_ACTIVE and (s.flags & OBJECT_POISON) and
                (not self.check_bytes_and_report(s, page, p, 'Poison', p,
                    POISON_FREE, s.object_size - 1, out_file) or
                not self.check_bytes_and_report(s, page, p, 'Poison',
                    p + s.object_size - 1, POISON_END, 1, out_file))):
                return

            # check_pad_bytes cleans up on its own.
            self.check_pad_bytes(s, page, p, out_file)


    def print_slab(self, ramdump, slab_start, slab, page, out_file, map_fn):
        p = slab_start
        if page is None:
            return
        n_objects = self.get_nobjects(self.ramdump, page)
        if n_objects is None:
            return
        bitarray = [0] * slab.max
        addr = page_address(self.ramdump, page)
        self.get_map(self.ramdump, slab, page, bitarray)
        while p < slab_start + n_objects * slab.size:
            idx = self.slab_index(self.ramdump, p, addr, slab)
            bitidx = self.slab_index(self.ramdump, p, addr, slab)
            if bitidx >= len(bitarray) or bitidx < 0:
                return
            map_fn(p, bitarray[bitidx], slab, page, out_file)
            p = p + slab.size

    def print_slab_page_info(self, ramdump, slab, slab_node, start, out_file, map_fn):
        page = self.ramdump.read_word(start)
        seen = []
        if page == 0:
            return
        slab_lru_offset = self.ramdump.field_offset('struct page', 'lru')
        page_flags_offset = self.ramdump.field_offset('struct page', 'flags')
        max_pfn_addr = self.ramdump.address_of('max_pfn')
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
            self.print_slab(self.ramdump, page_addr, slab, page, out_file, map_fn)
            page = self.ramdump.read_word(page + slab_lru_offset)

    def print_per_cpu_slab_info(self, ramdump, slab, slab_node, start, out_file, map_fn):
        page = self.ramdump.read_word(start)
        if page == 0:
            return
        page_flags_offset = self.ramdump.field_offset('struct page', 'flags')
        if page is None:
            return
        page_flags = self.ramdump.read_word(page + page_flags_offset)
        page_addr = page_address(self.ramdump, page)
        self.print_slab(self.ramdump, page_addr, slab, page, out_file, map_fn)

    def print_all_objects(self, p, free, slab, page, out_file):
        if free:
            out_file.write(
                '   Object {0:x}-{1:x} FREE\n'.format(p, p + slab.size))
        else:
            out_file.write(
                '   Object {0:x}-{1:x} ALLOCATED\n'.format(p, p + slab.size))
        if self.ramdump.is_config_defined('CONFIG_SLUB_DEBUG_ON'):
            self.print_track(self.ramdump, slab, p, 0, out_file)
            self.print_track(self.ramdump, slab, p, 1, out_file)

    def print_check_poison(self, p, free, slab, page, out_file):
        if free:
            self.check_object(slab, page, p, SLUB_RED_INACTIVE, out_file)
        else:
            self.check_object(slab, page, p, SLUB_RED_ACTIVE, out_file)

    # based on validate_slab_cache. Currently assuming there is only one numa node
    # in the system because the code to do that correctly is a big pain. This will
    # need to be changed if we ever do NUMA properly.
    def validate_slab_cache(self, slab_out, map_fn):
        original_slab = self.ramdump.address_of('slab_caches')
        cpu_present_bits_addr = self.ramdump.address_of('cpu_present_bits')
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
            slab_obj = kmem_cache(self.ramdump, slab)
            if not slab_obj.valid:
                continue
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
                self.ramdump, slab_obj, slab_node, slab_node_addr + slab_partial_offset, slab_out, map_fn)
            if self.ramdump.is_config_defined('CONFIG_SLUB_DEBUG'):
               slab_full_offset = self.ramdump.field_offset(
                    'struct kmem_cache_node', 'full')
               self.print_slab_page_info(
                    self.ramdump, slab_obj, slab_node, slab_node_addr + slab_full_offset, slab_out, map_fn)

            for i in range(0, cpus):
                cpu_slabn_addr = self.ramdump.read_word(cpu_slab_addr, cpu=i)
                self.print_per_cpu_slab_info(
                    self.ramdump, slab_obj, slab_node, cpu_slabn_addr + cpu_cache_page_offset, slab_out, map_fn)

            slab = self.ramdump.read_word(slab + slab_list_offset)

    def parse(self):
        slab_out = self.ramdump.open_file('slabs.txt')
        self.validate_slab_cache(slab_out, self.print_all_objects)
        print_out_str('---wrote slab information to slabs.txt')

@register_parser('--slabpoison', 'check slab poison', optional=True)
class Slabpoison(Slabinfo):
    """Note that this will NOT find any slab errors which are printed out by the
    kernel, because the slab object is removed from the freelist while being
    processed"""

    # since slabs are relatively "packed", caching has a large
    # performance benefit
    def read_byte_array(self, addr, size):
        page_addr = addr & -0x1000
        end_page_addr = (addr + size) & -0x1000
        # in cache
        if page_addr == end_page_addr and page_addr == self.cache_addr:
            idx = addr - self.cache_addr
            return self.cache[idx:idx + size]
        # accessing only one page
        elif page_addr == end_page_addr:
            fmtstr = '<{}B'.format(4096)
            self.cache = self.ramdump.read_string(page_addr, fmtstr)
            self.cache_addr = page_addr
            idx = addr - self.cache_addr
            return self.cache[idx:idx + size]
        else:
            fmtstr = '<{}B'.format(size)
            return self.ramdump.read_string(addr, fmtstr)

    def parse(self):
        self.cache = None
        self.cache_addr = None
        slab_out = self.ramdump.open_file('slabpoison.txt')
        self.validate_slab_cache(slab_out, self.print_check_poison)
        print_out_str('---wrote slab information to slabpoison.txt')
