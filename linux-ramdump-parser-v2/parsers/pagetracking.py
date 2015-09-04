# Copyright (c) 2012,2014-2015 The Linux Foundation. All rights reserved.
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
from parser_util import register_parser, RamParser
from mm import pfn_to_page, page_buddy

@register_parser('--print-pagetracking', 'print page tracking information (if available)')
class PageTracking(RamParser):

    def parse(self):
        if not self.ramdump.is_config_defined('CONFIG_PAGE_OWNER'):
            return

        min_pfn_addr = self.ramdump.address_of('min_low_pfn')
        max_pfn_addr = self.ramdump.address_of('max_pfn')
        min_pfn = self.ramdump.read_word(
            min_pfn_addr) + (self.ramdump.phys_offset >> 12)
        max_pfn = self.ramdump.read_word(
            max_pfn_addr) + (self.ramdump.phys_offset >> 12)

        order_offset = self.ramdump.field_offset('struct page', 'order')
        flags_offset = self.ramdump.field_offset('struct page', 'flags')
        trace_offset = self.ramdump.field_offset('struct page', 'trace')
        nr_entries_offset = self.ramdump.field_offset(
            'struct stack_trace', 'nr_entries')
        trace_entries_offset = self.ramdump.field_offset(
            'struct page', 'trace_entries')

        out_tracking = self.ramdump.open_file('page_tracking.txt')
        out_frequency = self.ramdump.open_file('page_frequency.txt')
        sorted_pages = {}
        trace_entry_size = self.ramdump.sizeof("unsigned long")

        for pfn in range(min_pfn, max_pfn):
            page = pfn_to_page(self.ramdump, pfn)

            # validate this page is free
            if page_buddy(self.ramdump, page):
                continue

            nr_trace_entries = self.ramdump.read_int(
                page + trace_offset + nr_entries_offset)

            if nr_trace_entries <= 0 or nr_trace_entries > 16:
                continue

            out_tracking.write('PFN 0x{0:x} page 0x{1:x}\n'.format(pfn, page))

            alloc_str = ''
            for i in range(0, nr_trace_entries):
                addr = self.ramdump.read_word(
                    page + trace_entries_offset + i * trace_entry_size)

                if addr == 0:
                    break
                look = self.ramdump.unwind_lookup(addr)
                if look is None:
                    break
                symname, offset = look
                unwind_dat = '      [<{0:x}>] {1}+0x{2:x}\n'.format(addr,
                                                                    symname, offset)
                out_tracking.write(unwind_dat)
                alloc_str = alloc_str + unwind_dat

            if alloc_str in sorted_pages:
                sorted_pages[alloc_str] = sorted_pages[alloc_str] + 1
            else:
                sorted_pages[alloc_str] = 1

            out_tracking.write('\n')

        sortlist = sorted(sorted_pages.iteritems(),
                          key=lambda(k, v): (v), reverse=True)

        for k, v in sortlist:
            out_frequency.write('Allocated {0} times\n'.format(v))
            out_frequency.write(k)
            out_frequency.write('\n')

        out_tracking.close()
        out_frequency.close()
        print_out_str(
            '---wrote page tracking information to page_tracking.txt')
        print_out_str(
            '---wrote page frequency information to page_frequency.txt')
