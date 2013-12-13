# Copyright (c) 2013, The Linux Foundation. All rights reserved.
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

'''
struct list_head {
	struct list_head *next, *prev;
};
'''


def get_list_offsets(ram_dump):
    next_offset = ram_dump.field_offset('struct list_head', 'next')
    prev_offset = ram_dump.field_offset('struct list_head', 'prev')
    return next_offset, prev_offset


class ListWalker(object):

    '''
    ram_dump: Reference to the ram dump
    node_addr: The address of the first element of the list
    list_elem_offset: The offset of the list_head in the structure that this list is container for.
    next_offset: The offset for the next pointer in the list
    prev_offset: The offset for the prev pointer in the list
    '''

    def __init__(self, ram_dump, node_addr, list_elem_offset, next_offset, prev_offset):
        self.LIST_OFFSETS = [
            ('((struct list_head *)0x0)', 'next', 0, 0),
            ('((struct list_head *)0x0)', 'prev', 0, 0),
        ]
        self.LIST_NEXT_IDX = 0
        self.LIST_PREV_IDX = 1

        self.ram_dump = ram_dump
        self.next_offset = next_offset
        self.prev_offset = prev_offset
        self.list_elem_offset = list_elem_offset

        self.last_node = node_addr
        self.seen_nodes = []

    def walk(self, node_addr, func):
        if node_addr != 0:
            func(node_addr - self.list_elem_offset)

            next_node_addr = node_addr + self.next_offset
            next_node = self.ram_dump.read_word(next_node_addr)

            if next_node != self.last_node:
                if next_node in self.seen_nodes:
                    print_out_str(
                        '[!] WARNING: Cycle found in attach list for IOMMU domain. List is corrupted!')
                else:
                    self.seen_nodes.append(node_addr)
                    self.walk(next_node, func)
