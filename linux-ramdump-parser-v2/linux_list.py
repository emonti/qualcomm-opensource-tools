# Copyright (c) 2013-2014, The Linux Foundation. All rights reserved.
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

class ListWalker(object):

    '''
    ram_dump: Reference to the ram dump
    node_addr: The address of the first element of the list
    list_elem_offset: The offset of the list_head in the structure that this list is container for.
    '''

    def __init__(self, ram_dump, node_addr, list_elem_offset):

        self.ram_dump = ram_dump
        self.list_elem_offset = list_elem_offset
        self.last_node = node_addr
        self.seen_nodes = []

    def walk(self, node_addr, func, extra=None):

        while True:
            if node_addr == 0:
                break

            func(node_addr - self.list_elem_offset, extra)

            next_node_addr = node_addr + self.ram_dump.field_offset('struct list_head', 'next')
            next_node = self.ram_dump.read_word(next_node_addr)

            if next_node == self.last_node:
                break

            if next_node in self.seen_nodes:
                print_out_str(
                   '[!] WARNING: Cycle found in attach list. List is corrupted!')
                break
            node_addr = next_node
            self.seen_nodes.append(node_addr)
