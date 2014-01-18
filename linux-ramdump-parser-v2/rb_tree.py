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

"""
struct rb_node
{
	unsigned long  rb_parent_color;
#define	RB_RED		0
#define	RB_BLACK	1
	struct rb_node *rb_right;
	struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));
"""


class RbTreeWalker(object):

    def __init__(self, ram_dump):
        self.ram_dump = ram_dump
        self.right_offset = self.ram_dump.field_offset(
            'struct rb_node', 'rb_right')
        self.left_offset = self.ram_dump.field_offset(
            'struct rb_node', 'rb_left')

    def walk(self, node, func):
        if node != 0:
            left_node_addr = node + self.left_offset
            left_node = self.ram_dump.read_word(left_node_addr)
            self.walk(left_node, func)

            func(node)

            right_node_addr = node + self.right_offset
            right_node = self.ram_dump.read_word(right_node_addr)
            self.walk(right_node, func)
