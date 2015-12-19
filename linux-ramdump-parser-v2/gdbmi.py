# Copyright (c) 2013-2015, The Linux Foundation. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and
# only version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

import sys
import re
import subprocess

GDB_SENTINEL = '(gdb) '
GDB_DATA_LINE = '~'
GDB_OOB_LINE = '^'


def gdb_hex_to_dec(val):
    match = re.search('(0x[0-9a-fA-F]+)', val)
    return int(match.group(1), 16)


class GdbSymbol(object):

    def __init__(self, symbol, section, addr):
        self.symbol = symbol
        self.section = section
        self.addr = addr


class GdbMIResult(object):

    def __init__(self, lines, oob_lines):
        self.lines = lines
        self.oob_lines = oob_lines


class GdbMIException(Exception):

    def __init__(self, *args):
        self.value = '\n *** '.join([str(i) for i in args])

    def __str__(self):
        return self.value


class GdbMI(object):
    """Interface to the ``gdbmi`` subprocess. This should generally be
    used as a context manager (using Python's ``with`` statement),
    like so::

        >>> with GdbMI(gdb_path, elf) as g:
                print('GDB Version: ' + g.version())
    """

    def __init__(self, gdb_path, elf):
        self.gdb_path = gdb_path
        self.elf = elf
        self._cache = {}
        self._gdbmi = None

    def open(self):
        """Open the connection to the ``gdbmi`` backend. Not needed if using
        ``gdbmi`` as a context manager (recommended).

        """
        self._gdbmi = subprocess.Popen(
            [self.gdb_path, '--interpreter=mi2', self.elf],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE
        )
        self._flush_gdbmi()

    def close(self):
        """Close the connection to the ``gdbmi`` backend. Not needed if using
        ``gdbmi`` as a context manager (recommended).

        """
        self._gdbmi.communicate('quit')

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, ex_type, ex_value, ex_traceback):
        self.close()

    def _flush_gdbmi(self):
        while True:
            line = self._gdbmi.stdout.readline().rstrip('\r\n')
            if line == GDB_SENTINEL:
                break

    def _run(self, cmd, skip_cache=False, save_in_cache=True):
        """Runs a gdb command and returns a GdbMIResult of the result. Results
        are cached (unless skip_cache=True) for quick future lookups.

        - cmd: Command to run (e.g. "show version")
        - skip_cache: Don't use a previously cached result
        - save_in_cache: Whether we should save this result in the cache

        """
        if self._gdbmi is None:
            raise Exception(
                'BUG: GdbMI not initialized. ' +
                'Please use GdbMI.open or a context manager.')

        if not skip_cache:
            if cmd in self._cache:
                return GdbMIResult(self._cache[cmd], [])

        self._gdbmi.stdin.write(cmd.rstrip('\n') + '\n')
        self._gdbmi.stdin.flush()

        output = []
        oob_output = []
        while True:
            line = self._gdbmi.stdout.readline().rstrip('\r\n')
            if line == GDB_SENTINEL:
                break
            if line.startswith(GDB_DATA_LINE):
                # strip the leading "~"
                line = line[1:]
                # strip the leading and trailing "
                line = line[1:-1]
                # strip any trailing (possibly escaped) newlines
                if line.endswith('\\n'):
                    line = line[:-2]
                elif line.endswith('\n'):
                    line = line.rstrip('\n')
                output.append(line)
            if line.startswith(GDB_OOB_LINE):
                oob_output.append(line[1:])

        if save_in_cache:
            self._cache[cmd] = output

        return GdbMIResult(output, oob_output)

    def _run_for_one(self, cmd):
        result = self._run(cmd)
        if len(result.lines) != 1:
            raise GdbMIException(
                cmd, '\n'.join(result.lines + result.oob_lines))
        return result.lines[0]

    def _run_for_first(self, cmd):
        return self._run(cmd).lines[0]

    def version(self):
        """Return GDB version"""
        return self._run_for_first('show version')

    def field_offset(self, the_type, field):
        """Returns the offset of a field in a struct or type.

        Example:

        >>> gdbmi.field_offset("struct ion_buffer", "heap")
        20

        ``the_type``
           struct or type (note that if it's a struct you should
           include the word ``"struct"`` (e.g.: ``"struct
           ion_buffer"``))

        ``field``
           the field whose offset we want to return

        """
        cmd = 'print /x (int)&(({0} *)0)->{1}'.format(the_type, field)
        result = self._run_for_one(cmd)
        return gdb_hex_to_dec(result)

    def container_of(self, ptr, the_type, member):
        """Like ``container_of`` from the kernel."""
        return ptr - self.field_offset(the_type, member)

    def sibling_field_addr(self, ptr, parent_type, member, sibling):
        """Returns the address of a sibling field within the parent
        structure.

        Example:

        Given a dump containing an instance of the following struct::

            struct pizza {
                int price;
                int qty;
            };

        If you have a pointer to qty, you can get a pointer to price with:

        >>> addr = sibling_field_addr(qty, 'struct pizza', 'qty', 'price')
        >>> price = dump.read_int(addr)
        >>> price
        10
        """
        return self.container_of(ptr, parent_type, member) + \
            self.field_offset(parent_type, sibling)

    def sizeof(self, the_type):
        """Returns the size of the type specified by ``the_type``."""
        result = self._run_for_one('print /x sizeof({0})'.format(the_type))
        return gdb_hex_to_dec(result)

    def address_of(self, symbol):
        """Returns the address of the specified symbol.

        >>> hex(dump.address_of('linux_banner'))
        '0xc0b0006a'
        """
        result = self._run_for_one('print /x &{0}'.format(symbol))
        return int(result.split(' ')[-1], 16)

    def get_symbol_info(self, address):
        """Returns a GdbSymbol representing the nearest symbol found at
        ``address``."""
        result = self._run_for_one('info symbol ' + hex(address))
        parts = result.split(' ')
        if len(parts) < 2:
            raise GdbMIException('Output looks bogus...', result)
        symbol = parts[0]
        section = parts[-1]
        return GdbSymbol(symbol, section, address)

    def symbol_at(self, address):
        """Get the symbol at the given address (using ``get_symbol_info``)"""
        return self.get_symbol_info(address).symbol

    def get_enum_lookup_table(self, enum, upperbound):
        """Return a table translating enum values to human readable
        strings.

        >>> dump.gdbmi.get_enum_lookup_table('ion_heap_type', 10)
        ['ION_HEAP_TYPE_SYSTEM',
         'ION_HEAP_TYPE_SYSTEM_CONTIG',
         'ION_HEAP_TYPE_CARVEOUT',
         'ION_HEAP_TYPE_CHUNK',
         'ION_HEAP_TYPE_CUSTOM',
         'ION_NUM_HEAPS',
         '6',
         '7',
         '8',
         '9']
        """
        table = []
        for i in range(0, upperbound):
            result = self._run_for_first(
                'print ((enum {0}){1})'.format(enum, i))
            parts = result.split(' ')
            if len(parts) < 3:
                raise GdbMIException(
                    "can't parse enum {0} {1}\n".format(enum, i), result)
            table.append(parts[2].rstrip())

        return table

    def get_func_info(self, address):
        """Returns the function info at a particular address, specifically
        line and file.

        >>> dump.gdbmi.get_func_info(dump.gdbmi.address_of('panic'))
        'Line 78 of \\"kernel/kernel/panic.c\\"'

        """
        result = self._run_for_one('info line *0x{0:x}'.format(address))
        m = re.search(r'(Line \d+ of \\?\".*\\?\")', result)
        if m is not None:
            return m.group(0)
        else:
            return '(unknown info for address 0x{0:x})'.format(address)

    def get_value_of(self, symbol):
        """Returns the value of a symbol (in decimal)"""
        result = self._run_for_one('print /d {0}'.format(symbol))
        return int(result.split(' ')[-1], 10)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: gdbmi.py gdb_path elf')
        sys.exit(1)

    gdb_path, elf = sys.argv[1:]

    with GdbMI(gdb_path, elf) as g:
        print('GDB Version: ' + g.version())
        print('ion_buffer.heap offset: ' + str(g.field_offset('struct ion_buffer', 'heap')))
        print('atomic_t.counter offset: ' + str(g.field_offset('atomic_t', 'counter')))
        print('sizeof(struct ion_buffer): ' + str(g.sizeof('struct ion_buffer')))
        addr = g.address_of('kernel_config_data')
        print('address of kernel_config_data: ' + hex(addr))
        symbol = g.get_symbol_info(addr)
        print('symbol at ' + hex(addr) + ' : ' + symbol.symbol + \
            ' which is in section ' + symbol.section)
