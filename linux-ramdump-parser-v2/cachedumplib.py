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
import struct
from print_out import print_out_str, print_out_exception

"""dictionary mapping from (hw_id, client_id, version) to class CacheDump"""
lookuptable = {}

def lookup_cache_type(hwid, client_id, version):
    """defaults to CacheDump() if no match found"""
    return lookuptable.get((hwid, client_id, version), CacheDump())

def formatwidth(string, limit):
    if len(string) >= limit:
        return string[0:limit]
    formatstr = '{{0:{0}}}'.format(limit)
    return formatstr.format(string)

class TableOutputFormat:
    """ Not sure if using PrettyTable (python lib) is a good idea, since people
    would need to install it"""

    def __init__(self):
        self.titlebar = []
        self.datafmt = []
        self.have_printed_title = False
        self.separator = ' '

    def addColumn(self, string, datafmt='{0}', width=0):
        width = max(len(string), width)
        string = formatwidth(string, width)
        self.titlebar.append(string)
        self.datafmt.append(datafmt)

    def printline(self, array, outfile):
        if (len(array) != len(self.titlebar)):
            raise Exception('BadTableDataSize', array, self.titlebar)

        if (not self.have_printed_title):
            self.have_printed_title = True
            outfile.write(self.separator.join(self.titlebar))
            outfile.write('\n')

        for item, title, fmt in zip(array, self.titlebar, self.datafmt):
            item = fmt.format(item)
            item = formatwidth(item, len(title))
            outfile.write(item)
            outfile.write(self.separator)

        outfile.write('\n')

class CacheDump(object):
    """ Class to describe a method to parse a particular type of cachedump.
    Users should not make instances of this class."""
    def __init__(self):
        """do nothing"""

    def parse(self, start, end, ramdump, outfile):
        """Called from debug_image_v2.py. Overriden by child classes"""
        raise NotImplementedError

struct_CacheDumpType_v1 = [
    ('<I', 'status0'),     #Status Registers
    ('I', 'status1'),
    ('I', 'status2'),
    ('I', 'status3'),
    ('I', 'TagSize'),     #Tag Size in u32 words
    ('I', 'LineSize'),    #Line Size in u32 words
    ('I', 'NumSets'),     #Number of sets
    ('I', 'NumWays'),     #Number of ways
    ('Q', 'next'),        #unused
    ('I', '__reserved0'),
    ('I', '__reserved1'),
    ('I', '__reserved2'),
    ('I', '__reserved3'),
]
CacheDumpFormatStr_v1 = ''.join(zip(*struct_CacheDumpType_v1)[0])
CacheDumpKeys_v1 = zip(*struct_CacheDumpType_v1)[1]

class CacheDumpType_v1(CacheDump):
    """Uses the format struct_CacheDumpType_v1, followed by an array of raw data"""

    def __init__(self):
        super(CacheDumpType_v1, self).__init__()
        self.tableformat = TableOutputFormat()
        self.tableformat.addColumn('Way', '{0:01x}')
        self.tableformat.addColumn('Set', '{0:03x}')
        self.ramdump = None
        self.linefmt = None
        # used for headers not matching CacheDumpType_v1 format
        self.unsupported_header_offset = -1

        for key in CacheDumpKeys_v1:
            setattr(self, key, None)

    def add_table_data_columns(self):
        for i in range(0, self.LineSize):
            str ="DATA{0}".format(i)
            self.tableformat.addColumn(str, '{0:08x}', 8)

    def read_line(self, start):
        if self.linefmt is None:
            self.linefmt = '<'
            self.linefmt += 'I'*(self.TagSize + self.LineSize)
        return self.ramdump.read_string(start, self.linefmt, virtual=False)

    def parse_tag_fn(output, data, nset, nway):
        """append data elements to output. Overriden by child classes"""
        raise NotImplementedError

    def parse_header(self, start, end):
        """add the information from the header to this object. Returns
        number of bytes read"""

        if self.unsupported_header_offset >= 0:
            return self.unsupported_header_offset

        items = self.ramdump.read_string(start, CacheDumpFormatStr_v1, virtual=False)
        if items is None:
            raise Exception('Unable to read header information')

        for i in range(len(items)):
            setattr(self, CacheDumpKeys_v1[i], items[i])

        struct_size = struct.calcsize(CacheDumpFormatStr_v1)
        size = 0x4 * (self.LineSize + self.TagSize) * self.NumWays * self.NumSets
        size = size + struct_size

        if (size < 0x1000 or size > end - start):
            raise Exception('Unable to read header information')

        return struct_size

    def parse(self, start, end, ramdump, outfile):
        self.ramdump = ramdump

        start = start + self.parse_header(start, end)
        self.add_table_data_columns()

        for nset in range(self.NumSets):
            for nway in range(self.NumWays):
                if start > end:
                    raise Exception('past the end of array')

                output = [nway, nset]
                line = self.read_line(start)
                self.parse_tag_fn(output, line[0:self.TagSize], nset, nway)
                output.extend(line[self.TagSize:])
                self.tableformat.printline(output, outfile)
                start = start + (self.TagSize + self.LineSize) * 0x4

class L1_DCache_A53(CacheDumpType_v1):
    """Refer to ARM documentation:cortex_a53_trm"""
    def __init__(self):
        super(L1_DCache_A53, self).__init__()
        self.tableformat.addColumn('P')
        self.tableformat.addColumn('MOESI')
        self.tableformat.addColumn('RAW_MOESI', '{0:04x}')
        self.tableformat.addColumn('N')
        self.tableformat.addColumn('Addr [39:12]', '{0:016x}', 16)
        self.tableformat.addColumn('P')
        self.tableformat.addColumn('DC', '{0:02b}')
        self.tableformat.addColumn('0A', '{0:02b}')
        self.tableformat.addColumn('0S', '{0:02b}')
        self.unsupported_header_offset = 0
        self.TagSize = 2
        self.LineSize = 16
        self.NumSets = 0x80
        self.NumWays = 4

    def MOESI_to_string(self, num):
        if (num & 0xC == 0x0):
            return 'I'
        if ((num & 0x4 == 0x4) and (num & 0x1 == 0x0)):
            return 'S'
        if ((num & 0x4 == 0x4) and (num & 0x1 == 0x1)):
            return 'O'
        if ((num & 0x8 == 0x8) and (num & 0x1 == 0x0)):
            return 'E'
        if ((num & 0x8 == 0x8) and (num & 0x1 == 0x1)):
            return 'M'

    def parse_tag_fn(self, output, data, nset, nway):
        p1 = (data[1] >> 31) & 0x1
        m1 = (data[1] >> 29) & 0x3
        n = (data[1] >> 28) & 0x1
        addr1 = (data[1] >> 0) & 0xfffffff
        addr2 = (data[0] >> 31) & 0x1
        p2 = (data[0] >> 5) & 0x1
        dc = (data[0] >> 4) & 0x1
        oa = (data[0] >> 3) & 0x1
        os = (data[0] >> 2) & 0x1
        m2 = (data[0] >> 0) & 0x3

        moesi = m1 << 2 | m2
        addr = ((addr1 << 1 | addr2) << 11) | (nset << 6)
        output.append(p1)
        output.append(self.MOESI_to_string(moesi))
        output.append(moesi)
        output.append(n)
        output.append(addr)
        output.append(p2)
        output.append(dc)
        output.append(oa)
        output.append(os)

class L1_DCache_A57(CacheDumpType_v1):
    """Refer to ARM documentation:cortex_a57_trm"""
    def __init__(self):
        super(L1_DCache_A57, self).__init__()
        self.tableformat.addColumn('MESI')
        self.tableformat.addColumn('RAW_MESI', '{0:02}')
        self.tableformat.addColumn('N')
        self.tableformat.addColumn('PA [43:14]', '{0:016x}', 16)
        self.unsupported_header_offset = 0x0
        self.TagSize = 2
        self.LineSize = 16
        self.NumSets = 0x100
        self.NumWays = 2

    def MESI_to_string(self, num):
        if (num == 0x0):
            return 'I'
        elif (num == 0x1):
            return 'E'
        elif (num == 0x2):
            return 'S'
        elif (num == 0x3):
            return 'M'
        else:
            raise Exception('invalid MOESI value:{:x}'.format(num))

    def parse_tag_fn(self, output, data, nset, nway):
        if self.TagSize != 2:
            raise Exception('cache tag size mismatch')

        mesi = (data[1] >> 0) & 0x3
        n = (data[0] >> 30) & 0x1
        addr = (data[0] >> 0) & 0x3fffffff

        addr = (addr << 14) | (nset << 6)
        output.append(self.MESI_to_string(mesi))
        output.append(mesi)
        output.append(n)
        output.append(addr)

class L1_ICache_A57(CacheDumpType_v1):
    """Refer to ARM documentation:cortex_a57_trm"""
    def __init__(self):
        super(L1_ICache_A57, self).__init__()
        self.tableformat.addColumn('VALID')
        self.tableformat.addColumn('N')
        self.tableformat.addColumn('PA [43:12]', '{0:016x}', 16)
        self.unsupported_header_offset = 0
        self.TagSize = 2
        self.LineSize = 16
        self.NumSets = 0x100
        self.NumWays = 2

    def parse_tag_fn(self, output, data, nset, nway):
        if self.TagSize != 2:
            raise Exception('cache tag size mismatch')

        valid = (data[1] >> 1) & 0x1
        n = (data[1] >> 0) & 0x1
        addr = (data[0] >> 0) & 0xffffffff

        addr = (addr << 12) | (nset << 6)
        output.append(valid)
        output.append(n)
        output.append(addr)

class L2_Cache_A57(CacheDumpType_v1):
    """Refer to ARM documentation:cortex_a57_trm"""
    def __init__(self, numsets):
        super(L2_Cache_A57, self).__init__()
        self.tableformat.addColumn('MESI')
        self.tableformat.addColumn('Raw MESI', '{0:02}')
        self.tableformat.addColumn('N')
        self.tableformat.addColumn('PA [43:15]', '{0:016x}', 16)
        self.unsupported_header_offset = 0
        self.TagSize = 4
        self.LineSize = 16
        self.NumSets = numsets
        self.NumWays = 0x10

    def MOESI_to_string(self, num):
        if (num == 0x0):
            return 'I'
        elif (num == 0x1):
            return 'E or M'
        elif (num == 0x2):
            raise Exception('invalid MOESI value:{:x}'.format(num))
        elif (num == 0x3):
            return 'S or O'
        else:
            raise Exception('invalid MOESI value:{:x}'.format(num))

    def parse_tag_fn(self, output, data, nset, nway):
        if self.TagSize != 4:
            raise Exception('cache tag size mismatch')

        n = (data[0] >> 31) & 0x1
        addr = (data[0] >> 2) & 0x1fffffff
        moesi = (data[0] >> 0) & 0x3

        addr = (addr << 15) | (nset << 6)
        output.append(self.MOESI_to_string(moesi))
        output.append(moesi)
        output.append(n)
        output.append(addr)

#8994

lookuptable[(8994, 0x80, 0)] = L1_DCache_A53()
lookuptable[(8994, 0x81, 0)] = L1_DCache_A53()
lookuptable[(8994, 0x82, 0)] = L1_DCache_A53()
lookuptable[(8994, 0x83, 0)] = L1_DCache_A53()
lookuptable[(8994, 0x84, 0)] = L1_DCache_A57()
lookuptable[(8994, 0x85, 0)] = L1_DCache_A57()
lookuptable[(8994, 0x86, 0)] = L1_DCache_A57()
lookuptable[(8994, 0x87, 0)] = L1_DCache_A57()

lookuptable[(8994, 0x64, 0)] = L1_ICache_A57()
lookuptable[(8994, 0x65, 0)] = L1_ICache_A57()
lookuptable[(8994, 0x66, 0)] = L1_ICache_A57()
lookuptable[(8994, 0x67, 0)] = L1_ICache_A57()

lookuptable[(8994, 0xC1, 0)] = L2_Cache_A57(numsets=0x800)

lookuptable[(8994, 0x80, 0x100)] = L1_DCache_A53()
lookuptable[(8994, 0x81, 0x100)] = L1_DCache_A53()
lookuptable[(8994, 0x82, 0x100)] = L1_DCache_A53()
lookuptable[(8994, 0x83, 0x100)] = L1_DCache_A53()
lookuptable[(8994, 0x84, 0x100)] = L1_DCache_A57()
lookuptable[(8994, 0x85, 0x100)] = L1_DCache_A57()
lookuptable[(8994, 0x86, 0x100)] = L1_DCache_A57()
lookuptable[(8994, 0x87, 0x100)] = L1_DCache_A57()

lookuptable[(8994, 0x64, 0x100)] = L1_ICache_A57()
lookuptable[(8994, 0x65, 0x100)] = L1_ICache_A57()
lookuptable[(8994, 0x66, 0x100)] = L1_ICache_A57()
lookuptable[(8994, 0x67, 0x100)] = L1_ICache_A57()

lookuptable[(8994, 0xC1, 0x100)] = L2_Cache_A57(numsets=0x800)


#8992
lookuptable[(8992, 0x80, 0x100)] = L1_DCache_A53()
lookuptable[(8992, 0x81, 0x100)] = L1_DCache_A53()
lookuptable[(8992, 0x82, 0x100)] = L1_DCache_A53()
lookuptable[(8992, 0x83, 0x100)] = L1_DCache_A53()
lookuptable[(8992, 0x84, 0x100)] = L1_DCache_A57()
lookuptable[(8992, 0x85, 0x100)] = L1_DCache_A57()

lookuptable[(8992, 0x64, 0x100)] = L1_ICache_A57()
lookuptable[(8992, 0x65, 0x100)] = L1_ICache_A57()

lookuptable[(8992, 0xC1, 0x100)] = L2_Cache_A57(numsets=0x400)
