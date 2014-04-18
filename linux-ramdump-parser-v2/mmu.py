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

from bitops import bm, bvalsel
from register import Register


class MMU(object):

    """Represents an MMU. Does virtual-to-physical address lookups,
    caching the results in a TLB.

    This is an abstract class that should not be used
    directly. Concrete subclasses should override the following
    methods:

    - load_page_tables()

    - page_table_walk(addr)

    - dump_page_tables(file_object)


    Interesting properties that will be set for usage in derived
    classes:

    - ramdump:: The RamDump instance being parsed

    """

    def __init__(self, ramdump):
        self._tlb = {}
        self.ramdump = ramdump
        self.ttbr = None
        self.load_page_tables()

    def virt_to_phys(self, addr, skip_tlb=False, save_in_tlb=True):
        """Do a virtual to physical address lookup and possibly cache the
        result in the "TLB".

        """
        if addr is None:
            return None

        if not skip_tlb:
            if addr in self._tlb:
                return self._tlb[addr]

        phys_addr = self.page_table_walk(addr)

        if save_in_tlb:
            self._tlb[addr] = phys_addr

        return phys_addr

    def load_page_tables(self):
        raise NotImplementedError

    def page_table_walk(self, virt):
        raise NotImplementedError

    def dump_page_tables(self, f):
        raise NotImplementedError


class Armv7MMU(MMU):

    """An MMU for ARMv7 (no LPAE)."""

    def load_page_tables(self):
        self.global_page_table = [0 for i in range(4096)]
        self.secondary_page_tables = [
            [0 for col in range(256)] for row in range(4096)]

        msm_ttbr0 = self.ramdump.phys_offset + 0x4000
        self.ttbr = msm_ttbr0
        virt_address = 0x0
        gb_i = 0
        se_i = 0
        for l1_pte_ptr in range(msm_ttbr0, msm_ttbr0 + (4096 * 4), 4):
            l1_pte = self.ramdump.read_word(l1_pte_ptr, False)
            self.global_page_table[gb_i] = l1_pte
            if l1_pte is None:
                gb_i += 1
                continue
            if (l1_pte & 3) == 0 or (l1_pte & 3) == 3:
                for k in range(0, 256):
                    virt_address += 0x1000
            elif (l1_pte & 3) == 2:
                if ((l1_pte & 0x40000) == 0):
                    l1_pte_counter = l1_pte & 0xFFF00000
                    for k in range(0, 256):
                        virt_address += 0x1000
                        l1_pte_counter += 0x1000
                else:
                    gb_i += 1
                    continue
            elif (l1_pte & 3) == 1:
                l2_pt_desc = l1_pte
                l2_pt_base = l2_pt_desc & (~0x3ff)
                for l2_pte_ptr in range(l2_pt_base, l2_pt_base + (256 * 4), 4):
                    virt_address += 0x1000
                    l2_pt_entry = self.ramdump.read_word(l2_pte_ptr, False)
                    self.secondary_page_tables[gb_i][se_i] = l2_pt_entry
                    se_i += 1
                se_i = 0
            gb_i += 1

    def page_table_walk(self, virt):
        global_offset = bvalsel(31, 20, virt)
        l1_pte = self.global_page_table[global_offset]
        if l1_pte is None:
            return None
        bit18 = (l1_pte & 0x40000) >> 18
        if (bvalsel(1, 0, l1_pte) == 1):
            l2_offset = bvalsel(19, 12, virt)
            l2_pte = self.secondary_page_tables[global_offset][l2_offset]
            if l2_pte is None:
                return None
            if (bvalsel(1, 0, l2_pte) == 2) or (bvalsel(1, 0, l2_pte) == 3):
                entry4kb = (l2_pte & bm(31, 12)) + bvalsel(11, 0, virt)
                return entry4kb
            elif (bvalsel(1, 0, l2_pte) == 1):
                entry64kb = (l2_pte & bm(31, 16)) + bvalsel(15, 0, virt)
                return entry64kb
        if (bvalsel(1, 0, l1_pte) == 2):
            onemb_entry = bm(31, 20) & l1_pte
            onemb_entry += bvalsel(19, 0, virt)
            return onemb_entry

        return 0

    def dump_page_tables(self, f):
        f.write(
            'Dumping page tables is not currently supported for Armv7MMU\n')
        f.flush()


class Armv7LPAEMMU(MMU):

    """An MMU for ARMv7 (with LPAE)"""
    # Descriptor types
    DESCRIPTOR_INVALID = 0x0
    DESCRIPTOR_BLOCK = 0x1
    DESCRIPTOR_TABLE = 0x3
    TL_DESCRIPTOR_RESERVED = 0x1
    TL_DESCRIPTOR_PAGE = 0x3

    def do_fl_sl_level_lookup(self, table_base_address, table_index,
                              input_addr_split, block_split):
        descriptor, addr = self.do_level_lookup(
            table_base_address, table_index,
            input_addr_split)
        if descriptor.dtype == Armv7LPAEMMU.DESCRIPTOR_BLOCK:
            descriptor.add_field('output_address', (39, block_split))
        elif descriptor.dtype == Armv7LPAEMMU.DESCRIPTOR_TABLE:
            # we have bits 39:12 of the next-level table in
            # next_level_base_addr_upper
            descriptor.add_field('next_level_base_addr_upper', (39, 12))
        else:
            raise Exception(
                'Invalid stage 1 first- or second-level translation\ndescriptor: (%s)\naddr: (%s)'
                % (str(descriptor), str(addr))
            )
        return descriptor

    def do_fl_level_lookup(self, table_base_address, table_index,
                           input_addr_split):
        return self.do_fl_sl_level_lookup(table_base_address, table_index,
                                     input_addr_split, 30)

    def do_sl_level_lookup(self, table_base_address, table_index):
        return self.do_fl_sl_level_lookup(table_base_address, table_index,
                                     12, 21)

    def do_tl_level_lookup(self, table_base_address, table_index):
        descriptor, addr = self.do_level_lookup(
            table_base_address, table_index, 12)
        if descriptor.dtype == Armv7LPAEMMU.TL_DESCRIPTOR_PAGE:
            descriptor.add_field('output_address', (39, 12))
        else:
            raise Exception(
                'Invalid stage 1 third-level translation\ndescriptor: (%s)\naddr: (%s)'
                % (str(descriptor), str(addr))
            )
        return descriptor

    def do_level_lookup(self, table_base_address, table_index,
                        input_addr_split):
        """Does a base + index descriptor lookup.

        Returns a tuple with the Register object representing the found
        descriptor and a Register object representing the the computed
        descriptor address.

        """
        n = input_addr_split
        # these Registers are overkill but nice documentation:).
        table_base = Register(table_base_address, base=(39, n))
        descriptor_addr = Register(base=(39, n),
                                   offset=(n - 1, 3))
        descriptor_addr.base = table_base.base
        descriptor_addr.offset = table_index
        descriptor_val = self.read_phys_dword(descriptor_addr.value)
        descriptor = Register(descriptor_val,
                              dtype=(1, 0))
        return descriptor, descriptor_addr

    def block_or_page_desc_2_phys(self, desc, virt_r, n):
        phys = Register(output_address=(39, n),
                        page_offset=(n - 1, 0))
        phys.output_address = desc.output_address
        virt_r.add_field('rest', (n - 1, 0))
        phys.page_offset |= virt_r.rest
        return phys.value

    def fl_block_desc_2_phys(self, desc, virt_r):
        """Block descriptor to physical address."""
        return self.block_or_page_desc_2_phys(desc, virt_r, 30)

    def sl_block_desc_2_phys(self, desc, virt_r):
        """Block descriptor to physical address."""
        return self.block_or_page_desc_2_phys(desc, virt_r, 21)

    def tl_page_desc_2_phys(self, desc, virt_r):
        """Page descriptor to physical address."""
        return self.block_or_page_desc_2_phys(desc, virt_r, 12)

    def read_phys_dword(self, physaddr):
        return self.ramdump.read_dword(physaddr, virtual=False)

    def load_page_tables(self):
        pass

    def __init__(self, ramdump, pgtbl, t1sz, initial_lkup_level):
        super(Armv7LPAEMMU, self).__init__(ramdump)
        self.pgtbl = pgtbl
        self.t1sz = t1sz
        self.initial_lkup_level = initial_lkup_level

    def page_table_walk(self, virt):

        if self.initial_lkup_level == 1:
            # see the ARMv7 ARM B3.6.6 (rev 0406C.b):
            input_addr_split = 5 - self.t1sz
            if input_addr_split not in [4, 5]:
                raise Exception("Invalid stage 1 first-level `n' value: 0x%x"
                                % input_addr_split)
            virt_r = Register(virt,
                              fl_index=(input_addr_split + 26, 30),
                              sl_index=(29, 21),
                              tl_index=(20, 12),
                              page_index=(11, 0))
            fl_desc = self.do_fl_level_lookup(
                self.pgtbl, virt_r.fl_index, input_addr_split)

            # if we got a block descriptor we're done:
            if fl_desc.dtype == Armv7LPAEMMU.DESCRIPTOR_BLOCK:
                return self.fl_block_desc_2_phys(fl_desc, virt_r)

            base = Register(base=(39, 12))
            base.base = fl_desc.next_level_base_addr_upper
            sl_desc = self.do_sl_level_lookup(
                base.value, virt_r.sl_index)

        elif self.initial_lkup_level == 2:
            # see the ARMv7 ARM B3.6.6 (rev 0406C.b):
            input_addr_split = 14 - self.t1sz
            if input_addr_split not in range(7, 13):
                raise Exception("Invalid stage 1 second-level (initial) `n' value: 0x%x"
                                % input_addr_split)
            virt_r = Register(virt,
                              sl_index=(input_addr_split + 17, 21),
                              tl_index=(20, 12),
                              page_index=(11, 0))
            try:
                sl_desc = self.do_fl_sl_level_lookup(
                    self.pgtbl, virt_r.sl_index, input_addr_split, 21)
            except:
                return None
        else:
            raise Exception('Invalid initial lookup level (0x%x)' %
                            self.initial_lkup_level)

        # if we got a block descriptor we're done:
        if sl_desc.dtype == Armv7LPAEMMU.DESCRIPTOR_BLOCK:
            return self.sl_block_desc_2_phys(sl_desc, virt_r)

        base = Register(base=(39, 12))
        base.base = sl_desc.next_level_base_addr_upper
        try:
            tl_desc = self.do_tl_level_lookup(
                base.value, virt_r.tl_index)
        except:
            return None

        return self.tl_page_desc_2_phys(tl_desc, virt_r)

    def dump_page_tables(self, f):
        f.write(
            'Dumping page tables is not currently supported for Armv7LPAEMMU\n')
        f.flush()

class Armv8MMU(MMU):

    """An MMU for ARMv8 VMSA"""
    # Descriptor types
    DESCRIPTOR_INVALID = 0x0
    DESCRIPTOR_BLOCK = 0x1
    DESCRIPTOR_TABLE = 0x3
    TL_DESCRIPTOR_RESERVED = 0x1
    TL_DESCRIPTOR_PAGE = 0x3

    def do_fl_sl_level_lookup(self, table_base_address, table_index,
                              input_addr_split, block_split):
        descriptor, addr = self.do_level_lookup(
            table_base_address, table_index,
            input_addr_split)
        if descriptor.dtype == Armv8MMU.DESCRIPTOR_BLOCK:
            descriptor.add_field('output_address', (47, block_split))
        elif descriptor.dtype == Armv8MMU.DESCRIPTOR_TABLE:
            # we have bits 39:12 of the next-level table in
            # next_level_base_addr_upper
            descriptor.add_field('next_level_base_addr_upper', (47, 12))
        else:
            raise Exception(
                'Invalid stage 1 first- or second-level translation\ndescriptor: (%s)\naddr: (%s)'
                % (str(descriptor), str(addr))
            )
        return descriptor

    def do_fl_level_lookup(self, table_base_address, table_index,
                           input_addr_split):
        return self.do_fl_sl_level_lookup(table_base_address, table_index,
                                     input_addr_split, 30)

    def do_sl_level_lookup(self, table_base_address, table_index):
        return self.do_fl_sl_level_lookup(table_base_address, table_index,
                                     12, 21)

    def do_tl_level_lookup(self, table_base_address, table_index):
        descriptor, addr = self.do_level_lookup(
            table_base_address, table_index, 12)
        if descriptor.dtype == Armv8MMU.TL_DESCRIPTOR_PAGE:
            descriptor.add_field('output_address', (47, 12))
        else:
            raise Exception(
                'Invalid stage 1 third-level translation\ndescriptor: (%s)\naddr: (%s)'
                % (str(descriptor), str(addr))
            )
        return descriptor

    def do_level_lookup(self, table_base_address, table_index,
                        input_addr_split):
        """Does a base + index descriptor lookup.

        Returns a tuple with the Register object representing the found
        descriptor and a Register object representing the the computed
        descriptor address.

        """
        n = input_addr_split
        # these Registers are overkill but nice documentation:).
        table_base = Register(table_base_address, base=(47, n))
        descriptor_addr = Register(table_base_address, base=(47, n),
                                   offset=(n - 1, 3))
        descriptor_addr.offset = table_index
        descriptor_val = self.read_phys_dword(descriptor_addr.value)
        descriptor = Register(descriptor_val,
                              dtype=(1, 0))
        return descriptor, descriptor_addr

    def block_or_page_desc_2_phys(self, desc, virt_r, n):
        phys = Register(output_address=(47, n),
                        page_offset=(n - 1, 0))
        phys.output_address = desc.output_address
        virt_r.add_field('rest', (n - 1, 0))
        phys.page_offset |= virt_r.rest
        return phys.value

    def fl_block_desc_2_phys(self, desc, virt_r):
        """Block descriptor to physical address."""
        return self.block_or_page_desc_2_phys(desc, virt_r, 30)

    def sl_block_desc_2_phys(self, desc, virt_r):
        """Block descriptor to physical address."""
        return self.block_or_page_desc_2_phys(desc, virt_r, 21)

    def tl_page_desc_2_phys(self, desc, virt_r):
        """Page descriptor to physical address."""
        return self.block_or_page_desc_2_phys(desc, virt_r, 12)

    def read_phys_dword(self, physaddr):
        return self.ramdump.read_dword(physaddr, virtual=False)

    def load_page_tables(self):
        pass

    def page_table_walk(self, virt):

        self.ttbr = self.ramdump.swapper_pg_dir_addr + self.ramdump.phys_offset

        virt_r = Register(virt,
            zl_index=(47,39),
            fl_index=(38,30),
            sl_index=(29,21),
            tl_index=(20,12),
            page_index=(11,0))

	fl_desc = self.do_fl_sl_level_lookup(self.ttbr, virt_r.fl_index, 12, 30)

        if fl_desc.dtype == Armv8MMU.DESCRIPTOR_BLOCK:
            return self.fl_block_desc_2_phys(fl_desc, virt_r)

        base = Register(base=(47, 12))
        base.base = fl_desc.next_level_base_addr_upper
        try:
            sl_desc = self.do_sl_level_lookup(
                base.value, virt_r.sl_index)
        except:
            return None

	if sl_desc.dtype == Armv8MMU.DESCRIPTOR_BLOCK:
            r = self.sl_block_desc_2_phys(sl_desc, virt_r)
            return r

        base.base = sl_desc.next_level_base_addr_upper
        try:
            tl_desc = self.do_tl_level_lookup(base.value, virt_r.tl_index)
        except:
            return None

        r = self.tl_page_desc_2_phys(tl_desc, virt_r)
        return r

    def dump_page_tables(self, f):
        f.write(
            'Dumping page tables is not currently supported for Armv8MMU\n')
        f.flush()
