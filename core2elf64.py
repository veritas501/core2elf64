#!/usr/bin/env python3
# coding=utf8

import sys
from typing import *
import struct

from elftools.elf import segments
from elftools.elf import elffile
from elftools.elf.structs import ELFStructs
import re

import keystone as ks


class TermColor:
    default = "\033[0m"
    red = "\033[31m"
    green = "\033[32m"
    yellow = "\033[33m"
    purple = "\033[35m"
    underline = "\033[4m"


ELF_HDR = b'\x7fELF'

Data = Union[str, bytes, bytearray]


class Log:
    @staticmethod
    def d(s):
        print("{}[*] {}{}".format(TermColor.default, s, TermColor.default))

    @staticmethod
    def i(s):
        print("{}[+] {}{}".format(TermColor.green, s, TermColor.default))

    @staticmethod
    def e(s):
        print("{}[-] {}{}".format(TermColor.red, s, TermColor.default))

    @staticmethod
    def w(s):
        print("{}[!] {}{}".format(TermColor.yellow, s, TermColor.default))


class DumpException(Exception):
    pass


class UnmapException(Exception):
    pass


class Core2ELF:
    def __init__(self, core_filename: Text, output_filename: Text) -> None:
        Log.d("Parsing core file ....")
        self.in_fp = open(core_filename, 'rb')
        self.out_fp = open(output_filename, 'wb')
        self.out_data = bytearray()
        # parsed result of ELFFile
        self.e_core = elffile.ELFFile(self.in_fp)

        # check input file is a valid core file
        Log.d("Do some small check to core file ...")
        if self.e_core.header.e_type != 'ET_CORE':
            raise DumpException("input file is not Core binary")

        # build struct type
        self.e_struct = ELFStructs(
            self.e_core.little_endian, self.e_core.elfclass)
        self.e_struct.create_basic_structs()
        self.e_struct.create_advanced_structs(
            self.e_core.header.e_type,
            self.e_core.header.e_machine,
            self.e_core.header.e_ident.EI_OSABI,
        )

        # [(vaddr, vaddr_end, offset, length), ...]
        self._vaddr_to_offset_map = []
        self._vaddr_to_offset_initialized = False

        # init keystone
        self.ks_arch = ks.KS_ARCH_X86
        self.ks_mode = ks.KS_MODE_LITTLE_ENDIAN if self.e_core.little_endian \
            else ks.KS_MODE_BIG_ENDIAN
        if self.e_core.header.e_machine == 'EM_X86_64':
            self.ks_arch = ks.KS_ARCH_X86
            self.ks_mode |= ks.KS_MODE_64
        elif self.e_core.header.e_machine == 'EM_386':
            self.ks_arch = ks.KS_ARCH_X86
            self.ks_mode |= ks.KS_MODE_32
        else:
            raise DumpException("Unsupported binary")
        self.ks = ks.Ks(self.ks_arch, self.ks_mode)

    def _vaddr_to_offset(self, addr: int) -> int:
        if not self._vaddr_to_offset_initialized:
            raise DumpException("vaddr to offset map is not initialized")
        for vaddr, vaddr_end, offset, length in self._vaddr_to_offset_map:
            if vaddr <= addr < vaddr + length:
                return offset + (addr - vaddr)

        raise UnmapException("vaddr 0x{0:016x} is not mapped", addr)

    def _offset_to_vaddr(self, offset: int) -> int:
        if not self._vaddr_to_offset_initialized:
            raise DumpException("vaddr to offset map is not initialized")

        for vaddr, vaddr_end, _offset, length in self._vaddr_to_offset_map:
            if _offset <= offset < _offset + length:
                return vaddr + (offset - _offset)

        raise UnmapException("offset 0x{0:016x} is not mapped", offset)

    def _check_elf_header(self, segment: segments.Segment) -> bool:
        """
        try to check if this segment contains elf header
        """
        if segment.header.p_type != 'PT_LOAD':
            return False
        return segment.data()[:4] == ELF_HDR

    def _write_at_offset(self, off: int, data: Data) -> None:
        if off < 0:
            raise DumpException(
                "cover_binary_data offset < 0, offset: {}".format(off))
        if isinstance(data, str):
            data = data.encode("latin-1")
        if off > len(self.out_data):
            self.out_data += b'\x00' * (off - len(self.out_data))
        self.out_data[off:off + len(data)] = bytearray(data)

    def _read_mem(self, vaddr: int, size: int) -> bytes:
        e = self.e_core
        read_size = size
        read_start = vaddr
        read_end = read_start + read_size
        ans = bytearray()
        while read_size:
            for i in range(e.num_segments()):
                seg = e.get_segment(i)
                if seg.header.p_vaddr <= read_start < seg.header.p_vaddr + seg.header.p_memsz:
                    tmp_read_size = min(
                        read_end, seg.header.p_vaddr + seg.header.p_memsz) - read_start
                    read_offset = read_start - seg.header.p_vaddr
                    ans += seg.data()[read_offset:read_offset + tmp_read_size]
                    read_start += tmp_read_size
                    read_size -= tmp_read_size
                    break
            else:
                raise DumpException(
                    "can't find target vaddr: 0x{0:016x}".format(read_start))

        return bytes(ans)

    def _write_out(self) -> None:
        """
        write rebuilt ELF out to file
        """
        self.out_fp.write(self.out_data)
        self.out_fp.close()

    def _align_page(self, vaddr, pagesize=0x1000) -> None:
        """
        align address to page end
        e.g. 0x1200 -> 2000, 0x3000 -> 0x3000
        """
        return (vaddr + (pagesize - 1)) - (vaddr + (pagesize - 1)) % pagesize

    def _auto_next_segment(self, length: int, prot: int):
        aligned_file_end = self._align_page(
            len(self.out_data)) + self.d_main_base
        next_segment_addr = aligned_file_end
        if not self._vaddr_to_offset_initialized:
            raise DumpException("vaddr to offset map is not initialized")
        for seg_start, seg_end, _, _ in self._vaddr_to_offset_map:
            if seg_start > aligned_file_end:
                continue
            next_segment_addr = max(next_segment_addr, seg_end)

        phdr = self.e_struct.Elf_Phdr
        ans = phdr.parse(b'\x00' * phdr.sizeof())
        ans.p_type = 'PT_LOAD'
        ans.p_flags = prot
        ans.p_offset = next_segment_addr - self.d_main_base
        ans.p_vaddr = next_segment_addr - self.d_dyn_base
        ans.p_paddr = next_segment_addr - self.d_dyn_base
        ans.p_filesz = length
        ans.p_memsz = length
        ans.p_align = 0x1000

        self._write_at_offset(ans.p_offset, b'\x00' * ans.p_filesz)
        return ans

    def _alloc_new_segment_for_phdr(self):
        # if capacity is enough
        if self.d_phdr_capacity >= self.d_phdr_elem_size * (self.d_phdr_elem_cnt + 1):
            return self.d_phdr_offset

        new_capacity = self._align_page(
            self.d_phdr_elem_size * (self.d_phdr_elem_cnt + 1))
        phdr_seg = self._auto_next_segment(new_capacity, 5)
        self._write_at_offset(phdr_seg.p_offset, b'\x00' * phdr_seg.p_filesz)

        # update phdr
        for phdr in self.d_phdr:
            if phdr.p_type == 'PT_PHDR':
                # update PT_PHDR
                phdr.p_offset = phdr_seg.p_offset
                phdr.p_paddr = phdr_seg.p_paddr
                phdr.p_vaddr = phdr_seg.p_vaddr
                phdr.p_filesz += self.d_ehdr.e_phentsize
                phdr.p_memsz += self.d_ehdr.e_phentsize

        self.d_phdr.append(phdr_seg)

        self.d_phdr_capacity = new_capacity
        self.d_phdr_elem_cnt += 1
        self.d_phdr_offset = phdr_seg.p_offset

        # update ehdr
        self.d_ehdr.e_phoff = phdr_seg.p_offset
        self.d_ehdr.e_phnum += 1

        # update vaddr to offset map
        if not self._vaddr_to_offset_initialized:
            raise DumpException("vaddr to offset map is not initialized")
        seg_vaddr = phdr_seg.p_vaddr + self.d_dyn_base
        seg_offset = phdr_seg.p_offset
        seg_size = phdr_seg.p_filesz
        seg_v_size = self._align_page(phdr_seg.p_memsz, phdr_seg.p_align)
        seg_vaddr_end = seg_vaddr + seg_v_size
        self._vaddr_to_offset_map.append(
            (seg_vaddr, seg_vaddr_end, seg_offset, seg_size))

        return self.d_phdr_offset

    def _add_segment(self, addr: int = 0, length: int = 0x1000, prot: int = 7) -> int:
        # if capacity is not enough
        if self.d_phdr_capacity < self.d_phdr_elem_size * (self.d_phdr_elem_cnt + 1):
            # increment element count temporarily
            self.d_phdr_elem_cnt += 1
            self._alloc_new_segment_for_phdr()
            self.d_phdr_elem_cnt -= 1

        if not addr:
            # auto next segment
            new_seg = self._auto_next_segment(length, prot)
        else:
            phdr = self.e_struct.Elf_Phdr
            new_seg = phdr.parse(b'\x00' * phdr.sizeof())
            new_seg.p_type = 'PT_LOAD'
            new_seg.p_flags = prot
            new_seg.p_offset = self._align_page(self.out_data)
            new_seg.p_vaddr = addr
            new_seg.p_paddr = addr
            new_seg.p_filesz = length
            new_seg.p_memsz = length
            new_seg.p_align = 0x1000
        self._write_at_offset(new_seg.p_offset, b'\x00' * new_seg.p_filesz)

        # update phdr
        for phdr in self.d_phdr:
            if phdr.p_type == 'PT_PHDR':
                phdr.p_filesz += self.d_ehdr.e_phentsize
                phdr.p_memsz += self.d_ehdr.e_phentsize
        self.d_phdr.append(new_seg)
        self.d_phdr_elem_cnt += 1

        # update ehdr
        self.d_ehdr.e_phnum += 1

        # update vaddr to offset map
        if not self._vaddr_to_offset_initialized:
            raise DumpException("vaddr to offset map is not initialized")
        seg_vaddr = new_seg.p_vaddr + self.d_dyn_base
        seg_offset = new_seg.p_offset
        seg_size = new_seg.p_filesz
        seg_v_size = self._align_page(new_seg.p_memsz, new_seg.p_align)
        seg_vaddr_end = seg_vaddr + seg_v_size
        self._vaddr_to_offset_map.append(
            (seg_vaddr, seg_vaddr_end, seg_offset, seg_size))

        return seg_vaddr

    def _dump_headers(self) -> None:
        """
        print core segments and let user choose which segment to dump
        """
        Log.d("Print segments from core file ...")
        print("\nIndex  Type     Virt. addr. start    Virt. addr. end     Flags")
        for i in range(self.e_core.num_segments()):
            seg = self.e_core.get_segment(i)
            seg_type = seg.header.p_type.replace("PT_", "")
            seg_vaddr = seg.header.p_vaddr
            seg_size = seg.header.p_memsz
            perm_r = (seg.header.p_flags & 0b100) != 0
            perm_w = (seg.header.p_flags & 0b010) != 0
            perm_x = (seg.header.p_flags & 0b001) != 0
            has_elf_header = self._check_elf_header(seg)

            if perm_r and perm_w and perm_x:
                term_color = TermColor.red + TermColor.underline
            elif perm_r and perm_x:
                term_color = TermColor.red
            elif perm_r and perm_w:
                term_color = TermColor.purple
            else:
                term_color = TermColor.default
            print("{0}[{1:3d}]  {2:8s} 0x{3:016x} - 0x{4:016x}  {5}{6}{7}  {8}{9}".format(
                term_color,
                i, seg_type, seg_vaddr, seg_vaddr + seg_size,
                'R' if perm_r else '-',
                'W' if perm_w else '-',
                'X' if perm_x else '-',
                "( find elf header )" if has_elf_header else "",
                TermColor.default
            ))

        print("")

        Log.d("Please specify a text segment index (usually the first segment contains elf header)")
        seg_index = int(input("> "))
        if not self._check_elf_header(self.e_core.get_segment(seg_index)):
            raise DumpException(
                "The segment you choose doesn't have elf header, this tool can't dump elf from it")
        print("")

        # dump ehdr, phdr, segments
        self.d_main_seg: segments.Segment = self.e_core.get_segment(seg_index)
        self.d_ehdr = self.e_struct.Elf_Ehdr.parse(self.d_main_seg.data())
        self.d_ehdr.e_shoff = 0
        self.d_ehdr.e_shnum = 0
        entry_point = self.d_ehdr.e_entry
        Log.d("found entry point: 0x{:016x}".format(entry_point))

        # do some check to ehdr
        if self.d_ehdr.e_type not in ('ET_EXEC', 'ET_DYN'):
            raise DumpException(
                "dump file has unsupported file type: {}".format(self.d_ehdr.e_type))

        self.d_main_base = self.d_main_seg.header.p_vaddr
        self.d_is_dyn_elf = self.d_ehdr.e_type == 'ET_DYN'
        self.d_dyn_base = self.d_main_base if self.d_is_dyn_elf else 0
        if self.d_is_dyn_elf:
            Log.d("dynamic elf, base: 0x{:016x}".format(self.d_dyn_base))

        # searching phdr
        self.d_phdr_offset = self.d_ehdr.e_phoff
        self.d_phdr_elem_size = self.d_ehdr.e_phentsize
        self.d_phdr_elem_cnt = self.d_ehdr.e_phnum
        self.d_phdr_capacity = self.d_phdr_elem_size * self.d_phdr_elem_cnt
        self.d_phdr = []
        self.d_dynamic_phdr = None
        for i in range(self.d_phdr_elem_cnt):
            data = self._read_mem(self.d_main_base + self.d_phdr_offset + self.d_phdr_elem_size * i,
                                  self.d_phdr_elem_size)
            phdr = self.e_struct.Elf_Phdr.parse(data)
            if phdr.p_type == 'PT_DYNAMIC':
                self.d_dynamic_phdr = phdr
            self.d_phdr.append(phdr)

    def _dump_segments(self) -> None:
        # dump all segments and build vaddr_to_offset_map
        Log.d("Dump ELF segments ...")
        for phdr in self.d_phdr:
            if phdr.p_type == 'PT_LOAD':
                seg_vaddr = self.d_dyn_base + phdr.p_vaddr
                seg_size = phdr.p_filesz
                seg_vaddr_end = self._align_page(
                    seg_vaddr + phdr.p_memsz, phdr.p_align)
                seg_data = self._read_mem(seg_vaddr, seg_size)

                perm_r = (phdr.p_flags & 0b100) != 0
                perm_w = (phdr.p_flags & 0b010) != 0
                perm_x = (phdr.p_flags & 0b001) != 0
                if perm_r and perm_w and perm_x:
                    term_color = TermColor.red + TermColor.underline
                elif perm_r and perm_x:
                    term_color = TermColor.red
                elif perm_r and perm_w:
                    term_color = TermColor.purple
                else:
                    term_color = TermColor.default
                print("{}0x{:016x} - 0x{:016x}  {}{}{}{}".format(
                    term_color,
                    seg_vaddr, seg_vaddr_end,
                    'R' if perm_r else '-',
                    'W' if perm_w else '-',
                    'X' if perm_x else '-',
                    TermColor.default
                ))

                self._write_at_offset(phdr.p_offset, seg_data)
                self._vaddr_to_offset_map.append(
                    (seg_vaddr, seg_vaddr_end, phdr.p_offset, seg_size))
        self._vaddr_to_offset_initialized = True

        Log.i("Dump segments success")
        print("")

    def _fix_dynamic(self) -> None:
        Log.d("Try to fix dynamic table ...")

        self.d_dynamic = []
        if not self.d_dynamic_phdr:
            Log.w("Can't found dynamic table")
            return

        dynamic_vaddr = self.d_dyn_base + self.d_dynamic_phdr.p_vaddr
        seg_size = self.d_dynamic_phdr.p_filesz
        dynamic_data = self._read_mem(dynamic_vaddr, seg_size)
        dynamic_elem_size = self.e_struct.Elf_Dyn.sizeof()

        for i in range(seg_size // dynamic_elem_size):
            dyn = self.e_struct.Elf_Dyn.parse(
                dynamic_data[dynamic_elem_size * i:])
            if dyn.d_tag in ('DT_GNU_HASH', 'DT_STRTAB', 'DT_SYMTAB', 'DT_REL',
                             'DT_PLTGOT', 'DT_JMPREL', 'DT_RELA', 'DT_VERSYM'):
                dyn.d_val -= self.d_dyn_base
                dyn.d_ptr = dyn.d_val
            elif dyn.d_tag in ('DT_DEBUG',):
                dyn.d_val = 0
                dyn.d_ptr = dyn.d_val
            self.d_dynamic.append(dyn)
            dyn_data = self.e_struct.Elf_Dyn.build(dyn)
            self._write_at_offset(
                self.d_dynamic_phdr.p_offset + dynamic_elem_size * i, dyn_data)

        Log.i("Fix dynamic table success")
        print("")

    def _fix_relocation(self) -> None:
        Log.d("Try to fix relocation table ...")

        if not self.d_dynamic:
            Log.w("Dynamic table are missing")
            return

        self.rel_is_rela = False
        
        rel_addr = 0
        rel_size = 0
        rel_elem_size = 0

        for dyn in self.d_dynamic:
            if dyn.d_tag in ['DT_RELA', 'DT_REL']:
                rel_addr = self.d_dyn_base + dyn.d_val
                if dyn.d_tag == 'DT_RELA':
                    self.rel_is_rela = True
            elif dyn.d_tag in ['DT_RELASZ', 'DT_RELSZ']:
                rel_size = dyn.d_val
            elif dyn.d_tag in ['DT_RELAENT', 'DT_RELENT']:
                rel_elem_size = dyn.d_val

        if not (rel_addr and rel_size and rel_elem_size):
            Log.w("Some important dynamic tag are missing, skip relocation fixing")
            return

        self.rel_type = self.e_struct.Elf_Rela if self.rel_is_rela else self.e_struct.Elf_Rel
        rel_cnt = rel_size // rel_elem_size
        for i in range(rel_cnt):
            d = self.rel_type.parse(self._read_mem(
                rel_addr + i * rel_elem_size, rel_elem_size))
            if d.r_info_type in (8, 6):
                addr = self.d_dyn_base + d.r_offset
                if self.rel_is_rela:
                    data = self.e_struct.Elf_sxword(
                        'r_addend').build(d.r_addend)
                    self._write_at_offset(self._vaddr_to_offset(addr), data)

        Log.i("Fix relocation table success")
        print("")

    def _fix_got_x86_64(self, jmprel_addr, rel_cnt, rel_elem_size, plt_got, plt_rel) -> bool:
        offset_type = self.e_struct.Elf_offset('ptr')

        # clear GOT[1] and GOT[2]
        Log.d("clear GOT[1] and GOT[2] ...")
        got1_addr = plt_got + offset_type.sizeof() * 1
        got2_addr = plt_got + offset_type.sizeof() * 2
        self._write_at_offset(self._vaddr_to_offset(
            got1_addr), offset_type.build(0))
        self._write_at_offset(self._vaddr_to_offset(
            got2_addr), offset_type.build(0))

        # search PLT[0] pattern
        Log.d("searching PLT[0] ...")
        find_plt0 = False
        find_plt_vaddr = 0
        find_pos = 0
        while find_pos >= 0:
            find_pos += 2
            # searching for `push cs:[GOT0]`
            find_pos = self.out_data.find(b"\xff\x35", find_pos)
            if find_pos < 0:
                break
            # check PLT[0]
            try:
                find_vaddr = self._offset_to_vaddr(find_pos)
            except UnmapException:
                continue

            expect_asm, _ = self.ks.asm(
                "push [{}]".format(got1_addr), find_vaddr)
            if bytes(expect_asm) == self.out_data[find_pos:find_pos + len(expect_asm)]:
                find_plt_vaddr = find_vaddr
                find_plt0 = True
                break

        if not find_plt0:
            Log.w("Can't find PLT[0], stop GOT fixing")
            return False
        else:
            Log.d("find PLT[0] !")

        approx_plt_size = 0
        if not self._vaddr_to_offset_initialized:
            raise DumpException("vaddr to offset map is not initialized")
        for vaddr, vaddr_end, _, length in self._vaddr_to_offset_map:
            if vaddr <= find_plt_vaddr < vaddr + length:
                approx_plt_size = vaddr + length - find_plt_vaddr
        plt_data = self._read_mem(find_plt_vaddr, approx_plt_size)

        # walk through rel table
        def int_to_re_pattern(num):
            return ''.join(map(lambda x: "\\x{:02x}".format(x), struct.pack("<I", num)))

        Log.d("Walking through rel table ...")
        for i in range(rel_cnt):
            d = self.e_struct.Elf_Rela.parse(self._read_mem(
                jmprel_addr + i * rel_elem_size, rel_elem_size))
            # if d.r_info_type == plt_rel:
            got_addr = d.r_offset + self.d_dyn_base

            # search PLT[i] for this GOT by pattern
            pat = b"(\\xF3\\x0F\\x1E\\xFA)?\\x68" + \
                int_to_re_pattern(i).encode('utf8') + b"(\\xF2)?\\xE9"
            match = re.search(pat, plt_data)
            if not match:
                Log.w("can't find PLT[{}] pattern".format(i))
                return False
            find_pos = find_plt_vaddr + match.start()
            self._write_at_offset(self._vaddr_to_offset(
                got_addr), offset_type.build(find_pos - self.d_dyn_base))

        return True

    def _fix_got_i386(self, jmprel_addr, rel_cnt, rel_elem_size, plt_got, plt_rel) -> bool:
        """
        base on PIE, i386
        """
        offset_type = self.e_struct.Elf_offset('ptr')

        Log.d("clear GOT[1] and GOT[2] ...")
        got_addr = 0
        for dyn in self.d_dynamic:
            if dyn.d_tag == 'DT_PLTGOT':
                got_addr = dyn.d_val + self.d_dyn_base
                break
        if got_addr:
            got1_addr = got_addr + offset_type.sizeof() * 1
            got2_addr = got_addr + offset_type.sizeof() * 2
            self._write_at_offset(self._vaddr_to_offset(
                got1_addr), offset_type.build(0))
            self._write_at_offset(self._vaddr_to_offset(
                got2_addr), offset_type.build(0))

        # search PLT[0] pattern
        Log.d("searching PLT[0] ...")
        find_plt0 = False
        find_plt_vaddr = 0
        find_pos = 0
        while find_pos >= 0:
            find_pos += 2
            # searching for PIE version PLT[0]
            find_pos = self.out_data.find(
                b"\xFF\xB3\x04\x00\x00\x00\xFF\xA3\x08\x00\x00\x00", find_pos)
            if find_pos < 0:
                break
            # check PLT[0]
            try:
                find_vaddr = self._offset_to_vaddr(find_pos)
            except UnmapException:
                continue

            find_plt_vaddr = find_vaddr
            find_plt0 = True
            break

        if not find_plt0:
            Log.w("Can't find PLT[0], stop GOT fixing")
            return False
        else:
            Log.d("find PLT[0] !")

        approx_plt_size = 0
        if not self._vaddr_to_offset_initialized:
            raise DumpException("vaddr to offset map is not initialized")
        for vaddr, vaddr_end, _, length in self._vaddr_to_offset_map:
            if vaddr <= find_plt_vaddr < vaddr + length:
                approx_plt_size = vaddr + length - find_plt_vaddr
        plt_data = self._read_mem(find_plt_vaddr, approx_plt_size)

        # walk through rel table
        def int_to_re_pattern(num):
            return ''.join(map(lambda x: "\\x{:02x}".format(x), struct.pack("<I", num)))

        Log.d("Walking through rel table ...")
        for i in range(rel_cnt):
            d = self.rel_type.parse(self._read_mem(
                jmprel_addr + i * rel_elem_size, rel_elem_size))
            got_elem_addr = d.r_offset + self.d_dyn_base
            # search PLT[i] for this GOT by pattern
            pat = b"(\\xF3\\x0F\\x1E\\xFB)?\\x68" + \
                int_to_re_pattern(i*8).encode('utf8') + b"(\\xF2)?\\xE9"
            match = re.search(pat, plt_data)
            if not match:
                Log.w("can't find PLT[{}] pattern".format(i))
                return False
            find_pos = find_plt_vaddr + match.start()
            self._write_at_offset(self._vaddr_to_offset(
                got_elem_addr), offset_type.build(find_pos - self.d_dyn_base))

        elem_sz = offset_type.sizeof()
        # TODO: ugly .GOT fix, try to fix me 
        if self.d_dyn_base:
            i = 2
            while True:
                i+=1
                got_elem_addr = got_addr + elem_sz * i
                try:
                    val = offset_type.parse(self._read_mem(got_elem_addr, elem_sz))
                except DumpException:
                    break
                try:
                    self._vaddr_to_offset(val)
                except UnmapException:
                    continue
                val -= self.d_dyn_base
                self._write_at_offset(
                    self._vaddr_to_offset(got_elem_addr), offset_type.build(val))

        return True

    def _fix_got_table(self) -> None:
        Log.d("Try to fix GOT table ...")
        if not self.d_dynamic:
            Log.w("Dynamic table are missing")
            return

        jmprel_addr = 0
        rel_size = 0
        rel_elem_size = 0
        plt_rel = 0
        plt_got = 0

        for dyn in self.d_dynamic:
            if dyn.d_tag == 'DT_JMPREL':
                jmprel_addr = dyn.d_val + self.d_dyn_base
            elif dyn.d_tag == 'DT_PLTRELSZ':
                rel_size = dyn.d_val
            elif dyn.d_tag in ['DT_RELAENT', 'DT_RELENT']:
                rel_elem_size = dyn.d_val
            elif dyn.d_tag == 'DT_PLTREL':
                plt_rel = dyn.d_val
            elif dyn.d_tag == 'DT_PLTGOT':
                plt_got = dyn.d_val + self.d_dyn_base

        if not (jmprel_addr and rel_size and rel_elem_size and plt_rel and plt_got):
            Log.w("Some important dynamic tag are missing, skip GOT fixing")
            return

        rel_cnt = rel_size // rel_elem_size
        e_arch = self.d_ehdr.e_machine
        if e_arch == 'EM_X86_64':
            fptr_fix_got = self._fix_got_x86_64
        elif e_arch == 'EM_386':
            fptr_fix_got = self._fix_got_i386
        else:
            Log.w("fix GOT table is currently not supported for arch {}".format(e_arch))
            return

        if not fptr_fix_got(jmprel_addr, rel_cnt, rel_elem_size, plt_got, plt_rel):
            Log.w("fix .got table failed")
            return

        Log.i("Fix GOT table success")
        print("")

    def _add_dummy_section(self) -> None:
        Log.d("Add dummy section, or gdb can't recognize it")

        # add dummy section, or gdb can't recognize it
        shstrtab_str = b"\x00.shstrtab\x00"
        aligned_length = self._align_page(len(shstrtab_str), 0x10)
        shstrtab_str = shstrtab_str.ljust(aligned_length, b'\x00')
        shstrtab_offset = self._align_page(len(self.out_data), 0x10)
        self._write_at_offset(shstrtab_offset, shstrtab_str)

        section_off = self._align_page(len(self.out_data), 0x10)
        sections = []
        shdr = self.e_struct.Elf_Shdr
        dummy_section = shdr.parse(b'\x00' * shdr.sizeof())
        sections.append(dummy_section)
        shstrtab_section = shdr.parse(b'\x00' * shdr.sizeof())
        shstrtab_section.sh_name = shstrtab_str.find(b".shstrtab")
        shstrtab_section.sh_type = 'SHT_STRTAB'
        shstrtab_section.sh_offset = shstrtab_offset
        shstrtab_section.sh_size = len(shstrtab_str)
        sections.append(shstrtab_section)

        for i, section in enumerate(sections):
            section_data = shdr.build(section)
            self._write_at_offset(
                section_off + shdr.sizeof() * i, section_data)

        self.d_ehdr.e_shoff = section_off
        self.d_ehdr.e_shnum = len(sections)
        self.d_ehdr.e_shstrndx = sections.index(shstrtab_section)

        Log.i("Add section success")
        print("")

    def _fix_init_fini(self):
        Log.d("Try to fix .init and .fini table ...")
        if not self.d_dynamic:
            Log.w("Dynamic table are missing")
            return

        init_array = 0
        fini_array = 0
        init_array_cnt = 0
        fini_array_cnt = 0
        elem_type = self.e_struct.Elf_offset('x')
        elem_sz = elem_type.sizeof()

        for dyn in self.d_dynamic:
            if dyn.d_tag == 'DT_INIT_ARRAY':
                init_array = dyn.d_val + self.d_dyn_base
            elif dyn.d_tag == 'DT_FINI_ARRAY':
                fini_array = dyn.d_val + self.d_dyn_base
            elif dyn.d_tag == 'DT_INIT_ARRAYSZ':
                init_array_cnt = dyn.d_val // elem_sz
            elif dyn.d_tag == 'DT_FINI_ARRAYSZ':
                fini_array_cnt = dyn.d_val // elem_sz

        for i in range(init_array_cnt):
            addr = init_array+elem_sz*i
            val = self._read_mem(addr, elem_sz)
            val = elem_type.parse(val)
            val -= self.d_dyn_base
            self._write_at_offset(
                self._vaddr_to_offset(addr), elem_type.build(val))

        for i in range(fini_array_cnt):
            addr = fini_array+elem_sz*i
            val = self._read_mem(addr, elem_sz)
            val = elem_type.parse(val)
            val -= self.d_dyn_base
            self._write_at_offset(
                self._vaddr_to_offset(addr), elem_type.build(val))

        Log.i("fix .init and .fini success")
        print("")

    def dump(self) -> None:
        """
        dump function entrypoint
        """
        self._dump_headers()
        self._dump_segments()
        self._fix_dynamic()
        self._fix_relocation()
        self._fix_got_table()
        self._fix_init_fini()
        self._add_dummy_section()

        # dump phdr
        start_pos = self.d_ehdr.e_phoff
        for i in range(len(self.d_phdr)):
            phdr = self.e_struct.Elf_Phdr.build(self.d_phdr[i])
            self._write_at_offset(start_pos, phdr)
            start_pos += len(phdr)

        # dump header
        dump_hdr_bin = self.e_struct.Elf_Ehdr.build(self.d_ehdr)
        self._write_at_offset(0, dump_hdr_bin)

        self._write_out()

        Log.i("Write out dump elf file success")


def main():
    if len(sys.argv) < 3:
        print("Usage: {} core_filename out_filename".format(sys.argv[0]))
        exit(1)

    in_filename = sys.argv[1]
    out_filename = sys.argv[2]

    try:
        Core2ELF(in_filename, out_filename).dump()
    except DumpException as ex:
        Log.e(str(ex))


if __name__ == "__main__":
    main()
