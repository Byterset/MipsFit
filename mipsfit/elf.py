"""Small, read-only ELF32/MIPS and GNU archive reader."""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Elf:
    def __init__(self, data: bytes, name="ELF"):
        self.data, self.name = data, str(name)
        if data[:4] != b"\x7fELF" or data[4:6] not in (b"\x01\x01", b"\x01\x02"):
            raise ValueError(f"{name}: expected an uncompressed ELF32 file")
        self.endian = "<" if data[5] == 1 else ">"
        header = self.unpack("HHIIIIIHHHHHH", 16)
        self.type, machine, _, self.entry, _, shoff, self.flags, _, _, _, shsize, shnum, shstr = header
        if machine != 8:
            raise ValueError(f"{name}: expected MIPS (e_machine=8)")
        if shsize != 40 or not shnum or shstr >= shnum:
            raise ValueError(f"{name}: unsupported or missing section table")
        self.sections = []
        for i in range(shnum):
            values = self.unpack("IIIIIIIIII", shoff + i * shsize)
            self.sections.append(dict(zip(
                ("name_offset", "type", "flags", "address", "offset", "size", "link", "info", "align", "entsize"), values), index=i))
        strings = self.section_data(self.sections[shstr])
        for section in self.sections:
            section["name"] = self.string(strings, section["name_offset"])
        self.symbols = []
        for section in self.sections:
            if section["type"] != 2:  # SHT_SYMTAB; don't count dynsym aliases twice
                continue
            if section["entsize"] != 16 or section["link"] >= shnum:
                raise ValueError(f"{name}: invalid symbol table")
            strings = self.section_data(self.sections[section["link"]])
            for offset in range(section["offset"], section["offset"] + section["size"], 16):
                stname, address, size, info, other, shndx = self.unpack("IIIBBH", offset)
                symbol = dict(name=self.string(strings, stname), address=address, size=size,
                              type=info & 15, bind=info >> 4, other=other, section=shndx)
                self.symbols.append(symbol)

    @classmethod
    def read(cls, path):
        return cls(Path(path).read_bytes(), path)

    def unpack(self, fmt, offset):
        try:
            return struct.unpack_from(self.endian + fmt, self.data, offset)
        except struct.error as exc:
            raise ValueError(f"{self.name}: truncated ELF") from exc

    @staticmethod
    def string(data, offset):
        if offset >= len(data):
            raise ValueError("ELF string offset out of range")
        end = data.find(b"\0", offset)
        if end < 0:
            raise ValueError("unterminated ELF string")
        return data[offset:end].decode("utf-8", errors="replace")

    def section_data(self, section):
        start, size = section["offset"], section["size"]
        if start + size > len(self.data):
            raise ValueError(f"{self.name}: section outside file")
        return self.data[start:start + size]

    def executable(self):
        return [s for s in self.sections if s["flags"] & 6 == 6 and s["size"]]

    def words(self, address, size):
        for section in self.executable():
            if section["address"] <= address and address + size <= section["address"] + section["size"]:
                start = section["offset"] + address - section["address"]
                return [(address + i, self.unpack("I", start + i)[0]) for i in range(0, size - 3, 4)]
        return []


def input_elfs(path):
    """Yield all ELF members, including currently unreferenced archive members."""
    data = Path(path).read_bytes()
    if data.startswith(b"\x7fELF"):
        yield "", Elf(data, path)
        return
    if not data.startswith(b"!<arch>\n"):
        raise ValueError(f"{path}: expected ELF or ordinary ar archive (thin archives unsupported)")
    offset, names = 8, b""
    while offset < len(data):
        header = data[offset:offset + 60]
        if len(header) != 60 or header[58:60] != b"`\n":
            raise ValueError(f"{path}: malformed archive")
        name = header[:16].decode("ascii").strip()
        size = int(header[48:58])
        body = data[offset + 60:offset + 60 + size]
        if len(body) != size:
            raise ValueError(f"{path}: truncated archive member")
        offset += 60 + size + size % 2
        if name == "//":
            names = body
            continue
        if name in ("/", "/SYM64/"):
            continue
        if name.startswith("#1/"):
            length = int(name[3:])
            name, body = body[:length].decode(), body[length:]
        elif name.startswith("/"):
            idx = int(name[1:])
            end = names.find(b"/\n", idx)
            if end < 0:
                raise ValueError(f"{path}: bad archive long name")
            name = names[idx:end].decode()
        else:
            name = name.rstrip("/")
        if body.startswith(b"\x7fELF"):
            yield name, Elf(body, f"{path}({name})")
