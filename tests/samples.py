"""Harmless test-sample generators. Nothing here is real malware.

Samples are built at test time so the repo itself never contains files that
trip other antivirus products.
"""
import io
import os
import struct
import tarfile
import zipfile

# EICAR assembled from two halves so this source file is not itself flagged.
EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
         b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")


def build_pe(sections, entry_rva=0x1000, timestamp=0x5F000000):
    """Build a tiny, non-runnable PE32 image for parser tests.

    sections: list of (name: bytes, data: bytes, characteristics: int)
    """
    file_align, sect_align = 0x200, 0x1000
    n = len(sections)
    headers_size = 0x40 + 4 + 20 + 224 + 40 * n
    headers_size = (headers_size + file_align - 1) // file_align * file_align

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    file_hdr = struct.pack("<HHIIIHH", 0x14C, n, timestamp, 0, 0, 224, 0x0102)

    sect_hdrs, raw = b"", b""
    va, ptr = sect_align, headers_size
    for name, data, chars in sections:
        raw_size = (len(data) + file_align - 1) // file_align * file_align
        sect_hdrs += struct.pack("<8sIIIIIIHHI", name, max(len(data), 1), va, raw_size,
                                 ptr if raw_size else 0, 0, 0, 0, 0, chars)
        raw += data.ljust(raw_size, b"\x00")
        ptr += raw_size
        va += sect_align
    size_of_image = va

    opt = struct.pack("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
                      0x10B, 14, 0, 0, 0, 0, entry_rva, 0x1000, 0, 0x400000,
                      sect_align, file_align, 6, 0, 0, 0, 6, 0, 0,
                      size_of_image, headers_size, 0, 2, 0,
                      0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"\x00" * (16 * 8)

    hdr = bytes(dos) + b"PE\x00\x00" + file_hdr + opt + sect_hdrs
    return hdr.ljust(headers_size, b"\x00") + raw


CODE_RX = 0x60000020   # code | execute | read
CODE_RWX = 0xE0000020  # code | execute | read | write
DATA_RW = 0xC0000040


def benign_pe():
    return build_pe([(b".text", b"\x90" * 300 + b"\xc3", CODE_RX),
                     (b".data", b"hello world\x00" * 10, DATA_RW)])


def packed_like_pe():
    """Looks like a UPX-packed binary: UPX0/UPX1 names, RWX, random payload, EP in last section."""
    payload = os.urandom(16 * 1024)
    return build_pe([(b"UPX0", b"", CODE_RWX),
                     (b"UPX1", b"UPX!" + payload, CODE_RWX)],
                    entry_rva=0x2000, timestamp=0)


def make_zip(files, compression=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def build_elf(*, bits=64, big=False, load_flags=5, entry=None, text=None, imports=(),
              with_sections=True, shoff_delta=0, etype=2):
    """Tiny, non-runnable ELF image for parser tests.

    One PT_LOAD segment covers the whole file at 0x400000 with `load_flags`
    (R=4, W=2, X=1, so 5 is the normal read+execute). Sections: null, .text,
    optionally .dynsym/.dynstr holding `imports` as undefined symbols, .shstrtab.
    """
    e = ">" if big else "<"
    eh, ph, sh, sym = (64, 56, 64, 24) if bits == 64 else (52, 32, 40, 16)
    base = 0x400000
    text = b"\x90" * 64 + b"\xc3" if text is None else text
    blob = bytearray()
    start = eh + ph

    def add(b):
        off = start + len(blob)
        blob.extend(b)
        return off

    # section table entries: (name, type, flags, offset, size, link, entsize)
    secs = [(b"", 0, 0, 0, 0, 0, 0)]
    secs.append((b".text", 1, 6, add(text), len(text), 0, 0))
    if imports:
        dynstr, offs = b"\0", []
        for name in imports:
            offs.append(len(dynstr))
            dynstr += name.encode() + b"\0"
        syms = bytes(sym)
        for o in offs:  # undefined global functions
            syms += (struct.pack(e + "IBBHQQ", o, 0x12, 0, 0, 0, 0) if bits == 64
                     else struct.pack(e + "IIIBBH", o, 0, 0, 0x12, 0, 0))
        dynstr_index = len(secs) + 1
        secs.append((b".dynsym", 11, 2, add(syms), len(syms), dynstr_index, sym))
        secs.append((b".dynstr", 3, 2, add(dynstr), len(dynstr), 0, 0))
    shstr = b"\0" + b"".join(s[0] + b"\0" for s in secs[1:]) + b".shstrtab\0"
    shstr_off = add(shstr)
    secs.append((b".shstrtab", 3, 0, shstr_off, len(shstr), 0, 0))

    shoff = (start + len(blob) + 7) // 8 * 8
    total = shoff + sh * len(secs) if with_sections else start + len(blob)
    entry = base + start if entry is None else entry

    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 2 if big else 1, 1, 0]) + bytes(8)
    if bits == 64:
        header = struct.pack(e + "HHIQQQIHHHHHH", etype, 62, 1, entry, eh, shoff if with_sections else 0,
                             0, eh, ph, 1, sh, len(secs) if with_sections else 0,
                             len(secs) - 1 if with_sections else 0)
        phdr = struct.pack(e + "IIQQQQQQ", 1, load_flags, 0, base, base, total, total, 0x1000)
    else:
        header = struct.pack(e + "HHIIIIIHHHHHH", etype, 3, 1, entry, eh, shoff if with_sections else 0,
                             0, eh, ph, 1, sh, len(secs) if with_sections else 0,
                             len(secs) - 1 if with_sections else 0)
        phdr = struct.pack(e + "IIIIIIII", 1, 0, base, base, total, total, load_flags, 0x1000)
    out = bytearray(ident + header + phdr + bytes(blob))
    if with_sections:
        out = out.ljust(shoff, b"\0")
        name_pos = 1
        for name, typ, flags, off, size, link, entsize in secs:
            n_off = name_pos if name else 0
            if name:
                name_pos += len(name) + 1
            if bits == 64:
                out += struct.pack(e + "IIQQQQIIQQ", n_off, typ, flags, base + off, off, size, link, 0, 8, entsize)
            else:
                out += struct.pack(e + "IIIIIIIIII", n_off, typ, flags, base + off, off, size, link, 0, 8, entsize)
        if shoff_delta:   # point the section table somewhere past the end of the file
            e_shoff = 40 if bits == 64 else 32
            fmt = e + ("Q" if bits == 64 else "I")
            struct.pack_into(fmt, out, e_shoff, len(out) + shoff_delta)
    return bytes(out)


def make_tar(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()
