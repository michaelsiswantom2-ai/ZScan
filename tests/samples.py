"""Harmless test-sample generators. Nothing here is real malware.

Samples are built at test time so the repo itself never contains files that
trip other antivirus products.
"""
import os
import struct

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
