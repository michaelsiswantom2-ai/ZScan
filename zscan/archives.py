"""Read archive members in memory so they can be scanned.

Nothing is written to disk and nothing is executed. Limits guard against
zip bombs and huge archives.
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import struct
import tarfile
import warnings
import zipfile
from dataclasses import dataclass
from typing import Iterator

ARCHIVE_TYPES = {"zip", "tar", "gzip", "bzip2", "xz"}
# Recognised, but zscan cannot open them; reported as "not fully scanned".
UNSUPPORTED_ARCHIVES = {"rar": "RAR", "7z": "7-Zip", "zstd": "Zstandard"}
# Finding group for zip-bomb signs: an archive with many bomb-like members is one trait, counted once.
ZIP_BOMB = "zip-bomb"


@dataclass
class Limits:
    max_depth: int = 3            # archive inside archive inside archive
    max_members: int = 10000      # per archive (about 1 ms each)
    max_member_bytes: int = 64 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024   # uncompressed, per top-level file
    # Uncompressed / compressed, for members over 1 MiB. Deflate tops out near 1030:1, which only
    # long runs of one byte reach; images in Office files and game data packs stay far below.
    max_ratio: int = 1000


@dataclass
class Member:
    name: str
    data: bytes | None = None     # None when the member was not read
    note: str | None = None       # why it was not read, or other remark
    encrypted: bool = False
    bomb: int = 0                 # severity of a zip-bomb sign: 3 extreme compression, 4 a forged layout


class Budget:
    """Tracks bytes read across one top-level file and all nested archives."""

    def __init__(self, limits: Limits):
        self.limits = limits
        self.used = 0

    def take(self, n: int) -> bool:
        if self.used + n > self.limits.max_total_bytes:
            return False
        self.used += n
        return True


def iter_members(data: bytes, file_type: str, budget: Budget) -> Iterator[Member]:
    try:
        if file_type == "zip":
            yield from _zip_members(data, budget)
        elif file_type == "tar":
            yield from _tar_members(data, budget)
        else:   # gzip, bzip2, xz: one compressed stream holding one file
            yield from _stream_member(data, file_type, budget)
    except Exception as e:  # noqa: BLE001 - corrupt or hostile archive: keep what was read so far
        yield Member("", note=f"unreadable {file_type}: {type(e).__name__}: {e}")


def _zip_members(data: bytes, budget: Budget) -> Iterator[Member]:
    lim = budget.limits
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = [i for i in zf.infolist() if not i.is_dir()]
    except Exception as e:  # noqa: BLE001
        yield Member("", note=f"unreadable zip: {type(e).__name__}: {e}")
        return
    if len(infos) > lim.max_members:
        yield Member("", note=f"only the first {lim.max_members} of {len(infos)} members scanned")
        infos = infos[:lim.max_members]
    overlap = _zip_overlap(infos)
    if overlap:
        # Entries that share bytes are how "non-recursive" zip bombs are built;
        # no normal zip tool writes them. Don't unpack anything.
        yield Member("", bomb=4, note=f"overlapping entries ({overlap}), not unpacked")
        return
    for info in infos:
        if info.flag_bits & 0x1:
            yield Member(info.filename, encrypted=True, note="password-protected")
            continue
        size, csize = info.file_size, max(info.compress_size, 1)
        if size > 1024 * 1024 and size / csize > lim.max_ratio:
            yield Member(info.filename, bomb=3,
                         note=f"compression ratio {size // csize}:1, not unpacked")
            continue
        if size > lim.max_member_bytes:
            yield Member(info.filename, note=f"larger than {lim.max_member_bytes // 2**20} MiB, skipped")
            continue
        if not budget.take(size):
            yield Member(info.filename, note="archive size budget used up, skipped")
            continue
        _accept_separator_spelling(data, info)
        try:
            # Read at most the declared size + 1 so a lying header cannot blow up memory.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")  # zipfile warns about overlaps; we check for them ourselves
                with zf.open(info) as fh:
                    body = fh.read(size + 1)
            if len(body) > size:
                yield Member(info.filename, bomb=4, note="member larger than its header says")
                continue
            yield Member(info.filename, body)
        except Exception as e:  # noqa: BLE001 - zlib.error, BadZipFile, lzma/bz2 errors, ...
            yield Member(info.filename, note=f"unreadable: {type(e).__name__}: {e}")


def _accept_separator_spelling(data: bytes, info) -> None:
    """Some tools (CryEngine game packs, for one) write a member's name with "\\" in its local
    header and "/" in the central directory. zipfile refuses such a member because the names
    differ. They name the same file, so read it under the header's spelling. Any other
    difference is left for zipfile to refuse."""
    off = info.header_offset
    if data[off:off + 4] != b"PK\x03\x04" or len(data) < off + 30:
        return
    (length,) = struct.unpack_from("<H", data, off + 26)
    try:
        local = data[off + 30:off + 30 + length].decode("utf-8" if info.flag_bits & 0x800 else "cp437")
    except UnicodeDecodeError:
        return
    if local != info.orig_filename and local.replace("\\", "/") == info.orig_filename.replace("\\", "/"):
        info.orig_filename = local


def _zip_overlap(infos) -> str:
    """Name two entries whose stored bytes overlap, or return ''."""
    prev_end, prev_name = 0, ""
    for info in sorted(infos, key=lambda i: i.header_offset):
        if info.header_offset < prev_end:
            return f"{prev_name} and {info.filename}"
        # local header (30 bytes) + file name + compressed data; the extra field only makes it longer
        prev_end = info.header_offset + 30 + len(info.filename.encode("utf-8", "replace")) + info.compress_size
        prev_name = info.filename
    return ""


def _tar_members(data: bytes, budget: Budget) -> Iterator[Member]:
    lim = budget.limits
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    except Exception as e:  # noqa: BLE001
        yield Member("", note=f"unreadable tar: {type(e).__name__}: {e}")
        return
    count = 0
    with tf:
        for info in tf:
            if not info.isfile():
                continue  # skip links, devices, dirs
            count += 1
            if count > lim.max_members:
                yield Member("", note=f"only the first {lim.max_members} members scanned")
                return
            if info.size > lim.max_member_bytes:
                yield Member(info.name, note=f"larger than {lim.max_member_bytes // 2**20} MiB, skipped")
                continue
            if not budget.take(info.size):
                yield Member(info.name, note="archive size budget used up, skipped")
                continue
            fh = tf.extractfile(info)
            yield Member(info.name, fh.read() if fh else b"")


def _open_stream(data: bytes, file_type: str):
    buf = io.BytesIO(data)
    if file_type == "gzip":
        return gzip.GzipFile(fileobj=buf)
    if file_type == "bzip2":
        return bz2.BZ2File(buf)
    return lzma.LZMAFile(buf)


def _stream_member(data: bytes, file_type: str, budget: Budget) -> Iterator[Member]:
    lim = budget.limits
    cap = min(lim.max_member_bytes, lim.max_total_bytes - budget.used)
    if cap <= 0:
        yield Member("(decompressed)", note="archive size budget used up, skipped")
        return
    try:
        with _open_stream(data, file_type) as stream:
            body = stream.read(cap + 1)    # never more than the cap, however big the stream claims to be
    except Exception as e:  # noqa: BLE001 - OSError, EOFError, lzma.LZMAError, ...
        yield Member("", note=f"unreadable {file_type}: {type(e).__name__}: {e}")
        return
    if len(body) > cap:
        ratio = len(body) // max(len(data), 1)
        yield Member("(decompressed)", bomb=3 if ratio > lim.max_ratio else 0,
                     note=f"decompresses to more than {cap // 2**20} MiB, not scanned")
        return
    budget.take(len(body))
    yield Member("(decompressed)", body)
