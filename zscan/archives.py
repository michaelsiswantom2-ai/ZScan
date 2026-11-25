"""Read archive members in memory so they can be scanned.

Nothing is written to disk and nothing is executed. Limits guard against
zip bombs and huge archives.
"""
from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from dataclasses import dataclass
from typing import Iterator

ARCHIVE_TYPES = {"zip", "tar", "gzip"}


@dataclass
class Limits:
    max_depth: int = 3            # archive inside archive inside archive
    max_members: int = 2000       # per archive
    max_member_bytes: int = 64 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024   # uncompressed, per top-level file
    max_ratio: int = 200          # uncompressed / compressed, for members over 1 MiB


@dataclass
class Member:
    name: str
    data: bytes | None = None     # None when the member was not read
    note: str | None = None       # why it was not read, or other remark
    encrypted: bool = False
    bomb: bool = False


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
    if file_type == "zip":
        yield from _zip_members(data, budget)
    elif file_type == "tar":
        yield from _tar_members(data, budget)
    elif file_type == "gzip":
        yield from _gzip_member(data, budget)


def _zip_members(data: bytes, budget: Budget) -> Iterator[Member]:
    lim = budget.limits
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = [i for i in zf.infolist() if not i.is_dir()]
    except (zipfile.BadZipFile, ValueError, NotImplementedError) as e:
        yield Member("", note=f"unreadable zip: {e}")
        return
    if len(infos) > lim.max_members:
        yield Member("", note=f"only the first {lim.max_members} of {len(infos)} members scanned")
        infos = infos[:lim.max_members]
    for info in infos:
        if info.flag_bits & 0x1:
            yield Member(info.filename, encrypted=True, note="password-protected")
            continue
        size, csize = info.file_size, max(info.compress_size, 1)
        if size > 1024 * 1024 and size / csize > lim.max_ratio:
            yield Member(info.filename, bomb=True,
                         note=f"compression ratio {size // csize}:1, not unpacked")
            continue
        if size > lim.max_member_bytes:
            yield Member(info.filename, note=f"larger than {lim.max_member_bytes // 2**20} MiB, skipped")
            continue
        if not budget.take(size):
            yield Member(info.filename, note="archive size budget used up, skipped")
            continue
        try:
            # Read at most the declared size + 1 so a lying header cannot blow up memory.
            with zf.open(info) as fh:
                body = fh.read(size + 1)
            if len(body) > size:
                yield Member(info.filename, bomb=True, note="member larger than its header says")
                continue
            yield Member(info.filename, body)
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, EOFError) as e:
            yield Member(info.filename, note=f"unreadable: {e}")


def _tar_members(data: bytes, budget: Budget) -> Iterator[Member]:
    lim = budget.limits
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    except (tarfile.TarError, OSError) as e:
        yield Member("", note=f"unreadable tar: {e}")
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


def _gzip_member(data: bytes, budget: Budget) -> Iterator[Member]:
    lim = budget.limits
    cap = min(lim.max_member_bytes, lim.max_total_bytes - budget.used)
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
            body = g.read(cap + 1)
    except (OSError, EOFError) as e:
        yield Member("", note=f"unreadable gzip: {e}")
        return
    if len(body) > cap:
        ratio = len(body) // max(len(data), 1)
        yield Member("(decompressed)", bomb=ratio > lim.max_ratio,
                     note=f"decompresses to more than {cap // 2**20} MiB, not scanned")
        return
    budget.take(len(body))
    yield Member("(decompressed)", body)
