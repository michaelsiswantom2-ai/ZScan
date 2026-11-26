"""EMBER2024-compatible features for files that are not Windows programs (ELF, PDF, APK).

The classifiers published with the EMBER2024 dataset (arXiv:2506.05074, Apache-2.0) for ELF,
PDF and APK files read four groups of numbers that need nothing but the file's bytes:

    general      size, entropy, "is a Windows program" flag, first four bytes          7 values
    histogram    how often each byte value occurs, as fractions                       256
    byteentropy  byte values grouped by the local entropy around them                 256
    strings      counts and statistics of the printable text in the file             177

This module recomputes them so the published models see the numbers they were trained on.
It follows the official extractor ("thrember", https://github.com/FutureComputing4AI/EMBER2024,
Apache License 2.0; see THIRD_PARTY_NOTICES.md): same text patterns, same order, same arithmetic.
This file was modified from the original: it was rewritten without scikit-learn, pefile and signify,
and the patterns are applied once over all text instead of once per string, because that is much
faster on large programs. `tests/test_ml_features.py` pins the numbers, and
`python -m zscan.ml.verify` compares against the official code on real files.

For the model's remaining columns (the Windows-only groups, 1,872 of 2,568), the official
extractor writes zeros for every file that is not a PE; see `pad_for_model`.

Needs numpy.
"""
from __future__ import annotations

import math
import re

import numpy as np

GENERAL_DIM = 7
HISTOGRAM_DIM = 256
BYTEENTROPY_DIM = 256
PRINTABLE_DIM = 96
NON_PE_DIM = 696            # all four groups above: 7 + 256 + 256 + 177
FULL_DIM = 2568             # what the official models expect (Windows-only columns come after)

_WINDOW = 2048              # byte-entropy histogram: window length and step, in bytes
_STEP = 1024

_RUN = re.compile(rb"[\x20-\x7f]{5,}")      # printable text of 5+ characters

# (name, pattern, case-insensitive). Sorted by name, which is the column order of the model.
# Copied from the official extractor, including its quirks (the "email_addr" pattern really is
# the MAC-address pattern; "onlick" and "KHEY_" are spelled as in the original).
_PATTERNS = [
    ('.click(', '.click', True),
    ('/EmbeddedFile', '/EmbeddedFile', False),
    ('/FlateDecode', '/FlateDecode', False),
    ('/URI', '/URI', False),
    ('/bin/', '/bin/', False),
    ('/dev/', '/dev/', False),
    ('/proc/', '/proc/', False),
    ('/tmp/', '/tmp/', False),
    ('/usr/', '/usr/', False),
    ('<script', '<script', True),
    ('Invoke-Command', 'Invoke-Command', False),
    ('Invoke-Expression', 'Invoke-Expression', False),
    ('Start-process', 'Start-process', False),
    ('base64', 'base64', True),
    ('base64string', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', False),
    ('btc_wallet', '[13][a-km-zA-HJ-NP-Z1-9]{25,34}', False),
    ('cache', 'cache', True),
    ('certificate', 'certificate', True),
    ('clipboard', 'clipboard', True),
    ('command', 'command', True),
    ('connect', 'connect', True),
    ('cookie', 'cookie', True),
    ('create', 'create', True),
    ('crypt', 'crypt', False),
    ('debug', 'debug', True),
    ('decode', 'decode', True),
    ('delete', 'delete', True),
    ('desktop', 'desktop', True),
    ('directory', 'directory', True),
    ('disk', 'disk', True),
    ('dos_msg', '!This program ', False),
    ('download', 'download', True),
    ('email_addr', '\\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\\b', False),
    ('encode', 'encode', True),
    ('enum', 'enum', True),
    ('environment', 'environment', True),
    ('exit', 'exit', True),
    ('file', 'file', True),
    ('file_path', '\\bC:/', False),
    ('ftp', 'ftp:', True),
    ('get', 'GET /', True),
    ('hidden', 'hidden', True),
    ('hostname', 'hostname', True),
    ('html', 'html', True),
    ('http', 'HTTP/', True),
    ('http://', 'http://', True),
    ('https://', 'https://', True),
    ('install', 'install', True),
    ('internet', 'internet', True),
    ('ipv4_addr', '\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b', False),
    ('ipv6_addr', '\\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\\b|\\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\\b|\\b:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){1,6}\\b', False),
    ('javascript', 'javascript', True),
    ('keyboard', 'keyboard', True),
    ('mac_addr', '\\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\\b', False),
    ('memory', 'memory', True),
    ('module', 'module', True),
    ('mutex', 'mutex', True),
    ('onlick', 'onclick', True),
    ('password', 'password', True),
    ('post', 'POST /', True),
    ('powershell', 'powershell', True),
    ('privilege', 'privilege', True),
    ('process', 'process', True),
    ('registry_key', '\\b(?:KHEY_|KHLM|HKCU)', False),
    ('remote', 'remote', True),
    ('resource', 'resource', True),
    ('security', 'security', True),
    ('service', 'service', True),
    ('shell', 'shell', True),
    ('snapshot', 'snapshot', True),
    ('system', 'system', True),
    ('thread', 'thread', True),
    ('token', 'token', True),
    ('url', "\\b(?:http|https|ftp):\\/\\/[a-zA-Z0-9-._~:?#[\\]@!$&'()*+,;=]+", False),
    ('useragent', 'User-Agent', True),
    ('wallet', 'wallet', True),
    ('window', 'window', True),
]
STRING_NAMES = [name for name, _, _ in _PATTERNS]
STRINGS_DIM = 3 + PRINTABLE_DIM + 1 + len(_PATTERNS)
assert GENERAL_DIM + HISTOGRAM_DIM + BYTEENTROPY_DIM + STRINGS_DIM == NON_PE_DIM

# Patterns are applied to bytes. Printable text is ASCII, where bytes and str patterns agree.
_COMPILED = [(name, re.compile(pat.encode("ascii"), re.IGNORECASE if nocase else 0))
             for name, pat, nocase in _PATTERNS]


# ---------------------------------------------------------------- raw features (from bytes)

def _general(data: bytes) -> dict:
    size = len(data)
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    # The official code sums over a Counter, i.e. in the order byte values first appear.
    # Floating-point addition is not associative, so keep that order to get the same last bit.
    present = [int(v) for v in np.flatnonzero(counts)]
    present.sort(key=lambda v: data.find(bytes((v,))))
    entropy = 0
    for v in present:
        p_x = float(counts[v]) / size
        entropy -= p_x * math.log(p_x, 2)
    start = list(data[:4]) + [0] * max(0, 4 - size)
    return {"size": size, "entropy": entropy, "is_pe": 0, "start_bytes": start}


def _histogram(data: bytes) -> list:
    return np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).tolist()


def _byte_entropy(data: bytes) -> list:
    """16 x 16 histogram: rows are the entropy of a 2048-byte window (0-8 bits in steps of
    half a bit), columns are the high four bits of each byte in that window."""
    a = np.frombuffer(data, dtype=np.uint8)
    out = np.zeros((16, 16), dtype=np.int32)
    n = a.shape[0]
    nibbles = a >> 4
    bincount, where, f32, log2 = np.bincount, np.where, np.float32, np.log2

    def add(block) -> None:
        c = bincount(block, minlength=16)
        p = c.astype(f32) / _WINDOW
        wh = where(c)[0]
        # x2 because 16 bins (4 bits) carry half the information of 256 bins (8 bits)
        h = np.sum(-p[wh] * log2(p[wh])) * 2
        row = int(h * 2)
        out[15 if row == 16 else row, :] += c

    if n < _WINDOW:
        add(nibbles)
    else:
        for start in range(0, n - _WINDOW + 1, _STEP):
            add(nibbles[start:start + _WINDOW])
    return out.flatten().tolist()


def _strings(data: bytes) -> dict:
    runs = _RUN.findall(data)
    if runs:
        lengths = np.fromiter((len(s) for s in runs), dtype=np.int64, count=len(runs))
        avlength = sum(lengths.tolist()) / len(runs)
        joined = b"".join(runs)
        c = np.bincount(np.frombuffer(joined, dtype=np.uint8) - 0x20, minlength=PRINTABLE_DIM)
        csum = c.sum()
        p = c.astype(np.float32) / csum
        wh = np.where(c)[0]
        entropy = np.sum(-p[wh] * np.log2(p[wh]))
    else:
        avlength = 0
        c = np.zeros((PRINTABLE_DIM,), dtype=np.float32)
        entropy = 0
        csum = 0

    counts: dict = {}
    if runs:
        # How many separate strings does each pattern occur in? One pass per pattern over all the
        # text (strings joined by newlines, which no pattern can match across) and then map
        # each hit back to its string, instead of one regex call per string and pattern.
        text = b"\n".join(runs)
        starts = np.concatenate(([0], np.cumsum(lengths[:-1] + 1)))
        for name, rx in _COMPILED:
            hits = np.fromiter((m.start() for m in rx.finditer(text)), dtype=np.int64)
            if hits.size:
                counts[name] = int(np.unique(np.searchsorted(starts, hits, side="right")).size)
    return {"numstrings": len(runs), "avlength": avlength, "printabledist": c.tolist(),
            "printables": int(csum), "entropy": float(entropy), "string_counts": counts}


def raw_features(data: bytes) -> dict:
    """The raw (unnormalised) features, in the same layout as the EMBER2024 data files."""
    return {"general": _general(data), "histogram": _histogram(data),
            "byteentropy": _byte_entropy(data), "strings": _strings(data)}


# ---------------------------------------------------------------- vectors (from raw features)

def process_raw_features(raw: dict) -> np.ndarray:
    """Turn raw features (computed here, or read from an EMBER2024 data file) into the 696
    numbers the models read."""
    g = raw["general"]
    general = np.array([g["size"], g["entropy"], g["is_pe"], *g["start_bytes"]], dtype=np.float32)

    counts = np.array(raw["histogram"], dtype=np.float32)
    histogram = counts / counts.sum() if counts.any() else counts       # an empty file has no bytes to count
    counts = np.array(raw["byteentropy"], dtype=np.float32)
    byteentropy = counts / counts.sum() if counts.any() else counts

    s = raw["strings"]
    divisor = float(s["printables"]) if s["printables"] > 0 else 1.0
    string_counts = np.zeros(len(STRING_NAMES), dtype=np.float32)
    for name, count in s["string_counts"].items():
        string_counts[STRING_NAMES.index(name)] = count
    strings = np.hstack([s["numstrings"], s["avlength"], s["printables"],
                         np.asarray(s["printabledist"]) / divisor, s["entropy"],
                         string_counts]).astype(np.float32)
    return np.hstack([general, histogram, byteentropy, strings]).astype(np.float32)


def feature_vector(data: bytes) -> np.ndarray:
    """The 696 format-independent numbers for one file's bytes."""
    return process_raw_features(raw_features(data))


def pad_for_model(vector: np.ndarray, n_features: int) -> np.ndarray:
    """Add the columns the model expects after ours. The official extractor fills the
    Windows-only groups with zeros for anything that is not a PE file."""
    if n_features == vector.shape[0]:
        return vector
    if n_features < vector.shape[0]:
        raise ValueError(f"model reads {n_features} columns, fewer than the {vector.shape[0]} we compute")
    return np.concatenate([vector, np.zeros(n_features - vector.shape[0], dtype=np.float32)])
