"""Static analysis: hashing, entropy, file type, suspicious strings, PE heuristics.

Nothing here executes the scanned file. Files are only read as bytes.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass, field

try:
    import pefile  # optional
except ImportError:  # pragma: no cover
    pefile = None


@dataclass
class Finding:
    source: str        # "yara", "entropy", "pe", "strings", ...
    title: str
    severity: int      # 1 = info, 2 = low, 3 = medium, 4 = high, 5 = critical
    detail: str = ""


@dataclass
class FileReport:
    path: str
    size: int = 0
    file_type: str = "unknown"
    hashes: dict = field(default_factory=dict)
    entropy: float = 0.0
    findings: list = field(default_factory=list)
    error: str | None = None
    skipped: str | None = None

    @property
    def score(self) -> int:
        weights = {1: 0, 2: 5, 3: 15, 4: 35, 5: 100}
        return min(100, sum(weights.get(f.severity, 0) for f in self.findings))

    @property
    def verdict(self) -> str:
        if self.error:
            return "error"
        if self.skipped:
            return "skipped"
        if any(f.severity >= 5 for f in self.findings) or self.score >= 70:
            return "malicious"
        if self.score >= 15:
            return "suspicious"
        return "clean"


# ---------------------------------------------------------------- basics

def hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


MAGIC = [
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"PK\x03\x04", "zip"),
    (b"%PDF", "pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"#!", "script"),
    (b"\xca\xfe\xba\xbe", "macho-fat"),
    (b"\xcf\xfa\xed\xfe", "macho"),
]


def detect_type(data: bytes) -> str:
    for magic, name in MAGIC:
        if data.startswith(magic):
            return name
    sample = data[:4096]
    if sample and all(32 <= b < 127 or b in (9, 10, 13) for b in sample):
        return "text"
    return "data"


# ---------------------------------------------------------------- strings

# (regex, title, severity). Patterns are matched against the lower-cased file
# (Python's case-insensitive regex is several times slower on big binaries),
# so write them in lower case. CASE_SENSITIVE ones run on the original bytes.
SUSPICIOUS_PATTERNS = [
    (rb"powershell(?:\.exe)?\s+.{0,40}-e(?:nc|ncodedcommand)?\s", "PowerShell encoded command", 4),
    (rb"iex\s*\(|invoke-expression", "PowerShell Invoke-Expression", 3),
    (rb"downloadstring|downloadfile|net\.webclient", "Script download primitive", 3),
    (rb"vssadmin(?:\.exe)?\s+delete\s+shadows", "Shadow copy deletion (ransomware trait)", 4),
    (rb"bcdedit(?:\.exe)?\s+/set\s+.{0,20}recoveryenabled\s+no", "Disables Windows recovery", 4),
    (rb"wevtutil(?:\.exe)?\s+cl\s", "Event log clearing", 3),
    (rb"software\\microsoft\\windows\\currentversion\\run", "Registry Run-key persistence", 3),
    (rb"schtasks(?:\.exe)?\s+/create", "Scheduled task creation", 2),
    (rb"(?:curl|wget)\s[^\n|]{1,200}\|\s*(?:ba)?sh\b", "Pipe-to-shell download", 3),
    (rb"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+", "Bash reverse shell", 4),
    (rb"\bnc(?:at)?\s+-[ec]\s", "Netcat command execution", 3),
    (rb"mimikatz|sekurlsa::", "Credential dumping tool reference", 4),
    (rb"your files (?:have been|are) encrypted", "Ransom note wording", 4),
    (rb"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?/", "URL with raw IP address", 2),
    (rb"\b[a-z2-7]{16,56}\.onion\b", "Tor .onion address", 3),
]
CASE_SENSITIVE_PATTERNS = [
    (rb"(?:[A-Za-z0-9+/]{4}){60,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", "Large base64 blob", 2),
]
_COMPILED = [(re.compile(r), t, s) for r, t, s in SUSPICIOUS_PATTERNS]
_COMPILED_CS = [(re.compile(r), t, s) for r, t, s in CASE_SENSITIVE_PATTERNS]


def string_findings(data: bytes) -> list[Finding]:
    out = []
    lowered = data.lower()
    for corpus, patterns in ((lowered, _COMPILED), (data, _COMPILED_CS)):
        for rx, title, sev in patterns:
            if title == "Tor .onion address" and b".onion" not in corpus:
                continue  # cheap literal prefilter; the regex is slow on big files
            m = rx.search(corpus)
            if m:
                snippet = data[m.start():m.start() + 80].decode("latin-1", "replace")
                out.append(Finding("strings", title, sev, f"e.g. {snippet!r}"))
    return out


# ---------------------------------------------------------------- PE

# Imports that are individually common but together suggest injection,
# keylogging, or anti-analysis. Grouped by behaviour.
SUSPICIOUS_IMPORTS = {
    "process injection": {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                          "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext"},
    "keylogging": {"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
                   "GetKeyState"},
    "anti-debugging": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                       "NtQueryInformationProcess", "OutputDebugStringA"},
    "dynamic API resolution": {"LoadLibraryA", "LoadLibraryW", "GetProcAddress"},
    "privilege manipulation": {"AdjustTokenPrivileges", "OpenProcessToken",
                               "LookupPrivilegeValueA", "LookupPrivilegeValueW"},
}
PACKER_SECTIONS = {"UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".petite", ".nsp0",
                   ".nsp1", "MPRESS1", "MPRESS2", ".themida", ".vmp0", ".vmp1"}


def pe_findings(data: bytes) -> list[Finding]:
    if pefile is None:
        return [Finding("pe", "pefile not installed; PE checks skipped", 1)]
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as e:
        return [Finding("pe", "Malformed PE header", 3, str(e))]

    out: list[Finding] = []

    # Sections: entropy, W+X, packer names
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
        ent = s.get_entropy()
        chars = s.Characteristics
        writable = bool(chars & 0x80000000)
        executable = bool(chars & 0x20000000)
        if name in PACKER_SECTIONS:
            out.append(Finding("pe", f"Packer section name '{name}'", 3))
        if ent > 7.2 and s.SizeOfRawData > 1024:
            out.append(Finding("pe", f"High-entropy section '{name}'", 3,
                               f"entropy {ent:.2f} (packed or encrypted code?)"))
        if writable and executable:
            out.append(Finding("pe", f"Section '{name}' is writable and executable", 3))
        if s.SizeOfRawData == 0 and s.Misc_VirtualSize > 0x10000 and executable:
            out.append(Finding("pe", f"Empty-on-disk executable section '{name}'", 2,
                               "typical of unpack-at-runtime stubs"))

    # Entry point outside any section, or in the last section
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_section = next((s for s in pe.sections if s.contains_rva(ep)), None)
    if ep and ep_section is None:
        out.append(Finding("pe", "Entry point outside all sections", 4))
    elif ep_section is not None and pe.sections and ep_section is pe.sections[-1] \
            and len(pe.sections) > 1:
        out.append(Finding("pe", "Entry point in last section", 2,
                           "common in packed or infected binaries"))

    # Imports
    imported = set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in entry.imports:
            if imp.name:
                imported.add(imp.name.decode("latin-1", "replace"))
    if not imported:
        out.append(Finding("pe", "No import table", 2, "may resolve APIs at runtime"))
    for behaviour, names in SUSPICIOUS_IMPORTS.items():
        hit = sorted(imported & names)
        if len(hit) < 2:
            continue
        if behaviour == "dynamic API resolution":
            # Normal programs import these alongside many others; only flag a
            # tiny import table that is basically just a loader.
            if len(imported) > 10:
                continue
            sev = 2
        elif behaviour == "process injection":
            sev = 4 if len(hit) >= 3 else 3
        else:
            sev = 2
        out.append(Finding("pe", f"Imports suggest {behaviour}", sev, ", ".join(hit)))

    # Timestamp sanity
    ts = pe.FILE_HEADER.TimeDateStamp
    if ts == 0 or ts > 0x7FFFFFFF:
        out.append(Finding("pe", "Zeroed or invalid compile timestamp", 1))

    # Overlay (data appended after the last section)
    overlay = pe.get_overlay_data_start_offset()
    if overlay is not None and len(data) - overlay > 1024:
        out.append(Finding("pe", "Appended overlay data", 1,
                           f"{len(data) - overlay} bytes after last section"))

    pe.close()
    return out
