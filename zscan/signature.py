"""Windows Authenticode check: is a program validly signed, and by whom?

Uses Windows' own WinVerifyTrust, for signatures embedded in the file and for the catalog
signatures that most of Windows' own files carry. The check stays offline: no revocation
lookups, and certificates are only taken from Windows' local caches, so nothing about the
file leaves the computer. Certificates that Windows itself distrusts (its local "Disallowed"
list, which holds known stolen certificates) still fail.

Elsewhere than on Windows nothing is checked, and check() returns None.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass

VALID = "valid"
MISMATCH = "hash-mismatch"      # signed, then changed: the file no longer matches its signature
DISTRUSTED = "distrusted"       # signed with a certificate Windows explicitly distrusts
UNTRUSTED = "untrusted"         # signed, but not trusted here (expired, unknown root, ...)
NOT_SIGNED = "not-signed"

EMBEDDED = "embedded"
CATALOG = "catalog"


@dataclass
class Signature:
    status: str
    kind: str = ""        # EMBEDDED or CATALOG, when there is a signature
    signer: str = ""      # the signing certificate's name, e.g. "Microsoft Windows"
    reason: str = ""      # why a signature is not valid, in plain words

    def as_dict(self) -> dict:
        return {"status": self.status, "kind": self.kind, "signer": self.signer, "reason": self.reason}


# WinVerifyTrust results (HRESULTs), with plain-word reasons.
_NO_SIGNATURE = {0x800B0100, 0x800B0003, 0x800B0001}   # NOSIGNATURE, SUBJECT_FORM_UNKNOWN, PROVIDER_UNKNOWN
_BAD_DIGEST = 0x80096010
_EXPLICIT_DISTRUST = 0x800B0111
_FILE_ERROR = 0x80092003        # CRYPT_E_FILE_ERROR: the file could not be read, so nothing was checked
_REASONS = {
    0x800B0101: "the certificate has expired and the signature has no timestamp",
    0x800B0109: "the certificate chain ends in a root that this computer does not trust",
    0x800B010A: "the certificate chain is incomplete",
    0x800B010C: "the certificate was revoked",
    0x800B010D: "the certificate is a test certificate",
    0x800B0004: "the signature is not trusted for this kind of file",
    0x80092026: "the signature uses an algorithm or setting this computer does not accept",
    0x800B0110: "the certificate is not meant for signing code",
    0x80096005: "the signature's timestamp could not be verified",
    0x80096010: "the file was changed after it was signed",
    0x800B0111: "Windows explicitly distrusts the signing certificate",
}

_api = None     # loaded on first use, once per process


def check(path) -> Signature | None:
    """Signature status of the file at `path`, or None where it cannot be checked
    (not Windows, or the check itself failed). Never raises."""
    if sys.platform != "win32":
        return None
    try:
        api = _load()
        return api.check(os.path.abspath(path))
    except Exception:  # noqa: BLE001 - a failed check must never break a scan
        return None


def _load():
    global _api
    if _api is None:
        _api = _WinTrust()
    return _api


class _WinTrust:
    """ctypes bindings for wintrust.dll and crypt32.dll."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes as wt

        self.ctypes, self.wt = ctypes, wt
        c_void_p, DWORD, BOOL, HANDLE, LPCWSTR = ctypes.c_void_p, wt.DWORD, wt.BOOL, wt.HANDLE, wt.LPCWSTR

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD),
                        ("Data4", ctypes.c_ubyte * 8)]

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [("cbStruct", DWORD), ("pcwszFilePath", LPCWSTR), ("hFile", HANDLE),
                        ("pgKnownSubject", c_void_p)]

        class WINTRUST_CATALOG_INFO(ctypes.Structure):
            _fields_ = [("cbStruct", DWORD), ("dwCatalogVersion", DWORD),
                        ("pcwszCatalogFilePath", LPCWSTR), ("pcwszMemberTag", LPCWSTR),
                        ("pcwszMemberFilePath", LPCWSTR), ("hMemberFile", HANDLE),
                        ("pbCalculatedFileHash", c_void_p), ("cbCalculatedFileHash", DWORD),
                        ("pcCatalogContext", c_void_p), ("hCatAdmin", HANDLE)]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [("cbStruct", DWORD), ("pPolicyCallbackData", c_void_p),
                        ("pSIPClientData", c_void_p), ("dwUIChoice", DWORD),
                        ("fdwRevocationChecks", DWORD), ("dwUnionChoice", DWORD), ("pInfo", c_void_p),
                        ("dwStateAction", DWORD), ("hWVTStateData", HANDLE),
                        ("pwszURLReference", c_void_p), ("dwProvFlags", DWORD), ("dwUIContext", DWORD),
                        ("pSignatureSettings", c_void_p)]

        class CATALOG_INFO(ctypes.Structure):
            _fields_ = [("cbStruct", DWORD), ("wszCatalogFile", ctypes.c_wchar * 260)]

        class CRYPT_PROVIDER_CERT(ctypes.Structure):    # only the fields read here
            _fields_ = [("cbStruct", DWORD), ("pCert", c_void_p)]

        self.GUID, self.WINTRUST_FILE_INFO = GUID, WINTRUST_FILE_INFO
        self.WINTRUST_CATALOG_INFO, self.WINTRUST_DATA = WINTRUST_CATALOG_INFO, WINTRUST_DATA
        self.CATALOG_INFO, self.CRYPT_PROVIDER_CERT = CATALOG_INFO, CRYPT_PROVIDER_CERT
        self.action = GUID(0x00AAC56B, 0xCD44, 0x11D0,
                           (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

        wintrust = ctypes.WinDLL("wintrust.dll", use_last_error=True)
        crypt32 = ctypes.WinDLL("crypt32.dll", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

        def fn(dll, name, restype, *argtypes):
            f = getattr(dll, name)
            f.restype, f.argtypes = restype, list(argtypes)
            return f

        self.WinVerifyTrust = fn(wintrust, "WinVerifyTrust", ctypes.c_long, HANDLE, c_void_p, c_void_p)
        self.WTHelperProvDataFromStateData = fn(wintrust, "WTHelperProvDataFromStateData", c_void_p, HANDLE)
        self.WTHelperGetProvSignerFromChain = fn(wintrust, "WTHelperGetProvSignerFromChain", c_void_p,
                                                 c_void_p, DWORD, BOOL, DWORD)
        self.WTHelperGetProvCertFromChain = fn(wintrust, "WTHelperGetProvCertFromChain", c_void_p,
                                               c_void_p, DWORD)
        self.AcquireContext2 = fn(wintrust, "CryptCATAdminAcquireContext2", BOOL,
                                  ctypes.POINTER(HANDLE), c_void_p, LPCWSTR, c_void_p, DWORD)
        self.CalcHash2 = fn(wintrust, "CryptCATAdminCalcHashFromFileHandle2", BOOL,
                            HANDLE, HANDLE, ctypes.POINTER(DWORD), c_void_p, DWORD)
        self.EnumCatalog = fn(wintrust, "CryptCATAdminEnumCatalogFromHash", HANDLE,
                              HANDLE, c_void_p, DWORD, DWORD, c_void_p)
        self.CatalogInfo = fn(wintrust, "CryptCATCatalogInfoFromContext", BOOL,
                              HANDLE, ctypes.POINTER(CATALOG_INFO), DWORD)
        self.ReleaseCatalog = fn(wintrust, "CryptCATAdminReleaseCatalogContext", BOOL, HANDLE, HANDLE, DWORD)
        self.CertGetNameStringW = fn(crypt32, "CertGetNameStringW", DWORD,
                                     c_void_p, DWORD, DWORD, c_void_p, c_void_p, DWORD)
        self.CreateFileW = fn(kernel32, "CreateFileW", HANDLE,
                              LPCWSTR, DWORD, DWORD, c_void_p, DWORD, DWORD, HANDLE)
        self.CloseHandle = fn(kernel32, "CloseHandle", BOOL, HANDLE)
        self.SetFilePointerEx = fn(kernel32, "SetFilePointerEx", BOOL, HANDLE, ctypes.c_longlong, c_void_p, DWORD)
        # Catalog contexts are opened once per hash algorithm and kept: opening one reads
        # Windows' catalog database, which is slow. Newer catalogs use SHA-256, older ones SHA-1.
        self.cat_admins = []
        for algorithm in ("SHA256", None):
            h = HANDLE()
            if self.AcquireContext2(ctypes.byref(h), None, algorithm, None, 0):
                self.cat_admins.append(h)

    # -------------------------------------------------------------------------

    def check(self, path: str) -> Signature | None:
        ctypes = self.ctypes
        long_path = path if path.startswith("\\\\") or len(path) < 250 else "\\\\?\\" + path
        GENERIC_READ, SHARE_ALL, OPEN_EXISTING = 0x80000000, 0x7, 3
        handle = self.CreateFileW(long_path, GENERIC_READ, SHARE_ALL, None, OPEN_EXISTING, 0, None)
        if not handle or handle == ctypes.c_void_p(-1).value:
            return None
        try:
            info = self.WINTRUST_FILE_INFO(ctypes.sizeof(self.WINTRUST_FILE_INFO), long_path, handle, None)
            code, signer = self._verify(1, ctypes.addressof(info))      # WTD_CHOICE_FILE
            if code not in _NO_SIGNATURE:
                return _result(code, EMBEDDED, signer)
            if not self.cat_admins:
                return None     # catalogs could not be opened, so "not signed" would be a guess
            self.SetFilePointerEx(handle, 0, None, 0)    # FILE_BEGIN: hash the catalog member from the start
            return self._check_catalog(long_path, handle)
        finally:
            self.CloseHandle(handle)

    def _check_catalog(self, path: str, handle) -> Signature:
        ctypes, wt = self.ctypes, self.wt
        for admin in self.cat_admins:
            size = wt.DWORD(0)
            self.CalcHash2(admin, handle, ctypes.byref(size), None, 0)
            if not size.value or size.value > 64:
                continue
            digest = (ctypes.c_ubyte * size.value)()
            if not self.CalcHash2(admin, handle, ctypes.byref(size), digest, 0):
                continue
            catalog = self.EnumCatalog(admin, digest, size, 0, None)
            if not catalog:
                continue
            try:
                cat_info = self.CATALOG_INFO()
                cat_info.cbStruct = ctypes.sizeof(cat_info)
                if not self.CatalogInfo(catalog, ctypes.byref(cat_info), 0):
                    continue
                tag = bytes(digest).hex().upper()
                member = self.WINTRUST_CATALOG_INFO(
                    ctypes.sizeof(self.WINTRUST_CATALOG_INFO), 0, cat_info.wszCatalogFile, tag, path,
                    handle, ctypes.cast(digest, ctypes.c_void_p), size, None, admin)
                code, signer = self._verify(2, ctypes.addressof(member))   # WTD_CHOICE_CATALOG
                return _result(code, CATALOG, signer)
            finally:
                self.ReleaseCatalog(admin, catalog, 0)
        return Signature(NOT_SIGNED)

    def _verify(self, union_choice: int, info_address: int) -> tuple[int, str]:
        """WinVerifyTrust with no UI, no revocation checks and no network access."""
        ctypes = self.ctypes
        data = self.WINTRUST_DATA()
        data.cbStruct = ctypes.sizeof(data)
        data.dwUIChoice = 2                 # WTD_UI_NONE
        data.fdwRevocationChecks = 0        # WTD_REVOKE_NONE
        data.dwUnionChoice = union_choice
        data.pInfo = info_address
        data.dwStateAction = 1              # WTD_STATEACTION_VERIFY, so the signer can be read
        data.dwProvFlags = 0x10 | 0x1000    # WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
        no_window = ctypes.c_void_p(-1)     # INVALID_HANDLE_VALUE: no interactive user
        code = self.WinVerifyTrust(no_window, ctypes.byref(self.action), ctypes.byref(data)) & 0xFFFFFFFF
        signer = ""
        try:
            if code not in _NO_SIGNATURE:
                signer = self._signer(data.hWVTStateData)
        finally:
            data.dwStateAction = 2          # WTD_STATEACTION_CLOSE
            self.WinVerifyTrust(no_window, ctypes.byref(self.action), ctypes.byref(data))
        return code, signer

    def _signer(self, state) -> str:
        ctypes = self.ctypes
        provider = self.WTHelperProvDataFromStateData(state)
        if not provider:
            return ""
        signer = self.WTHelperGetProvSignerFromChain(provider, 0, False, 0)
        if not signer:
            return ""
        cert = self.WTHelperGetProvCertFromChain(signer, 0)
        if not cert:
            return ""
        context = ctypes.cast(cert, ctypes.POINTER(self.CRYPT_PROVIDER_CERT)).contents.pCert
        if not context:
            return ""
        CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
        n = self.CertGetNameStringW(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None, 0)
        if n <= 1:
            return ""
        buf = ctypes.create_unicode_buffer(n)
        self.CertGetNameStringW(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, buf, n)
        return buf.value


def _result(code: int, kind: str, signer: str) -> Signature | None:
    if code == _FILE_ERROR:
        return None
    if code == 0:
        return Signature(VALID, kind, signer)
    if code == _BAD_DIGEST:
        return Signature(MISMATCH, kind, signer, _REASONS[code])
    if code == _EXPLICIT_DISTRUST:
        return Signature(DISTRUSTED, kind, signer, _REASONS[code])
    return Signature(UNTRUSTED, kind, signer, _REASONS.get(code, f"WinVerifyTrust error 0x{code:08X}"))
