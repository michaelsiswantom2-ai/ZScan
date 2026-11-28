"""A file that crashes a scan worker (say, a bug in a native library) must not end a
whole-drive scan: that file is named, everything else is still scanned."""
import json
from concurrent.futures.process import BrokenProcessPool

import pytest

import zscan.scanner as scanner_mod
from zscan.cli import main
from zscan.scanner import CRASHED, Scanner, WorkerCrashed
from zscan.yara_engine import YaraEngine

from samples import EICAR

CRASH_ON = "ZSCAN_TEST_CRASH_ON"     # workers exit abruptly on files whose name contains this


@pytest.fixture()
def tree(tmp_path):
    files = {"a.txt": b"hello", "b-boom.bin": b"\x00" * 100, "c.txt": b"bye", "eicar.com": EICAR}
    for i in range(12):
        files[f"d{i:02}.txt"] = b"more %d" % i
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    return tmp_path


def test_the_crashing_file_is_named_and_the_rest_is_scanned(tree, monkeypatch):
    monkeypatch.setenv(CRASH_ON, "boom")
    s = Scanner(YaraEngine(community=False))
    paths = list(s.iter_paths(tree))
    reports = list(s.scan_many(paths, jobs=2))
    assert [r.path for r in reports] == [str(p) for p in paths]        # all of them, in order
    crashed = [r for r in reports if r.error]
    assert [r.path for r in crashed] == [str(tree / "b-boom.bin")] and crashed[0].error == CRASHED
    assert next(r for r in reports if r.path.endswith("eicar.com")).verdict == "malicious"


def test_crashed_files_are_listed_in_the_report(tree, monkeypatch, capsys):
    monkeypatch.setenv(CRASH_ON, "boom")
    assert main(["--no-community", "-q", "--no-color", "-j", "2", str(tree)]) == 2   # EICAR was found
    out = capsys.readouterr().out
    assert "Files that crashed a scan worker (1), so they were not scanned:" in out
    assert str(tree / "b-boom.bin") in out and "1 file(s) crashed a scan worker" in out

    main(["--no-community", "--json", "-j", "2", str(tree)])
    data = json.loads(capsys.readouterr().out)
    assert data["crashed_files"] == [str(tree / "b-boom.bin")]
    assert data["summary"]["crashed"] == 1 and data["summary"]["stopped_early"] is None


def test_workers_that_always_crash_stop_the_scan_with_exit_code_4(tree, monkeypatch, capsys):
    monkeypatch.setenv(CRASH_ON, "*")       # every worker dies, even on the start-up probe
    with pytest.raises(WorkerCrashed):
        list(Scanner(YaraEngine(community=False)).scan_many(sorted(tree.iterdir()), jobs=2))
    assert main(["--no-community", "--no-color", "-j", "2", str(tree)]) == 4
    captured = capsys.readouterr()
    assert "the scan stopped early" in captured.err
    assert "STOPPED EARLY" in captured.out


def test_a_pool_that_breaks_while_work_is_handed_out(tree, monkeypatch):
    # A worker can die between two hand-outs, so the next one fails at once (seen in CI).
    real_new_pool, made = scanner_mod._new_pool, []

    class BreaksOnSecondHandOut:
        def __init__(self, pool):
            self.pool, self.calls = pool, 0

        def submit(self, *args):
            self.calls += 1
            if self.calls == 2:
                raise BrokenProcessPool("a child process terminated abruptly")
            return self.pool.submit(*args)

        def shutdown(self, **kw):
            self.pool.shutdown(**kw)

    def new_pool(jobs, config):
        pool = real_new_pool(jobs, config)
        made.append(pool)
        return BreaksOnSecondHandOut(pool) if len(made) == 1 else pool

    monkeypatch.setattr(scanner_mod, "_new_pool", new_pool)
    s = Scanner(YaraEngine(community=False))
    paths = list(s.iter_paths(tree))
    reports = list(s.scan_many(paths, jobs=2))
    assert [r.path for r in reports] == [str(p) for p in paths]
    assert not [r for r in reports if r.error]         # nothing crashed, so nothing is blamed
    assert len(made) >= 2                               # it carried on with a new pool
