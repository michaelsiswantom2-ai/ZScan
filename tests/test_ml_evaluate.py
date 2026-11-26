"""The evaluation tools for the ML check, run on generated data and the toy model."""
import io
import json
import random
import sys
import types
import urllib.request
import zipfile

import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("lightgbm")

import ml_toy  # noqa: E402

from zscan.ml import evaluate as ev  # noqa: E402
from zscan.ml import features as F  # noqa: E402
from zscan.ml import verify  # noqa: E402
from zscan.ml.model import MODEL_FILES  # noqa: E402


@pytest.fixture(scope="module")
def toy_model_file(tmp_path_factory):
    path = tmp_path_factory.mktemp("toy") / "toy.model"
    ml_toy.train(path)
    return path


def fake_dataset_rows(n=30):
    rng = random.Random(7)
    rows = []
    for i in range(n):
        malicious = i % 2
        raw = F.raw_features(ml_toy.noisy_elf(rng) if malicious else ml_toy.plain_elf(rng))
        raw.update(sha256=f"{i:064x}", label=malicious, file_type="ELF",
                   first_submission_date=f"2024-10-{i % 28 + 1:02d}T00:00:00")
        rows.append(raw)
    rows.append(dict(rows[0], file_type="Win32"))        # another file type: ignored
    rows.append(dict(rows[0], label=None))               # unlabelled: ignored
    return rows


def write_zip(path, rows):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("2024-10-06_ELF_test.jsonl", "\n".join(json.dumps(r) for r in rows) + "\n")


# ------------------------------------------------------------ metrics

def test_roc_auc():
    y = np.array([0, 0, 1, 1])
    assert ev.roc_auc(y, np.array([0.1, 0.2, 0.8, 0.9])) == 1.0
    assert ev.roc_auc(y, np.array([0.9, 0.8, 0.2, 0.1])) == 0.0
    assert ev.roc_auc(y, np.array([0.5, 0.5, 0.5, 0.5])) == 0.5
    assert ev.roc_auc(y, np.array([0.1, 0.6, 0.5, 0.9])) == 0.75


def test_threshold_and_rates():
    y = np.array([0] * 10 + [1] * 4)
    s = np.array([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.85, 0.95, 0.9, 0.97, 0.99, 0.5])
    t = ev.threshold_at_fpr(y, s, 0.2)        # at most 2 of 10 benign files above the cut-off
    assert t == 0.8 and ((s[y == 0] > t).sum() == 2)
    assert ev.rates(y, s, 0.9) == (0.75, 0.1)


# ------------------------------------------------------------ test / local / fetch

def test_test_command_on_generated_rows(tmp_path, toy_model_file, capsys):
    z = tmp_path / "ELF_test.zip"
    write_zip(z, fake_dataset_rows())
    challenge = tmp_path / "challenge.zip"
    write_zip(challenge, [dict(r, label=1) for r in fake_dataset_rows(10)[:10]])
    code = ev.main(["test", "--kind", "elf", "--data", str(z), "--challenge", str(challenge),
                    "--model", str(toy_model_file)])
    out = capsys.readouterr().out
    assert code == 0
    assert "30 files (15 malicious, 15 benign)" in out and "ROC AUC 1.0000" in out
    assert "first seen between 2024-10-01 and 2024-10-28" in out
    assert "challenge set (10 ELF files" in out


def test_test_command_explains_when_no_rows_match(tmp_path, toy_model_file, capsys):
    z = tmp_path / "x.zip"
    write_zip(z, [dict(r, file_type="PDF") for r in fake_dataset_rows(4)])
    assert ev.main(["test", "--kind", "elf", "--data", str(z), "--model", str(toy_model_file)]) == 3
    assert "{'pdf': 6}" in capsys.readouterr().out   # 4 rows plus the helper's 2 extra ones


def test_local_command_scores_files_and_lists_the_highest(tmp_path, toy_model_file, capsys):
    mdir = tmp_path / "models"
    mdir.mkdir()
    (mdir / MODEL_FILES["elf"]).write_bytes(toy_model_file.read_bytes())
    d = tmp_path / "bin"
    d.mkdir()
    rng = random.Random(1)
    (d / "plain").write_bytes(ml_toy.plain_elf(rng))
    (d / "noisy").write_bytes(ml_toy.noisy_elf(rng))
    (d / "notes.txt").write_bytes(b"not a program\n" * 20)
    assert ev.main(["local", "--kind", "elf", str(d), "--model-dir", str(mdir), "--jobs", "1", "--top", "2"]) == 0
    out = capsys.readouterr().out
    assert "2 files scored" in out and "score >= 0.9: 1 files (50.00%)" in out
    assert out.index("noisy") < out.index("plain")      # highest first


def test_fetch_downloads_once(tmp_path, monkeypatch, capsys):
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(req.full_url)
        return io.BytesIO(b"PK-fake-zip")
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert ev.main(["fetch", str(tmp_path / "data"), "--kind", "elf"]) == 0
    assert calls == ["https://huggingface.co/datasets/joyce8/EMBER2024/resolve/main/ELF_test.zip",
                     "https://huggingface.co/datasets/joyce8/EMBER2024/resolve/main/challenge.zip"]
    assert (tmp_path / "data" / "ELF_test.zip").read_bytes() == b"PK-fake-zip"
    assert ev.main(["fetch", str(tmp_path / "data"), "--kind", "elf"]) == 0
    assert len(calls) == 2 and "already there" in capsys.readouterr().out


# ------------------------------------------------------------ verify against the official extractor

def stub_official(monkeypatch, tamper=False):
    """A stand-in for `thrember` whose classes just call our own functions (plumbing test only)."""
    def make(fn, group):
        class Extractor:
            def raw_features(self, data, pe=None):
                out = fn(data)
                if tamper and group == "strings":
                    out = dict(out, numstrings=out["numstrings"] + 1)
                return out
        return Extractor
    mod = types.ModuleType("thrember.features")
    mod.GeneralFileInfo = make(F._general, "general")
    mod.ByteHistogram = make(F._histogram, "histogram")
    mod.ByteEntropyHistogram = make(F._byte_entropy, "byteentropy")
    mod.StringExtractor = make(F._strings, "strings")
    pkg = types.ModuleType("thrember")
    pkg.features = mod
    monkeypatch.setitem(sys.modules, "thrember", pkg)
    monkeypatch.setitem(sys.modules, "thrember.features", mod)


def test_verify_passes_and_flags_differences(tmp_path, monkeypatch, capsys):
    (tmp_path / "a").write_bytes(ml_toy.plain_elf(random.Random(1)))
    (tmp_path / "b").write_bytes(b"hello http://example.com " * 30)
    (tmp_path / "w.exe").write_bytes(b"MZ" + bytes(100))
    stub_official(monkeypatch)
    assert verify.main([str(tmp_path)]) == 0
    assert "checked 2 files (1 Windows programs skipped): 2 identical, 0 different" in capsys.readouterr().out
    stub_official(monkeypatch, tamper=True)
    assert verify.main([str(tmp_path)]) == 1
    assert "DIFFERENT" in capsys.readouterr().out


def test_verify_needs_the_official_extractor(tmp_path, monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "thrember", None)       # makes the import fail
    assert verify.main([str(tmp_path)]) == 3
    assert "EMBER2024" in capsys.readouterr().err
