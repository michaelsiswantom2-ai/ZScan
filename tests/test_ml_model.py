"""The opt-in ML check: model files, scanning, command line. Uses a toy model, see ml_toy.py."""
import json
import random
import shutil

import pytest

pytest.importorskip("numpy")
lgb = pytest.importorskip("lightgbm")

import ml_toy  # noqa: E402
from samples import benign_pe, build_elf, make_zip  # noqa: E402

from zscan.cli import main, to_dict  # noqa: E402
from zscan.ml import MODEL_FILES, MlScorer, MlUnavailable, installed_models, models_dir, update_models  # noqa: E402
from zscan.ml.model import kind_for, looks_like_apk  # noqa: E402
from zscan.scanner import Scanner  # noqa: E402
from zscan.yara_engine import YaraEngine  # noqa: E402

RNG = random.Random(99)
PLAIN = ml_toy.plain_elf(RNG)
NOISY = ml_toy.noisy_elf(RNG)
PDF = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n" + b"BT (hello world) Tj ET\n" * 30 + b"%%EOF\n"
APK = make_zip({"AndroidManifest.xml": b"<manifest/>" * 20, "classes.dex": b"dex\n035\0" + bytes(200)})


@pytest.fixture(scope="module")
def toy_model_file(tmp_path_factory):
    path = tmp_path_factory.mktemp("toy") / "toy.model"
    ml_toy.train(path)
    return path


@pytest.fixture()
def models(toy_model_file):
    """The toy model installed as the ELF, PDF and APK model in this test's cache folder."""
    d = models_dir()
    d.mkdir(parents=True)
    for name in MODEL_FILES.values():
        shutil.copy(toy_model_file, d / name)
    return d


def scanner(models_path, threshold=0.9, **kw):
    return Scanner(YaraEngine(community=False), ml=MlScorer(threshold, models_path), **kw)


def test_toy_model_separates_its_two_classes(models):
    s = MlScorer(directory=models)
    assert s.score("elf", PLAIN).score < 0.2
    assert s.score("elf", NOISY).score > 0.8


def test_scan_reports_the_score_and_a_hint_above_the_threshold(models):
    sc = scanner(models)
    plain = sc.finalize(sc.analyze_bytes(PLAIN, "plain", sc_budget(sc), 0))
    noisy = sc.finalize(sc.analyze_bytes(NOISY, "noisy", sc_budget(sc), 0))
    assert plain.ml["model"] == "EMBER2024_ELF" and plain.ml["score"] < 0.2
    assert [f.severity for f in plain.findings if f.source == "ml"] == [1]      # INFO: score only
    ml_findings = [f for f in noisy.findings if f.source == "ml"]
    assert len(ml_findings) == 1 and ml_findings[0].severity == 3
    assert "EMBER2024 ELF model" in ml_findings[0].detail
    assert noisy.ml["score"] > 0.9 and to_dict(noisy)["ml"] == noisy.ml


def sc_budget(sc):
    from zscan.archives import Budget
    return Budget(sc.limits)


def test_ml_alone_never_makes_a_file_malicious(models):
    sc = scanner(models, threshold=0.5)
    rep = sc.finalize(sc.analyze_bytes(NOISY, "noisy", sc_budget(sc), 0))
    assert max(f.severity for f in rep.findings if f.source == "ml") <= 3


def test_severity_bands(models):
    s = MlScorer(0.99, models)
    assert [s.severity(x) for x in (0.995, 0.99, 0.95, 0.90, 0.89, 0.2)] == [3, 3, 2, 2, 1, 1]
    s = MlScorer(0.7, models)
    assert [s.severity(x) for x in (0.7, 0.62, 0.61, 0.6)] == [3, 2, 2, 1]
    with pytest.raises(ValueError):
        MlScorer(0.3, models)


def test_only_elf_pdf_and_apk_are_scored(models):
    sc = scanner(models)
    for name, data in {"script": b"#!/bin/sh\necho hi\n" * 20, "text": b"hello world\n" * 50,
                       "pe": benign_pe(), "zip": make_zip({"a.txt": b"hi"})}.items():
        rep = sc.finalize(sc.analyze_bytes(data, name, sc_budget(sc), 0))
        assert rep.ml is None and not [f for f in rep.findings if f.source == "ml"], name
    for name, data, model in (("pdf", PDF, "EMBER2024_PDF"), ("apk", APK, "EMBER2024_APK")):
        rep = sc.finalize(sc.analyze_bytes(data, name, sc_budget(sc), 0))
        assert rep.ml and rep.ml["model"] == model, name


def test_apk_detection():
    assert looks_like_apk(APK)
    assert not looks_like_apk(make_zip({"AndroidManifest.xml": b"x"}))
    assert not looks_like_apk(b"PK\x03\x04 broken")
    assert kind_for("zip", APK) == "apk" and kind_for("zip", make_zip({"a": b"b"})) is None
    assert kind_for("elf", b"") == "elf" and kind_for("pdf", b"") == "pdf" and kind_for("pe", b"") is None


def test_missing_model_for_a_type_is_reported_not_hidden(toy_model_file):
    d = models_dir()
    d.mkdir(parents=True)
    shutil.copy(toy_model_file, d / MODEL_FILES["elf"])
    sc = scanner(d)
    rep = sc.finalize(sc.analyze_bytes(PDF, "doc.pdf", sc_budget(sc), 0))
    assert rep.ml is None and any("no PDF model installed" in u for u in rep.unscanned)
    assert rep.partly_scanned


def test_tiny_elf_is_reported_as_not_judged(models):
    sc = scanner(models)
    rep = sc.finalize(sc.analyze_bytes(b"\x7fELF\x02\x01\x01" + bytes(20), "tiny", sc_budget(sc), 0))
    assert rep.ml is None and any("too small" in u for u in rep.unscanned)


def test_damaged_files_never_crash_the_ml_check(models):
    sc = scanner(models)
    rng = random.Random(5)
    for seed in (PLAIN, NOISY, PDF, APK):
        for _ in range(40):
            b = bytearray(seed)
            if rng.random() < 0.5:
                del b[rng.randrange(1, len(b)):]
            for _ in range(rng.randint(0, 6)):
                b[rng.randrange(len(b))] = rng.randrange(256)
            rep = sc.analyze_bytes(bytes(b), "x", sc_budget(sc), 0)
            assert rep.error is None


def test_parallel_scan_gives_the_same_scores(models, tmp_path):
    files = []
    for i, data in enumerate([PLAIN, NOISY, PDF, APK, b"plain text\n" * 30]):
        p = tmp_path / f"f{i}"
        p.write_bytes(data)
        files.append(p)
    sc = scanner(models)
    serial = [(r.path, r.ml) for r in sc.scan_many(files, jobs=1)]
    parallel = [(r.path, r.ml) for r in sc.scan_many(files, jobs=2)]
    assert serial == parallel and sum(1 for _, m in serial if m) == 4


# ------------------------------------------------------------ models on disk

def test_update_installs_and_checks_models(toy_model_file, tmp_path):
    blob = toy_model_file.read_bytes()
    asked = []
    metas = update_models(fetch=lambda url: asked.append(url) or blob, directory=tmp_path)
    assert sorted(metas) == ["apk", "elf", "pdf"]
    assert asked[0] == "https://huggingface.co/joyce8/EMBER2024-benchmark-models/resolve/main/EMBER2024_ELF.model"
    assert metas["elf"]["features"] == 2568 and len(metas["elf"]["sha256"]) == 64
    assert installed_models(tmp_path)["pdf"]["trees"] == metas["pdf"]["trees"]
    assert MlScorer(directory=tmp_path).has_model("apk")
    assert not list(tmp_path.glob("*.tmp"))


def test_a_bad_download_never_replaces_a_working_model(toy_model_file, tmp_path):
    update_models(kinds=["elf"], fetch=lambda url: toy_model_file.read_bytes(), directory=tmp_path)
    before = (tmp_path / MODEL_FILES["elf"]).read_bytes()
    with pytest.raises(ValueError, match="not a usable model"):
        update_models(kinds=["elf"], fetch=lambda url: b"<html>sign in</html>", directory=tmp_path)
    assert (tmp_path / MODEL_FILES["elf"]).read_bytes() == before and not list(tmp_path.glob("*.tmp"))


def test_a_model_with_another_feature_layout_is_refused(tmp_path):
    odd = tmp_path / "odd.model"
    ml_toy.train(odd, n_features=10)
    with pytest.raises(ValueError, match="10 features"):
        update_models(kinds=["elf"], fetch=lambda url: odd.read_bytes(), directory=tmp_path / "ml")
    assert not (tmp_path / "ml" / MODEL_FILES["elf"]).exists()


def test_no_models_installed_says_how_to_get_them():
    with pytest.raises(MlUnavailable, match="--update-ml"):
        MlScorer()


# ------------------------------------------------------------ command line

def test_cli_ml_json(models, tmp_path, capsys):
    f = tmp_path / "noisy.bin"
    f.write_bytes(NOISY)
    code = main(["--ml", "--ml-threshold", "0.9", "--json", "--no-community", str(f)])
    out = json.loads(capsys.readouterr().out)
    assert out["files"][0]["ml"]["model"] == "EMBER2024_ELF" and out["files"][0]["ml"]["score"] > 0.9
    assert code == 1    # suspicious


def test_cli_ml_text_shows_the_score_with_verbose(models, tmp_path, capsys):
    f = tmp_path / "plain.bin"
    f.write_bytes(PLAIN)
    main(["--ml", "-v", "--no-community", "--no-color", str(f)])
    cap = capsys.readouterr()
    assert "ML model score" in cap.out and "ml: scoring ELF, PDF, APK files" in cap.err


def test_cli_ml_without_models_fails_clearly(tmp_path, capsys):
    f = tmp_path / "a.bin"
    f.write_bytes(PLAIN)
    assert main(["--ml", "--no-community", str(f)]) == 3
    assert "--update-ml" in capsys.readouterr().err


def test_cli_ml_threshold_needs_ml(tmp_path):
    with pytest.raises(SystemExit):
        main(["--ml-threshold", "0.9", str(tmp_path)])


def test_cli_update_ml_reports_download_problems(monkeypatch, capsys):
    import zscan.cli as cli

    def boom(**kw):
        raise OSError("network is unreachable")
    monkeypatch.setattr(cli, "update_models", boom)
    assert main(["--update-ml"]) == 3
    assert "could not download the ML models" in capsys.readouterr().err


def test_cli_update_ml_prints_what_was_installed(monkeypatch, toy_model_file, capsys):
    import zscan.ml.model as model_mod
    monkeypatch.setattr(model_mod, "_download", lambda url: toy_model_file.read_bytes())
    assert main(["--update-ml"]) == 0
    out = capsys.readouterr().out
    assert "EMBER2024 ELF model" in out and "EMBER2024 PDF model" in out and "EMBER2024 APK model" in out
