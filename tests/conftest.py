import pytest


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path_factory, monkeypatch):
    """Keep tests away from the user's real ~/.cache/zscan and API keys."""
    monkeypatch.setenv("ZSCAN_HOME", str(tmp_path_factory.mktemp("zscan-home")))
    for k in ("VT_API_KEY", "MALWAREBAZAAR_API_KEY", "ABUSE_CH_AUTH_KEY"):
        monkeypatch.delenv(k, raising=False)
