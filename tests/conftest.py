import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest


@pytest.fixture(autouse=True)
def _isolated_panel_config(tmp_path_factory, monkeypatch):
    """Never read or write the developer's real `usepanel init --token` config (~/.config/usepanel/cloud.json)."""
    monkeypatch.setenv("PANEL_CONFIG_DIR", str(tmp_path_factory.mktemp("usepanel-config")))
