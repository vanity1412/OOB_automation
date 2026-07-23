from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = Path(tempfile.mkdtemp(prefix="oob_app_smoke_"))
os.environ["OOB_DB_PATH"] = str(TEST_ROOT / "oob_app_smoke.db")
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from streamlit.testing.v1 import AppTest


def navigation_radio(app: AppTest):
    for radio in app.radio:
        if "▦  Devices" in list(radio.options):
            return radio
    raise AssertionError("Navigation radio not found.")


def run() -> None:
    app = AppTest.from_file(str(REPO_ROOT / "app.py"))
    app.run(timeout=30)
    assert not app.exception, [exc.value for exc in app.exception]

    for page in list(navigation_radio(app).options):
        navigation_radio(app).set_value(page)
        app.run(timeout=30)
        assert not app.exception, [exc.value for exc in app.exception]

    print("app smoke tests: OK")


if __name__ == "__main__":
    run()
