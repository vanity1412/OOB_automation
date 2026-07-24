from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from pathlib import Path

try:
    import pandas as pd
except ModuleNotFoundError:
    pd = None

TEST_ROOT = Path(tempfile.mkdtemp(prefix="oob_hardening_"))
os.environ["OOB_DB_PATH"] = str(TEST_ROOT / "oob_test.db")
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.database import DB_PATH, backup_db, init_db
from core.connection import _clear_line_command
from core.discovery import preserve_previous_mapping
from core.repository import save_device, save_oob
from core.scanner import first_working
from core.terminal import (
    _securecrt_ssh_args,
    _securecrt_telnet_args,
    _ssh_args,
    _telnet_args,
    check_tcp_reachable,
)

if pd is not None:
    from core.importer import preview_inventory_import
else:
    preview_inventory_import = None


def expect_raises(fn, text: str) -> None:
    try:
        fn()
    except Exception as exc:
        assert text in str(exc), str(exc)
        return
    raise AssertionError("Expected exception was not raised.")


class FakeSession:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def command(self, cmd: str, timeout: int = 15) -> str:
        self.calls.append(cmd)
        if cmd == "bad":
            return "% Invalid input detected at '^' marker."
        return " 66 Tty idle"


def test_first_working_skips_cli_error() -> None:
    session = FakeSession()
    cmd, output, errors = first_working(
        session,
        ["bad", "good"],
        command_timeout=15,
    )
    assert cmd == "good"
    assert output.strip() == "66 Tty idle"
    assert session.calls == ["bad", "good"]
    assert any("CLI_ERROR" in err for err in errors)


def test_preserve_previous_mapping_overrides_untrusted_alias() -> None:
    previous = {
        66: {"line_no": 66, "alias": "BRAS01", "tcp_port": 2066, "target_host": "10.0.0.1"}
    }
    current = [
        {"line_no": 66, "alias": "WRONG", "tcp_port": 2999, "target_host": "1.1.1.1"},
        {"line_no": 67, "alias": "NEWBAD", "tcp_port": 2067, "target_host": "10.0.0.1"},
    ]

    rows = preserve_previous_mapping(current, previous)

    assert rows[0]["alias"] == "BRAS01"
    assert rows[0]["tcp_port"] == 2066
    assert rows[1]["alias"] == ""
    assert rows[1]["tcp_port"] is None


def test_ssh_args_are_validated() -> None:
    assert _ssh_args("10.0.0.1", 22, "admin") == ["ssh", "-p", "22", "admin@10.0.0.1"]
    assert _ssh_args("oob-01.local", 2222, "") == ["ssh", "-p", "2222", "oob-01.local"]
    assert _telnet_args("10.0.0.1", 2066) == ["telnet", "10.0.0.1", "2066"]
    assert _securecrt_telnet_args("10.0.0.1", 2066, "SecureCRT.exe") == [
        "SecureCRT.exe", "/TELNET", "10.0.0.1", "2066",
    ]
    assert _securecrt_ssh_args("10.0.0.1", 22, "admin", "SecureCRT.exe") == [
        "SecureCRT.exe", "/SSH2", "/P", "22", "/L", "admin", "10.0.0.1",
    ]

    expect_raises(lambda: _ssh_args("10.0.0.1; calc", 22, "admin"), "Invalid SSH host")
    expect_raises(lambda: _ssh_args("10.0.0.1", 22, "-oProxyCommand=calc"), "Invalid SSH username")
    expect_raises(lambda: _ssh_args("10.0.0.1", 70000, "admin"), "Invalid SSH port")
    expect_raises(lambda: _telnet_args("bad host", 23), "Invalid telnet host")
    expect_raises(lambda: check_tcp_reachable("bad host", 2003), "Invalid console host")
    expect_raises(
        lambda: check_tcp_reachable("bad host", 2003, attempts=4),
        "Invalid console host",
    )


def test_clear_line_command_is_validated() -> None:
    assert _clear_line_command(14) == "clear line 14"
    expect_raises(lambda: _clear_line_command(-1), "between 0 and 9999")
    expect_raises(lambda: _clear_line_command(10000), "between 0 and 9999")


def test_inventory_uniqueness_and_import_preview() -> None:
    init_db()
    oob_id = save_oob(
        oob_id=None,
        name="OOB1",
        vendor="cisco",
        profile_key="cisco",
        host="10.0.0.1",
        port=22,
        username="admin",
        site="",
        notes="",
    )
    save_device(
        device_id=None,
        oob_id=oob_id,
        hostname="BRAS01",
        device_type="Router",
        vendor="",
        model="",
        serial="",
        mgmt_ip="",
        site="",
        rack="",
        u_position="",
        expected_line=66,
        expected_alias="BRAS01",
        notes="",
    )

    expect_raises(
        lambda: save_device(
            device_id=None,
            oob_id=oob_id,
            hostname="PE01",
            device_type="Router",
            vendor="",
            model="",
            serial="",
            mgmt_ip="",
            site="",
            rack="",
            u_position="",
            expected_line=66,
            expected_alias="PE01",
            notes="",
        ),
        "already assigned",
    )
    expect_raises(
        lambda: save_device(
            device_id=None,
            oob_id=oob_id,
            hostname="PE02",
            device_type="Router",
            vendor="",
            model="",
            serial="",
            mgmt_ip="",
            site="",
            rack="",
            u_position="",
            expected_line=67,
            expected_alias="bras01",
            notes="",
        ),
        "already assigned",
    )

    if pd is None or preview_inventory_import is None:
        return

    preview = preview_inventory_import(
        pd.DataFrame(
            [
                {"oob_name": "OOB1", "hostname": "PE03", "expected_line": 66, "expected_alias": "PE03"},
                {"oob_name": "OOB1", "hostname": "PE04", "expected_line": 67, "expected_alias": "bras01"},
                {"oob_name": "OOB1", "hostname": "PE05", "expected_line": "66.5", "expected_alias": "PE05"},
                {"oob_name": "OOB1", "hostname": "PE06", "expected_line": 68, "expected_alias": "PE06"},
                {"oob_name": "OOB1", "hostname": "PE07", "expected_line": 68, "expected_alias": "PE07"},
            ]
        )
    )

    joined = "\n".join(preview.issues)
    assert "expected_line 66 already assigned" in joined
    assert "expected_alias bras01 already assigned" in joined
    assert "66.5" in joined
    assert "expected_line 68 duplicates row" in joined


def test_backup_contains_latest_committed_data() -> None:
    target = backup_db()
    assert target.parent == DB_PATH.parent / "backups"

    with sqlite3.connect(target) as conn:
        count = conn.execute("SELECT COUNT(*) FROM oob_nodes WHERE name='OOB1'").fetchone()[0]
    assert count == 1


def run() -> None:
    test_first_working_skips_cli_error()
    test_preserve_previous_mapping_overrides_untrusted_alias()
    test_ssh_args_are_validated()
    test_clear_line_command_is_validated()
    test_inventory_uniqueness_and_import_preview()
    test_backup_contains_latest_committed_data()
    print("hardening regression tests: OK")


if __name__ == "__main__":
    run()
