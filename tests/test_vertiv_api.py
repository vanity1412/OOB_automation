from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Any

TEST_ROOT = Path(tempfile.mkdtemp(prefix="oob_vertiv_"))
os.environ["OOB_DB_PATH"] = str(TEST_ROOT / "oob_vertiv.db")
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.database import init_db
from core.profiles import load_profile
from core.repository import list_change_events, list_detected, save_device, save_oob
from core.vertiv_api import normalize_vertiv_records, preflight_vertiv_api, scan_vertiv_api


class FakeVertivClient:
    def __init__(self) -> None:
        self.logged_in = False
        self.logged_out = False

    def login(self) -> None:
        self.logged_in = True

    def logout(self) -> None:
        self.logged_out = True

    def get_access_serial_ports(self) -> dict[str, Any]:
        return {
            "serialPorts": [
                {"port": 1, "name": "BRAS-A", "type": "Serial", "status": "In-Use"},
                {"port": 2, "name": "PE-B", "type": "Serial", "status": "Idle"},
                {"port": 3, "name": "", "type": "Serial", "status": "not in use"},
            ]
        }

    def get_config_serial_ports(self) -> dict[str, Any]:
        return {
            "serialPorts": [
                {"port": 1, "profile": "cas", "name": "BRAS-A"},
                {"port": 2, "profile": "cas", "name": "PE-B"},
                {"port": 3, "profile": "cas", "name": "SPARE-3"},
            ]
        }

    def get_sessions(self) -> dict[str, Any]:
        return {
            "sessions": [
                {
                    "id": 43,
                    "user": "noc1",
                    "sessionType": "ssh",
                    "connectionType": "serial",
                    "target": "BRAS-A",
                },
                {
                    "id": 44,
                    "user": "webadmin",
                    "sessionType": "http",
                    "connectionType": "wmi",
                    "target": "",
                },
            ]
        }

    def get_system_info(self) -> dict[str, Any]:
        return {"type": "ACS8048", "firmware": "2.30"}


def run() -> None:
    access = {
        "serialPorts": [
            {"port": 1, "name": "BRAS-A", "status": "In-Use"},
            {"port": 2, "name": "PE-B", "status": "Idle"},
            {"port": 3, "name": "SPARE-3", "status": "not in use"},
        ]
    }
    sessions = {
        "sessions": [
            {
                "id": 10,
                "user": "noc1",
                "sessionType": "ssh",
                "connectionType": "serial",
                "target": "BRAS-A",
            }
        ]
    }
    rows = normalize_vertiv_records(access, sessions_payload=sessions)
    assert rows[0]["line_no"] == 1
    assert rows[0]["alias"] == "BRAS-A"
    assert rows[0]["state"] == "BUSY"
    assert rows[0]["session_user"] == "noc1"
    assert rows[1]["state"] == "AVAILABLE"
    assert rows[2]["state"] == "AVAILABLE"

    init_db()
    oob_id = save_oob(
        oob_id=None,
        name="VERTIV-ACS",
        vendor="vertiv",
        profile_key="vertiv",
        host="10.255.30.1",
        port=22,
        username="admin",
        site="LAB",
        notes="",
    )
    save_device(
        device_id=None,
        oob_id=oob_id,
        hostname="BRAS-A",
        device_type="BRAS",
        vendor="Cisco",
        model="",
        serial="",
        mgmt_ip="",
        site="LAB",
        rack="R1",
        u_position="U1",
        expected_line=1,
        expected_alias="BRAS-A",
        notes="",
    )
    save_device(
        device_id=None,
        oob_id=oob_id,
        hostname="PE-B",
        device_type="PE",
        vendor="Juniper",
        model="",
        serial="",
        mgmt_ip="",
        site="LAB",
        rack="R1",
        u_position="U2",
        expected_line=2,
        expected_alias="PE-EXPECTED",
        notes="",
    )

    fake = FakeVertivClient()
    preflight = preflight_vertiv_api(fake)
    assert preflight["ok"]
    assert preflight["serial_port_count"] == 3
    assert preflight["session_count"] == 2
    assert fake.logged_in
    assert fake.logged_out

    fake = FakeVertivClient()
    result = scan_vertiv_api(
        fake,
        oob_id=oob_id,
        profile=load_profile("vertiv"),
        acquire_lock=False,
    )
    assert fake.logged_in
    assert fake.logged_out
    assert result["accepted"]
    assert result["transport"] == "VERTIV_API"
    assert result["mapping_confident"]
    assert result["session_confident"]
    detected = list_detected(oob_id)
    assert len(detected) == 3
    assert detected[0]["alias"] == "BRAS-A"
    assert detected[0]["session_user"] == "noc1"
    assert detected[0]["session_health"] == "ACTIVE_OPERATOR"
    assert any(event["event_type"] == "EXPECTED_ALIAS_MISMATCH" for event in list_change_events())

    print("vertiv api tests: OK")


if __name__ == "__main__":
    run()
