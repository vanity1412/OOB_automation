from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pandas as pd

TEST_ROOT = Path(tempfile.mkdtemp(prefix="oob_foundation_"))
os.environ["OOB_DB_PATH"] = str(TEST_ROOT / "oob_foundation.db")
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.change_detection import detect_changes
from core.database import init_db
from core.importer import preview_inventory_import
from core.repository import (
    assign_device_console_line,
    delete_console_power_map,
    list_console_power_map,
    list_devices,
    save_console_power_map,
    save_device,
    save_oob,
)


def run() -> None:
    init_db()
    oob_id = save_oob(
        oob_id=None,
        name="OOB-FDN",
        vendor="cisco",
        profile_key="cisco",
        host="10.255.10.1",
        port=22,
        username="admin",
        site="LAB",
        notes="",
    )
    bras_id = save_device(
        device_id=None,
        oob_id=oob_id,
        hostname="BRAS-X",
        device_type="BRAS",
        vendor="Cisco",
        model="",
        serial="",
        mgmt_ip="",
        site="LAB",
        rack="R1",
        u_position="U1",
        expected_line=66,
        expected_alias="BRAS-X",
        notes="",
    )
    no_alias_id = save_device(
        device_id=None,
        oob_id=oob_id,
        hostname="PE-NOALIAS",
        device_type="PE",
        vendor="Juniper",
        model="",
        serial="",
        mgmt_ip="",
        site="LAB",
        rack="R1",
        u_position="U2",
        expected_line=67,
        expected_alias="",
        notes="",
    )

    events = detect_changes(
        oob_id=oob_id,
        previous={},
        current_rows=[
            {"line_no": 66, "alias": "", "state": "AVAILABLE", "session_user": ""},
            {"line_no": 67, "alias": "", "state": "AVAILABLE", "session_user": ""},
            {"line_no": 88, "alias": "", "state": "AVAILABLE", "session_user": ""},
        ],
    )
    types = {event["event_type"] for event in events}
    assert "ALIAS_MISSING" in types
    assert "UNVERIFIED_LINE" in types
    assert "LINE_OCCUPIED_BY_UNKNOWN" in types

    assign_device_console_line(
        device_id=no_alias_id,
        oob_id=oob_id,
        line_no=77,
        expected_alias="PE-VERIFIED",
        ticket_ref="CHG-1",
        confidence=0.9,
        note="Verified from console prompt.",
    )
    updated = next(d for d in list_devices() if int(d["id"]) == int(no_alias_id))
    assert updated["expected_line"] == 77
    assert updated["expected_alias"] == "PE-VERIFIED"
    assert updated["verification_status"] == "VERIFIED"
    assert updated["verification_ticket_ref"] == "CHG-1"
    assert abs(float(updated["verification_confidence"]) - 0.9) < 0.001

    mapping_id = save_console_power_map(
        oob_id=oob_id,
        device_id=bras_id,
        line_no=66,
        pdu_name="PDU-A",
        pdu_host="10.255.20.1",
        outlet_label="A1",
        control_mode="MANUAL",
        notes="Manual-only mapping.",
    )
    assert any(int(row["id"]) == int(mapping_id) for row in list_console_power_map())
    delete_console_power_map(mapping_id)
    assert not any(int(row["id"]) == int(mapping_id) for row in list_console_power_map())

    preview = preview_inventory_import(
        pd.DataFrame(
            [
                {
                    "oob_name": "OOB-FDN",
                    "hostname": "SW-SRC",
                    "expected_line": 90,
                    "source": "Excel",
                    "source_id": "row-9",
                }
            ]
        )
    )
    assert preview.valid
    assert preview.rows[0]["source"] == "Excel"
    assert preview.rows[0]["source_id"] == "row-9"

    print("foundation workflow tests: OK")


if __name__ == "__main__":
    run()
