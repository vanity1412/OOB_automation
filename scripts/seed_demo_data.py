from __future__ import annotations

import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEMO_DB = BASE_DIR / "data" / "demo_oob_manager.db"
os.environ.setdefault("OOB_DB_PATH", str(DEMO_DB))
sys.path.insert(0, str(BASE_DIR))

from core.database import audit, init_db
from core.repository import (
    create_or_update_change_event,
    create_scan,
    finish_scan,
    record_scan_issue,
    save_device,
    save_oob,
    save_snapshots,
    upsert_detected,
)


def reset_demo_db() -> None:
    for suffix in ("", "-wal", "-shm"):
        path = Path(str(DEMO_DB) + suffix)
        if path.exists():
            path.unlink()


def main() -> None:
    reset_demo_db()
    init_db()

    cisco_id = save_oob(
        oob_id=None,
        name="DEMO-CISCO-OOB",
        vendor="cisco",
        profile_key="cisco",
        host="10.10.10.10",
        port=22,
        username="admin",
        site="HCM-DC1",
        notes="Demo terminal server for UI testing only.",
    )
    viettix_id = save_oob(
        oob_id=None,
        name="DEMO-VIETTIX-OOB",
        vendor="viettix",
        profile_key="viettix",
        host="10.20.20.20",
        port=22,
        username="operator",
        site="HN-POP1",
        notes="Mapping disabled by default until real CLI is verified.",
    )

    bras_id = save_device(
        device_id=None,
        oob_id=cisco_id,
        hostname="BRAS-HCM-01",
        device_type="BRAS",
        vendor="Cisco",
        model="ASR1001-X",
        serial="FTX-DEMO-001",
        mgmt_ip="172.16.10.11",
        site="HCM-DC1",
        rack="R01",
        u_position="U12",
        expected_line=66,
        expected_alias="BRAS-HCM-01",
        notes="Expected to be on line 66.",
    )
    pe_id = save_device(
        device_id=None,
        oob_id=cisco_id,
        hostname="PE-HCM-02",
        device_type="PE",
        vendor="Cisco",
        model="NCS-5501",
        serial="FTX-DEMO-002",
        mgmt_ip="172.16.10.12",
        site="HCM-DC1",
        rack="R02",
        u_position="U08",
        expected_line=67,
        expected_alias="PE-HCM-02",
        notes="This line is currently busy in demo data.",
    )
    save_device(
        device_id=None,
        oob_id=viettix_id,
        hostname="SW-HN-ACCESS-01",
        device_type="Switch",
        vendor="Viettix",
        model="VX-DEMO",
        serial="VX-DEMO-003",
        mgmt_ip="172.20.10.21",
        site="HN-POP1",
        rack="R05",
        u_position="U20",
        expected_line=12,
        expected_alias="SW-HN-ACCESS-01",
        notes="Inventory only sample.",
    )

    scan_id = create_scan(cisco_id)
    rows = [
        {
            "line_no": 66,
            "alias": "BRAS-HCM-01",
            "tcp_port": 2066,
            "target_host": "10.10.10.10",
            "state": "AVAILABLE",
            "session_user": "",
            "raw_line": " 66 Tty idle",
        },
        {
            "line_no": 67,
            "alias": "PE-HCM-02",
            "tcp_port": 2067,
            "target_host": "10.10.10.10",
            "state": "BUSY",
            "session_user": "operator1",
            "raw_line": "*67 Tty connected",
        },
        {
            "line_no": 68,
            "alias": "UNMANAGED-FW",
            "tcp_port": 2068,
            "target_host": "10.10.10.10",
            "state": "AVAILABLE",
            "session_user": "",
            "raw_line": " 68 Tty idle",
        },
    ]
    upsert_detected(cisco_id, rows, scan_id)
    save_snapshots(scan_id=scan_id, oob_id=cisco_id, rows=rows)
    finish_scan(
        scan_id,
        success=True,
        line_count=len(rows),
        error_text="",
        raw_json='{"demo": true}',
        parse_status="ACCEPTED",
        parse_quality=0.95,
    )

    event_id, _ = create_or_update_change_event(
        oob_id=cisco_id,
        device_id=pe_id,
        line_no=67,
        event_type="CONSOLE_SESSION_STARTED",
        severity="INFO",
        old_value="AVAILABLE:",
        new_value="BUSY:operator1",
        message="Demo: console line 67 is BUSY by operator1.",
        scan_id=scan_id,
    )
    create_or_update_change_event(
        oob_id=cisco_id,
        device_id=bras_id,
        line_no=66,
        event_type="EXPECTED_ALIAS_MISMATCH",
        severity="HIGH",
        old_value="BRAS-HCM-01",
        new_value="BRAS-HCM-01-OLD",
        message="Demo alert for testing acknowledge/resolve workflow.",
        scan_id=scan_id,
    )
    record_scan_issue(
        scan_id=scan_id,
        oob_id=cisco_id,
        issue_type="DEMO_NOTE",
        severity="INFO",
        message=f"Demo data loaded. Example event id: {event_id}.",
    )
    audit("seed_demo_data", oob_id=cisco_id, detail=str(DEMO_DB))

    print(f"Demo DB ready: {DEMO_DB}")


if __name__ == "__main__":
    main()
