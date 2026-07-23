from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

TEST_ROOT = Path(tempfile.mkdtemp(prefix="oob_analytics_"))
os.environ["OOB_DB_PATH"] = str(TEST_ROOT / "oob_analytics.db")
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.database import init_db
from core.repository import (
    analytics_alert_severity,
    analytics_daily_summary,
    create_or_update_change_event,
    create_scan,
    finish_scan,
    list_devices,
    list_scans_range,
    operational_foundation_summary,
    save_device,
    save_oob,
    save_snapshots,
)


def run() -> None:
    init_db()
    oob_id = save_oob(
        oob_id=None,
        name="OOB-ANALYTICS",
        vendor="cisco",
        profile_key="cisco",
        host="10.255.0.1",
        port=22,
        username="admin",
        site="LAB",
        notes="",
    )
    device_id = save_device(
        device_id=None,
        oob_id=oob_id,
        hostname="RTR01",
        device_type="Router",
        vendor="Cisco",
        model="",
        serial="",
        mgmt_ip="",
        site="LAB",
        rack="R1",
        u_position="U1",
        expected_line=66,
        expected_alias="RTR01",
        notes="",
    )

    accepted_scan = create_scan(oob_id)
    save_snapshots(
        scan_id=accepted_scan,
        oob_id=oob_id,
        rows=[
            {
                "line_no": 66,
                "alias": "RTR01",
                "tcp_port": 2066,
                "target_host": "10.255.0.1",
                "state": "AVAILABLE",
                "session_user": "",
                "raw_line": "66 Tty idle",
            }
        ],
    )
    finish_scan(
        accepted_scan,
        success=True,
        line_count=1,
        error_text="",
        raw_json="{}",
        parse_status="ACCEPTED",
        parse_quality=0.9,
    )

    rejected_scan = create_scan(oob_id)
    finish_scan(
        rejected_scan,
        success=False,
        line_count=0,
        error_text="parser rejected",
        raw_json="{}",
        parse_status="REJECTED",
        parse_quality=0,
    )

    create_or_update_change_event(
        oob_id=oob_id,
        device_id=device_id,
        line_no=66,
        event_type="EXPECTED_ALIAS_MISMATCH",
        severity="HIGH",
        old_value="RTR01",
        new_value="RTR01-OLD",
        message="expected alias mismatch",
        scan_id=accepted_scan,
    )

    start = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    end = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    daily = analytics_daily_summary(start, end)
    today = datetime.now().date().isoformat()
    today_row = next(row for row in daily if row["day"] == today)

    assert today_row["scan_count"] == 2
    assert today_row["scan_accepted"] == 1
    assert today_row["scan_rejected"] == 1
    assert today_row["snapshot_count"] == 1
    assert today_row["alert_new"] == 1
    assert today_row["alerts_open_end"] == 1
    assert abs(today_row["avg_parse_quality"] - 0.9) < 0.001

    severity = analytics_alert_severity(start, end)
    assert any(row["severity"] == "HIGH" and row["count"] == 1 for row in severity)
    assert len(list_scans_range(start, end)) == 2

    devices = list_devices()
    assert devices[0]["verification_status"] == "UNVERIFIED"

    foundation = operational_foundation_summary()
    assert any(row["Capability"] == "Verified inventory" for row in foundation)
    assert any(row["Capability"] == "Disaster readiness check" for row in foundation)

    print("data analytics tests: OK")


if __name__ == "__main__":
    run()
