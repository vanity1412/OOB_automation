from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

TEST_ROOT = Path(tempfile.mkdtemp(prefix="oob_viewmodel_"))
os.environ["OOB_DB_PATH"] = str(TEST_ROOT / "oob_viewmodel.db")
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.database import init_db
from core.repository import create_scan, save_device, save_oob, upsert_detected
from core.viewmodel import build_rows


def run() -> None:
    init_db()
    oob_id = save_oob(
        oob_id=None,
        name="HCM-OOB-FNX02L03H1-01",
        vendor="cisco",
        profile_key="cisco",
        host="10.10.10.10",
        port=22,
        username="admin",
        site="HCM",
        notes="",
    )
    save_device(
        device_id=None,
        oob_id=oob_id,
        hostname="HCM-CDNLeaf-Quan9-10G-01",
        device_type="Switch",
        vendor="",
        model="",
        serial="",
        mgmt_ip="192.0.2.31",
        site="HCM",
        rack="",
        u_position="",
        expected_line=3,
        expected_alias="HCM-CDNLeaf-Quan9-10G-01",
        notes="",
    )
    save_device(
        device_id=None,
        oob_id=oob_id,
        hostname="MGMT-ONLY",
        device_type="Switch",
        vendor="",
        model="",
        serial="",
        mgmt_ip="192.0.2.99",
        site="HCM",
        rack="",
        u_position="",
        expected_line=None,
        expected_alias="",
        notes="",
    )
    scan_id = create_scan(oob_id)
    upsert_detected(
        oob_id,
        [
            {
                "line_no": 3,
                "alias": "HCM-CDNLeaf-Quan9-10G-01",
                "tcp_port": 2003,
                "target_host": "172.28.200.11",
                "state": "AVAILABLE",
            },
            {
                "line_no": 4,
                "alias": "HCM-CDNLeaf-Quan9-10G-02",
                "tcp_port": 2004,
                "target_host": "172.28.200.12",
                "state": "AVAILABLE",
            },
        ],
        scan_id,
    )

    rows = build_rows()
    leaf_01 = next(row for row in rows if row["Device"] == "HCM-CDNLeaf-Quan9-10G-01")
    assert leaf_01["IP"] == "172.28.200.11"
    assert leaf_01["Mgmt IP"] == "192.0.2.31"
    assert leaf_01["OOB Host"] == "10.10.10.10"
    assert leaf_01["TCP Port"] == 2003

    unmanaged = next(row for row in rows if row["Device"] == "HCM-CDNLeaf-Quan9-10G-02")
    assert unmanaged["IP"] == "172.28.200.12"
    assert unmanaged["Mapping"] == "UNMANAGED"

    mgmt_only = next(row for row in rows if row["Device"] == "MGMT-ONLY")
    assert mgmt_only["IP"] == ""
    assert mgmt_only["Mgmt IP"] == "192.0.2.99"

    print("viewmodel tests: OK")


if __name__ == "__main__":
    run()
