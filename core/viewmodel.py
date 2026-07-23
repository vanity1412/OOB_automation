from __future__ import annotations

from typing import Any
from .repository import list_devices, list_detected


def build_rows() -> list[dict[str, Any]]:
    inv = list_devices()
    det = list_detected()

    det_by_key = {(x["oob_id"], x["line_no"]): x for x in det}
    inv_by_key = {
        (x["oob_id"], x["expected_line"]): x
        for x in inv
        if x["oob_id"] is not None and x["expected_line"] is not None
    }

    keys = sorted(
        set(det_by_key) | set(inv_by_key),
        key=lambda x: ((x[0] or 0), (x[1] or 0))
    )
    rows: list[dict[str, Any]] = []

    for key in keys:
        d = det_by_key.get(key, {})
        i = inv_by_key.get(key, {})
        expected_alias = (i.get("expected_alias") or "").strip().lower()
        actual_alias = (d.get("alias") or "").strip().lower()

        if i and d:
            if expected_alias and actual_alias and expected_alias != actual_alias:
                mapping = "MISMATCH"
            else:
                mapping = "MATCH"
        elif i:
            mapping = "NOT DETECTED"
        else:
            mapping = "UNMANAGED"

        rows.append({
            "DeviceID": i.get("id"),
            "OOBID": key[0],
            "OOB": i.get("oob_name") or d.get("oob_name") or "",
            "OOB Host": i.get("oob_host") or d.get("oob_host") or "",
            "Line": key[1],
            "Device": i.get("hostname") or d.get("alias") or f"Line {key[1]}",
            "Type": i.get("device_type") or "",
            "Vendor": i.get("vendor") or "",
            "Model": i.get("model") or "",
            "Serial": i.get("serial") or "",
            "Mgmt IP": i.get("mgmt_ip") or "",
            "Site": i.get("site") or "",
            "Rack": i.get("rack") or "",
            "U": i.get("u_position") or "",
            "Alias": d.get("alias") or i.get("expected_alias") or "",
            "Expected Alias": i.get("expected_alias") or "",
            "TCP Port": d.get("tcp_port"),
            "Target": d.get("target_host") or "",
            "Status": d.get("state") or "UNKNOWN",
            "Session": d.get("session_user") or "",
            "Mapping": mapping,
            "Last Seen": d.get("last_seen") or "",
            "Notes": i.get("notes") or "",
        })

    # Devices without an assigned console line.
    included = {r["DeviceID"] for r in rows if r["DeviceID"] is not None}
    for i in inv:
        if i["id"] in included:
            continue
        rows.append({
            "DeviceID": i["id"],
            "OOBID": i["oob_id"],
            "OOB": i.get("oob_name") or "",
            "OOB Host": i.get("oob_host") or "",
            "Line": None,
            "Device": i["hostname"],
            "Type": i["device_type"],
            "Vendor": i["vendor"],
            "Model": i["model"],
            "Serial": i["serial"],
            "Mgmt IP": i["mgmt_ip"],
            "Site": i["site"],
            "Rack": i["rack"],
            "U": i["u_position"],
            "Alias": i["expected_alias"],
            "Expected Alias": i["expected_alias"],
            "TCP Port": None,
            "Target": "",
            "Status": "UNKNOWN",
            "Session": "",
            "Mapping": "NO LINE",
            "Last Seen": "",
            "Notes": i["notes"],
        })
    return rows
