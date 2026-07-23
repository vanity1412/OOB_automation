from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pandas as pd

from .repository import list_devices, list_oobs, save_device

IMPORT_FIELDS = [
    "oob_name", "hostname", "device_type", "vendor", "model", "serial",
    "mgmt_ip", "site", "rack", "u_position", "expected_line",
    "expected_alias", "notes",
]


@dataclass
class ImportPreview:
    rows: list[dict[str, Any]]
    issues: list[str]

    @property
    def valid(self) -> bool:
        return not self.issues


def _clean(value: Any) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    return str(value).strip()


def preview_inventory_import(frame: pd.DataFrame) -> ImportPreview:
    issues: list[str] = []
    if "hostname" not in frame.columns:
        return ImportPreview([], ["CSV thiếu cột bắt buộc: hostname"])

    oobs = list_oobs()
    oob_by_name = {x["name"].strip().lower(): x for x in oobs}
    existing = list_devices()
    existing_by_key = {
        ((x.get("oob_name") or "").strip().lower(), x["hostname"].strip().lower()): x
        for x in existing
    }
    existing_by_line = {
        (x.get("oob_id"), int(x["expected_line"])): x
        for x in existing
        if x.get("oob_id") is not None and x.get("expected_line") is not None
    }
    existing_by_alias = {
        (x.get("oob_id"), _clean(x.get("expected_alias")).lower()): x
        for x in existing
        if x.get("oob_id") is not None and _clean(x.get("expected_alias"))
    }

    seen: set[tuple[str, str]] = set()
    seen_line: dict[tuple[int, int], int] = {}
    seen_alias: dict[tuple[int, str], int] = {}
    preview: list[dict[str, Any]] = []

    for idx, src in frame.iterrows():
        row_num = int(idx) + 2
        hostname = _clean(src.get("hostname"))
        oob_name = _clean(src.get("oob_name"))
        if not hostname:
            issues.append(f"Dòng {row_num}: hostname trống.")
            continue

        oob = None
        if oob_name:
            oob = oob_by_name.get(oob_name.lower())
            if not oob:
                issues.append(f"Dòng {row_num}: OOB '{oob_name}' chưa tồn tại.")
                continue

        key = (oob_name.lower(), hostname.lower())
        if key in seen:
            issues.append(f"Dòng {row_num}: trùng key OOB+hostname trong chính CSV: {oob_name}/{hostname}.")
            continue
        seen.add(key)

        line_value = None
        raw_line = src.get("expected_line")
        if raw_line is not None and not (isinstance(raw_line, float) and pd.isna(raw_line)) and str(raw_line).strip():
            try:
                parsed_line = float(raw_line)
                if not parsed_line.is_integer():
                    raise ValueError
                line_value = int(parsed_line)
                if line_value < 0:
                    raise ValueError
            except ValueError:
                issues.append(f"Dòng {row_num}: expected_line không hợp lệ: {raw_line}")
                continue

        alias_value = _clean(src.get("expected_alias"))
        old = existing_by_key.get(key)
        old_id = int(old["id"]) if old else None

        if oob and line_value is not None:
            line_key = (int(oob["id"]), line_value)
            prior_row = seen_line.get(line_key)
            if prior_row is not None:
                issues.append(
                    f"Row {row_num}: expected_line {line_value} duplicates row {prior_row} in CSV."
                )
                continue
            seen_line[line_key] = row_num
            conflict = existing_by_line.get(line_key)
            if conflict and int(conflict["id"]) != int(old_id or -1):
                issues.append(
                    f"Row {row_num}: expected_line {line_value} already assigned to {conflict['hostname']}."
                )
                continue

        if oob and alias_value:
            alias_key = (int(oob["id"]), alias_value.lower())
            prior_row = seen_alias.get(alias_key)
            if prior_row is not None:
                issues.append(
                    f"Row {row_num}: expected_alias {alias_value} duplicates row {prior_row} in CSV."
                )
                continue
            seen_alias[alias_key] = row_num
            conflict = existing_by_alias.get(alias_key)
            if conflict and int(conflict["id"]) != int(old_id or -1):
                issues.append(
                    f"Row {row_num}: expected_alias {alias_value} already assigned to {conflict['hostname']}."
                )
                continue

        normalized = {
            "oob_id": oob["id"] if oob else None,
            "oob_name": oob_name,
            "hostname": hostname,
            "device_type": _clean(src.get("device_type")),
            "vendor": _clean(src.get("vendor")),
            "model": _clean(src.get("model")),
            "serial": _clean(src.get("serial")),
            "mgmt_ip": _clean(src.get("mgmt_ip")),
            "site": _clean(src.get("site")),
            "rack": _clean(src.get("rack")),
            "u_position": _clean(src.get("u_position")),
            "expected_line": line_value,
            "expected_alias": alias_value,
            "notes": _clean(src.get("notes")),
        }

        if old:
            changed_fields = []
            for field in (
                "device_type", "vendor", "model", "serial", "mgmt_ip", "site",
                "rack", "u_position", "expected_line", "expected_alias", "notes",
            ):
                old_val = old.get(field)
                new_val = normalized.get(field)
                if str(old_val or "") != str(new_val or ""):
                    changed_fields.append(field)
            action = "UPDATE" if changed_fields else "UNCHANGED"
            normalized["existing_id"] = old["id"]
            normalized["action"] = action
            normalized["changed_fields"] = ", ".join(changed_fields)
        else:
            normalized["existing_id"] = None
            normalized["action"] = "ADD"
            normalized["changed_fields"] = ""

        preview.append(normalized)

    return ImportPreview(preview, issues)


def apply_inventory_import(rows: list[dict[str, Any]], *, allow_updates: bool) -> dict[str, int]:
    counts = {"added": 0, "updated": 0, "unchanged": 0, "skipped": 0}
    for row in rows:
        action = row.get("action")
        if action == "UNCHANGED":
            counts["unchanged"] += 1
            continue
        if action == "UPDATE" and not allow_updates:
            counts["skipped"] += 1
            continue
        device_id = row.get("existing_id") if action == "UPDATE" else None
        save_device(
            device_id=device_id,
            oob_id=row.get("oob_id"),
            hostname=row["hostname"],
            device_type=row.get("device_type", ""),
            vendor=row.get("vendor", ""),
            model=row.get("model", ""),
            serial=row.get("serial", ""),
            mgmt_ip=row.get("mgmt_ip", ""),
            site=row.get("site", ""),
            rack=row.get("rack", ""),
            u_position=row.get("u_position", ""),
            expected_line=row.get("expected_line"),
            expected_alias=row.get("expected_alias", ""),
            notes=row.get("notes", ""),
        )
        if action == "UPDATE":
            counts["updated"] += 1
        else:
            counts["added"] += 1
    return counts
