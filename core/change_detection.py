from __future__ import annotations

from typing import Any

from .repository import list_devices


def _norm(value: Any) -> str:
    return str(value or "").strip()


def detect_changes(
    *,
    oob_id: int,
    previous: dict[int, dict[str, Any]],
    current_rows: list[dict[str, Any]],
    emit_history_events: bool = True,
    mapping_confident: bool = True,
    session_confident: bool = True,
) -> list[dict[str, Any]]:
    """Generate non-overlapping, operator-friendly change events.

    Precedence for mapping-related conditions:
      1) DEVICE_CONSOLE_LINE_CHANGED
      2) EXPECTED_ALIAS_MISMATCH / ALIAS_MISSING
      3) EXPECTED_DEVICE_NOT_DETECTED
      4) UNVERIFIED_LINE
      5) CONSOLE_MAPPING_CHANGED / NEW_CONSOLE_DEVICE / CONSOLE_LINE_MISSING

    Session events are independent INFO events and are emitted only when session
    parsing is trusted for the scan.
    """
    current = {int(r["line_no"]): r for r in current_rows}
    inventory = [d for d in list_devices() if d.get("oob_id") == oob_id]
    inv_by_line = {
        int(d["expected_line"]): d
        for d in inventory
        if d.get("expected_line") is not None
    }
    inv_by_alias = {
        _norm(d.get("expected_alias")).lower(): d
        for d in inventory
        if _norm(d.get("expected_alias"))
    }
    current_alias_to_line = {
        _norm(r.get("alias")).lower(): int(r["line_no"])
        for r in current_rows
        if _norm(r.get("alias"))
    }

    events: list[dict[str, Any]] = []
    claimed_lines: set[int] = set()

    # ---------- Inventory-aware events first ----------
    for device in inventory:
        device_id = int(device["id"])
        expected_line = device.get("expected_line")
        expected_alias = _norm(device.get("expected_alias"))
        verification_status = _norm(device.get("verification_status")).upper() or "UNVERIFIED"
        hostname = _norm(device.get("hostname")) or "device"

        # Highest precedence: expected alias is found, but on another line.
        if mapping_confident and expected_alias and expected_line is not None:
            detected_line = current_alias_to_line.get(expected_alias.lower())
            if detected_line is not None and int(detected_line) != int(expected_line):
                events.append({
                    "device_id": device_id,
                    "line_no": int(detected_line),
                    "event_type": "DEVICE_CONSOLE_LINE_CHANGED",
                    "severity": "HIGH",
                    "old_value": str(expected_line),
                    "new_value": str(detected_line),
                    "message": (
                        f"{hostname} ({expected_alias}) is expected on line {expected_line}, "
                        f"but is detected on line {detected_line}."
                    ),
                })
                claimed_lines.update({int(expected_line), int(detected_line)})
                continue

        if expected_line is None:
            continue

        expected_line = int(expected_line)
        row = current.get(expected_line)

        # Line itself is absent from a parser-valid scan.
        if row is None:
            events.append({
                "device_id": device_id,
                "line_no": expected_line,
                "event_type": "EXPECTED_DEVICE_NOT_DETECTED",
                "severity": "HIGH",
                "old_value": expected_alias or hostname,
                "new_value": "",
                "message": (
                    f"{hostname} is expected on line {expected_line}, but that line/device "
                    "was not detected in the accepted scan."
                ),
            })
            claimed_lines.add(expected_line)
            continue

        actual_alias = _norm(row.get("alias"))

        if mapping_confident and expected_alias and not actual_alias:
            events.append({
                "device_id": device_id,
                "line_no": expected_line,
                "event_type": "ALIAS_MISSING",
                "severity": "WARNING",
                "old_value": expected_alias,
                "new_value": "",
                "message": (
                    f"{hostname}: expected alias {expected_alias} on line {expected_line}, "
                    "but the accepted scan did not parse an alias for that line."
                ),
            })
            claimed_lines.add(expected_line)
            continue

        # Mapping mismatch only when alias parser is trusted.
        if mapping_confident and expected_alias:
            if actual_alias and actual_alias.lower() != expected_alias.lower():
                events.append({
                    "device_id": device_id,
                    "line_no": expected_line,
                    "event_type": "EXPECTED_ALIAS_MISMATCH",
                    "severity": "HIGH",
                    "old_value": expected_alias,
                    "new_value": actual_alias,
                    "message": (
                        f"{hostname}: expected alias {expected_alias} on line {expected_line}, "
                        f"but detected {actual_alias}."
                    ),
                })
                claimed_lines.add(expected_line)
                continue

        if verification_status != "VERIFIED" and (not expected_alias or not actual_alias):
            events.append({
                "device_id": device_id,
                "line_no": expected_line,
                "event_type": "UNVERIFIED_LINE",
                "severity": "WARNING",
                "old_value": verification_status,
                "new_value": actual_alias or f"line {expected_line}",
                "message": (
                    f"{hostname} is detected on line {expected_line}, but identity is not verified. "
                    "Verify from prompt/show output before trusting alias-only or alias-missing mapping."
                ),
            })
            claimed_lines.add(expected_line)

    # ---------- Generic historical mapping changes ----------
    if emit_history_events:
        all_lines = sorted(set(previous) | set(current))
        for line_no in all_lines:
            old = previous.get(line_no)
            new = current.get(line_no)

            if old is not None and new is None:
                if line_no not in claimed_lines:
                    old_alias = _norm(old.get("alias"))
                    events.append({
                        "device_id": inv_by_alias.get(old_alias.lower(), {}).get("id"),
                        "line_no": line_no,
                        "event_type": "CONSOLE_LINE_MISSING",
                        "severity": "HIGH",
                        "old_value": old_alias,
                        "new_value": "",
                        "message": f"Console line {line_no} is missing from the current accepted scan.",
                    })
                continue

            if old is None and new is not None:
                if mapping_confident and line_no not in claimed_lines and line_no not in inv_by_line:
                    alias = _norm(new.get("alias"))
                    # Only call it unmanaged/new if the alias is not a managed alias.
                    if alias and alias.lower() not in inv_by_alias:
                        events.append({
                            "device_id": None,
                            "line_no": line_no,
                            "event_type": "NEW_CONSOLE_DEVICE",
                            "severity": "WARNING",
                            "old_value": "",
                            "new_value": alias,
                            "message": f"New console mapping detected on line {line_no}: {alias}.",
                        })
                    elif not alias:
                        events.append({
                            "device_id": None,
                            "line_no": line_no,
                            "event_type": "LINE_OCCUPIED_BY_UNKNOWN",
                            "severity": "WARNING",
                            "old_value": "",
                            "new_value": f"line {line_no}",
                            "message": (
                                f"Line {line_no} appeared in an accepted scan without inventory or alias. "
                                "Add inventory or verify the physical console mapping."
                            ),
                        })
                continue

            if old is None or new is None:
                continue

            if mapping_confident and line_no not in claimed_lines:
                old_alias = _norm(old.get("alias"))
                new_alias = _norm(new.get("alias"))
                if old_alias != new_alias:
                    events.append({
                        "device_id": (
                            inv_by_alias.get(new_alias.lower(), {}).get("id")
                            or inv_by_alias.get(old_alias.lower(), {}).get("id")
                        ),
                        "line_no": line_no,
                        "event_type": "CONSOLE_MAPPING_CHANGED",
                        "severity": "HIGH",
                        "old_value": old_alias,
                        "new_value": new_alias,
                        "message": (
                            f"Console mapping line {line_no} changed: "
                            f"{old_alias or '(empty)'} -> {new_alias or '(empty)'}."
                        ),
                    })

            # Session changes are independent from mapping precedence.
            if session_confident:
                old_state = _norm(old.get("state")).upper()
                new_state = _norm(new.get("state")).upper()
                old_user = _norm(old.get("session_user"))
                new_user = _norm(new.get("session_user"))
                if old_state != new_state or old_user != new_user:
                    if new_state == "BUSY" and old_state != "BUSY":
                        events.append({
                            "device_id": inv_by_line.get(line_no, {}).get("id"),
                            "line_no": line_no,
                            "event_type": "CONSOLE_SESSION_STARTED",
                            "severity": "INFO",
                            "old_value": f"{old_state}:{old_user}",
                            "new_value": f"{new_state}:{new_user}",
                            "message": (
                                f"Console line {line_no} changed to BUSY"
                                + (f" by {new_user}." if new_user else ".")
                            ),
                        })
                    elif old_state == "BUSY" and new_state != "BUSY":
                        events.append({
                            "device_id": inv_by_line.get(line_no, {}).get("id"),
                            "line_no": line_no,
                            "event_type": "CONSOLE_SESSION_ENDED",
                            "severity": "INFO",
                            "old_value": f"{old_state}:{old_user}",
                            "new_value": f"{new_state}:{new_user}",
                            "message": f"Console line {line_no} is no longer BUSY.",
                        })

    # Exact duplicate guard within one scan.
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for event in events:
        key = (
            event["event_type"], event.get("device_id"), event.get("line_no"),
            event.get("old_value"), event.get("new_value"),
        )
        unique[key] = event
    return list(unique.values())
