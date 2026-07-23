from __future__ import annotations

from typing import Any


def _clean(value: Any) -> str:
    return str(value or "").strip()


def classify_session_health(
    row: dict[str, Any],
    previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    state = _clean(row.get("state")).upper() or "UNKNOWN"
    user = _clean(row.get("session_user"))
    raw_line = _clean(row.get("raw_line"))
    raw_low = raw_line.lower()
    prev_state = _clean((previous or {}).get("state")).upper()
    prev_user = _clean((previous or {}).get("session_user"))

    context = "OOB_LINE_STATE" if raw_line else "UNKNOWN"
    confidence = 0.7 if raw_line else 0.0
    bootloader_markers = ("rommon", "bootloader", "loader>", "switch:", "loader:", "monitor mode")

    if any(marker in raw_low for marker in bootloader_markers):
        health = "BOOTLOADER_OR_ROMMON"
        reason = "Line output contains bootloader/ROMMON-like markers."
        context = "TARGET_BOOTLOADER"
        confidence = 0.85
    elif state == "AVAILABLE" and not user:
        health = "AVAILABLE_CONFIRMED"
        reason = "Line reports idle/free and no session user was parsed."
    elif state == "AVAILABLE" and user:
        health = "INCONSISTENT"
        reason = "Line reports available but a session user was parsed."
    elif state == "BUSY" and user:
        health = "ACTIVE_OPERATOR"
        reason = f"Line is busy with parsed session user {user}."
    elif state == "BUSY" and prev_state == "BUSY" and not user and not prev_user:
        health = "STALE_SESSION"
        reason = "Line stayed busy across scans but no user was parsed."
    elif state == "BUSY":
        health = "BUSY_NO_USER"
        reason = "Line is busy but no session user was parsed."
    elif not raw_line:
        health = "NO_OUTPUT"
        reason = "No line output was captured for this row."
    else:
        health = "UNKNOWN_CONTEXT"
        reason = "Line state exists but context could not be classified confidently."

    return {
        "session_health": health,
        "health_reason": reason,
        "prompt_context": context,
        "context_confidence": confidence,
    }


def annotate_session_health(
    rows: list[dict[str, Any]],
    previous: dict[int, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    previous = previous or {}
    annotated: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        line_no = int(item["line_no"])
        item.update(classify_session_health(item, previous.get(line_no)))
        annotated.append(item)
    return annotated
