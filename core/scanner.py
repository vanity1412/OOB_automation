from __future__ import annotations

import json
from contextlib import nullcontext
from typing import Any

from .change_detection import detect_changes
from .discovery import (
    evaluate_parse_quality,
    has_cli_error,
    merge,
    parse_cisco_hosts,
    parse_generic_host_mappings,
    parse_lines,
    parse_users,
    preserve_previous_mapping,
)
from .profiles import load_profile
from .repository import (
    create_or_update_change_event,
    create_scan,
    finish_scan,
    get_setting,
    latest_snapshot_map,
    prune_history,
    record_scan_issue,
    save_snapshots,
    upsert_detected,
)
from .scan_lock import global_scan_lock
from .session_health import annotate_session_health


def first_working(
    session,
    candidates: list[str],
    *,
    command_timeout: int,
) -> tuple[str, str, list[str]]:
    errors: list[str] = []
    for cmd in candidates:
        try:
            output = session.command(cmd, timeout=command_timeout)
            if output.strip():
                if has_cli_error(output):
                    first_line = next(
                        (line.strip() for line in output.splitlines() if line.strip()),
                        "CLI error",
                    )
                    errors.append(f"{cmd}: CLI_ERROR: {first_line[:200]}")
                    continue
                return cmd, output, errors
        except Exception as exc:
            # No credentials are included in these messages.
            errors.append(f"{cmd}: {type(exc).__name__}: {exc}")
    return "", "", errors


def scan(session, oob_id: int, profile_key: str, *, acquire_lock: bool = True) -> dict[str, Any]:
    profile = load_profile(profile_key)
    command_timeout = int(profile.get("command_timeout", 15))

    lock_ctx = global_scan_lock() if acquire_lock else nullcontext()
    with lock_ctx:
        scan_id = create_scan(oob_id)
        raw: dict[str, dict[str, Any]] = {}
        all_errors: list[str] = []

        try:
            for kind, candidates in profile.get("commands", {}).items():
                cmd, output, errors = first_working(
                    session,
                    candidates,
                    command_timeout=command_timeout,
                )
                raw[kind] = {"command": cmd, "output": output}
                all_errors.extend(errors)

            base = int(profile.get("reverse_tcp_base", 2000))
            host_text = raw.get("hosts", {}).get("output", "")
            line_text = raw.get("lines", {}).get("output", "")
            user_text = raw.get("users", {}).get("output", "")

            previous = latest_snapshot_map(oob_id)
            line_map = parse_lines(line_text)
            users = parse_users(user_text)
            if profile.get("vendor") == "cisco":
                host_records = parse_cisco_hosts(host_text, base)
            else:
                host_records = parse_generic_host_mappings(host_text, base)

            parsed_records = merge(host_records, line_map, users)
            quality = evaluate_parse_quality(
                profile=profile,
                line_output=line_text,
                user_output=user_text,
                host_output=host_text,
                line_map=line_map,
                host_records=host_records,
                users=users,
                merged_rows=parsed_records,
                previous=previous,
            )

            # Hard quality gate: rejected parse never overwrites current state,
            # never becomes a snapshot, and never creates change alerts.
            if not quality.accepted:
                message = quality.summary()
                record_scan_issue(
                    scan_id=scan_id,
                    oob_id=oob_id,
                    issue_type="PARSE_REJECTED",
                    severity="WARNING",
                    message=message,
                )
                finish_scan(
                    scan_id,
                    success=False,
                    line_count=len(parsed_records),
                    error_text="\n".join(all_errors + [message]),
                    raw_json=json.dumps(raw, ensure_ascii=False),
                    parse_status="REJECTED",
                    parse_quality=quality.score,
                )
                return {
                    "scan_id": scan_id,
                    "records": parsed_records,
                    "raw": raw,
                    "errors": all_errors,
                    "profile": profile,
                    "accepted": False,
                    "parse_quality": quality.score,
                    "parse_summary": message,
                    "mapping_confident": quality.mapping_confident,
                    "session_confident": quality.session_confident,
                    "change_count": 0,
                    "new_event_count": 0,
                    "event_ids": [],
                    "baseline_created": not bool(previous),
                }

            # If host/alias parser is not trusted, preserve the last-known aliases
            # instead of turning missing parse data into fake mapping changes.
            effective_records = parsed_records
            if previous and not quality.mapping_confident:
                effective_records = preserve_previous_mapping(parsed_records, previous)
            effective_records = annotate_session_health(effective_records, previous)

            upsert_detected(oob_id, effective_records, scan_id)

            candidates = detect_changes(
                oob_id=oob_id,
                previous=previous,
                current_rows=effective_records,
                emit_history_events=bool(previous),
                mapping_confident=quality.mapping_confident,
                session_confident=quality.session_confident,
            )

            event_ids: list[int] = []
            new_event_count = 0
            for event in candidates:
                event_id, is_new = create_or_update_change_event(
                    oob_id=oob_id,
                    device_id=event.get("device_id"),
                    line_no=event.get("line_no"),
                    event_type=event["event_type"],
                    severity=event["severity"],
                    old_value=event.get("old_value", ""),
                    new_value=event.get("new_value", ""),
                    message=event["message"],
                    scan_id=scan_id,
                )
                event_ids.append(event_id)
                new_event_count += int(is_new)

            save_snapshots(scan_id=scan_id, oob_id=oob_id, rows=effective_records)

            # Automatic data-growth control after every accepted scan.
            snapshot_days = int(get_setting("snapshot_retention_days", "90"))
            raw_days = int(get_setting("scan_raw_retention_days", "30"))
            prune_history(snapshot_days, raw_days)

            warning_text = quality.summary() if quality.warnings else ""
            finish_scan(
                scan_id,
                success=True,
                line_count=len(effective_records),
                error_text="\n".join(all_errors + ([warning_text] if warning_text else [])),
                raw_json=json.dumps(raw, ensure_ascii=False),
                parse_status="ACCEPTED",
                parse_quality=quality.score,
            )

            return {
                "scan_id": scan_id,
                "records": effective_records,
                "raw": raw,
                "errors": all_errors,
                "profile": profile,
                "accepted": True,
                "parse_quality": quality.score,
                "parse_summary": quality.summary(),
                "mapping_confident": quality.mapping_confident,
                "session_confident": quality.session_confident,
                "change_count": len(event_ids),
                "new_event_count": new_event_count,
                "event_ids": event_ids,
                "baseline_created": not bool(previous),
            }

        except Exception as exc:
            finish_scan(
                scan_id,
                success=False,
                line_count=0,
                error_text=f"{type(exc).__name__}: {exc}",
                raw_json=json.dumps(raw, ensure_ascii=False),
                parse_status="ERROR",
                parse_quality=0.0,
            )
            raise
