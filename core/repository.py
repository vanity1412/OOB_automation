from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from .database import current_actor, db, now_ts


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(str(value).strip().replace(" ", "T"))


def _day_rows(start_ts: str, end_ts: str) -> list[str]:
    start_day = _parse_ts(start_ts).date()
    end_day = _parse_ts(end_ts).date()
    days: list[str] = []
    current = start_day
    max_days = 3660
    while current <= end_day and len(days) < max_days:
        days.append(current.isoformat())
        current += timedelta(days=1)
    return days


# ---------- Settings ----------
def get_setting(key: str, default: str = "") -> str:
    with db() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
    return str(row["value"]) if row else default


def set_setting(key: str, value: str) -> None:
    stamp = now_ts()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO app_settings(key,value,updated_at)
            VALUES(?,?,?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
            """,
            (key, str(value), stamp),
        )


# ---------- OOB ----------
def list_oobs() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM oob_nodes ORDER BY name COLLATE NOCASE").fetchall()
    return [dict(r) for r in rows]


def get_oob(oob_id: int) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM oob_nodes WHERE id=?", (oob_id,)).fetchone()
    return dict(row) if row else None


def save_oob(
    *, oob_id: int | None, name: str, vendor: str, profile_key: str,
    host: str, port: int, username: str, site: str, notes: str,
) -> int:
    name, host = name.strip(), host.strip()
    if not name or not host:
        raise ValueError("Tên OOB và IP/Hostname không được trống.")
    stamp = now_ts()
    with db() as conn:
        if oob_id:
            conn.execute(
                """
                UPDATE oob_nodes SET name=?,vendor=?,profile_key=?,host=?,port=?,
                    username=?,site=?,notes=?,updated_at=?
                WHERE id=?
                """,
                (
                    name, vendor, profile_key, host, int(port), username.strip(),
                    site.strip(), notes.strip(), stamp, oob_id,
                ),
            )
            return int(oob_id)
        cur = conn.execute(
            """
            INSERT INTO oob_nodes(
                name,vendor,profile_key,host,port,username,site,notes,created_at,updated_at
            )
            VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (
                name, vendor, profile_key, host, int(port), username.strip(),
                site.strip(), notes.strip(), stamp, stamp,
            ),
        )
        return int(cur.lastrowid)


def delete_oob(oob_id: int) -> None:
    with db() as conn:
        conn.execute("DELETE FROM oob_nodes WHERE id=?", (oob_id,))


# ---------- Device inventory ----------
def list_devices() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT d.*, o.name AS oob_name, o.host AS oob_host, o.vendor AS oob_vendor
            FROM devices d
            LEFT JOIN oob_nodes o ON o.id=d.oob_id
            ORDER BY d.hostname COLLATE NOCASE
            """
        ).fetchall()
    return [dict(r) for r in rows]


def get_device(device_id: int) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    return dict(row) if row else None


def save_device(
    *, device_id: int | None, oob_id: int | None, hostname: str,
    device_type: str, vendor: str, model: str, serial: str, mgmt_ip: str,
    site: str, rack: str, u_position: str, expected_line: int | None,
    expected_alias: str, notes: str, source: str = "", source_id: str = "",
    last_imported_at: str = "", verification_status: str = "UNVERIFIED",
    verification_source: str = "", verified_hostname: str = "",
    verified_serial: str = "", verified_model: str = "",
    verified_at: str = "", verified_by: str = "", verification_ticket_ref: str = "",
    verification_confidence: float = 0.0, verification_note: str = "",
) -> int:
    hostname = hostname.strip()
    if not hostname:
        raise ValueError("Hostname không được trống.")
    if expected_line is not None:
        expected_line = int(expected_line)
        if expected_line < 0:
            raise ValueError("Console line must be zero or greater.")
    expected_alias = expected_alias.strip()
    stamp = now_ts()
    values = (
        oob_id, hostname, device_type.strip(), vendor.strip(), model.strip(),
        serial.strip(), mgmt_ip.strip(), site.strip(), rack.strip(),
        u_position.strip(), expected_line, expected_alias, source.strip(),
        source_id.strip(), last_imported_at.strip(), notes.strip(),
    )
    with db() as conn:
        current_id = int(device_id or -1)
        if oob_id is not None and expected_line is not None:
            conflict = conn.execute(
                """
                SELECT id,hostname FROM devices
                WHERE oob_id=? AND expected_line=? AND id!=?
                LIMIT 1
                """,
                (oob_id, int(expected_line), current_id),
            ).fetchone()
            if conflict:
                raise ValueError(
                    f"Console line {expected_line} already assigned to {conflict['hostname']}."
                )
        if oob_id is not None and expected_alias:
            conflict = conn.execute(
                """
                SELECT id,hostname FROM devices
                WHERE oob_id=? AND LOWER(expected_alias)=LOWER(?) AND id!=?
                LIMIT 1
                """,
                (oob_id, expected_alias, current_id),
            ).fetchone()
            if conflict:
                raise ValueError(
                    f"Expected alias {expected_alias} already assigned to {conflict['hostname']}."
                )
        status = verification_status.strip().upper() or "UNVERIFIED"
        if status not in {"UNVERIFIED", "VERIFIED", "STALE"}:
            raise ValueError("Verification status must be UNVERIFIED, VERIFIED, or STALE.")
        verification_values = (
            status, verification_source.strip(), verified_hostname.strip(),
            verified_serial.strip(), verified_model.strip(), verified_at.strip(),
            verified_by.strip(), verification_ticket_ref.strip()[:128],
            max(0.0, min(float(verification_confidence or 0), 1.0)),
            verification_note.strip(),
        )
        if device_id:
            conn.execute(
                """
                UPDATE devices SET oob_id=?,hostname=?,device_type=?,vendor=?,model=?,serial=?,
                    mgmt_ip=?,site=?,rack=?,u_position=?,expected_line=?,expected_alias=?,
                    source=?,source_id=?,last_imported_at=?,notes=?,
                    verification_status=?,verification_source=?,verified_hostname=?,
                    verified_serial=?,verified_model=?,verified_at=?,verified_by=?,
                    verification_ticket_ref=?,verification_confidence=?,verification_note=?,
                    updated_at=?
                WHERE id=?
                """,
                values + verification_values + (stamp, device_id),
            )
            return int(device_id)
        cur = conn.execute(
            """
            INSERT INTO devices(
                oob_id,hostname,device_type,vendor,model,serial,mgmt_ip,
                site,rack,u_position,expected_line,expected_alias,source,source_id,last_imported_at,notes,
                verification_status,verification_source,verified_hostname,
                verified_serial,verified_model,verified_at,verified_by,
                verification_ticket_ref,verification_confidence,verification_note,
                created_at,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            values + verification_values + (stamp, stamp),
        )
        return int(cur.lastrowid)


def update_device_verification(
    *,
    device_id: int,
    status: str,
    source: str = "",
    verified_hostname: str | None = None,
    verified_serial: str | None = None,
    verified_model: str | None = None,
    ticket_ref: str = "",
    confidence: float = 0.0,
    note: str = "",
) -> None:
    status = status.strip().upper() or "UNVERIFIED"
    if status not in {"UNVERIFIED", "VERIFIED", "STALE"}:
        raise ValueError("Verification status must be UNVERIFIED, VERIFIED, or STALE.")

    stamp = now_ts()
    actor = current_actor()
    with db() as conn:
        existing = conn.execute("SELECT * FROM devices WHERE id=?", (int(device_id),)).fetchone()
        if not existing:
            raise ValueError("Device not found.")

        conn.execute(
            """
            UPDATE devices SET
                verification_status=?,
                verification_source=?,
                verified_hostname=?,
                verified_serial=?,
                verified_model=?,
                verified_at=?,
                verified_by=?,
                verification_ticket_ref=?,
                verification_confidence=?,
                verification_note=?,
                updated_at=?
            WHERE id=?
            """,
            (
                status,
                source.strip() or "operator",
                (verified_hostname if verified_hostname is not None else existing["verified_hostname"]) or "",
                (verified_serial if verified_serial is not None else existing["verified_serial"]) or "",
                (verified_model if verified_model is not None else existing["verified_model"]) or "",
                stamp,
                actor,
                ticket_ref.strip()[:128] or existing["verification_ticket_ref"] or "",
                max(0.0, min(float(confidence or 0), 1.0)),
                note.strip() or existing["verification_note"] or "",
                stamp,
                int(device_id),
            ),
        )


def assign_device_console_line(
    *,
    device_id: int,
    oob_id: int,
    line_no: int,
    expected_alias: str = "",
    ticket_ref: str = "",
    confidence: float = 0.0,
    note: str = "",
) -> None:
    line_no = int(line_no)
    stamp = now_ts()
    actor = current_actor()
    with db() as conn:
        device = conn.execute("SELECT * FROM devices WHERE id=?", (int(device_id),)).fetchone()
        if not device:
            raise ValueError("Device not found.")
        conflict = conn.execute(
            """
            SELECT id,hostname FROM devices
            WHERE oob_id=? AND expected_line=? AND id!=?
            LIMIT 1
            """,
            (int(oob_id), line_no, int(device_id)),
        ).fetchone()
        if conflict:
            raise ValueError(f"Console line {line_no} already assigned to {conflict['hostname']}.")

        verification_note = note.strip() or (
            f"Operator assigned OOB {oob_id} line {line_no} to {device['hostname']}."
        )
        conn.execute(
            """
            UPDATE devices SET
                oob_id=?,
                expected_line=?,
                expected_alias=?,
                verification_status='VERIFIED',
                verification_source='operator_line_assignment',
                verified_hostname=?,
                verified_at=?,
                verified_by=?,
                verification_ticket_ref=?,
                verification_confidence=?,
                verification_note=?,
                updated_at=?
            WHERE id=?
            """,
            (
                int(oob_id),
                line_no,
                expected_alias.strip() or device["expected_alias"] or "",
                device["hostname"],
                stamp,
                actor,
                ticket_ref.strip()[:128],
                max(0.0, min(float(confidence or 0), 1.0)),
                verification_note,
                stamp,
                int(device_id),
            ),
        )


def delete_device(device_id: int) -> None:
    with db() as conn:
        conn.execute("DELETE FROM devices WHERE id=?", (device_id,))


# ---------- Current detected state ----------
def upsert_detected(oob_id: int, rows: list[dict[str, Any]], scan_id: int) -> None:
    stamp = now_ts()
    with db() as conn:
        conn.execute("DELETE FROM detected_console WHERE oob_id=?", (oob_id,))
        for row in rows:
            last_output_at = stamp if (row.get("raw_line") or row.get("session_user")) else ""
            conn.execute(
                """
                INSERT INTO detected_console(
                    oob_id,line_no,alias,tcp_port,target_host,state,session_user,raw_line,
                    session_health,health_reason,prompt_context,context_confidence,last_output_at,
                    scan_id,last_seen
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    oob_id, row["line_no"], row.get("alias", ""), row.get("tcp_port"),
                    row.get("target_host", ""), row.get("state", "UNKNOWN"),
                    row.get("session_user", ""), row.get("raw_line", ""),
                    row.get("session_health", "UNKNOWN"), row.get("health_reason", ""),
                    row.get("prompt_context", "UNKNOWN"), float(row.get("context_confidence", 0) or 0),
                    row.get("last_output_at") or last_output_at,
                    scan_id, stamp,
                ),
            )


def list_detected(oob_id: int | None = None) -> list[dict[str, Any]]:
    with db() as conn:
        if oob_id is not None:
            rows = conn.execute(
                """
                SELECT dc.*, o.name AS oob_name, o.host AS oob_host
                FROM detected_console dc JOIN oob_nodes o ON o.id=dc.oob_id
                WHERE dc.oob_id=? ORDER BY dc.line_no
                """,
                (oob_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT dc.*, o.name AS oob_name, o.host AS oob_host
                FROM detected_console dc JOIN oob_nodes o ON o.id=dc.oob_id
                ORDER BY o.name, dc.line_no
                """
            ).fetchall()
    return [dict(r) for r in rows]


# ---------- Scan ----------
def create_scan(oob_id: int) -> int:
    stamp = now_ts()
    with db() as conn:
        cur = conn.execute("INSERT INTO scans(oob_id,started_at) VALUES(?,?)", (oob_id, stamp))
        return int(cur.lastrowid)


def finish_scan(
    scan_id: int, *, success: bool, line_count: int, error_text: str,
    raw_json: str, parse_status: str = "UNKNOWN", parse_quality: float = 0.0,
) -> None:
    stamp = now_ts()
    with db() as conn:
        conn.execute(
            """
            UPDATE scans SET finished_at=?,success=?,line_count=?,
                error_text=?,raw_json=?,parse_status=?,parse_quality=?
            WHERE id=?
            """,
            (
                stamp, 1 if success else 0, int(line_count), error_text[:4000], raw_json,
                parse_status[:64], float(parse_quality), scan_id,
            ),
        )


def record_scan_issue(
    *, scan_id: int, oob_id: int, issue_type: str, severity: str, message: str,
) -> int:
    stamp = now_ts()
    with db() as conn:
        cur = conn.execute(
            """
            INSERT INTO scan_issues(scan_id,oob_id,issue_type,severity,message,created_at)
            VALUES(?,?,?,?,?,?)
            """,
            (scan_id, oob_id, issue_type, severity, message[:2000], stamp),
        )
        return int(cur.lastrowid)


def list_scan_issues(limit: int = 200) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT si.*, o.name AS oob_name
            FROM scan_issues si JOIN oob_nodes o ON o.id=si.oob_id
            ORDER BY si.id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def list_scans(limit: int = 100) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT s.*, o.name AS oob_name, o.host AS oob_host
            FROM scans s JOIN oob_nodes o ON o.id=s.oob_id
            ORDER BY s.id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def list_scans_range(start_ts: str, end_ts: str, limit: int = 300) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT s.*, o.name AS oob_name, o.host AS oob_host
            FROM scans s JOIN oob_nodes o ON o.id=s.oob_id
            WHERE s.started_at BETWEEN ? AND ?
            ORDER BY s.id DESC LIMIT ?
            """,
            (start_ts, end_ts, int(limit)),
        ).fetchall()
    return [dict(r) for r in rows]


def list_scan_issues_range(start_ts: str, end_ts: str, limit: int = 300) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT si.*, o.name AS oob_name
            FROM scan_issues si JOIN oob_nodes o ON o.id=si.oob_id
            WHERE si.created_at BETWEEN ? AND ?
            ORDER BY si.id DESC LIMIT ?
            """,
            (start_ts, end_ts, int(limit)),
        ).fetchall()
    return [dict(r) for r in rows]


def analytics_daily_summary(start_ts: str, end_ts: str) -> list[dict[str, Any]]:
    days = {
        day: {
            "day": day,
            "scan_count": 0,
            "scan_accepted": 0,
            "scan_rejected": 0,
            "scan_error": 0,
            "snapshot_count": 0,
            "alert_new": 0,
            "alert_resolved": 0,
            "alerts_open_end": 0,
            "avg_parse_quality": None,
        }
        for day in _day_rows(start_ts, end_ts)
    }

    if not days:
        return []

    with db() as conn:
        scan_rows = conn.execute(
            """
            SELECT
                date(started_at) AS day,
                COUNT(*) AS scan_count,
                SUM(CASE WHEN parse_status='ACCEPTED' THEN 1 ELSE 0 END) AS scan_accepted,
                SUM(CASE WHEN parse_status='REJECTED' THEN 1 ELSE 0 END) AS scan_rejected,
                SUM(
                    CASE
                        WHEN parse_status='ERROR'
                          OR (success=0 AND parse_status NOT IN ('ACCEPTED','REJECTED'))
                        THEN 1 ELSE 0
                    END
                ) AS scan_error,
                AVG(CASE WHEN parse_quality > 0 THEN parse_quality END) AS avg_parse_quality
            FROM scans
            WHERE started_at BETWEEN ? AND ?
            GROUP BY date(started_at)
            """,
            (start_ts, end_ts),
        ).fetchall()

        snapshot_rows = conn.execute(
            """
            SELECT date(captured_at) AS day, COUNT(*) AS snapshot_count
            FROM console_snapshots
            WHERE captured_at BETWEEN ? AND ?
            GROUP BY date(captured_at)
            """,
            (start_ts, end_ts),
        ).fetchall()

        alert_new_rows = conn.execute(
            """
            SELECT date(first_seen) AS day, COUNT(*) AS alert_new
            FROM change_events
            WHERE first_seen BETWEEN ? AND ?
            GROUP BY date(first_seen)
            """,
            (start_ts, end_ts),
        ).fetchall()

        alert_resolved_rows = conn.execute(
            """
            SELECT date(resolved_at) AS day, COUNT(*) AS alert_resolved
            FROM change_events
            WHERE resolved_at IS NOT NULL
              AND resolved_at != ''
              AND resolved_at BETWEEN ? AND ?
            GROUP BY date(resolved_at)
            """,
            (start_ts, end_ts),
        ).fetchall()

        open_events = [
            dict(r)
            for r in conn.execute(
                """
                SELECT first_seen, resolved_at, status
                FROM change_events
                WHERE first_seen <= ?
                  AND (resolved_at IS NULL OR resolved_at='' OR resolved_at >= ?)
                """,
                (end_ts, start_ts),
            ).fetchall()
        ]

    for row in scan_rows:
        item = days.get(row["day"])
        if item:
            item.update(
                {
                    "scan_count": int(row["scan_count"] or 0),
                    "scan_accepted": int(row["scan_accepted"] or 0),
                    "scan_rejected": int(row["scan_rejected"] or 0),
                    "scan_error": int(row["scan_error"] or 0),
                    "avg_parse_quality": (
                        round(float(row["avg_parse_quality"]), 3)
                        if row["avg_parse_quality"] is not None
                        else None
                    ),
                }
            )

    for row in snapshot_rows:
        if row["day"] in days:
            days[row["day"]]["snapshot_count"] = int(row["snapshot_count"] or 0)
    for row in alert_new_rows:
        if row["day"] in days:
            days[row["day"]]["alert_new"] = int(row["alert_new"] or 0)
    for row in alert_resolved_rows:
        if row["day"] in days:
            days[row["day"]]["alert_resolved"] = int(row["alert_resolved"] or 0)

    for day, item in days.items():
        day_end = f"{day} 23:59:59"
        open_count = 0
        for event in open_events:
            first_seen = str(event.get("first_seen") or "")
            resolved_at = str(event.get("resolved_at") or "")
            if first_seen <= day_end and (not resolved_at or resolved_at > day_end):
                open_count += 1
        item["alerts_open_end"] = open_count

    return [days[day] for day in sorted(days)]


def analytics_alert_severity(start_ts: str, end_ts: str) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT date(first_seen) AS day, severity, COUNT(*) AS count
            FROM change_events
            WHERE first_seen BETWEEN ? AND ?
            GROUP BY date(first_seen), severity
            ORDER BY day, severity
            """,
            (start_ts, end_ts),
        ).fetchall()
    return [dict(r) for r in rows]


# ---------- Snapshot history ----------
def latest_snapshot_map(oob_id: int) -> dict[int, dict[str, Any]]:
    with db() as conn:
        row = conn.execute(
            "SELECT scan_id FROM console_snapshots WHERE oob_id=? ORDER BY id DESC LIMIT 1",
            (oob_id,),
        ).fetchone()
        if not row:
            return {}
        rows = conn.execute(
            "SELECT * FROM console_snapshots WHERE oob_id=? AND scan_id=? ORDER BY line_no",
            (oob_id, row["scan_id"]),
        ).fetchall()
    return {int(r["line_no"]): dict(r) for r in rows}


def save_snapshots(*, scan_id: int, oob_id: int, rows: list[dict[str, Any]]) -> None:
    stamp = now_ts()
    with db() as conn:
        for row in rows:
            conn.execute(
                """
                INSERT INTO console_snapshots(
                    scan_id,oob_id,line_no,alias,tcp_port,target_host,state,session_user,raw_line,
                    session_health,health_reason,prompt_context,context_confidence,captured_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    scan_id, oob_id, row["line_no"], row.get("alias", ""), row.get("tcp_port"),
                    row.get("target_host", ""), row.get("state", "UNKNOWN"),
                    row.get("session_user", ""), row.get("raw_line", ""),
                    row.get("session_health", "UNKNOWN"), row.get("health_reason", ""),
                    row.get("prompt_context", "UNKNOWN"), float(row.get("context_confidence", 0) or 0),
                    stamp,
                ),
            )


def list_snapshots(
    *,
    oob_id: int | None = None,
    line_no: int | None = None,
    days: int | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    sql = """
        SELECT cs.*, o.name AS oob_name
        FROM console_snapshots cs JOIN oob_nodes o ON o.id=cs.oob_id
        WHERE 1=1
    """
    args: list[Any] = []
    if oob_id is not None:
        sql += " AND cs.oob_id=?"
        args.append(oob_id)
    if line_no is not None:
        sql += " AND cs.line_no=?"
        args.append(line_no)
    if days is not None:
        days = max(1, min(int(days), 3650))
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        sql += " AND cs.captured_at >= ?"
        args.append(cutoff)
    sql += " ORDER BY cs.id DESC LIMIT ?"
    args.append(limit)
    with db() as conn:
        rows = conn.execute(sql, tuple(args)).fetchall()
    return [dict(r) for r in rows]


def list_snapshots_range(
    start_ts: str,
    end_ts: str,
    *,
    oob_id: int | None = None,
    line_no: int | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    sql = """
        SELECT cs.*, o.name AS oob_name
        FROM console_snapshots cs JOIN oob_nodes o ON o.id=cs.oob_id
        WHERE cs.captured_at BETWEEN ? AND ?
    """
    args: list[Any] = [start_ts, end_ts]
    if oob_id is not None:
        sql += " AND cs.oob_id=?"
        args.append(oob_id)
    if line_no is not None:
        sql += " AND cs.line_no=?"
        args.append(line_no)
    sql += " ORDER BY cs.id DESC LIMIT ?"
    args.append(int(limit))
    with db() as conn:
        rows = conn.execute(sql, tuple(args)).fetchall()
    return [dict(r) for r in rows]


def history_summary(days: int | None = None) -> dict[str, int]:
    where_scan = ""
    where_snapshot = ""
    where_event = ""
    scan_args: list[Any] = []
    snapshot_args: list[Any] = []
    event_args: list[Any] = []
    if days is not None:
        days = max(1, min(int(days), 3650))
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        where_scan = " WHERE started_at >= ?"
        where_snapshot = " WHERE captured_at >= ?"
        where_event = " WHERE first_seen >= ?"
        scan_args = [cutoff]
        snapshot_args = [cutoff]
        event_args = [cutoff]

    with db() as conn:
        scans = conn.execute(
            f"SELECT COUNT(*) AS c FROM scans{where_scan}", tuple(scan_args)
        ).fetchone()["c"]
        snapshots = conn.execute(
            f"SELECT COUNT(*) AS c FROM console_snapshots{where_snapshot}",
            tuple(snapshot_args),
        ).fetchone()["c"]
        events = conn.execute(
            f"SELECT COUNT(*) AS c FROM change_events{where_event}",
            tuple(event_args),
        ).fetchone()["c"]
        open_events = conn.execute(
            "SELECT COUNT(*) AS c FROM change_events WHERE status!='RESOLVED'"
        ).fetchone()["c"]
        detected = conn.execute("SELECT COUNT(*) AS c FROM detected_console").fetchone()["c"]

    return {
        "scans": int(scans),
        "snapshots": int(snapshots),
        "events": int(events),
        "open_events": int(open_events),
        "detected": int(detected),
    }


def prune_history(snapshot_days: int, raw_days: int) -> dict[str, int]:
    snapshot_days = max(1, min(int(snapshot_days), 3650))
    raw_days = max(1, min(int(raw_days), 3650))
    snapshot_cutoff = (datetime.now() - timedelta(days=snapshot_days)).strftime("%Y-%m-%d %H:%M:%S")
    raw_cutoff = (datetime.now() - timedelta(days=raw_days)).strftime("%Y-%m-%d %H:%M:%S")
    with db() as conn:
        cur1 = conn.execute(
            "DELETE FROM console_snapshots WHERE captured_at < ?",
            (snapshot_cutoff,),
        )
        cur2 = conn.execute(
            "UPDATE scans SET raw_json='' WHERE finished_at < ? AND raw_json!=''",
            (raw_cutoff,),
        )
    return {"snapshots_deleted": cur1.rowcount, "raw_scans_cleared": cur2.rowcount}


# ---------- Change events / alerts ----------
def create_or_update_change_event(
    *, oob_id: int, device_id: int | None, line_no: int | None,
    event_type: str, severity: str, old_value: str, new_value: str,
    message: str, scan_id: int,
) -> tuple[int, bool]:
    """Dedup/rate-limit: same unresolved event type + OOB + line/device is updated."""
    stamp = now_ts()
    with db() as conn:
        if line_no is not None:
            existing = conn.execute(
                """
                SELECT id FROM change_events
                WHERE oob_id=? AND line_no=? AND event_type=? AND status!='RESOLVED'
                ORDER BY id DESC LIMIT 1
                """,
                (oob_id, line_no, event_type),
            ).fetchone()
        else:
            existing = conn.execute(
                """
                SELECT id FROM change_events
                WHERE oob_id=?
                  AND COALESCE(device_id,-1)=COALESCE(?,-1)
                  AND line_no IS NULL
                  AND event_type=?
                  AND status!='RESOLVED'
                ORDER BY id DESC LIMIT 1
                """,
                (oob_id, device_id, event_type),
            ).fetchone()
        if existing:
            event_id = int(existing["id"])
            conn.execute(
                """
                UPDATE change_events SET device_id=?,severity=?,new_value=?,message=?,scan_id=?,
                    last_seen=?,occurrence_count=occurrence_count+1
                WHERE id=?
                """,
                (device_id, severity, new_value[:1000], message[:1500], scan_id, stamp, event_id),
            )
            return event_id, False
        cur = conn.execute(
            """
            INSERT INTO change_events(
                oob_id,device_id,line_no,event_type,severity,old_value,new_value,
                message,status,scan_id,first_seen,last_seen,occurrence_count
            ) VALUES(?,?,?,?,?,?,?,?, 'NEW', ?, ?, ?, 1)
            """,
            (
                oob_id, device_id, line_no, event_type, severity,
                old_value[:1000], new_value[:1000], message[:1500], scan_id, stamp, stamp,
            ),
        )
        return int(cur.lastrowid), True


def list_change_events(
    *, status: str | None = None, severity: str | None = None,
    oob_id: int | None = None, limit: int = 500,
) -> list[dict[str, Any]]:
    sql = """
        SELECT ce.*, o.name AS oob_name, d.hostname AS device_name
        FROM change_events ce
        JOIN oob_nodes o ON o.id=ce.oob_id
        LEFT JOIN devices d ON d.id=ce.device_id
        WHERE 1=1
    """
    args: list[Any] = []
    if status:
        sql += " AND ce.status=?"
        args.append(status)
    if severity:
        sql += " AND ce.severity=?"
        args.append(severity)
    if oob_id is not None:
        sql += " AND ce.oob_id=?"
        args.append(oob_id)
    sql += """
        ORDER BY
            CASE ce.status WHEN 'NEW' THEN 0 WHEN 'ACKNOWLEDGED' THEN 1 ELSE 2 END,
            CASE ce.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'WARNING' THEN 2 ELSE 3 END,
            ce.last_seen DESC
        LIMIT ?
    """
    args.append(limit)
    with db() as conn:
        rows = conn.execute(sql, tuple(args)).fetchall()
    return [dict(r) for r in rows]


def list_change_events_range(
    start_ts: str,
    end_ts: str,
    *,
    status: str | None = None,
    severity: str | None = None,
    oob_id: int | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    sql = """
        SELECT ce.*, o.name AS oob_name, d.hostname AS device_name
        FROM change_events ce
        JOIN oob_nodes o ON o.id=ce.oob_id
        LEFT JOIN devices d ON d.id=ce.device_id
        WHERE (
            ce.first_seen BETWEEN ? AND ?
            OR ce.last_seen BETWEEN ? AND ?
            OR ce.resolved_at BETWEEN ? AND ?
        )
    """
    args: list[Any] = [start_ts, end_ts, start_ts, end_ts, start_ts, end_ts]
    if status:
        sql += " AND ce.status=?"
        args.append(status)
    if severity:
        sql += " AND ce.severity=?"
        args.append(severity)
    if oob_id is not None:
        sql += " AND ce.oob_id=?"
        args.append(oob_id)
    sql += """
        ORDER BY
            CASE ce.status WHEN 'NEW' THEN 0 WHEN 'ACKNOWLEDGED' THEN 1 ELSE 2 END,
            CASE ce.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'WARNING' THEN 2 ELSE 3 END,
            ce.last_seen DESC
        LIMIT ?
    """
    args.append(int(limit))
    with db() as conn:
        rows = conn.execute(sql, tuple(args)).fetchall()
    return [dict(r) for r in rows]


def update_change_event_status(event_id: int, *, status: str, note: str = "") -> None:
    status = status.upper()
    if status not in {"NEW", "ACKNOWLEDGED", "RESOLVED"}:
        raise ValueError("Alert status không hợp lệ.")
    actor = current_actor()
    stamp = now_ts()
    with db() as conn:
        if status == "ACKNOWLEDGED":
            conn.execute(
                """
                UPDATE change_events SET status='ACKNOWLEDGED',acknowledged_at=?,
                    acknowledged_by=?,note=? WHERE id=?
                """,
                (stamp, actor, note.strip(), event_id),
            )
        elif status == "RESOLVED":
            conn.execute(
                """
                UPDATE change_events SET status='RESOLVED',resolved_at=?,
                    resolved_by=?,note=? WHERE id=?
                """,
                (stamp, actor, note.strip(), event_id),
            )
        else:
            conn.execute(
                """
                UPDATE change_events SET status='NEW',acknowledged_at=NULL,acknowledged_by='',
                    resolved_at=NULL,resolved_by='',note=? WHERE id=?
                """,
                (note.strip(), event_id),
            )


def count_open_events() -> dict[str, int]:
    with db() as conn:
        rows = conn.execute(
            "SELECT severity,COUNT(*) AS c FROM change_events WHERE status!='RESOLVED' GROUP BY severity"
        ).fetchall()
    out = {"CRITICAL": 0, "HIGH": 0, "WARNING": 0, "INFO": 0}
    for row in rows:
        out[row["severity"]] = int(row["c"])
    return out


# ---------- Audit ----------
def list_audit(limit: int = 300) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def list_audit_range(
    start_ts: str,
    end_ts: str,
    *,
    actor: str | None = None,
    action: str | None = None,
    oob_id: int | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    sql = "SELECT * FROM audit WHERE ts BETWEEN ? AND ?"
    args: list[Any] = [start_ts, end_ts]
    if actor:
        sql += " AND actor=?"
        args.append(actor)
    if action:
        sql += " AND action=?"
        args.append(action)
    if oob_id is not None:
        sql += " AND oob_id=?"
        args.append(oob_id)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(int(limit))
    with db() as conn:
        rows = conn.execute(sql, tuple(args)).fetchall()
    return [dict(r) for r in rows]


# ---------- Real OOB operations foundation ----------
def operational_foundation_summary() -> list[dict[str, Any]]:
    with db() as conn:
        total_devices = conn.execute("SELECT COUNT(*) AS c FROM devices").fetchone()["c"]
        verified_devices = conn.execute(
            """
            SELECT COUNT(*) AS c FROM devices
            WHERE UPPER(COALESCE(verification_status,'UNVERIFIED'))='VERIFIED'
            """
        ).fetchone()["c"]
        stale_devices = conn.execute(
            """
            SELECT COUNT(*) AS c FROM devices
            WHERE UPPER(COALESCE(verification_status,''))='STALE'
            """
        ).fetchone()["c"]
        terminal_contexts = conn.execute("SELECT COUNT(*) AS c FROM terminal_contexts").fetchone()["c"]
        known_health = conn.execute(
            """
            SELECT COUNT(*) AS c FROM detected_console
            WHERE UPPER(COALESCE(session_health,'UNKNOWN'))!='UNKNOWN'
            """
        ).fetchone()["c"]
        total_detected = conn.execute("SELECT COUNT(*) AS c FROM detected_console").fetchone()["c"]
        power_maps = conn.execute("SELECT COUNT(*) AS c FROM console_power_map").fetchone()["c"]
        readiness_checks = conn.execute("SELECT COUNT(*) AS c FROM readiness_checks").fetchone()["c"]
        safe_runs = conn.execute("SELECT COUNT(*) AS c FROM safe_automation_runs").fetchone()["c"]
        audit_ticketed = conn.execute(
            "SELECT COUNT(*) AS c FROM audit WHERE COALESCE(ticket_ref,'')!=''"
        ).fetchone()["c"]
        audit_total = conn.execute("SELECT COUNT(*) AS c FROM audit").fetchone()["c"]

    unverified = max(0, int(total_devices or 0) - int(verified_devices or 0) - int(stale_devices or 0))
    return [
        {
            "Capability": "Verified inventory",
            "Status": "READY" if verified_devices else "FOUNDATION",
            "Signal": f"verified={int(verified_devices or 0)}, stale={int(stale_devices or 0)}, unverified={unverified}",
            "Safe Next Step": "Verify target identity from prompt/show output before trusting alias-only mapping.",
        },
        {
            "Capability": "Context-aware terminal",
            "Status": "FOUNDATION",
            "Signal": f"context records={int(terminal_contexts or 0)}",
            "Safe Next Step": "Record OOB vs target context before enabling any command automation.",
        },
        {
            "Capability": "Session health",
            "Status": "READY" if known_health else "FOUNDATION",
            "Signal": f"known health={int(known_health or 0)}/{int(total_detected or 0)} detected lines",
            "Safe Next Step": "Classify stale session, no output, bootloader, wrong baud, or active operator.",
        },
        {
            "Capability": "Vendor abstraction",
            "Status": "READY",
            "Signal": "Cisco CLI and Vertiv ACS API profiles",
            "Safe Next Step": "Keep new vendor profiles out of production until real output/API payloads are verified.",
        },
        {
            "Capability": "Safe automation",
            "Status": "FOUNDATION",
            "Signal": f"guarded runs={int(safe_runs or 0)}",
            "Safe Next Step": "Require target context, show-only scope, and ticket/note before batch commands.",
        },
        {
            "Capability": "Readable audit",
            "Status": "READY" if audit_total else "FOUNDATION",
            "Signal": f"ticketed={int(audit_ticketed or 0)}/{int(audit_total or 0)} audit rows",
            "Safe Next Step": "Use actor/date/action filters and attach ticket_ref/note for operator actions.",
        },
        {
            "Capability": "Console + power mapping",
            "Status": "FOUNDATION",
            "Signal": f"power mappings={int(power_maps or 0)}",
            "Safe Next Step": "Map console line to PDU/outlet first; keep reboot action manual until verified.",
        },
        {
            "Capability": "Disaster readiness check",
            "Status": "FOUNDATION",
            "Signal": f"checks={int(readiness_checks or 0)}",
            "Safe Next Step": "Schedule reachability/port-response/credential checks without storing passwords.",
        },
    ]


def list_terminal_contexts(limit: int = 100) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT tc.*, o.name AS oob_name, d.hostname AS device_name
            FROM terminal_contexts tc
            JOIN oob_nodes o ON o.id=tc.oob_id
            LEFT JOIN devices d ON d.id=tc.device_id
            ORDER BY tc.id DESC LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
    return [dict(r) for r in rows]


def list_console_power_map(limit: int = 100) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT pm.*, o.name AS oob_name, d.hostname AS device_name
            FROM console_power_map pm
            JOIN oob_nodes o ON o.id=pm.oob_id
            LEFT JOIN devices d ON d.id=pm.device_id
            ORDER BY pm.id DESC LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
    return [dict(r) for r in rows]


def save_console_power_map(
    *,
    mapping_id: int | None = None,
    oob_id: int,
    device_id: int | None,
    line_no: int | None,
    pdu_name: str,
    pdu_host: str,
    outlet_label: str,
    control_mode: str = "MANUAL",
    verified_at: str = "",
    notes: str = "",
) -> int:
    pdu_name = pdu_name.strip()
    outlet_label = outlet_label.strip()
    if not pdu_name or not outlet_label:
        raise ValueError("PDU name and outlet label are required.")
    control_mode = control_mode.strip().upper() or "MANUAL"
    if control_mode != "MANUAL":
        raise ValueError("Only MANUAL power mapping is allowed in this build.")
    stamp = now_ts()
    values = (
        int(oob_id),
        device_id,
        None if line_no is None else int(line_no),
        pdu_name,
        pdu_host.strip(),
        outlet_label,
        control_mode,
        verified_at.strip() or stamp,
        notes.strip(),
    )
    with db() as conn:
        if mapping_id:
            conn.execute(
                """
                UPDATE console_power_map SET
                    oob_id=?,device_id=?,line_no=?,pdu_name=?,pdu_host=?,outlet_label=?,
                    control_mode=?,verified_at=?,notes=?,updated_at=?
                WHERE id=?
                """,
                values + (stamp, int(mapping_id)),
            )
            return int(mapping_id)
        cur = conn.execute(
            """
            INSERT INTO console_power_map(
                oob_id,device_id,line_no,pdu_name,pdu_host,outlet_label,
                control_mode,verified_at,notes,created_at,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """,
            values + (stamp, stamp),
        )
        return int(cur.lastrowid)


def delete_console_power_map(mapping_id: int) -> None:
    with db() as conn:
        conn.execute("DELETE FROM console_power_map WHERE id=?", (int(mapping_id),))


def list_readiness_checks(limit: int = 100) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT rc.*, o.name AS oob_name, d.hostname AS device_name
            FROM readiness_checks rc
            LEFT JOIN oob_nodes o ON o.id=rc.oob_id
            LEFT JOIN devices d ON d.id=rc.device_id
            ORDER BY rc.id DESC LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
    return [dict(r) for r in rows]
