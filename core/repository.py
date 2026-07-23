from __future__ import annotations

from typing import Any

from .database import current_actor, db


# ---------- Settings ----------
def get_setting(key: str, default: str = "") -> str:
    with db() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
    return str(row["value"]) if row else default


def set_setting(key: str, value: str) -> None:
    with db() as conn:
        conn.execute(
            """
            INSERT INTO app_settings(key,value,updated_at)
            VALUES(?,?,CURRENT_TIMESTAMP)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP
            """,
            (key, str(value)),
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
    with db() as conn:
        if oob_id:
            conn.execute(
                """
                UPDATE oob_nodes SET name=?,vendor=?,profile_key=?,host=?,port=?,
                    username=?,site=?,notes=?,updated_at=CURRENT_TIMESTAMP
                WHERE id=?
                """,
                (name, vendor, profile_key, host, int(port), username.strip(), site.strip(), notes.strip(), oob_id),
            )
            return int(oob_id)
        cur = conn.execute(
            """
            INSERT INTO oob_nodes(name,vendor,profile_key,host,port,username,site,notes)
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (name, vendor, profile_key, host, int(port), username.strip(), site.strip(), notes.strip()),
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
    expected_alias: str, notes: str,
) -> int:
    hostname = hostname.strip()
    if not hostname:
        raise ValueError("Hostname không được trống.")
    if expected_line is not None:
        expected_line = int(expected_line)
        if expected_line < 0:
            raise ValueError("Console line must be zero or greater.")
    expected_alias = expected_alias.strip()
    values = (
        oob_id, hostname, device_type.strip(), vendor.strip(), model.strip(),
        serial.strip(), mgmt_ip.strip(), site.strip(), rack.strip(),
        u_position.strip(), expected_line, expected_alias, notes.strip(),
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
        if device_id:
            conn.execute(
                """
                UPDATE devices SET oob_id=?,hostname=?,device_type=?,vendor=?,model=?,serial=?,
                    mgmt_ip=?,site=?,rack=?,u_position=?,expected_line=?,expected_alias=?,notes=?,
                    updated_at=CURRENT_TIMESTAMP
                WHERE id=?
                """,
                values + (device_id,),
            )
            return int(device_id)
        cur = conn.execute(
            """
            INSERT INTO devices(
                oob_id,hostname,device_type,vendor,model,serial,mgmt_ip,
                site,rack,u_position,expected_line,expected_alias,notes
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            values,
        )
        return int(cur.lastrowid)


def delete_device(device_id: int) -> None:
    with db() as conn:
        conn.execute("DELETE FROM devices WHERE id=?", (device_id,))


# ---------- Current detected state ----------
def upsert_detected(oob_id: int, rows: list[dict[str, Any]], scan_id: int) -> None:
    with db() as conn:
        conn.execute("DELETE FROM detected_console WHERE oob_id=?", (oob_id,))
        for row in rows:
            conn.execute(
                """
                INSERT INTO detected_console(
                    oob_id,line_no,alias,tcp_port,target_host,state,session_user,raw_line,scan_id,last_seen
                ) VALUES(?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
                """,
                (
                    oob_id, row["line_no"], row.get("alias", ""), row.get("tcp_port"),
                    row.get("target_host", ""), row.get("state", "UNKNOWN"),
                    row.get("session_user", ""), row.get("raw_line", ""), scan_id,
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
    with db() as conn:
        cur = conn.execute("INSERT INTO scans(oob_id) VALUES(?)", (oob_id,))
        return int(cur.lastrowid)


def finish_scan(
    scan_id: int, *, success: bool, line_count: int, error_text: str,
    raw_json: str, parse_status: str = "UNKNOWN", parse_quality: float = 0.0,
) -> None:
    with db() as conn:
        conn.execute(
            """
            UPDATE scans SET finished_at=CURRENT_TIMESTAMP,success=?,line_count=?,
                error_text=?,raw_json=?,parse_status=?,parse_quality=?
            WHERE id=?
            """,
            (
                1 if success else 0, int(line_count), error_text[:4000], raw_json,
                parse_status[:64], float(parse_quality), scan_id,
            ),
        )


def record_scan_issue(
    *, scan_id: int, oob_id: int, issue_type: str, severity: str, message: str,
) -> int:
    with db() as conn:
        cur = conn.execute(
            """
            INSERT INTO scan_issues(scan_id,oob_id,issue_type,severity,message)
            VALUES(?,?,?,?,?)
            """,
            (scan_id, oob_id, issue_type, severity, message[:2000]),
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
    with db() as conn:
        for row in rows:
            conn.execute(
                """
                INSERT INTO console_snapshots(
                    scan_id,oob_id,line_no,alias,tcp_port,target_host,state,session_user,raw_line
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    scan_id, oob_id, row["line_no"], row.get("alias", ""), row.get("tcp_port"),
                    row.get("target_host", ""), row.get("state", "UNKNOWN"),
                    row.get("session_user", ""), row.get("raw_line", ""),
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
        sql += f" AND cs.captured_at >= datetime('now','-{days} days')"
    sql += " ORDER BY cs.id DESC LIMIT ?"
    args.append(limit)
    with db() as conn:
        rows = conn.execute(sql, tuple(args)).fetchall()
    return [dict(r) for r in rows]


def history_summary(days: int | None = None) -> dict[str, int]:
    where_scan = ""
    where_snapshot = ""
    where_event = ""
    if days is not None:
        days = max(1, min(int(days), 3650))
        where_scan = f" WHERE started_at >= datetime('now','-{days} days')"
        where_snapshot = f" WHERE captured_at >= datetime('now','-{days} days')"
        where_event = f" WHERE first_seen >= datetime('now','-{days} days')"

    with db() as conn:
        scans = conn.execute(f"SELECT COUNT(*) AS c FROM scans{where_scan}").fetchone()["c"]
        snapshots = conn.execute(
            f"SELECT COUNT(*) AS c FROM console_snapshots{where_snapshot}"
        ).fetchone()["c"]
        events = conn.execute(
            f"SELECT COUNT(*) AS c FROM change_events{where_event}"
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
    with db() as conn:
        cur1 = conn.execute(
            f"DELETE FROM console_snapshots WHERE captured_at < datetime('now','-{snapshot_days} days')"
        )
        cur2 = conn.execute(
            f"UPDATE scans SET raw_json='' WHERE finished_at < datetime('now','-{raw_days} days') AND raw_json!=''"
        )
    return {"snapshots_deleted": cur1.rowcount, "raw_scans_cleared": cur2.rowcount}


# ---------- Change events / alerts ----------
def create_or_update_change_event(
    *, oob_id: int, device_id: int | None, line_no: int | None,
    event_type: str, severity: str, old_value: str, new_value: str,
    message: str, scan_id: int,
) -> tuple[int, bool]:
    """Dedup/rate-limit: same unresolved event type + OOB + line/device is updated."""
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
                    last_seen=CURRENT_TIMESTAMP,occurrence_count=occurrence_count+1
                WHERE id=?
                """,
                (device_id, severity, new_value[:1000], message[:1500], scan_id, event_id),
            )
            return event_id, False
        cur = conn.execute(
            """
            INSERT INTO change_events(
                oob_id,device_id,line_no,event_type,severity,old_value,new_value,
                message,status,scan_id,last_seen,occurrence_count
            ) VALUES(?,?,?,?,?,?,?,?, 'NEW', ?, CURRENT_TIMESTAMP, 1)
            """,
            (
                oob_id, device_id, line_no, event_type, severity,
                old_value[:1000], new_value[:1000], message[:1500], scan_id,
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


def update_change_event_status(event_id: int, *, status: str, note: str = "") -> None:
    status = status.upper()
    if status not in {"NEW", "ACKNOWLEDGED", "RESOLVED"}:
        raise ValueError("Alert status không hợp lệ.")
    actor = current_actor()
    with db() as conn:
        if status == "ACKNOWLEDGED":
            conn.execute(
                """
                UPDATE change_events SET status='ACKNOWLEDGED',acknowledged_at=CURRENT_TIMESTAMP,
                    acknowledged_by=?,note=? WHERE id=?
                """,
                (actor, note.strip(), event_id),
            )
        elif status == "RESOLVED":
            conn.execute(
                """
                UPDATE change_events SET status='RESOLVED',resolved_at=CURRENT_TIMESTAMP,
                    resolved_by=?,note=? WHERE id=?
                """,
                (actor, note.strip(), event_id),
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
