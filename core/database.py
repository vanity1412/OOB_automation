from __future__ import annotations

import getpass
import os
import socket
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = Path(os.environ.get("OOB_DB_PATH", str(DATA_DIR / "oob_manager.db")))


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 10000")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    if column not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS oob_nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                vendor TEXT NOT NULL,
                profile_key TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 22,
                username TEXT DEFAULT '',
                site TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(host, port)
            );

            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                oob_id INTEGER,
                hostname TEXT NOT NULL,
                device_type TEXT DEFAULT '',
                vendor TEXT DEFAULT '',
                model TEXT DEFAULT '',
                serial TEXT DEFAULT '',
                mgmt_ip TEXT DEFAULT '',
                site TEXT DEFAULT '',
                rack TEXT DEFAULT '',
                u_position TEXT DEFAULT '',
                expected_line INTEGER,
                expected_alias TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(oob_id) REFERENCES oob_nodes(id) ON DELETE SET NULL,
                UNIQUE(oob_id, hostname)
            );

            CREATE TABLE IF NOT EXISTS detected_console (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                oob_id INTEGER NOT NULL,
                line_no INTEGER NOT NULL,
                alias TEXT DEFAULT '',
                tcp_port INTEGER,
                target_host TEXT DEFAULT '',
                state TEXT DEFAULT 'UNKNOWN',
                session_user TEXT DEFAULT '',
                raw_line TEXT DEFAULT '',
                scan_id INTEGER,
                last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(oob_id) REFERENCES oob_nodes(id) ON DELETE CASCADE,
                UNIQUE(oob_id, line_no)
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                oob_id INTEGER NOT NULL,
                started_at TEXT DEFAULT CURRENT_TIMESTAMP,
                finished_at TEXT,
                success INTEGER DEFAULT 0,
                line_count INTEGER DEFAULT 0,
                error_text TEXT DEFAULT '',
                raw_json TEXT DEFAULT '',
                parse_status TEXT DEFAULT 'UNKNOWN',
                parse_quality REAL DEFAULT 0,
                FOREIGN KEY(oob_id) REFERENCES oob_nodes(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scan_issues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                oob_id INTEGER NOT NULL,
                issue_type TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'WARNING',
                message TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                FOREIGN KEY(oob_id) REFERENCES oob_nodes(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS console_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                oob_id INTEGER NOT NULL,
                line_no INTEGER NOT NULL,
                alias TEXT DEFAULT '',
                tcp_port INTEGER,
                target_host TEXT DEFAULT '',
                state TEXT DEFAULT 'UNKNOWN',
                session_user TEXT DEFAULT '',
                raw_line TEXT DEFAULT '',
                captured_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                FOREIGN KEY(oob_id) REFERENCES oob_nodes(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS change_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                oob_id INTEGER NOT NULL,
                device_id INTEGER,
                line_no INTEGER,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'INFO',
                old_value TEXT DEFAULT '',
                new_value TEXT DEFAULT '',
                message TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'NEW',
                first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                acknowledged_at TEXT,
                acknowledged_by TEXT DEFAULT '',
                resolved_at TEXT,
                resolved_by TEXT DEFAULT '',
                note TEXT DEFAULT '',
                scan_id INTEGER,
                FOREIGN KEY(oob_id) REFERENCES oob_nodes(id) ON DELETE CASCADE,
                FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE SET NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT DEFAULT CURRENT_TIMESTAMP,
                actor TEXT DEFAULT '',
                source_host TEXT DEFAULT '',
                source_ip TEXT DEFAULT '',
                action TEXT NOT NULL,
                oob_id INTEGER,
                device_id INTEGER,
                detail TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_snapshots_oob_line_time
            ON console_snapshots(oob_id, line_no, captured_at);

            CREATE INDEX IF NOT EXISTS idx_change_events_status_legacy
            ON change_events(status, severity, first_seen);

            CREATE INDEX IF NOT EXISTS idx_scan_issues_scan
            ON scan_issues(scan_id, severity);
            """
        )

        # Safe migrations from previous builds.
        _ensure_column(conn, "scans", "parse_status", "TEXT DEFAULT 'UNKNOWN'")
        _ensure_column(conn, "scans", "parse_quality", "REAL DEFAULT 0")
        _ensure_column(conn, "change_events", "last_seen", "TEXT DEFAULT ''")
        conn.execute("UPDATE change_events SET last_seen=COALESCE(NULLIF(last_seen,''), first_seen)")
        _ensure_column(conn, "change_events", "occurrence_count", "INTEGER NOT NULL DEFAULT 1")
        _ensure_column(conn, "change_events", "acknowledged_by", "TEXT DEFAULT ''")
        _ensure_column(conn, "change_events", "resolved_by", "TEXT DEFAULT ''")
        _ensure_column(conn, "audit", "actor", "TEXT DEFAULT ''")
        _ensure_column(conn, "audit", "source_host", "TEXT DEFAULT ''")
        _ensure_column(conn, "audit", "source_ip", "TEXT DEFAULT ''")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_change_events_status ON change_events(status,severity,last_seen)"
        )

        defaults = {
            "snapshot_retention_days": "90",
            "scan_raw_retention_days": "30",
            "backup_keep_count": "30",
        }
        for key, value in defaults.items():
            conn.execute(
                "INSERT OR IGNORE INTO app_settings(key,value) VALUES(?,?)",
                (key, value),
            )


def current_actor() -> str:
    try:
        return getpass.getuser() or os.environ.get("USERNAME", "local-user")
    except Exception:
        return os.environ.get("USERNAME", "local-user")


def current_source() -> tuple[str, str]:
    host = socket.gethostname() or "localhost"
    ip = "127.0.0.1"
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        pass
    return host, ip


def audit(
    action: str,
    *,
    oob_id: int | None = None,
    device_id: int | None = None,
    detail: str = "",
    actor: str | None = None,
    source_host: str | None = None,
    source_ip: str | None = None,
) -> None:
    actor = actor or current_actor()
    auto_host, auto_ip = current_source()
    source_host = source_host or auto_host
    source_ip = source_ip or auto_ip

    with db() as conn:
        conn.execute(
            """
            INSERT INTO audit(actor,source_host,source_ip,action,oob_id,device_id,detail)
            VALUES(?,?,?,?,?,?,?)
            """,
            (
                actor[:128], source_host[:255], source_ip[:64], action,
                oob_id, device_id, detail[:1000],
            ),
        )


def backup_db() -> Path:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    backup_dir = DB_PATH.parent / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = backup_dir / f"oob_manager_{stamp}.db"
    if not DB_PATH.exists():
        init_db()
    with sqlite3.connect(DB_PATH, timeout=30) as src:
        src.execute("PRAGMA busy_timeout = 10000")
        src.execute("PRAGMA wal_checkpoint(PASSIVE)")
        with sqlite3.connect(target) as dst:
            src.backup(dst)
    return target


def prune_backups(keep_count: int = 30) -> int:
    backup_dir = DB_PATH.parent / "backups"
    if not backup_dir.exists():
        return 0
    files = sorted(backup_dir.glob("oob_manager_*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    removed = 0
    for path in files[max(1, int(keep_count)):]:
        try:
            path.unlink()
            removed += 1
        except OSError:
            pass
    return removed
