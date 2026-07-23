from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from core.database import DB_PATH, init_db
from core.repository import get_setting
from core.terminal import (
    _securecrt_ssh_args,
    _securecrt_telnet_args,
    _ssh_args,
    _telnet_args,
    launch_securecrt_ssh,
    launch_securecrt_telnet,
    launch_windows_ssh,
    launch_windows_telnet,
)


def find_matches(term: str) -> list[dict[str, Any]]:
    import sqlite3

    needle = f"%{term.strip().lower()}%"
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT
                d.id AS device_id,
                d.hostname AS hostname,
                d.expected_alias AS expected_alias,
                d.mgmt_ip AS mgmt_ip,
                d.expected_line AS expected_line,
                o.id AS oob_id,
                o.name AS oob_name,
                o.host AS oob_host,
                o.port AS oob_ssh_port,
                o.username AS username,
                dc.alias AS detected_alias,
                dc.tcp_port AS tcp_port,
                dc.state AS state,
                dc.session_user AS session_user
            FROM devices d
            LEFT JOIN oob_nodes o ON o.id=d.oob_id
            LEFT JOIN detected_console dc ON dc.oob_id=d.oob_id AND dc.line_no=d.expected_line
            WHERE LOWER(d.hostname) LIKE ?
               OR LOWER(d.expected_alias) LIKE ?
               OR LOWER(d.mgmt_ip) LIKE ?
               OR LOWER(COALESCE(dc.alias,'')) LIKE ?
            ORDER BY d.hostname COLLATE NOCASE
            LIMIT 20
            """,
            (needle, needle, needle, needle),
        ).fetchall()

        unmanaged = conn.execute(
            """
            SELECT
                NULL AS device_id,
                dc.alias AS hostname,
                '' AS expected_alias,
                '' AS mgmt_ip,
                dc.line_no AS expected_line,
                o.id AS oob_id,
                o.name AS oob_name,
                o.host AS oob_host,
                o.port AS oob_ssh_port,
                o.username AS username,
                dc.alias AS detected_alias,
                dc.tcp_port AS tcp_port,
                dc.state AS state,
                dc.session_user AS session_user
            FROM detected_console dc
            JOIN oob_nodes o ON o.id=dc.oob_id
            LEFT JOIN devices d ON d.oob_id=dc.oob_id AND d.expected_line=dc.line_no
            WHERE d.id IS NULL AND LOWER(dc.alias) LIKE ?
            ORDER BY dc.alias COLLATE NOCASE
            LIMIT 20
            """,
            (needle,),
        ).fetchall()

    return [dict(row) for row in rows] + [dict(row) for row in unmanaged]


def choose_match(matches: list[dict[str, Any]]) -> dict[str, Any]:
    if not matches:
        raise SystemExit("No device matched.")
    if len(matches) == 1:
        return matches[0]

    print("Multiple matches:")
    for idx, row in enumerate(matches, start=1):
        print(
            f"{idx}. {row['hostname']} | OOB={row['oob_name']} | "
            f"line={row['expected_line']} | mgmt={row['mgmt_ip'] or '-'} | "
            f"tcp={row['tcp_port'] or '-'}"
        )
    selected = input("Choose number: ").strip()
    try:
        return matches[int(selected) - 1]
    except (ValueError, IndexError):
        raise SystemExit("Invalid selection.") from None


def build_command(row: dict[str, Any], mode: str, launcher: str) -> tuple[str, list[str]]:
    securecrt_path = get_setting("securecrt_path", "SecureCRT.exe")
    console_default = get_setting("console_launcher", "Windows Telnet")
    mgmt_default = get_setting("mgmt_launcher", "Windows SSH")

    if mode == "auto":
        mode = "console" if row.get("tcp_port") and row.get("oob_host") else "mgmt"

    if launcher == "auto":
        if mode == "console":
            launcher = "securecrt-telnet" if console_default == "SecureCRT Telnet" else "windows-telnet"
        else:
            launcher = "securecrt-ssh" if mgmt_default == "SecureCRT SSH" else "windows-ssh"

    if mode == "console":
        if not row.get("tcp_port") or not row.get("oob_host"):
            raise SystemExit("Matched device has no detected console TCP port.")
        host = str(row["oob_host"])
        port = int(row["tcp_port"])
        if launcher == "securecrt-telnet":
            return launcher, _securecrt_telnet_args(host, port, securecrt_path)
        return launcher, _telnet_args(host, port)

    if not row.get("mgmt_ip"):
        raise SystemExit("Matched device has no management IP.")
    host = str(row["mgmt_ip"])
    username = str(row.get("username") or "")
    if launcher == "securecrt-ssh":
        return launcher, _securecrt_ssh_args(host, 22, username, securecrt_path)
    return launcher, _ssh_args(host, 22, username)


def launch(row: dict[str, Any], mode: str, launcher: str) -> str:
    selected_launcher, _ = build_command(row, mode, launcher)
    if selected_launcher == "securecrt-telnet":
        launch_securecrt_telnet(row["oob_host"], int(row["tcp_port"]), get_setting("securecrt_path", "SecureCRT.exe"))
    elif selected_launcher == "windows-telnet":
        launch_windows_telnet(row["oob_host"], int(row["tcp_port"]))
    elif selected_launcher == "securecrt-ssh":
        launch_securecrt_ssh(row["mgmt_ip"], 22, row.get("username") or "", get_setting("securecrt_path", "SecureCRT.exe"))
    else:
        launch_windows_ssh(row["mgmt_ip"], 22, row.get("username") or "")
    return selected_launcher


def main() -> None:
    parser = argparse.ArgumentParser(description="Open OOB console or management SSH by hostname.")
    parser.add_argument("hostname", nargs="?", help="Hostname, alias, or management IP to find.")
    parser.add_argument("--mode", choices=["auto", "console", "mgmt"], default="auto")
    parser.add_argument(
        "--launcher",
        choices=["auto", "windows-telnet", "securecrt-telnet", "windows-ssh", "securecrt-ssh"],
        default="auto",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print command args without launching.")
    parser.add_argument("--list", action="store_true", help="List matches without launching.")
    args = parser.parse_args()

    init_db()
    term = args.hostname or input("Hostname / alias / IP: ").strip()
    matches = find_matches(term)
    row = choose_match(matches)

    if args.list:
        for item in matches:
            print(
                f"{item['hostname']} | OOB={item['oob_name']} | line={item['expected_line']} | "
                f"mgmt={item['mgmt_ip'] or '-'} | tcp={item['tcp_port'] or '-'} | state={item['state'] or '-'}"
            )
        return

    launcher, command = build_command(row, args.mode, args.launcher)
    print(
        f"Matched: {row['hostname']} | OOB={row['oob_name']} | line={row['expected_line']} | "
        f"mgmt={row['mgmt_ip'] or '-'} | tcp={row['tcp_port'] or '-'}"
    )
    print("Launcher:", launcher)
    print("Command:", " ".join(command))
    if args.dry_run:
        return
    selected = launch(row, args.mode, args.launcher)
    print(f"Launched: {selected}")


if __name__ == "__main__":
    main()
