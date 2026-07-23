from __future__ import annotations

import json
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

from .change_detection import detect_changes
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


class VertivAPIError(RuntimeError):
    pass


class VertivAPIAuthenticationError(VertivAPIError):
    pass


class VertivACSClient:
    """Short-lived Vertiv ACS800/ACS8000 REST API client.

    The password is used only for login and is scrubbed immediately after a
    token is received. The token stays in memory for this scan session only.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int = 48048,
        username: str,
        password: str,
        verify_tls: bool = False,
        timeout: int = 10,
    ) -> None:
        self.host = host.strip()
        self.port = int(port)
        self.username = username.strip()
        self._password = password
        self.verify_tls = bool(verify_tls)
        self.timeout = max(3, min(int(timeout), 45))
        self.token = ""
        self.base_url = f"https://{self.host}:{self.port}/api/v1/"

    def _ssl_context(self) -> ssl.SSLContext | None:
        if self.verify_tls:
            return None
        return ssl._create_unverified_context()

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        url = urljoin(self.base_url, path.lstrip("/"))
        payload = None
        headers = {"Accept": "application/json"}
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        req = Request(url, data=payload, headers=headers, method=method.upper())
        try:
            with urlopen(req, timeout=self.timeout, context=self._ssl_context()) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                if not raw.strip():
                    return {}
                return json.loads(raw)
        except HTTPError as exc:
            text = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            message = _extract_error_message(text) or exc.reason or f"HTTP {exc.code}"
            if exc.code in {401, 403}:
                raise VertivAPIAuthenticationError(message) from exc
            raise VertivAPIError(f"Vertiv API {method} {path} failed: {message}") from exc
        except URLError as exc:
            raise VertivAPIError(f"Vertiv API connection failed: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise VertivAPIError(f"Vertiv API returned non-JSON data for {path}.") from exc

    def login(self) -> None:
        if not self.username or not self._password:
            raise VertivAPIAuthenticationError("Username/password is required.")
        data = self._request(
            "POST",
            "/sessions/login",
            {"username": self.username, "password": self._password},
        )
        self._password = ""
        token = str((data or {}).get("token") or "").strip()
        if not token:
            raise VertivAPIAuthenticationError("Vertiv API login did not return a token.")
        self.token = token

    def logout(self) -> None:
        if not self.token:
            self._password = ""
            return
        try:
            self._request("POST", "/sessions/logout")
        finally:
            self.token = ""
            self._password = ""

    def get_access_serial_ports(self) -> Any:
        return self._request("GET", "/access/serialPorts")

    def get_config_serial_ports(self) -> Any:
        return self._request("GET", "/serialPorts")

    def get_sessions(self) -> Any:
        return self._request("GET", "/sessions")

    def get_system_info(self) -> Any:
        return self._request("GET", "/system/info")


def _extract_error_message(text: str) -> str:
    if not text.strip():
        return ""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return text[:300]
    err = data.get("error") if isinstance(data, dict) else None
    if isinstance(err, dict):
        return str(err.get("message") or err.get("code") or "")[:300]
    return str(data)[:300]


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _norm_key(value: Any) -> str:
    return _clean(value).lower().replace("_", " ").replace("-", " ")


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        number = float(text)
    except ValueError:
        return None
    if not number.is_integer():
        return None
    return int(number)


def _field(data: dict[str, Any], *names: str) -> Any:
    for name in names:
        current: Any = data
        found = True
        for part in name.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                found = False
                break
        if found and current not in (None, ""):
            return current
    return ""


def _records(payload: Any, *keys: str) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
        if isinstance(value, dict):
            nested = _records(value, *keys)
            if nested:
                return nested
    for value in payload.values():
        if isinstance(value, list) and all(isinstance(x, dict) for x in value):
            return value
    return []


def _port_number(item: dict[str, Any]) -> int | None:
    return _as_int(_field(item, "port", "portNumber", "number", "id", "index"))


def _port_name(item: dict[str, Any]) -> str:
    return _clean(
        _field(
            item,
            "name",
            "alias",
            "targetName",
            "deviceName",
            "cas.name",
            "settings.alias",
        )
    )


def _port_status(item: dict[str, Any]) -> str:
    raw = _clean(_field(item, "status", "state", "connectionStatus", "accessStatus"))
    low = _norm_key(raw)
    busy_tokens = {"in use", "inuse", "busy", "active", "connected", "open"}
    idle_tokens = {"idle", "available", "free", "not in use", "closed"}
    if low in idle_tokens or any(token in low for token in idle_tokens):
        return "AVAILABLE"
    if low in busy_tokens or any(token in low for token in busy_tokens):
        return "BUSY"
    return "UNKNOWN"


def _session_targets(sessions_payload: Any) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for session in _records(sessions_payload, "sessions", "items"):
        target = _clean(_field(session, "targetName", "target", "name"))
        if not target:
            continue
        session_type = _norm_key(_field(session, "sessionType"))
        connection_type = _norm_key(_field(session, "connectionType"))
        if session_type and session_type not in {"ssh", "telnet", "console", "raw", "unknown"}:
            continue
        if connection_type and connection_type not in {"serial", "cli", "unknown"}:
            continue
        out[target.lower()] = session
    return out


def normalize_vertiv_records(
    access_ports_payload: Any,
    *,
    config_ports_payload: Any | None = None,
    sessions_payload: Any | None = None,
) -> list[dict[str, Any]]:
    """Normalize Vertiv ACS API responses into the app's detected-console rows."""

    access_ports = _records(access_ports_payload, "serialPorts", "ports", "items", "data")
    config_by_port = {
        _port_number(item): item
        for item in _records(config_ports_payload, "serialPorts", "ports", "items", "data")
        if _port_number(item) is not None
    }
    sessions_by_target = _session_targets(sessions_payload)

    rows: list[dict[str, Any]] = []
    for item in access_ports:
        line_no = _port_number(item)
        if line_no is None:
            continue
        config = config_by_port.get(line_no, {})
        alias = _port_name(item) or _port_name(config)
        status = _port_status(item)

        session = sessions_by_target.get(alias.lower()) if alias else None
        if session is None:
            session = sessions_by_target.get(str(line_no))
        user = _clean(_field(session or {}, "user", "username", "owner"))
        if user:
            status = "BUSY"

        raw_line = (
            f"vertiv_api port={line_no} name={alias or '-'} "
            f"status={_clean(_field(item, 'status', 'state')) or '-'} "
            f"user={user or '-'}"
        )
        rows.append(
            {
                "line_no": line_no,
                "alias": alias,
                "tcp_port": None,
                "target_host": "",
                "state": status,
                "session_user": user,
                "raw_line": raw_line,
            }
        )
    return sorted(rows, key=lambda row: int(row["line_no"]))


def _payload_label(payload: Any) -> str:
    if isinstance(payload, dict):
        return ",".join(sorted(str(k) for k in payload.keys())[:6]) or "dict"
    if isinstance(payload, list):
        return f"list[{len(payload)}]"
    return type(payload).__name__


def scan_vertiv_api(
    client: VertivACSClient,
    *,
    oob_id: int,
    profile: dict[str, Any],
    acquire_lock: bool = True,
) -> dict[str, Any]:
    lock_ctx = global_scan_lock() if acquire_lock else _NullContext()
    with lock_ctx:
        scan_id = create_scan(oob_id)
        raw: dict[str, dict[str, Any]] = {}
        errors: list[str] = []

        try:
            client.login()
            access_ports = client.get_access_serial_ports()
            raw["access_serial_ports"] = {
                "endpoint": "GET /access/serialPorts",
                "payload": access_ports,
                "summary": _payload_label(access_ports),
            }

            config_ports = {}
            try:
                config_ports = client.get_config_serial_ports()
                raw["config_serial_ports"] = {
                    "endpoint": "GET /serialPorts",
                    "payload": config_ports,
                    "summary": _payload_label(config_ports),
                }
            except VertivAPIError as exc:
                errors.append(f"GET /serialPorts: {exc}")

            sessions = {}
            session_confident = True
            try:
                sessions = client.get_sessions()
                raw["sessions"] = {
                    "endpoint": "GET /sessions",
                    "payload": sessions,
                    "summary": _payload_label(sessions),
                }
            except VertivAPIError as exc:
                session_confident = False
                errors.append(f"GET /sessions: {exc}")

            try:
                system_info = client.get_system_info()
                raw["system_info"] = {
                    "endpoint": "GET /system/info",
                    "payload": system_info,
                    "summary": _payload_label(system_info),
                }
            except VertivAPIError as exc:
                errors.append(f"GET /system/info: {exc}")

            previous = latest_snapshot_map(oob_id)
            records = normalize_vertiv_records(
                access_ports,
                config_ports_payload=config_ports,
                sessions_payload=sessions,
            )
            if not records:
                message = "Vertiv API returned no usable serial-port rows."
                record_scan_issue(
                    scan_id=scan_id,
                    oob_id=oob_id,
                    issue_type="VERTIV_API_EMPTY_PORTS",
                    severity="WARNING",
                    message=message,
                )
                finish_scan(
                    scan_id,
                    success=False,
                    line_count=0,
                    error_text="\n".join(errors + [message]),
                    raw_json=json.dumps(raw, ensure_ascii=False),
                    parse_status="REJECTED",
                    parse_quality=0.0,
                )
                return {
                    "scan_id": scan_id,
                    "records": [],
                    "raw": raw,
                    "errors": errors,
                    "profile": profile,
                    "accepted": False,
                    "parse_quality": 0.0,
                    "parse_summary": message,
                    "mapping_confident": False,
                    "session_confident": False,
                    "change_count": 0,
                    "new_event_count": 0,
                    "event_ids": [],
                    "baseline_created": not bool(previous),
                    "transport": "VERTIV_API",
                }

            effective_records = annotate_session_health(records, previous)
            upsert_detected(oob_id, effective_records, scan_id)

            candidates = detect_changes(
                oob_id=oob_id,
                previous=previous,
                current_rows=effective_records,
                emit_history_events=bool(previous),
                mapping_confident=True,
                session_confident=session_confident,
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
            snapshot_days = int(get_setting("snapshot_retention_days", "90"))
            raw_days = int(get_setting("scan_raw_retention_days", "30"))
            prune_history(snapshot_days, raw_days)

            quality = 0.95 if session_confident else 0.85
            summary = "OK" if not errors else "WARN: " + "; ".join(errors)
            finish_scan(
                scan_id,
                success=True,
                line_count=len(effective_records),
                error_text="\n".join(errors),
                raw_json=json.dumps(raw, ensure_ascii=False),
                parse_status="ACCEPTED",
                parse_quality=quality,
            )
            return {
                "scan_id": scan_id,
                "records": effective_records,
                "raw": raw,
                "errors": errors,
                "profile": profile,
                "accepted": True,
                "parse_quality": quality,
                "parse_summary": summary,
                "mapping_confident": True,
                "session_confident": session_confident,
                "change_count": len(event_ids),
                "new_event_count": new_event_count,
                "event_ids": event_ids,
                "baseline_created": not bool(previous),
                "transport": "VERTIV_API",
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
        finally:
            client.logout()


def preflight_vertiv_api(client: VertivACSClient) -> dict[str, Any]:
    """Check Vertiv API readiness without writing scan data."""
    try:
        client.login()
        access_ports = client.get_access_serial_ports()
        sessions = {}
        session_error = ""
        try:
            sessions = client.get_sessions()
        except VertivAPIError as exc:
            session_error = str(exc)
        rows = normalize_vertiv_records(access_ports, sessions_payload=sessions)
        return {
            "ok": bool(rows),
            "serial_port_count": len(rows),
            "session_count": len(_records(sessions, "sessions", "items")),
            "session_error": session_error,
            "message": (
                f"API OK. Read {len(rows)} serial port(s)."
                if rows
                else "API login OK but no serial ports were returned."
            ),
        }
    finally:
        client.logout()


class _NullContext:
    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        return False
