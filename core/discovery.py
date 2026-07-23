from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class PortRecord:
    line_no: int
    alias: str = ""
    tcp_port: int | None = None
    target_host: str = ""
    state: str = "UNKNOWN"
    session_user: str = ""
    raw_line: str = ""

    def dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ParseQuality:
    accepted: bool
    score: float
    mapping_confident: bool
    session_confident: bool
    reasons: list[str]
    warnings: list[str]

    def summary(self) -> str:
        parts = []
        if self.reasons:
            parts.append("REJECT: " + "; ".join(self.reasons))
        if self.warnings:
            parts.append("WARN: " + "; ".join(self.warnings))
        return " | ".join(parts) or "OK"


INVALID_MARKERS = (
    "% invalid input",
    "invalid input",
    "unknown command",
    "unrecognized command",
    "command not found",
    "incomplete command",
    "ambiguous command",
    "syntax error",
)


def has_cli_error(text: str) -> bool:
    low = (text or "").lower()
    return any(marker in low for marker in INVALID_MARKERS)


def port_to_line(port: int, base: int = 2000) -> int | None:
    if base <= port < base + 1000:
        return port - base
    return None


def parse_cisco_hosts(text: str, base: int) -> list[PortRecord]:
    out: list[PortRecord] = []
    pat = re.compile(r"^\s*ip\s+host\s+(\S+)\s+(\d+)\s+(\S+)", re.I | re.M)
    for alias, p, host in pat.findall(text or ""):
        port = int(p)
        line = port_to_line(port, base)
        if line is not None:
            out.append(PortRecord(line_no=line, alias=alias, tcp_port=port, target_host=host))
    return out


def parse_generic_host_mappings(text: str, base: int) -> list[PortRecord]:
    out: list[PortRecord] = []
    seen: set[tuple[int, str]] = set()
    for raw in (text or "").splitlines():
        tokens = raw.strip().split()
        if len(tokens) < 2:
            continue
        port = None
        host = ""
        alias = ""
        for token in tokens:
            if token.isdigit():
                n = int(token)
                if base <= n < base + 1000:
                    port = n
                    break
        if port is None:
            continue
        for token in reversed(tokens):
            try:
                ipaddress.ip_address(token.strip("[](),"))
                host = token.strip("[](),")
                break
            except ValueError:
                pass
        for token in tokens:
            low = token.lower().strip(":")
            if low not in {"ip", "host", "line", "port", "tcp", "console", "device"} and not token.isdigit():
                alias = token.strip(":")
                break
        line = port_to_line(port, base)
        if line is None:
            continue
        key = (line, alias)
        if key in seen:
            continue
        seen.add(key)
        out.append(PortRecord(line_no=line, alias=alias, tcp_port=port, target_host=host))
    return out


def parse_lines(text: str) -> dict[int, dict[str, str]]:
    rows: dict[int, dict[str, str]] = {}
    for raw in (text or "").splitlines():
        m = re.match(r"^\s*(\*)?\s*(\d+)\s+(.+)$", raw)
        if not m:
            continue
        active = bool(m.group(1))
        line_no = int(m.group(2))
        rest = m.group(3).strip()
        low = rest.lower()
        state = "BUSY" if active else "AVAILABLE"
        busy_words = ("active", "connected", "in use", "busy")
        free_words = ("idle", "free", "available")
        if any(word in low for word in busy_words):
            state = "BUSY"
        elif any(word in low for word in free_words):
            state = "AVAILABLE"
        rows[line_no] = {"state": state, "raw_line": raw.rstrip()}
    return rows


def parse_users(text: str) -> dict[int, str]:
    rows: dict[int, str] = {}
    for raw in (text or "").splitlines():
        m = re.match(r"^\s*\*?\s*(\d+)\s+(\S+)", raw)
        if not m:
            continue
        line_no = int(m.group(1))
        user = m.group(2)
        if user.lower() not in {"line", "tty", "user", "con", "vty"}:
            rows[line_no] = user
    return rows


def merge(
    hosts: list[PortRecord], lines: dict[int, dict[str, str]], users: dict[int, str]
) -> list[dict[str, Any]]:
    data: dict[int, PortRecord] = {x.line_no: x for x in hosts}
    for line_no, info in lines.items():
        data.setdefault(line_no, PortRecord(line_no=line_no))
        data[line_no].state = info.get("state", "UNKNOWN")
        data[line_no].raw_line = info.get("raw_line", "")
    for line_no, user in users.items():
        data.setdefault(line_no, PortRecord(line_no=line_no))
        data[line_no].session_user = user
        data[line_no].state = "BUSY"
    return [data[k].dict() for k in sorted(data)]


def preserve_previous_mapping(
    current_rows: list[dict[str, Any]],
    previous: dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    """If alias mapping could not be parsed reliably, keep last-known mapping.

    This allows line/session state refresh without turning a parser failure into a
    fake mapping change. We intentionally mark no new alias in this situation.
    """
    out: list[dict[str, Any]] = []
    for row in current_rows:
        item = dict(row)
        old = previous.get(int(row["line_no"]))
        if old:
            item["alias"] = old.get("alias", "")
            item["tcp_port"] = old.get("tcp_port")
            item["target_host"] = old.get("target_host", "")
        else:
            item["alias"] = ""
            item["tcp_port"] = None
            item["target_host"] = ""
        out.append(item)
    return out


def evaluate_parse_quality(
    *,
    profile: dict[str, Any],
    line_output: str,
    user_output: str,
    host_output: str,
    line_map: dict[int, dict[str, str]],
    host_records: list[PortRecord],
    users: dict[int, str],
    merged_rows: list[dict[str, Any]],
    previous: dict[int, dict[str, Any]],
) -> ParseQuality:
    reasons: list[str] = []
    warnings: list[str] = []

    if not line_output.strip():
        reasons.append("Không nhận được output console-line.")
    elif has_cli_error(line_output):
        reasons.append("Command console-line trả về CLI error.")
    elif not line_map:
        reasons.append("Có output console-line nhưng parser không parse được line nào.")

    previous_count = len(previous)
    current_count = len(line_map)
    min_ratio = float(profile.get("min_line_retention_ratio", 0.60))
    if previous_count >= 4 and current_count > 0:
        ratio = current_count / previous_count
        if ratio < min_ratio:
            reasons.append(
                f"Số line parse được giảm bất thường ({current_count}/{previous_count}, ratio={ratio:.2f})."
            )

    mapping_supported = bool(profile.get("mapping_supported", profile.get("vendor") == "cisco"))
    mapping_confident = False
    if mapping_supported:
        if host_output.strip() and not has_cli_error(host_output) and host_records:
            mapping_confident = True
        else:
            warnings.append("Host/alias mapping chưa đủ tin cậy; bỏ qua mapping alerts cho scan này.")
    else:
        warnings.append("Profile chưa bật mapping_supported; mapping alerts bị tắt.")

    session_confident = False
    if user_output.strip() and not has_cli_error(user_output):
        # Zero parsed users is valid when nobody is logged in. Parsed users must
        # however reference known line IDs, otherwise the format is probably not
        # the parser variant we expect.
        unknown_user_lines = set(users) - set(line_map)
        if unknown_user_lines:
            warnings.append(
                "User/session parser trả line không tồn tại trong show line: "
                + ",".join(str(x) for x in sorted(unknown_user_lines)[:10])
                + ". Bỏ qua session alerts."
            )
        else:
            session_confident = True
    else:
        warnings.append("Session/user output chưa đủ tin cậy; bỏ qua session alerts.")

    accepted = not reasons
    score = 1.0
    if reasons:
        score = 0.0
    else:
        if not mapping_confident:
            score -= 0.20
        if not session_confident:
            score -= 0.10
        if previous_count and len(merged_rows) < previous_count:
            score -= 0.05
        score = max(0.0, min(score, 1.0))

    return ParseQuality(
        accepted=accepted,
        score=score,
        mapping_confident=mapping_confident,
        session_confident=session_confident,
        reasons=reasons,
        warnings=warnings,
    )
