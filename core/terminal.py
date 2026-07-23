from __future__ import annotations

import os
import re
import subprocess

SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}$")
SAFE_USER_RE = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_.@\\-]{0,127}$")


def _validate_host_port(host: str, port: int, protocol: str) -> tuple[str, int]:
    safe_host = (host or "").strip()
    safe_port = int(port)

    if not (1 <= safe_port <= 65535):
        raise ValueError(f"Invalid {protocol} port.")
    if not SAFE_HOST_RE.fullmatch(safe_host):
        raise ValueError(f"Invalid {protocol} host.")
    return safe_host, safe_port


def _validate_user(username: str) -> str:
    safe_user = (username or "").strip()
    if safe_user and not SAFE_USER_RE.fullmatch(safe_user):
        raise ValueError("Invalid SSH username.")
    return safe_user


def _ssh_args(host: str, port: int, username: str) -> list[str]:
    safe_host, safe_port = _validate_host_port(host, port, "SSH")
    safe_user = _validate_user(username)
    target = f"{safe_user}@{safe_host}" if safe_user else safe_host
    return ["ssh", "-p", str(safe_port), target]


def _telnet_args(host: str, port: int) -> list[str]:
    safe_host, safe_port = _validate_host_port(host, port, "telnet")
    return ["telnet", safe_host, str(safe_port)]


def _securecrt_exe(path: str = "") -> str:
    exe = (path or "").strip().strip('"') or "SecureCRT.exe"
    if any(ch in exe for ch in "\r\n"):
        raise ValueError("Invalid SecureCRT path.")
    return exe


def _securecrt_telnet_args(host: str, port: int, securecrt_path: str = "") -> list[str]:
    safe_host, safe_port = _validate_host_port(host, port, "telnet")
    return [_securecrt_exe(securecrt_path), "/TELNET", safe_host, str(safe_port)]


def _securecrt_ssh_args(
    host: str,
    port: int,
    username: str,
    securecrt_path: str = "",
) -> list[str]:
    safe_host, safe_port = _validate_host_port(host, port, "SSH")
    safe_user = _validate_user(username)
    args = [_securecrt_exe(securecrt_path), "/SSH2", "/P", str(safe_port)]
    if safe_user:
        args.extend(["/L", safe_user])
    args.append(safe_host)
    return args


def _launch_windows(args: list[str]) -> None:
    if os.name != "nt":
        raise RuntimeError("This launcher only runs on Windows.")
    subprocess.Popen(args, creationflags=subprocess.CREATE_NEW_CONSOLE)


def launch_windows_ssh(host: str, port: int, username: str) -> None:
    """Open Windows OpenSSH in a new console. Password is never embedded."""
    _launch_windows(_ssh_args(host, port, username))


def launch_windows_telnet(host: str, port: int) -> None:
    _launch_windows(_telnet_args(host, port))


def launch_securecrt_telnet(host: str, port: int, securecrt_path: str = "") -> None:
    _launch_windows(_securecrt_telnet_args(host, port, securecrt_path))


def launch_securecrt_ssh(
    host: str,
    port: int,
    username: str,
    securecrt_path: str = "",
) -> None:
    _launch_windows(_securecrt_ssh_args(host, port, username, securecrt_path))
