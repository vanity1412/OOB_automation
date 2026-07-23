from __future__ import annotations

import time
from typing import Any

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


class LiveOOB:
    """Authenticated SSH transport without persisting plaintext credentials.

    Password exists only in the caller/local function while authenticating. After
    authentication, known Netmiko credential attributes are scrubbed. The app uses
    this object as a short-lived scan transport and disconnects immediately after scan.
    """

    def __init__(self) -> None:
        self.conn: Any | None = None
        self.oob_id: int | None = None
        self.name = ""
        self.host = ""
        self.port = 22
        self.username = ""
        self.profile_key = ""
        self.prompt = ""
        self.last_connect_attempts = 0

    @property
    def connected(self) -> bool:
        if self.conn is None:
            return False
        try:
            return bool(self.conn.is_alive())
        except Exception:
            return False

    @staticmethod
    def _scrub_netmiko_credentials(conn: Any) -> None:
        # Netmiko's authenticated channel no longer needs these for read-only show
        # commands. We intentionally do not support enable/config mode here.
        for attr in ("password", "secret", "passphrase"):
            try:
                if hasattr(conn, attr):
                    setattr(conn, attr, "")
            except Exception:
                pass

    def connect(
        self,
        *,
        oob_id: int | None,
        name: str,
        host: str,
        port: int,
        username: str,
        password: str,
        device_type: str,
        profile_key: str,
        connect_timeout: int = 8,
        auth_timeout: int = 10,
        banner_timeout: int = 10,
        retries: int = 2,
        retry_delay: float = 1.0,
    ) -> str:
        self.disconnect()
        retries = max(1, min(int(retries), 3))
        last_exc: Exception | None = None

        for attempt in range(1, retries + 1):
            self.last_connect_attempts = attempt
            try:
                conn = ConnectHandler(
                    device_type=device_type,
                    host=host.strip(),
                    port=int(port),
                    username=username.strip(),
                    password=password,
                    conn_timeout=max(3, int(connect_timeout)),
                    auth_timeout=max(3, int(auth_timeout)),
                    banner_timeout=max(3, int(banner_timeout)),
                    fast_cli=False,
                )
                prompt = conn.find_prompt()
                self._scrub_netmiko_credentials(conn)

                self.conn = conn
                self.oob_id = oob_id
                self.name = name
                self.host = host.strip()
                self.port = int(port)
                self.username = username.strip()
                self.profile_key = profile_key
                self.prompt = prompt
                return prompt

            except NetmikoAuthenticationException:
                # Wrong credentials are not retried to avoid account lockouts.
                raise
            except NetmikoTimeoutException as exc:
                last_exc = exc
                if attempt < retries:
                    time.sleep(max(0.2, float(retry_delay)))
            except Exception as exc:
                # Only one retry for transport-like failures; never loop forever.
                last_exc = exc
                if attempt < retries:
                    time.sleep(max(0.2, float(retry_delay)))

        if last_exc:
            raise last_exc
        raise RuntimeError("Không thể kết nối OOB.")

    def command(self, cmd: str, timeout: int = 15) -> str:
        if not self.connected:
            raise RuntimeError("Chưa có phiên OOB.")
        command = cmd.strip()
        if not command:
            raise ValueError("Command trống.")
        if not command.lower().startswith(("show ", "display ")):
            raise ValueError("Discovery chỉ cho show/display command.")
        return self.conn.send_command(
            command,
            read_timeout=max(5, min(int(timeout), 45)),
            strip_prompt=True,
            strip_command=True,
        )

    def disconnect(self) -> None:
        if self.conn is not None:
            try:
                self._scrub_netmiko_credentials(self.conn)
                self.conn.disconnect()
            except Exception:
                pass
        self.conn = None
        self.oob_id = None
        self.name = ""
        self.host = ""
        self.port = 22
        self.username = ""
        self.profile_key = ""
        self.prompt = ""
