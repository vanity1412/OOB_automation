import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.session_health import annotate_session_health, classify_session_health


def run() -> None:
    available = classify_session_health({"state": "AVAILABLE", "session_user": "", "raw_line": "66 idle"})
    assert available["session_health"] == "AVAILABLE_CONFIRMED"

    active = classify_session_health({"state": "BUSY", "session_user": "noc1", "raw_line": "*67 active"})
    assert active["session_health"] == "ACTIVE_OPERATOR"

    first_busy = classify_session_health({"state": "BUSY", "session_user": "", "raw_line": "*68 active"})
    assert first_busy["session_health"] == "BUSY_NO_USER"

    stale = classify_session_health(
        {"state": "BUSY", "session_user": "", "raw_line": "*68 active"},
        {"state": "BUSY", "session_user": "", "raw_line": "*68 active"},
    )
    assert stale["session_health"] == "STALE_SESSION"

    rommon = classify_session_health({"state": "BUSY", "session_user": "", "raw_line": "rommon 1 >"})
    assert rommon["session_health"] == "BOOTLOADER_OR_ROMMON"

    annotated = annotate_session_health(
        [{"line_no": 69, "state": "AVAILABLE", "session_user": "", "raw_line": "69 idle"}]
    )
    assert annotated[0]["prompt_context"] == "OOB_LINE_STATE"

    print("session health tests: OK")


if __name__ == "__main__":
    run()
