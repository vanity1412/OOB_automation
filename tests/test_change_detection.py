import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.database import init_db
from core.change_detection import detect_changes

def run():
    init_db()

    previous = {
        66: {"line_no": 66, "alias": "BRAS01", "state": "AVAILABLE", "session_user": ""},
        67: {"line_no": 67, "alias": "PE01", "state": "AVAILABLE", "session_user": ""},
    }

    current = [
        {"line_no": 66, "alias": "PE02", "state": "AVAILABLE", "session_user": ""},
        {"line_no": 67, "alias": "PE01", "state": "BUSY", "session_user": "operator1"},
    ]

    events = detect_changes(
        oob_id=999,
        previous=previous,
        current_rows=current,
    )

    types = {e["event_type"] for e in events}
    assert "CONSOLE_MAPPING_CHANGED" in types
    assert "CONSOLE_SESSION_STARTED" in types
    print("change-detection tests: OK")

if __name__ == "__main__":
    run()
