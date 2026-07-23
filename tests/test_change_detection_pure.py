def compare_minimal(previous, current):
    events = []
    current_map = {r["line_no"]: r for r in current}
    for line_no in set(previous) | set(current_map):
        old = previous.get(line_no)
        new = current_map.get(line_no)
        if old and new and old.get("alias","") != new.get("alias",""):
            events.append("CONSOLE_MAPPING_CHANGED")
        if old and new and old.get("state") != "BUSY" and new.get("state") == "BUSY":
            events.append("CONSOLE_SESSION_STARTED")
    return events

def run():
    previous = {
        66: {"alias": "BRAS01", "state": "AVAILABLE"},
        67: {"alias": "PE01", "state": "AVAILABLE"},
    }
    current = [
        {"line_no": 66, "alias": "PE02", "state": "AVAILABLE"},
        {"line_no": 67, "alias": "PE01", "state": "BUSY"},
    ]
    events = compare_minimal(previous, current)
    assert "CONSOLE_MAPPING_CHANGED" in events
    assert "CONSOLE_SESSION_STARTED" in events
    print("pure change-detection smoke test: OK")

if __name__ == "__main__":
    run()
