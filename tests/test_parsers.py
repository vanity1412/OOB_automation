import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.discovery import (
    evaluate_parse_quality,
    merge,
    parse_cisco_hosts,
    parse_cisco_menu,
    parse_lines,
    port_to_line,
)

def run():
    assert port_to_line(2066, 2000) == 66
    hosts = parse_cisco_hosts(
        "ip host BRAS01 2066 10.0.0.1\nip host PE01 2067 10.0.0.1",
        2000
    )
    assert len(hosts) == 2
    assert hosts[0].alias == "BRAS01"
    lines = parse_lines(" 66 Tty idle\n*67 Tty connected")
    assert lines[66]["state"] == "AVAILABLE"
    assert lines[67]["state"] == "BUSY"
    rows = merge(hosts, lines, {67:"operator1"})
    assert rows[1]["session_user"] == "operator1"
    assert rows[1]["state"] == "BUSY"

    menu_output = (
        "HCM-OOB#show run | i menu username root autocommand "
        "menu OOB title ^CCCCCCC "
        "menu OOB text [4] ----> HCM-CDNLeaf-Quan9-10G-04 "
        "menu OOB command 4 telnet 172.28.200.11 2006 "
        "menu OOB text [1] ----> HCM-CDNLeaf-Quan9-10G-01 "
        "menu OOB command 1 telnet 172.28.200.11 2003 "
        "menu cisco clear-screen"
    )
    menu_hosts = parse_cisco_menu(menu_output)
    assert [row.line_no for row in menu_hosts] == [3, 6]
    assert menu_hosts[0].alias == "HCM-CDNLeaf-Quan9-10G-01"
    assert menu_hosts[0].target_host == "172.28.200.11"
    assert menu_hosts[0].tcp_port == 2003
    assert "item 1" in menu_hosts[0].raw_line
    assert menu_hosts[1].alias == "HCM-CDNLeaf-Quan9-10G-04"
    assert menu_hosts[1].tcp_port == 2006

    menu_rows = merge(
        menu_hosts,
        parse_lines(" 0 CTY idle\n 132 TTY idle"),
        {},
        include_unmapped_lines=False,
        apply_line_state=False,
    )
    assert len(menu_rows) == 2
    assert menu_rows[0]["alias"] == "HCM-CDNLeaf-Quan9-10G-01"
    assert menu_rows[0]["state"] == "UNKNOWN"

    quality = evaluate_parse_quality(
        profile={"mapping_supported": True},
        line_output=" 0 CTY idle\n 132 TTY idle",
        user_output="",
        host_output=menu_output,
        line_map={0: {"state": "AVAILABLE", "raw_line": "0 CTY idle"}},
        host_records=menu_hosts,
        users={},
        merged_rows=menu_rows,
        previous={},
    )
    assert quality.accepted
    assert quality.mapping_confident
    print("parser tests: OK")

if __name__ == "__main__":
    run()
