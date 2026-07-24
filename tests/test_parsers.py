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
    modular_lines = parse_lines(
        "   Tty Line Typ     Tx/Rx    A Modem\n"
        "      0    0 CTY              -    -\n"
        "  0/0/0    3 TTY   9600/9600  -    -\n"
        "* 0/0/2    5 TTY   4800/4800  F    -\n"
        "  0/1/7   26 TTY   9600/9600  -    -\n"
    )
    assert sorted(modular_lines) == [0, 3, 5, 26]
    assert modular_lines[3]["state"] == "AVAILABLE"
    assert modular_lines[5]["state"] == "BUSY"
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

    hcm_menu_output = (
        "HCM-OOB-FNX02L03H1-01#show run | i menu username root autocommand "
        "menu OOB menu OOB title ^CCCCCCC menu OOB-MP04-New prompt ^C "
        "menu OOB text [4] ----> HCM-CDNLeaf-Quan9-10G-04 "
        "menu OOB command 4 telnet 172.28.200.11 2006 "
        "menu OOB text [1] ----> HCM-CDNLeaf-Quan9-10G-01 "
        "menu OOB command 1 telnet 172.28.200.11 2003 "
        "menu OOB text [2] ----> HCM-CDNLeaf-Quan9-10G-02 "
        "menu OOB command 2 telnet 172.28.200.11 2004 "
        "menu OOB text [3] ----> HCM-CDNLeaf-Quan9-10G-03 "
        "menu OOB command 3 telnet 172.28.200.11 2005 "
        "menu OOB text [5] ----> HCM-CDNBDL-Quan9-QF5130-02 "
        "menu OOB command 5 telnet 172.28.200.11 2022 "
        "menu OOB text [13] ----> HCM-DCQ9-MNG-01-mem0 "
        "menu OOB command 13 telnet 172.28.200.11 2007 "
        "menu cisco clear-screen menu cisco line-mode"
    )
    hcm_hosts = parse_cisco_menu(hcm_menu_output)
    hcm_by_alias = {row.alias: row for row in hcm_hosts}
    assert hcm_by_alias["HCM-CDNLeaf-Quan9-10G-01"].target_host == "172.28.200.11"
    assert hcm_by_alias["HCM-CDNLeaf-Quan9-10G-01"].tcp_port == 2003
    assert hcm_by_alias["HCM-CDNLeaf-Quan9-10G-01"].line_no == 3
    assert hcm_by_alias["HCM-CDNLeaf-Quan9-10G-04"].tcp_port == 2006
    assert hcm_by_alias["HCM-CDNBDL-Quan9-QF5130-02"].line_no == 22
    assert hcm_by_alias["HCM-DCQ9-MNG-01-mem0"].line_no == 7
    print("parser tests: OK")

if __name__ == "__main__":
    run()
