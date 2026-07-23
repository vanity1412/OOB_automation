from core.discovery import port_to_line, parse_cisco_hosts, parse_lines, merge

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
    print("parser tests: OK")

if __name__ == "__main__":
    run()
