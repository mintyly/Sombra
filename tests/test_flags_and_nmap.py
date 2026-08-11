from sombra.flags import find_flag
from sombra.net import parse_nmap
from sombra.scope import Scope


def test_find_flag_basic():
    assert find_flag("noise\nFLAG{abc-123}\nmore") == "FLAG{abc-123}"


def test_find_flag_case_insensitive():
    assert find_flag("flag{lower}") == "flag{lower}"


def test_find_flag_none():
    assert find_flag("no flag here") is None
    assert find_flag("") is None


def test_find_flag_does_not_run_away():
    # [^}]* must stop at the first brace, not swallow the rest of the file.
    assert find_flag("FLAG{x} trailing } junk") == "FLAG{x}"


NMAP_SAMPLE = """Starting Nmap
Nmap scan report for 192.168.56.1
Host is up.
PORT   STATE SERVICE
22/tcp open  ssh
Nmap scan report for 192.168.56.178
Host is up (0.00042s latency).
PORT     STATE SERVICE
80/tcp   open  http
3306/tcp open  mysql
Nmap done
"""


def test_parse_nmap_keeps_in_scope_only():
    scope = Scope(target_subnets=("192.168.56.0/24",), deny=frozenset({"192.168.56.1"}))
    hosts = parse_nmap(NMAP_SAMPLE, scope)
    assert set(hosts) == {"192.168.56.178"}  # gateway dropped
    assert hosts["192.168.56.178"]["open_ports"] == [80, 3306]


def test_parse_nmap_windows_os_tag():
    scope = Scope(target_subnets=("192.168.56.0/24",))
    out = "Nmap scan report for 192.168.56.50\n5985/tcp open wsman\nRunning: Microsoft Windows\n"
    hosts = parse_nmap(out, scope)
    assert hosts["192.168.56.50"]["os"] == "Windows"


def test_parse_nmap_empty():
    assert parse_nmap("", Scope()) == {}
