from sombra.scope import Scope


def test_target_in_subnet_allowed():
    s = Scope(target_subnets=("192.168.56.0/24",))
    assert s.is_target_allowed("192.168.56.178")


def test_gateway_denied_even_inside_subnet():
    s = Scope(target_subnets=("192.168.56.0/24",), deny=frozenset({"192.168.56.1"}))
    assert not s.is_target_allowed("192.168.56.1")


def test_default_deny_for_public_ip():
    # The core of the denylist -> allowlist change: an address nobody blacklisted
    # is now refused by default instead of allowed.
    s = Scope(target_subnets=("192.168.56.0/24",))
    assert not s.is_target_allowed("8.8.8.8")  # not a target
    ok, reason = s.check_command("curl http://93.184.216.34/x")
    assert not ok and "not within" in reason


def test_substring_false_positive_not_triggered():
    # The classic bug: 192.168.56.1 is a substring of 192.168.56.178, but they
    # are different addresses. A command against the real target must pass.
    s = Scope(target_subnets=("192.168.56.0/24",), deny=frozenset({"192.168.56.1"}))
    ok, _ = s.check_command("nmap 192.168.56.178")
    assert ok


def test_denied_ip_in_command_refused():
    s = Scope(target_subnets=("192.168.56.0/24",), deny=frozenset({"192.168.56.1"}))
    ok, reason = s.check_command("nmap 192.168.56.1")
    assert not ok and "out-of-scope" in reason


def test_infra_references_allowed():
    # DNS heal and loopback are references, not targets.
    s = Scope(target_subnets=("192.168.56.0/24",))
    ok, _ = s.check_command("sudo resolvectl dns enp0s3 8.8.8.8 1.1.1.1")
    assert ok
    assert not s.is_target_allowed("8.8.8.8")  # ...but still not a target


def test_version_strings_are_not_ips():
    s = Scope(target_subnets=("192.168.56.0/24",))
    ok, _ = s.check_command("echo tool 1.2.3.4.5 && curl http://192.168.56.10/")
    assert ok  # 1.2.3.4.5 is not a valid IPv4; the in-scope target is fine


def test_nmap_exclude_arg_sorted():
    s = Scope(deny=frozenset({"192.168.57.1", "192.168.56.1"}))
    assert s.nmap_exclude_arg() == "192.168.56.1,192.168.57.1"


def test_filter_discovered():
    s = Scope(target_subnets=("192.168.56.0/24",), deny=frozenset({"192.168.56.1"}))
    assert s.filter_discovered(["192.168.56.178", "192.168.56.1", "10.0.0.5"]) == ["192.168.56.178"]


# -- forbidden_patterns (target-specific command hardening) --------------------

def test_forbidden_pattern_refused():
    s = Scope(
        target_subnets=("192.168.56.0/24",),
        forbidden_patterns=((r"security_level\s*(?:=|%3d)\s*[01]\b", "no downgrades"),),
    )
    ok, reason = s.check_command(
        "curl -d 'login=bee&password=bug&security_level=0&form=submit' http://192.168.56.178/bWAPP/login.php"
    )
    assert not ok and reason == "no downgrades"


def test_forbidden_pattern_is_case_insensitive_and_url_encoded():
    s = Scope(
        target_subnets=("192.168.56.0/24",),
        forbidden_patterns=((r"security_level\s*(?:=|%3d)\s*[01]\b", "no downgrades"),),
    )
    # medium (1), and the '=' URL-encoded as %3D, with mixed case.
    ok, _ = s.check_command("curl 'http://192.168.56.178/bWAPP/rlfi.php?SECURITY_LEVEL%3D1'")
    assert not ok


def test_high_security_level_allowed():
    s = Scope(
        target_subnets=("192.168.56.0/24",),
        forbidden_patterns=((r"security_level\s*(?:=|%3d)\s*[01]\b", "no downgrades"),),
    )
    # Setting the level to high (2) is exactly what the range wants — not refused.
    ok, _ = s.check_command("curl -d 'security_level=2' http://192.168.56.178/bWAPP/login.php")
    assert ok
    # And a bare number that merely ends in 0/1 (e.g. level 10) must not trip it.
    ok2, _ = s.check_command("curl http://192.168.56.178/x?security_level=20")
    assert ok2


def test_no_forbidden_patterns_by_default():
    # The generic default scope carries no content denylist — behaviour unchanged.
    s = Scope(target_subnets=("192.168.56.0/24",))
    ok, _ = s.check_command("curl -d 'security_level=0' http://192.168.56.178/bWAPP/login.php")
    assert ok
