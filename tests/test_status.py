from datetime import datetime, timezone, timedelta
from app.checker import (
    compute_days_remaining,
    determine_status,
    check_hostname_against_cert,
    match_wildcard_or_name,
)
from app.main import get_color_code

def test_compute_days_remaining():
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    
    # 45 days in future
    future = now + timedelta(days=45, hours=5)
    assert compute_days_remaining(future, now=now) == 45

    # 10 days in future
    future_10 = now + timedelta(days=10, hours=2)
    assert compute_days_remaining(future_10, now=now) == 10

    # Expired 5 days ago
    past = now - timedelta(days=5, hours=2)
    assert compute_days_remaining(past, now=now) < 0

def test_determine_status_logic():
    # UNREACHABLE
    assert determine_status(is_unreachable=True, days_remaining=100, chain_trusted=True, hostname_matches=True) == "UNREACHABLE"
    assert determine_status(is_unreachable=False, days_remaining=None, chain_trusted=True, hostname_matches=True) == "UNREACHABLE"

    # EXPIRED (takes priority over chain problems)
    assert determine_status(is_unreachable=False, days_remaining=-1, chain_trusted=True, hostname_matches=True) == "EXPIRED"
    assert determine_status(is_unreachable=False, days_remaining=-10, chain_trusted=False, hostname_matches=False) == "EXPIRED"

    # INVALID (chain not trusted or hostname mismatch)
    assert determine_status(is_unreachable=False, days_remaining=50, chain_trusted=False, hostname_matches=True) == "INVALID"
    assert determine_status(is_unreachable=False, days_remaining=50, chain_trusted=True, hostname_matches=False) == "INVALID"
    assert determine_status(is_unreachable=False, days_remaining=5, chain_trusted=False, hostname_matches=True) == "INVALID"

    # EXPIRING SOON (30 days or less, chain trusted and hostname matches)
    assert determine_status(is_unreachable=False, days_remaining=30, chain_trusted=True, hostname_matches=True) == "EXPIRING SOON"
    assert determine_status(is_unreachable=False, days_remaining=14, chain_trusted=True, hostname_matches=True) == "EXPIRING SOON"
    assert determine_status(is_unreachable=False, days_remaining=0, chain_trusted=True, hostname_matches=True) == "EXPIRING SOON"

    # OK (> 30 days)
    assert determine_status(is_unreachable=False, days_remaining=31, chain_trusted=True, hostname_matches=True) == "OK"
    assert determine_status(is_unreachable=False, days_remaining=180, chain_trusted=True, hostname_matches=True) == "OK"

def test_hostname_matching():
    # Exact SAN
    assert check_hostname_against_cert("bank.com", ["bank.com", "www.bank.com"], None) is True
    assert check_hostname_against_cert("api.bank.com", ["bank.com"], "api.bank.com") is True

    # Wildcard SAN
    assert check_hostname_against_cert("api.bank.com", ["*.bank.com"], None) is True
    assert check_hostname_against_cert("auth.bank.com", ["*.bank.com"], None) is True
    # Wildcard should NOT match sub-subdomain
    assert check_hostname_against_cert("sub.api.bank.com", ["*.bank.com"], None) is False

    # Mismatch
    assert check_hostname_against_cert("malicious.com", ["bank.com", "www.bank.com"], "bank.com") is False

def test_color_code_ranges():
    # > 30 days: green
    assert get_color_code("OK", 45) == "green"
    assert get_color_code("OK", 31) == "green"

    # 14 to 30: yellow
    assert get_color_code("EXPIRING SOON", 30) == "yellow"
    assert get_color_code("EXPIRING SOON", 15) == "yellow"
    assert get_color_code("EXPIRING SOON", 14) == "yellow"

    # 7 to 14: orange
    assert get_color_code("EXPIRING SOON", 13) == "orange"
    assert get_color_code("EXPIRING SOON", 7) == "orange"

    # under 7 or expired: red
    assert get_color_code("EXPIRING SOON", 6) == "red"
    assert get_color_code("EXPIRING SOON", 0) == "red"
    assert get_color_code("EXPIRED", -3) == "red"

    # unreachable: grey
    assert get_color_code("UNREACHABLE", None) == "grey"

    # invalid: purple
    assert get_color_code("INVALID", 60) == "purple"
