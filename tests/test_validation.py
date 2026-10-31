import pytest
from app.schemas import parse_and_validate_domain, parse_bulk_domains

def test_valid_domain_default_port():
    host, port = parse_and_validate_domain("example.com")
    assert host == "example.com"
    assert port == 443

def test_valid_domain_custom_port():
    host, port = parse_and_validate_domain("api.chase.com:8443")
    assert host == "api.chase.com"
    assert port == 8443

def test_whitespace_stripping_and_lowercasing():
    host, port = parse_and_validate_domain("   BANKOFAMERICA.COM:443   ")
    assert host == "bankofamerica.com"
    assert port == 443

def test_reject_schemes():
    with pytest.raises(ValueError, match="URL schemes"):
        parse_and_validate_domain("https://example.com")
    with pytest.raises(ValueError, match="URL schemes"):
        parse_and_validate_domain("http://example.com:443")
    with pytest.raises(ValueError, match="URL schemes"):
        parse_and_validate_domain("//example.com")

def test_reject_paths():
    with pytest.raises(ValueError, match="Paths, queries"):
        parse_and_validate_domain("example.com/login")
    with pytest.raises(ValueError, match="Paths, queries"):
        parse_and_validate_domain("example.com/")

def test_reject_query_and_fragments():
    with pytest.raises(ValueError, match="Paths, queries"):
        parse_and_validate_domain("example.com?auth=true")
    with pytest.raises(ValueError, match="Paths, queries"):
        parse_and_validate_domain("example.com#header")

def test_reject_invalid_ports():
    with pytest.raises(ValueError, match="out of range"):
        parse_and_validate_domain("example.com:0")
    with pytest.raises(ValueError, match="out of range"):
        parse_and_validate_domain("example.com:65536")
    with pytest.raises(ValueError, match="Invalid port"):
        parse_and_validate_domain("example.com:abc")

def test_reject_invalid_hostnames():
    with pytest.raises(ValueError, match="Invalid hostname"):
        parse_and_validate_domain("example..com")
    with pytest.raises(ValueError, match="Invalid hostname"):
        parse_and_validate_domain("-badlabel.com")
    with pytest.raises(ValueError, match="cannot be empty"):
        parse_and_validate_domain("   ")

def test_valid_ip_addresses():
    h4, p4 = parse_and_validate_domain("127.0.0.1:8080")
    assert h4 == "127.0.0.1"
    assert p4 == 8080

    h6, p6 = parse_and_validate_domain("[::1]:8443")
    assert h6 == "::1"
    assert p6 == 8443

def test_bulk_parsing():
    raw_text = """
    google.com
    github.com:443
    https://invalid-scheme.com
    badpath.com/test
    google.com
    valid-internal.corp:9000
    bad..domain.org
    """
    result = parse_bulk_domains(raw_text)
    valid = result["valid"]
    duplicates = result["duplicates"]
    invalid = result["invalid"]

    assert len(valid) == 3
    assert {"hostname": "google.com", "port": 443, "raw": "google.com"} in valid
    assert {"hostname": "github.com", "port": 443, "raw": "github.com:443"} in valid
    assert {"hostname": "valid-internal.corp", "port": 9000, "raw": "valid-internal.corp:9000"} in valid

    assert len(duplicates) == 1
    assert duplicates[0]["hostname"] == "google.com"

    assert len(invalid) == 3
    reasons = [inv["reason"] for inv in invalid]
    assert any("URL schemes" in r for r in reasons)
    assert any("Paths" in r for r in reasons)
    assert any("Invalid hostname" in r for r in reasons)
