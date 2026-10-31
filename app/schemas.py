import re
import ipaddress
from typing import Tuple, List, Dict, Any

# RFC 1123 hostname regex
# Each label: 1-63 chars, alphanumeric with hyphens, not starting or ending with hyphen
HOSTNAME_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")

def is_valid_ipv4_or_ipv6(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False

def is_valid_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > 253:
        return False
    
    # Check if valid IP
    if is_valid_ipv4_or_ipv6(hostname):
        return True

    # Standard domain name
    labels = hostname.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not HOSTNAME_LABEL_REGEX.match(label):
            return False
    return True

def parse_and_validate_domain(raw_input: str, default_port: int = 443) -> Tuple[str, int]:
    """
    Parses and strictly validates a domain string in format 'hostname' or 'hostname:port'.
    Strips whitespace, rejects schemes (https://, etc.), paths, invalid characters.
    Returns (cleaned_hostname, port).
    Raises ValueError with descriptive message on invalid input.
    """
    if raw_input is None:
        raise ValueError("Domain cannot be empty.")
    
    cleaned = raw_input.strip()
    if not cleaned:
        raise ValueError("Domain cannot be empty.")

    # Reject schemes
    if "://" in cleaned or cleaned.startswith(("//", "\\\\")):
        raise ValueError("URL schemes (e.g. https://, http://) are not allowed. Enter only hostname or hostname:port.")
    
    # Reject paths, query parameters, or fragments
    if any(char in cleaned for char in ("/", "\\", "?", "#", " ", "\t", "@")):
        raise ValueError("Paths, queries, fragments, or special URL characters are not allowed.")

    port = default_port
    hostname = cleaned

    # Check for IPv6 bracketed notation e.g. [::1]:443 or [::1]
    if hostname.startswith("["):
        bracket_end = hostname.find("]")
        if bracket_end == -1:
            raise ValueError("Malformed IPv6 address brackets.")
        ipv6_part = hostname[1:bracket_end]
        after_bracket = hostname[bracket_end+1:]
        if after_bracket.startswith(":"):
            port_str = after_bracket[1:]
            try:
                port = int(port_str)
            except ValueError:
                raise ValueError(f"Invalid port '{port_str}'. Port must be an integer between 1 and 65535.")
        elif after_bracket != "":
            raise ValueError(f"Unexpected characters after IPv6 bracket: {after_bracket}")
        hostname = ipv6_part
    elif ":" in hostname:
        parts = hostname.split(":")
        if len(parts) == 2:
            hostname = parts[0]
            port_str = parts[1]
            try:
                port = int(port_str)
            except ValueError:
                raise ValueError(f"Invalid port '{port_str}'. Port must be an integer between 1 and 65535.")
        else:
            # Could be unbracketed IPv6
            if is_valid_ipv4_or_ipv6(cleaned):
                hostname = cleaned
                port = default_port
            else:
                raise ValueError(f"Invalid format '{cleaned}'. Use hostname or hostname:port.")

    # Validate port range
    if not (1 <= port <= 65535):
        raise ValueError(f"Port {port} is out of range. Port must be between 1 and 65535.")

    # Lowercase hostname
    hostname = hostname.lower()

    # Validate hostname / IP
    if not is_valid_hostname(hostname):
        raise ValueError(f"Invalid hostname '{hostname}'. Hostname must be a valid domain or IP address.")

    return hostname, port

def parse_bulk_domains(text: str) -> Dict[str, Any]:
    """
    Parses a multiline string of domains.
    Returns:
      - valid: list of {"hostname": h, "port": p, "raw": line}
      - duplicates: list of {"hostname": h, "port": p, "raw": line} (duplicates within this batch)
      - invalid: list of {"raw": line, "reason": str}
    """
    valid: List[Dict[str, Any]] = []
    duplicates: List[Dict[str, Any]] = []
    invalid: List[Dict[str, str]] = []
    seen = set()

    for line in text.splitlines():
        trimmed = line.strip()
        if not trimmed:
            continue
        try:
            h, p = parse_and_validate_domain(trimmed)
            target = f"{h}:{p}"
            if target in seen:
                duplicates.append({"hostname": h, "port": p, "raw": trimmed})
            else:
                seen.add(target)
                valid.append({"hostname": h, "port": p, "raw": trimmed})
        except ValueError as ex:
            invalid.append({"raw": trimmed, "reason": str(ex)})

    return {
        "valid": valid,
        "duplicates": duplicates,
        "invalid": invalid,
    }
