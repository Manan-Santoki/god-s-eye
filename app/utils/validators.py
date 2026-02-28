"""
Input validation utilities for GOD_EYE.

Functions for validating and normalizing all target types.
"""

import ipaddress
import re
from urllib.parse import urlparse

# RFC 5322 email regex
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}$"
)

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

_PHONE_RE = re.compile(r"^\+?[\d\s\-\(\)\.]{7,20}$")
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._\-]{1,64}$")


def is_valid_email(email: str) -> bool:
    """Validate email format using RFC 5322 regex."""
    return bool(_EMAIL_RE.match(email.strip()))


def is_valid_domain(domain: str) -> bool:
    """Validate domain name format."""
    domain = normalize_domain(domain)
    return bool(_DOMAIN_RE.match(domain))


def is_valid_ip(ip: str) -> bool:
    """Validate IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def is_valid_phone(phone: str) -> bool:
    """Basic phone number format validation."""
    return bool(_PHONE_RE.match(phone.strip()))


def is_valid_username(username: str) -> bool:
    """Validate username (alphanumeric + underscore/dash/dot)."""
    return bool(_USERNAME_RE.match(username.strip()))


def detect_target_type(target: str) -> str:
    """
    Auto-detect the type of a target string.

    Returns: "email" | "ip" | "domain" | "phone" | "username" | "person"
    """
    target = target.strip()

    if is_valid_email(target):
        return "email"

    if is_valid_ip(target):
        return "ip"

    # Phone: starts with + and has digits
    if target.startswith("+") and is_valid_phone(target):
        return "phone"

    if is_valid_domain(target):
        return "domain"

    # Username: single word, no spaces, alphanumeric
    if " " not in target and is_valid_username(target):
        return "username"

    # Default: treat multi-word as person name
    return "person"


def normalize_domain(domain: str) -> str:
    """Strip http://, www., trailing slashes and spaces from a domain."""
    domain = domain.strip().lower()
    # Strip URL scheme
    if "://" in domain:
        domain = urlparse(domain).netloc or domain.split("://", 1)[1]
    # Strip www.
    if domain.startswith("www."):
        domain = domain[4:]
    # Strip path
    domain = domain.split("/")[0].split("?")[0].split("#")[0]
    return domain


def normalize_email(email: str) -> str:
    """Normalize email: lowercase, strip whitespace."""
    return email.strip().lower()


def normalize_phone(phone: str) -> str:
    """Normalize phone number by removing spaces, dashes, dots."""
    import re
    # Keep only digits and leading +
    digits = re.sub(r"[^\d+]", "", phone.strip())
    return digits


def sanitize_target(target: str, max_len: int = 256) -> str:
    """Sanitize a target string to prevent injection attacks."""
    # Remove shell metacharacters
    dangerous = set(';&|<>`$(){}[]\\"\'\n\r\t\x00')
    cleaned = "".join(c for c in target if c not in dangerous)
    return cleaned[:max_len].strip()
