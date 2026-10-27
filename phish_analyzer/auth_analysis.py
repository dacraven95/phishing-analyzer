"""Interpretation of authentication headers from explicitly trusted ingress."""
from __future__ import annotations
import os
import re
import ipaddress
from email.utils import parseaddr
from typing import Any
from .url_analysis import _normalized_host

TRUSTED_AUTH_SERVERS = frozenset(
    part.strip().lower().rstrip(".")
    for part in os.getenv("TRUSTED_AUTH_SERVERS", "").split(",") if part.strip()
)

def get_domain_from_address(header_value: str | None) -> tuple[str | None, str | None]:
    """
    Extract domain from an email address header like 'Name <user@example.com>'

    :param header_value: Description
    :type header_value: str | None
    :return: Description
    :rtype: str | None
    """

    # Validation checks
    if not header_value:
        return None, None

    display_name, email_addr = parseaddr(header_value)

    if not email_addr or "@" not in email_addr:
        return None, display_name or None

    # Return lowercase domain name from email
    return email_addr.split("@", 1)[1].lower(), (display_name or None)

def parse_received_spf(spf_header: str):
    """
    Extracts SPF result (pass/fail/etc) and client-ip from a Received-SPF header.
    Returns dict like:
    {
        "result": "fail",
        "client_ip": "74.120.121.159"
    }
    """

    # SPF result appears at the very beginning, e.g.:
    # "Fail (....)" or "Pass (....)"
    result_match = re.match(r"\s*([A-Za-z]+)", spf_header)
    result = result_match.group(1).lower() if result_match else None

    # Extract client-ip=...
    ip_match = re.search(r"\bclient-ip\s*=\s*([^;\s)]+)", spf_header, re.IGNORECASE)
    client_ip = None
    if ip_match:
        candidate = ip_match.group(1).strip("[]")
        try:
            client_ip = str(ipaddress.ip_address(candidate))
        except ValueError:
            pass

    return {
        "result": result,
        "client_ip": client_ip
    }

def parse_auth_results_header(header_value: str) -> dict:
    """
    Parse an Authentication-Results header and extract spf/dkim/dmarc results.

    Returns dict like:
    {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "bestguesspass",
    }
    """
    results = {}
    # Look for "spf=pass", "dkim=fail", "dmarc=bestguesspass", etc.
    pattern = re.compile(r'\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z0-9_-]+)', re.IGNORECASE)

    for mech, status in pattern.findall(header_value):
        results[mech.lower()] = status.lower()

    return results

def _authserv_id(header: str) -> str:
    """Return the Authentication-Results authserv-id, before any result methods."""
    first = str(header).split(";", 1)[0].strip().split()
    return first[0].lower().rstrip(".") if first else ""

def _auth_property(header: str, name: str) -> str | None:
    match = re.search(r"(?<![\w.-])" + re.escape(name) +
                      r"\s*=\s*(?:\"([^\"]+)\"|([^;\s()]+))", header, re.I)
    return (match.group(1) or match.group(2)).strip().lower() if match else None

def evaluate_authentication(headers: list[str], from_domain: str | None) -> dict[str, Any]:
    """Only trust authenticated results from explicitly configured upstream authority.

    IMPORTANT: TRUSTED_AUTH_SERVERS is safe ONLY if the trusted ingress removes
    untrusted Authentication-Results headers from inbound messages. Header IDs
    alone are forgeable, so a configuration is not cryptographic verification.
    """
    selected = next((str(h) for h in headers if _authserv_id(str(h)) in TRUSTED_AUTH_SERVERS), None)
    if not selected:
        return {"trusted": False, "status": "unverified", "authserv_id": None,
                "spf": None, "dkim": None, "dmarc": None,
                "spf_domain": None, "dkim_domain": None, "alignment": "unknown",
                "score": 0, "warnings": [
                    "Authentication-Results not verified; SPF/DKIM/DMARC header claims are excluded from scoring."
                ]}
    methods = parse_auth_results_header(selected)
    spf, dkim, dmarc = (methods.get(m) for m in ("spf", "dkim", "dmarc"))
    spf_domain = _auth_property(selected, "smtp.mailfrom")
    dkim_domain = _auth_property(selected, "header.d")
    # Strict alignment is determinable; relaxed organizational-domain alignment
    # must not be guessed from suffixes without the Public Suffix List.
    spf_exact = bool(from_domain and spf_domain and
                     _normalized_host(from_domain) == _normalized_host(spf_domain))
    dkim_exact = bool(from_domain and dkim_domain and
                      _normalized_host(from_domain) == _normalized_host(dkim_domain))
    if dmarc == "pass":
        alignment = "pass (reported by trusted receiver)"
    elif dmarc == "fail":
        alignment = "fail (reported by trusted receiver)"
    elif (spf == "pass" and spf_exact) or (dkim == "pass" and dkim_exact):
        alignment = "strict alignment observed; DMARC result unavailable"
    else:
        alignment = "unknown; relaxed alignment not inferred"
    score = (85 if dmarc == "fail" else
             25 if dmarc != "pass" and spf == "fail" and dkim == "fail" else
             15 if dmarc != "pass" and (spf == "fail" or dkim == "fail") else 0)
    return {"trusted": True, "status": "reported by configured receiver",
            "authserv_id": _authserv_id(selected), "spf": spf, "dkim": dkim,
            "dmarc": dmarc, "spf_domain": spf_domain, "dkim_domain": dkim_domain,
            "alignment": alignment, "score": score, "warnings": []}

