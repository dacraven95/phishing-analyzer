"""
Module for making WHOIS calls through the RDAP service
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional, List

import requests


def _normalize_domain(raw: str) -> Optional[str]:
    """
    Take a raw string (domain, URL, or email) and return a normalized domain,
    or None if it's clearly invalid.
    """
    if not raw:
        return None

    s = raw.strip().lower()

    # If an email, grab the part after '@'
    if "@" in s:
        parts = s.split("@", 1)
        if len(parts) == 2:
            s = parts[1].strip()

    # Strip protocol
    if s.startswith("http://"):
        s = s[len("http://") :]
    elif s.startswith("https://"):
        s = s[len("https://") :]

    # Strip path
    if "/" in s:
        s = s.split("/", 1)[0]

    # Basic sanity
    if "." not in s:
        return None

    return s


def _parse_rdap_datetime(value: Optional[str]) -> Optional[str]:
    """
    RDAP dates are usually ISO8601 with 'Z' at the end.
    Normalize to ISO 8601 string, or None.
    """
    if not value:
        return None

    try:
        # Handle trailing 'Z'
        if value.endswith("Z"):
            value_dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            value_dt = datetime.fromisoformat(value)
        # return as ISO8601 string
        return value_dt.astimezone(timezone.utc).isoformat()
    except Exception:
        # Fallback: just return the raw string
        return value


def _get_event_date(events: List[Dict[str, Any]], action: str) -> Optional[str]:
    """
    From RDAP 'events' array, pull the first date for a given eventAction
    like 'registration', 'expiration', etc.
    """
    for ev in events or []:
        if ev.get("eventAction") == action and "eventDate" in ev:
            return _parse_rdap_datetime(ev["eventDate"])
    return None


def _calculate_domain_age_days(creation_iso: Optional[str]) -> Optional[int]:
    if not creation_iso:
        return None
    try:
        dt = datetime.fromisoformat(creation_iso)
        now = datetime.now(timezone.utc)
        delta = now - dt
        return delta.days
    except Exception:
        return None


def lookup_rdap(domain_or_email: str) -> Dict[str, Any]:
    """
    Perform an RDAP lookup for the given domain (or email, from which
    the domain will be extracted).

    Returns a dict:
    {
      "success": True/False,
      "domain": "example.com",
      "registrar": "...",
      "creation_date": "...",
      "expiration_date": "...",
      "updated_date": "...",
      "name_servers": [...],
      "status": [...],
      "domain_age_days": int | None,
      "raw": {...},      # full RDAP JSON
      "error": "..."     # only if success=False
    }
    """
    norm = _normalize_domain(domain_or_email)

    if not norm:
        return {
            "success": False,
            "domain": None,
            "error": f"Invalid domain/email input: {domain_or_email!r}",
        }

    url = f"https://rdap.verisign.com/com/v1/domain/{norm}"

    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code != 200:
            return {
                "success": False,
                "domain": norm,
                "error": f"RDAP HTTP {resp.status_code}: {resp.text[:200]}",
                # "rdap_info": resp,
            }

        data = resp.json()

        events = data.get("events", []) or []
        creation_date = _get_event_date(events, "registration")
        expiration_date = _get_event_date(events, "expiration")
        updated_date = _get_event_date(events, "last changed")

        status = data.get("status", []) or []
        # nameServers may be a list of objects or strings depending on RDAP server
        name_servers = []
        for ns in data.get("nameservers", []) or []:
            if isinstance(ns, dict):
                ns_name = ns.get("ldhName") or ns.get("unicodeName")
                if ns_name:
                    name_servers.append(ns_name)
            elif isinstance(ns, str):
                name_servers.append(ns)

        # Registrar can be buried in 'entities'
        registrar = None
        for ent in data.get("entities", []) or []:
            roles = ent.get("roles") or []
            if "registrar" in roles:
                vcard = ent.get("vcardArray", [])
                # vcardArray is ["vcard", [[...],[...]]]
                if len(vcard) == 2 and isinstance(vcard[1], list):
                    for item in vcard[1]:
                        if len(item) >= 4 and item[0] == "fn":  # formatted name
                            registrar = item[3]
                            break
                if registrar:
                    break

        domain_age_days = _calculate_domain_age_days(creation_date)

        return {
            "success": True,
            "domain": norm,
            "registrar": registrar,
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "updated_date": updated_date,
            "name_servers": name_servers,
            "status": status,
            "domain_age_days": domain_age_days,
            "raw": data,
            "error": None,
        }

    except Exception as e:
        return {
            "success": False,
            "domain": norm,
            "error": str(e),
        }
