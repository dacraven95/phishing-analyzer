#!/usr/bin/env python3

"""
Core module for processing the email files for analysis
"""
from __future__ import annotations
import os, hashlib
import re
import math
import zipfile
import ipaddress
import json
import io
import contextlib
import mimetypes
import base64
import quopri

from email import message_from_string, policy
from email.policy import default as default_policy
from email.utils import parseaddr
from email.message import Message
from email.parser import BytesParser
from html.parser import HTMLParser
from urllib.parse import urlparse, urlunparse, parse_qs, unquote
from enum import Enum
from datetime import datetime
from typing import Any, List, Dict, Optional, Tuple, Union

from dataclasses import dataclass
from pathlib import Path

# Third party imports
from halo import Halo
import dns.resolver

# first party imports
from phish_analyzer.rdapHelper import lookup_rdap

# Local imports
from .colors import RED, YELLOW, RESET, CYAN, BRIGHT_GREEN, BRIGHT_RED, BRIGHT_BLUE, BRIGHT_WHITE, BRIGHT_YELLOW
from .pdfReport import generate_pdf_report

BASE_DIR = Path(__file__).resolve().parent
ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

# Parsing header blocks / full EML repeatedly is expensive. These helpers cache the
# parsed Message object keyed by file path + mtime.
_PARSED_MSG_CACHE: dict[str, tuple[float, Message]] = {}


def _get_cached_parsed_message(file_path: str) -> Message:
    """Parse the email/headers file once per mtime and reuse the Message."""
    try:
        mtime = Path(file_path).stat().st_mtime
    except Exception:
        # Fall back to uncached parse if we can't stat the file.
        ext = get_file_extension(file_path)
        return parse_detected_filetype(ext, file_path)

    cached = _PARSED_MSG_CACHE.get(file_path)
    if cached and cached[0] == mtime:
        return cached[1]

    ext = get_file_extension(file_path)
    msg = parse_detected_filetype(ext, file_path)
    _PARSED_MSG_CACHE[file_path] = (mtime, msg)
    return msg


class Category(str, Enum):
    HEADERS = "headers"
    SPF = "spf"
    DKIM = "dkim"
    DMARC = "dmarc"
    AUTH_RESULTS = "auth_results"
    URLs = "urls"
    BODY = "body"
    CONTENT = "content"
    METADATA = "metadata"
    GENERAL = "general"

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Code(str, Enum):
    # SPF
    SPF_STATUS = "SPF_STATUS"
    SPF_PASS = "SPF_PASS"
    SPF_FAIL = "SPF_FAIL"
    SPF_SOFTFAIL = "SPF_SOFTFAIL"
    SPF_NONE = "SPF_NONE"

    # DKIM
    DKIM_STATUS = "DKIM_STATUS"
    DKIM_PASS = "DKIM_PASS"
    DKIM_FAIL = "DKIM_FAIL"
    DKIM_MISSING = "DKIM_MISSING"

    # DMARC
    DMARC_STATUS = "DMARC_STATUS"
    DMARC_PASS = "DMARC_PASS"
    DMARC_FAIL = "DMARC_FAIL"
    DMARC_NONE = "DMARC_NONE"

    # URL-related
    URL_IP_LITERAL = "URL_IP_LITERAL"
    URL_SUSPICIOUS_TLD = "URL_SUSPICIOUS_TLD"
    URL_PUNYCODE = "URL_PUNYCODE"
    URL_BRAND_IMPERSONATION = "URL_BRAND_IMPERSONATION"
    URL_OBFUSCATED_PATH = "URL_OBFUSCATED_PATH"
    URL_SUSPICIOUS_PATH = "URL_SUSPICIOUS_PATH"

    # Headers
    CROSSTENANT_PRESENT = "CROSSTENANT_PRESENT"
    FROM_REPLYTO_MISMATCH = "FROM_REPLYTO_MISMATCH"
    FROM_RETURNPATH_MISMATCH = "FROM_RETURNPATH_MISMATCH"
    MISSING_HEADER = "MISSING_HEADER"

    # Domain Related
    WHOIS_BASIC_INFO = "WHOIS_BASIC_INFO"
    WHOIS_LOOKUP_FAILED = "WHOIS_LOOKUP_FAILED"

URL_REGEX = re.compile(
    r'(?i)\b((?:https?://|www\.)[^\s<>"]+)',
    re.IGNORECASE
)

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "link", "club", "work", "online", "loan", "buzz",
    "mom", "country", "kim", "men", "party", "science"
}

SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "password",
    "billing", "account", "confirm", "webscr"
]

BRAND_KEYWORDS = [
    "paypal", "microsoft", "office365", "outlook", "apple", "google",
    "amazon", "bankofamerica", "chase", "wellsfargo"
]

RISKY_EXTENSION_REASONS = {
    # Executables & installers
    ".exe": "Executable files can directly run malware when opened.",
    ".msi": "Windows installer packages can silently install malicious software.",
    ".msp": "Installer patch files can modify software to introduce malware.",
    ".scr": "Screen saver files are executable binaries commonly abused for malware delivery.",
    ".com": "Legacy executable format that runs immediately on open.",
    ".bat": "Batch scripts can automatically run multiple malicious system commands.",
    ".cmd": "Command scripts capable of executing system-level operations.",
    ".ps1": "PowerShell scripts can download, execute, and persist malware stealthily.",
    ".vbs": "VBScript files are frequently used as malware droppers.",
    ".js": "JavaScript files can execute malicious code outside of a browser.",
    ".jse": "Encoded JavaScript used to evade detection and analysis.",

    # Shortcuts & redirection
    ".lnk": "Shortcut files can hide malicious commands behind legitimate-looking icons.",
    ".scf": "Explorer command files can execute code when viewed in Windows Explorer.",
    ".url": "Internet shortcut files can redirect users to credential-harvesting websites.",
    ".pif": "Legacy shortcut format that can execute hidden programs.",

    # HTML & web-based phishing
    ".html": "HTML attachments commonly contain fake login pages designed to steal credentials.",
    ".htm": "HTML attachments are often used to deliver credential-harvesting pages.",
    ".xhtml": "Web document format capable of embedding scripts and phishing forms.",
    ".mhtml": "Archived web pages that may contain embedded malicious scripts.",
    ".mht": "Web archive format frequently used to bypass email filtering controls.",
    ".shtml": "HTML files that may contain embedded executable or scripted content.",

    # Office macro files
    ".docm": "Macro-enabled Word documents can execute malicious code.",
    ".xlsm": "Macro-enabled Excel files are commonly used to deliver malware.",
    ".pptm": "Macro-enabled PowerPoint files can execute malicious scripts.",

    # Compressed & container formats
    ".zip": "Compressed archives are often used to hide malicious payloads.",
    ".rar": "Archive files commonly abused to conceal malware.",
    ".7z": "Highly compressed archives that can evade content scanning.",
    ".iso": "Disk image files can contain executables that bypass security controls.",
    ".img": "Disk image files capable of mounting malicious content.",
    ".cab": "Windows cabinet files used to package and distribute malware.",
    ".tar": "Archive format that can hide malicious files.",
    ".gz": "Compressed files often used to conceal malware.",
    ".bz2": "Compression format sometimes used to evade detection.",

    # Scripts & automation
    ".hta": "HTML applications execute with full user privileges.",
    ".jar": "Java archives can execute malicious code across platforms.",
    ".py": "Python scripts can perform automated malicious actions.",

    # System & platform-specific
    ".reg": "Registry files can modify system settings to enable persistence or disable security.",
    ".dll": "Dynamic link libraries can be loaded by malicious programs.",
    ".sys": "System driver files can operate at kernel level if malicious.",
    ".apk": "Android application packages commonly used to distribute mobile malware.",
    ".dmg": "macOS disk images capable of delivering malicious applications."
}

ATTACHMENT_SIGNATURES = {
    "content_disposition_attachment": b"content-disposition: attachment",
    "filename_param": b"filename=",
    "base64_encoding": b"content-transfer-encoding: base64",
    "binary_content_type": (
        b"content-type: application/",
        b"content-type: image/",
        b"content-type: audio/",
        b"content-type: video/",
    ),
}


# optional: known-good company domains (can expand later)
TRUSTED_BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "office.com", "live.com"},
    "google": {"google.com", "accounts.google.com", "gmail.com"},
    "amazon": {"amazon.com"},
    # add domains here as needed
}

VERSION = None

def get_version():
    global  VERSION
    if VERSION is None:
        version_file = BASE_DIR / 'config' / 'version.txt'
        try:
            with open(version_file, 'r') as vf:
                VERSION = vf.read().strip()
        except FileNotFoundError:
            VERSION = "unknown"
    return VERSION

def print_banner():

    banner = rf"""
==================================================
   PHISH ANALYZER - Email Header & Body Scanner
   Version: {get_version()}
==================================================
"""
    print(BRIGHT_GREEN + banner + RESET)

def normalize_raw_with_qp(raw: bytes) -> bytes:
    """
    Decode quoted-printable once, then normalize line endings + case.
    Safe for detection purposes.
    """
    try:
        decoded = quopri.decodestring(raw)
    except Exception:
        decoded = raw

    # Normalize all common line endings: CRLF and CR -> LF
    decoded = decoded.replace(b"\r\n", b"\n").replace(b"\r", b"\n")

    return decoded.replace(b"\r\n", b"\n").lower()

def normalize_raw(raw: bytes) -> bytes:
    return raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n").lower()

def raw_attachment_signature_detected(raw: bytes) -> dict:
    data = normalize_raw_with_qp(raw)
    sigs = ATTACHMENT_SIGNATURES

    binary_type_prefixes = (
        b"content-type: application/",
        b"content-type: image/",
        b"content-type: audio/",
        b"content-type: video/",
    )

    return {
        "content_disposition_attachment":
            sigs["content_disposition_attachment"] in data,

        "filename_param":
            sigs["filename_param"] in data,

        "base64_encoding":
            sigs["base64_encoding"] in data,

        "binary_content_type":
            any(prefix in data for prefix in binary_type_prefixes),
    }

def has_hidden_attachment(raw: bytes) -> bool:
    hits = raw_attachment_signature_detected(raw)

    # Tunable threshold
    return sum(hits.values()) >= 3


def load_email(path):
    with open(path, "rb") as f:
        raw = f.read()
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    return msg, raw

def load_email_lenient_with_raw(path: str):
    with open(path, "rb") as f:
        raw = f.read()

    strict_msg = BytesParser(policy=policy.default).parsebytes(raw)
    lenient_msg = BytesParser(policy=policy.compat32).parsebytes(raw)
    return strict_msg, lenient_msg, raw

PDF_BLOCK_RE = re.compile(
    rb"""
    Content-Type:\s*application/pdf.*?
    Content-Transfer-Encoding:\s*base64\s+
    (?:Content-Disposition:.*?\n)?
    \n
    ([A-Za-z0-9+/=\r\n]+)
    """,
    re.IGNORECASE | re.DOTALL | re.VERBOSE
)

def salvage_pdf_attachments_from_raw(raw_bytes: bytes):
    attachments = []

    for match in PDF_BLOCK_RE.finditer(raw_bytes):
        b64_blob = match.group(1)

        try:
            pdf_bytes = base64.b64decode(b64_blob, validate=False)
            if pdf_bytes.startswith(b"%PDF-"):
                attachments.append({
                    "filename": "salvaged.pdf",
                    "content_type": "application/pdf",
                    "size": len(pdf_bytes),
                    "payload": pdf_bytes,
                    "virtual": True,
                    "virtual_kind": "orphaned_mime_attachment",
                    "source": "raw-mime-salvage",
                })
        except Exception:
            continue

    return attachments

def add_finding(results_list,
                category: Category,
                code: Code,
                severity: Severity,
                message: str,
                **data):
    """
    Append a standardized finding object into the shared analysis_results list.
    """
    results_list.append({
        "category": category.value,
        "code": code.value,
        "severity": severity.value,
        "message": message,
        "data": data or None,
    })

class HrefExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for name, value in attrs:
                if name.lower() == "href" and value:
                    self.hrefs.append(value)

def extract_header_block(raw: str) -> str:
    """
    Extracts the header block from text, even if there is extra text before/after.
    Headers end at the first blank line.
    """
    lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")

    header_started = False
    header_lines = []

    for line in lines:
        if not header_started:
            # Heuristic: looks like "Header-Name: value"
            if ":" in line:
                name, _, _ = line.partition(":")
                if name and name.strip() == name and " " not in name:
                    header_started = True
                    header_lines.append(line)
        else:
            if not line.strip():  # blank line = end of headers
                break
            header_lines.append(line)

    return "\n".join(header_lines)

def parse_full_eml(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()
    return message_from_string(raw, policy=default_policy)

def extract_bodies(msg):
    """
    Extract plain text and HTML bodies from an email.message.Message.

    Returns (plain_body, html_body) where each is a string or None.
    """
    plain_body = None
    html_body = None

    if msg.is_multipart():
        # Walk through all parts of the message
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = part.get_content_disposition()

            # Skip attachments
            if disp == "attachment":
                continue

            if ctype == "text/plain" and plain_body is None:
                plain_body = part.get_content()
            elif ctype == "text/html" and html_body is None:
                html_body = part.get_content()
    else:

        content = msg.get_content()
        if isinstance(content, bytes):
            content_str = content.decode(errors="ignore")
        else:
            content_str = content or ""

        # Single-part message
        ctype = msg.get_content_type()
        if ctype == "text/plain" and "<html" not in content_str.lower():
            plain_body = msg.get_content()
        elif ctype == "text/html" or "<html" in content_str.lower():
            html_body = msg.get_content()

    return plain_body, html_body

def extract_urls_from_body(plain_body: str | None, html_body: str | None):
    """
    Extract URLs from plain text and HTML bodies.

    - Uses regex to find http(s)/www URLs in text.
    - Extracts all hrefs from HTML <a> tags.
    - Normalizes URLs.
    - Deduplicates them.

    Returns a list of normalized URLs.
    """
    raw_urls = []

    # 1) Regex URLs from plain text
    if plain_body:
        raw_urls.extend(URL_REGEX.findall(plain_body))

    # 2) Regex URLs from HTML text
    if html_body:
        raw_urls.extend(URL_REGEX.findall(html_body))

    # 3) hrefs from <a href="...">
    hrefs = extract_hrefs_from_html(html_body)
    raw_urls.extend(hrefs)

    # 4) Normalize + deduplicate
    seen = set()
    deduped = []

    for url in raw_urls:
        norm = normalize_url(url)
        if not norm:
            continue
        if norm in seen:
            continue
        seen.add(norm)
        deduped.append(norm)

    return deduped

def extract_hrefs_from_html(html_body: str | None):
    """
    Extract all href attributes from <a> tags in HTML.
    Returns a list of raw href values (may include mailto:, javascript:, etc.)
    """
    if not html_body:
        return []

    parser = HrefExtractor()
    parser.feed(html_body)
    return parser.hrefs

def normalize_url(url: str) -> str | None:
    """
    Normalize a URL string for consistent comparison/storage.

    - Strips surrounding whitespace and trailing punctuation.
    - Adds http:// if it starts with 'www.' and has no scheme.
    - Lowercases scheme and host.
    - Removes default ports (:80 for http, :443 for https).
    - Drops fragment (#...).
    """
    if not url:
        return None

    # Basic cleanup
    url = url.strip()
    # Strip common trailing punctuation that often follows pasted URLs
    url = url.rstrip(").,;]\"'")

    # Ignore obvious non-http(s) schemes (you can expand this later)
    if url.startswith(("mailto:", "javascript:", "data:")):
        return None

    # If it starts with www. but has no scheme, add http:// for parsing
    if url.startswith("www."):
        url = "http://" + url

    parsed = urlparse(url)

    # If still no netloc, maybe it's something weird; bail out
    if not parsed.netloc and not parsed.path:
        return None

    scheme = (parsed.scheme or "http").lower()
    netloc = parsed.netloc.lower()

    # Remove default ports
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    # Ensure we always have some path
    path = parsed.path or "/"

    # Rebuild without fragment
    normalized = urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))

    return normalized

def is_ip_literal_url(url: str) -> bool:
    """
    Returns True if the URL host is a literal IP address (IPv4 or IPv6).
    Example: http://45.15.200.12/login
    """
    parsed = urlparse(url)
    host = parsed.hostname  # strips brackets for IPv6, removes port
    if not host:
        return False

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def looks_random_segment(segment: str) -> bool:
    """
    Heuristic: return True if a URL path segment looks like random junk.
    Example: very long, mostly alphanumeric, no vowels, etc.
    """
    if len(segment) < 10:
        return False
    # mostly [a-zA-Z0-9]
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", segment):
        return False
    # high consonant ratio can be a weak signal of randomness
    vowels = sum(1 for c in segment.lower() if c in "aeiou")
    return vowels / len(segment) < 0.2

def analyze_url(url: str, analysis_results) -> dict:
    """
    Analyze a single normalized URL and return:
    {
        "url": "...",
        "domain": "...",
        "flags": [...],
    }
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    domain = host.lower()
    flags: list[str] = []

    # 1) IP-literal
    if is_ip_literal_url(url):
        flags.append("IP_LITERAL")
        add_finding(
            analysis_results,
            category=Category.URLs,
            code=Code.URL_IP_LITERAL,
            severity=Severity.HIGH,
            message=f"URL host is a literal IP: {url}",
            url=url,
        )

    # 2) Suspicious TLD
    # crude: last label after the final dot
    parts = domain.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append("SUSPICIOUS_TLD")
        add_finding(
            analysis_results,
            category=Category.URLs,
            code=Code.URL_SUSPICIOUS_TLD,
            severity=Severity.HIGH,
            message=f"URL host has a suspicious tld: {url}",
            url=url,
        )

    # 3) Punycode / IDN
    if "xn--" in domain:
        flags.append("PUNYCODE_DOMAIN")
        add_finding(
            analysis_results,
            category=Category.URLs,
            code=Code.URL_PUNYCODE,
            severity=Severity.HIGH,
            message=f"URL has a punycode domain: {url}",
            url=url,
        )

    # 4) HTTP (no HTTPS)
    if parsed.scheme == "http":
        flags.append("PLAIN_HTTP")

    # 5) Suspicious path keywords
    path_lower = (parsed.path or "").lower()
    query_lower = (parsed.query or "").lower()
    for kw in SUSPICIOUS_PATH_KEYWORDS:
        if kw in path_lower or kw in query_lower:
            flags.append(f"KEYWORD_{kw.upper()}")
            # don't break; we want all hits
            add_finding(
                analysis_results,
                category=Category.URLs,
                code=Code.URL_SUSPICIOUS_PATH,
                severity=Severity.HIGH,
                message=f"URL has suspicous path keywords: {url}",
                url=url,
            )

    # 6) Random-looking path segments
    segments = [seg for seg in parsed.path.split("/") if seg]
    randomish_count = sum(1 for seg in segments if looks_random_segment(seg))
    if randomish_count >= 2:
        flags.append("OBFUSCATED_PATH")
        add_finding(
            analysis_results,
            category=Category.URLs,
            code=Code.URL_OBFUSCATED_PATH,
            severity=Severity.HIGH,
            message=f"URL has obfuscated path: {url}",
            url=url,
        )

    # 7) Brand impersonation-ish
    for brand in BRAND_KEYWORDS:
        if brand in domain:
            trusted = TRUSTED_BRAND_DOMAINS.get(brand, set())
            if domain not in trusted:
                flags.append(f"BRAND_IMPERSONATION_{brand.upper()}")
                add_finding(
                    analysis_results,
                    category=Category.URLs,
                    code=Code.URL_BRAND_IMPERSONATION,
                    severity=Severity.HIGH,
                    message=f"URL may be attempting brand impersonation: {url}",
                    url=url,
                )
            break

    return {
        "url": url,
        "domain": domain,
        "flags": flags,
    }

def parse_headers_from_file(path: str):
    """
    Read raw header text from a file and parse into an email Message object.

    :param path: Path to headers text file.
    :type path: str
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()

    # Extract header block from text file
    header_block = extract_header_block(raw)

    msg = message_from_string(header_block, policy=default_policy)
    return msg

def get_domain_from_address(header_value: str | None) -> str | None:
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
    ip_match = re.search(r"client-ip=([\d\.]+)", spf_header)
    client_ip = ip_match.group(1) if ip_match else None

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

def has_crosstenant_headers(headers: dict) -> bool:
    """
    Returns True if any header name or value contains 'crosstenant'
    (case-insensitive).
    """
    for key, value in headers.items():
        if "crosstenant" in key.lower() or ("crosstenant" in value.lower() if value else False):
            return True
    return False

def safe_dns_query(domain: str, record_type: str):
    """
    Perform a DNS query safely and return:
      - list of answers, or
      - None if not found / error

    Does NOT raise exceptions.
    """
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [r.to_text() for r in answers]

    except dns.resolver.NoAnswer:
        # Domain exists, but record type doesn't
        return None

    except dns.resolver.NXDOMAIN:
        # Domain does not exist at all
        return None

    except dns.resolver.NoNameservers:
        # Nameserver exists but cannot answer
        return None

    except dns.exception.Timeout:
        # DNS resolution timed out
        return None

    except Exception:
        # Catch-all safety fallback
        return None

def extract_dns_records(domain: str):

    # Look for all record types
    mx_records = safe_dns_query(f"{domain}", "MX") or []
    a_records = safe_dns_query(f"{domain}", "A") or []
    cname_records = safe_dns_query(f"{domain}", "CNAME") or []
    txt_records = safe_dns_query(f"{domain}", "TXT") or []

    output = []

    for r in a_records:
        output.append("A        " + r)

    for r in cname_records:
        output.append("CNAME    " + r)

    for r in mx_records:
        output.append("MX       " + r)

    for r in txt_records:
        output.append("TXT      " + r)

    return output

def get_file_extension(file):
    '''
    Identify & return the file extension
    
    :param file: The file
    '''

    _, ext = os.path.splitext(file)
    return ext.lower()

# (path, mtime_ns, ext) -> parsed message object
_PARSED_MSG_CACHE: Dict[Tuple[str, int, str], Any] = {}

def parse_detected_filetype(ext: str, file_path: Union[str, Path]):
    ext = (ext or "").lower()
    if ext and not ext.startswith("."):
        ext = "." + ext

    file_path = str(file_path)

    try:
        mtime_ns = os.stat(file_path).st_mtime_ns
    except OSError:
        # If we can't stat it, just parse normally (no caching).
        return parse_full_eml(file_path) if ext == ".eml" else parse_headers_from_file(file_path)

    key = (file_path, mtime_ns, ext)
    cached = _PARSED_MSG_CACHE.get(key)
    if cached is not None:
        return cached

    parsed = parse_full_eml(file_path) if ext == ".eml" else parse_headers_from_file(file_path)
    _PARSED_MSG_CACHE[key] = parsed
    return parsed

def get_email_body(file_path):
    # Parse once (cached) and then extract bodies
    msg = _get_cached_parsed_message(file_path)
    plain_body, html_body = extract_bodies(msg)

    email_body = None
    if plain_body:
        email_body = plain_body or None
    if html_body:
        email_body = html_body or None

    return email_body

    # Check for file type .eml, .txt and parse message
    msg = parse_detected_filetype(ext, file_path)

    plain_body, html_body = extract_bodies(msg)

    email_body = None

    if plain_body:
        email_body = plain_body or None
    if html_body:
        email_body = html_body or None

    return email_body

def get_headers(file_path, header: str = None):
    
    # Check if header was passed in and cancel if not
    if header is None:
        return
    
    # Get file extension
    msg = _get_cached_parsed_message(file_path)
    selected_hdr = msg.get_all(header) or []
    return selected_hdr

    headers = parse_detected_filetype(ext, file_path)
    selected_hdr = headers.get_all(header) or []

    return selected_hdr

def get_header(file_path, header: str = None):
    
    # Check if header was passed in and cancel if not
    if header is None:
        return
    
    # Get file extension
    msg = _get_cached_parsed_message(file_path)
    return msg[header] or None

    headers = parse_detected_filetype(ext, file_path)
    selected_hdr = headers[header] or None

    return selected_hdr

_RX_FROM = re.compile(r"\bfrom\s+([^\s;]+)", re.IGNORECASE)
_RX_BY = re.compile(r"\bby\s+([^\s;]+)", re.IGNORECASE)

def parse_received_hops(received_headers: list[str]) -> list[dict[str, Any]]:
    """
    Turns Received headers into a list of hops. Very simple parsing:
    - extracts 'from' host token and 'by' host token
    - keeps raw line for reference
    """
    hops: list[dict[str, Any]] = []
    for raw in received_headers:
        from_m = _RX_FROM.search(raw)
        by_m = _RX_BY.search(raw)
        hops.append({
            "from": from_m.group(1) if from_m else None,
            "by": by_m.group(1) if by_m else None,
            "raw": " ".join(raw.split()),  # compact whitespace
        })
    return hops


def has_attachment(msg: Message) -> bool:
    """
    Return True if the email message contains at least one attachment.
    """
    for part in msg.walk():
        # Skip container parts
        if part.is_multipart():
            continue

        # Explicit attachment
        if part.get_content_disposition() == "attachment":
            return True

        # Some attachments are marked inline but still have filenames
        if part.get_filename():
            return True

    return False

def list_attachments(msg: Message):
    files = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_content_disposition() == "attachment" or part.get_filename():
            files.append({
                "filename": part.get_filename(),
                "content_type": part.get_content_type(),
                "size": len(part.get_payload(decode=True) or b""),
            })
    return files

# Embedded PDF data URI (rare but real)
DATA_PDF_RE = re.compile(
    r"""(?is)data:application/pdf\s*;\s*base64\s*,\s*([a-z0-9+/=\s]+)"""
)

def _get_html_body(msg) -> str:
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            b = part.get_payload(decode=True) or b""
            return b.decode("utf-8", errors="ignore")
    return ""

def _looks_like_pdf_url(url: str) -> bool:
    u = url.lower()

    # Strong signal
    if u.endswith(".pdf") or ".pdf?" in u or ".pdf#" in u or ".pdf&" in u:
        return True

    # Common viewer/service hints (Outlook “attachment-like” UI often comes from these)
    hints = (
        "application/pdf",
        "contenttype=application/pdf",
        "mime=application/pdf",
        "format=pdf",
        "type=pdf",
        "pdfviewer",
        "view=pdf",
        "/pdf",
    )
    if any(h in u for h in hints):
        return True

    # Query parameters that often carry filenames
    try:
        qs = parse_qs(urlparse(url).query)
        for _, vals in qs.items():
            for v in vals:
                v2 = unquote(v).lower()
                if v2.endswith(".pdf") or ".pdf" in v2:
                    return True
    except Exception:
        pass

    return False

def _extract_virtual_attachments_from_html(html: str):
    virtual = []

    # 1) Embedded PDFs (data URI)
    for b64 in DATA_PDF_RE.findall(html):
        cleaned = re.sub(r"\s+", "", b64)
        try:
            pdf_bytes = base64.b64decode(cleaned, validate=False)
            if pdf_bytes.startswith(b"%PDF-"):
                virtual.append({
                    "filename": "embedded.pdf",
                    "content_type": "application/pdf",
                    "size": len(pdf_bytes),
                    "payload": pdf_bytes,
                    "virtual": True,
                    "virtual_kind": "embedded_pdf",
                    "source": "html:data-uri",
                })
        except Exception:
            continue

    # 2) “PDF-ish” URLs (what Outlook often surfaces like attachments)
    urls = sorted(set(URL_REGEX.findall(html)))
    for url in urls:
        if _looks_like_pdf_url(url):
            # we don’t have bytes (unless you choose to fetch it later)
            virtual.append({
                "filename": "linked.pdf",          # placeholder name for reporting
                "content_type": "application/pdf", # how we’re classifying the artifact
                "size": 0,
                "payload": None,                   # no bytes
                "virtual": True,
                "virtual_kind": "pdf_link",
                "source": "html:url",
                "url": url,
            })

    return virtual

def extract_attachments(msg):
    """
    Returns a list of attachment-like objects:
    - Real MIME attachments always included.
    - If none are found, also returns “virtual attachments” inferred from HTML.
    """
    attachments = []

    # ---- Stage 1: real MIME attachments ----
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue

        ctype = part.get_content_type()
        disp = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        data = part.get_payload(decode=True)

        if not data:
            continue

        # candidate rules
        is_candidate = bool(filename) or disp in ("attachment", "inline") or ctype.startswith("application/")
        if not is_candidate:
            continue

        if not filename:
            # infer extension for unnamed parts
            guessed = { "application/pdf": ".pdf", "text/html": ".html", "text/plain": ".txt" }.get(ctype, "")
            filename = f"unnamed-part{guessed}"

        attachments.append({
            "filename": filename,
            "content_type": ctype,
            "content_disposition": disp or None,
            "size": len(data),
            "payload": data,
            "virtual": False,
        })

    # ---- Stage 2: fallback “virtual attachments” (Outlook-style) ----
    if not attachments:
        html = _get_html_body(msg)
        # print('Scanning HTML body for virtual attachments...')
        if html:
            attachments.extend(_extract_virtual_attachments_from_html(html))

    return attachments

def dump_mime_tree(msg: Message):
    print("Top Content-Type:", msg.get_content_type())
    print("Is multipart:", msg.is_multipart())
    print("---- MIME TREE ----")

    count = 0
    for i, part in enumerate(msg.walk()):
        ctype = part.get_content_type()
        maintype = part.get_content_maintype()
        disp = part.get_content_disposition()  # attachment/inline/None
        fname = part.get_filename()

        # payload length without decoding (safe)
        raw_payload = part.get_payload()
        raw_len = len(raw_payload) if isinstance(raw_payload, (bytes, str)) else None

        # decoded length (best effort)
        dec = part.get_payload(decode=True)
        dec_len = len(dec) if isinstance(dec, (bytes, bytearray)) else 0

        print(f"{i:02d}  {ctype:25}  disp={disp!s:10}  fname={fname!s:30}  decoded={dec_len:7}  raw={raw_len}")
        count += 1

    print("Parts walked:", count)

def dump_mime_tree_plus(raw: bytes):
    """
    Dump what the parser sees AND what the raw email contains.
    Call this with the raw .eml bytes.
    """
    # Parse both strict and lenient to compare
    msg_strict = BytesParser(policy=policy.default).parsebytes(raw)
    msg_lenient = BytesParser(policy=policy.compat32).parsebytes(raw)

    def _dump(msg: Message, label: str):
        print(CYAN + f"\n==== PARSED MIME TREE ({label}) ====" + RESET)
        print("Top Content-Type:", msg.get_content_type())
        print("Is multipart:", msg.is_multipart())
        print("---- MIME TREE ----")

        for i, part in enumerate(msg.walk()):
            ctype = part.get_content_type()
            disp = part.get_content_disposition()  # attachment/inline/None (strict only)
            fname = part.get_filename()

            # encoding + id
            cte = part.get("Content-Transfer-Encoding", "")
            cid = part.get("Content-ID", "")
            boundary = ""
            if part.get_content_maintype() == "multipart":
                try:
                    boundary = part.get_boundary() or ""
                except Exception:
                    boundary = ""

            dec = part.get_payload(decode=True)
            dec_len = len(dec) if isinstance(dec, (bytes, bytearray)) else 0

            print(
                f"{i:02d}  {ctype:30} "
                f"disp={str(disp):10} "
                f"cte={str(cte):8} "
                f"fname={str(fname)[:40]:40} "
                f"cid={str(cid)[:28]:28} "
                f"decoded={dec_len:7} "
                f"boundary={boundary}"
            )

    _dump(msg_strict, "policy.default")
    _dump(msg_lenient, "policy.compat32")

    # ---- RAW SCAN ----
    print(CYAN + "\n==== RAW SCAN (parser-independent) ====" + RESET)
    raw_l = raw.replace(b"\r\n", b"\n").lower()

    # Count common attachment headers by type
    ct_hits = re.findall(rb"\ncontent-type:\s*([^\n;]+)", raw_l)
    disp_hits = re.findall(rb"\ncontent-disposition:\s*([^\n;]+)", raw_l)
    cte_hits = re.findall(rb"\ncontent-transfer-encoding:\s*([^\n]+)", raw_l)

    print("Raw 'Content-Type:' lines found:", len(ct_hits))
    print("Raw 'Content-Disposition:' lines found:", len(disp_hits))
    print("Raw 'Content-Transfer-Encoding:' lines found:", len(cte_hits))

    # Show a small histogram of the most common content-types
    from collections import Counter
    ct_counter = Counter([c.strip() for c in ct_hits])
    for c, n in ct_counter.most_common(10):
        print(f"  CT {c.decode('utf-8', 'ignore')[:60]} => {n}")

    # Specifically look for "application/pdf" and filenames
    # pdf_ct = b"content-type: application/pdf" in raw_l
    # pdf_fname = re.search(rb'filename\*?=(?:"([^"]+)"|([^;\n]+))', raw_l)
    # print("Contains 'Content-Type: application/pdf' in raw:", pdf_ct)
    # if pdf_fname:
        # fn = (pdf_fname.group(1) or pdf_fname.group(2) or b"").strip()
        # print("First filename= found (raw):", fn.decode("utf-8", "ignore")[:120])

    # Boundary sanity: extract declared boundary from top headers
    # (works even if later parts are malformed)
    m = re.search(rb'content-type:\s*multipart/[^\n;]+;\s*boundary="?([^"\n;]+)"?', raw_l)
    if m:
        boundary = m.group(1)
        bline = b"\n--" + boundary
        count_boundary = raw_l.count(bline)
        print("Top boundary (raw):", boundary.decode("utf-8", "ignore"))
        print("Occurrences of top boundary delimiter in raw:", count_boundary)
    else:
        print("Top boundary not found in raw headers (or folded/odd formatting).")

    # Show context around application/pdf if present
    idx = raw_l.find(b"content-type: application/pdf")
    if idx != -1:
        start = max(0, idx - 300)
        end = min(len(raw), idx + 600)
        print("\n--- RAW CONTEXT around application/pdf ---")
        print(raw[start:end].decode("utf-8", errors="ignore"))

def analyze_attachment(att, content_bytes=None):
    path = Path(att["filename"])
    
    return {
        "filename": att["filename"],
        "extension": path.suffix.lower(),
        "all_extensions": path.suffixes,
        "declared_mime": att.get("content_type"),
        "guessed_mime": mimetypes.guess_type(att["filename"])[0],
        "suspicious": len(path.suffixes) > 1
    }

@dataclass
class Finding:
    code: str
    weight: int
    message: str
    evidence: Optional[str] = None

def shannon_entropy(data: bytes, max_len: int = 200_000) -> float:
    data = data[:max_len]
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    n = len(data)
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent

def detect_magic(data: bytes) -> str:
    # very small signature set, expand as needed
    if data.startswith(b"MZ"):
        return "pe_executable"
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    if data.startswith(b"{\\rtf"):
        return "rtf"
    if data.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
        return "ole2"
    return "unknown"

RLO_CHARS = {"\u202E", "\u202D", "\u2066", "\u2067", "\u2068", "\u2069"}

SVG_BLOCK_RE = re.compile(r"<svg\b.*?</svg>", flags=re.I | re.S)
SCRIPT_BLOCK_RE = re.compile(r"<script\b.*?</script>", flags=re.I | re.S)

# crude but effective for embedded long base64 blobs
BASE64_LONG_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")

def _html_sniff(data: bytes) -> str:
    return data[:300_000].decode("utf-8", errors="ignore")

def _extract_inline_svgs(html_text: str) -> List[str]:
    return SVG_BLOCK_RE.findall(html_text)

def _svg_script_obfuscation_findings(svg_text_lower: str) -> List[Finding]:
    f: List[Finding] = []

    # SVG + script is already a big deal
    if "<script" in svg_text_lower:
        f.append(Finding("svg_script", 55, "Inline SVG contains <script> (active scripting inside embedded SVG)."))

        # Obfuscation / execution indicators
        if "cdata" in svg_text_lower:
            f.append(Finding("svg_cdata", 5, "SVG script uses CDATA wrapper (common in weaponized SVG)."))
        if "atob" in svg_text_lower or "fromcharcode" in svg_text_lower:
            f.append(Finding("svg_base64_decode", 15, "SVG script performs Base64 decoding (atob/fromCharCode), consistent with obfuscation."))
        if "constructor" in svg_text_lower:
            f.append(Finding("svg_function_ctor", 20, "SVG script references constructor (Function constructor abuse pattern)."))
        if "return eval" in svg_text_lower or "eval(" in svg_text_lower:
            f.append(Finding("svg_eval", 25, "SVG script uses eval (dynamic code execution)."))
        # XOR-ish decrypt loop signals
        if "charcodeat" in svg_text_lower and "^" in svg_text_lower:
            f.append(Finding("svg_xor_decrypt", 20, "SVG script shows XOR decrypt loop pattern (charCodeAt + ^), consistent with staged payload decryption."))
        if BASE64_LONG_RE.search(svg_text_lower):
            f.append(Finding("svg_long_base64_blob", 10, "SVG script contains long Base64-like blob(s), likely hidden payload."))

    return f

def analyze_pdf_bytes(data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    
    try:
        from pypdf import PdfReader
    except Exception:
        findings.append(Finding(
            "pdf_parser_missing", 0,
            "PDF deep inspection not available because 'pypdf' is not installed."
        ))
        return findings

    # Quick raw scan (cheap, catches many malicious PDFs even if parsing fails)
    raw_head = data[:500_000].lower()
    if b"/javascript" in raw_head or b"/js" in raw_head:
        findings.append(Finding("pdf_javascript_raw", 40,
                                "PDF contains JavaScript markers (raw scan), which may execute on open."))

    if b"/openaction" in raw_head or b"/aa" in raw_head:
        findings.append(Finding("pdf_auto_action_raw", 45,
                                "PDF contains auto-action markers (OpenAction/AA) that can trigger behavior on open."))

    # Deep parse
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
    except Exception as e:
        findings.append(Finding("pdf_parse_fail", 20,
                                "PDF could not be fully parsed (corrupt/obfuscated), which is suspicious for email attachments.",
                                evidence=str(e)[:200]))
        return findings

    if getattr(reader, "is_encrypted", False):
        findings.append(Finding("pdf_encrypted", 20,
                                "PDF is encrypted, which can prevent scanning and is sometimes used to hide malicious content."))

    # Safely access catalog/root
    try:
        root = reader.trailer.get("/Root")
    except Exception:
        root = None

    def walk_obj(obj, depth=0):
        # Very conservative recursion guard
        if depth > 20:
            return
        try:
            # pypdf objects often behave like dicts
            if hasattr(obj, "keys"):
                for k in obj.keys():
                    key = str(k)
                    val = obj.get(k)

                    lowk = key.lower()
                    if lowk in ("/openaction", "/aa"):
                        findings.append(Finding("pdf_auto_action", 50,
                                                f"PDF defines {key}, which can trigger actions automatically."))
                    if lowk in ("/javascript", "/js"):
                        findings.append(Finding("pdf_javascript", 55,
                                                f"PDF contains {key} actions/scripts."))

                    if lowk == "/launch":
                        findings.append(Finding("pdf_launch", 70,
                                                "PDF contains a Launch action, which can attempt to run external programs."))

                    if lowk == "/uri":
                        # Extract URL-ish evidence if possible
                        ev = None
                        try:
                            ev = str(val)[:200]
                        except Exception:
                            pass
                        findings.append(Finding("pdf_external_uri", 25,
                                                "PDF contains external URI actions/links (can be used for phishing redirects).",
                                                evidence=ev))

                    if lowk in ("/embeddedfile", "/filespec"):
                        findings.append(Finding("pdf_embedded_file", 70,
                                                "PDF references embedded files (EmbeddedFile/Filespec), a common malware delivery method."))

                    if lowk == "/acroform":
                        findings.append(Finding("pdf_forms", 25,
                                                "PDF contains an AcroForm (interactive form), which is sometimes used for phishing."))

                    # Recurse
                    walk_obj(val, depth + 1)

            # Handle arrays/lists
            elif isinstance(obj, list):
                for item in obj:
                    walk_obj(item, depth + 1)
        except Exception:
            return

    if root is not None:
        walk_obj(root, 0)

    # Simple URL extraction from raw bytes (helps analysts)
    urls = set(re.findall(rb"https?://[^\s<>\"]{6,200}", data[:1_000_000]))
    if urls:
        sample = b", ".join(sorted(list(urls))[:5]).decode("utf-8", "ignore")
        findings.append(Finding("pdf_urls_found", 10,
                                "Extracted URLs from PDF content (review for phishing destinations).",
                                evidence=sample))

    return findings

def analyze_attachment_bytes(filename: str, declared_mime: str, data: bytes,
                             risky_ext_reasons: Dict[str, str]) -> Tuple[int, List[Finding]]:
    findings: List[Finding] = []
    path = Path(filename)
    suffixes = [s.lower() for s in path.suffixes]
    last_ext = suffixes[-1] if suffixes else ""

    # 1) Filename tricks
    if any(ch in filename for ch in RLO_CHARS):
        findings.append(Finding("unicode_direction_override", 25,
                                "Filename contains Unicode directionality characters often used to disguise extensions."))

    if len(suffixes) > 1:
        findings.append(Finding("multi_extension", 15,
                                "Filename has multiple extensions, a common disguise technique.",
                                evidence="".join(suffixes)))

    for ext in suffixes:
        if ext in risky_ext_reasons:
            findings.append(Finding("risky_extension", 30,
                                    f"Potentially risky filetype detected => {ext}",
                                    evidence=risky_ext_reasons[ext]))
            break  # keep it simple; or keep all matches

    # 2) Magic / type sniff
    magic = detect_magic(data)
    findings.append(Finding("magic_type", 0, f"Detected file signature: {magic}"))

    if magic == "pdf":
        findings.extend(analyze_pdf_bytes(data))

    # 3) MIME mismatch (best-effort)
    # declared_mime might be wrong; still useful as a signal
    if declared_mime:
        if magic == "pdf" and "pdf" not in declared_mime.lower():
            findings.append(Finding("mime_mismatch", 20, "Declared MIME type doesn't match detected PDF signature.",
                                    evidence=f"declared={declared_mime}"))
        if magic == "zip" and "zip" not in declared_mime.lower() and "officedocument" not in declared_mime.lower():
            findings.append(Finding("mime_mismatch", 20, "Declared MIME type doesn't match detected ZIP signature.",
                                    evidence=f"declared={declared_mime}"))

    # 4) ZIP inspection (covers OOXML + zipped droppers)
    if magic == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                names = [n.lower() for n in z.namelist()]

                # Macro in OOXML
                if any("vbaproject.bin" in n for n in names):
                    findings.append(Finding("office_macro", 60,
                                            "Office document appears to contain macros (vbaProject.bin), a common malware vector."))

                # Dangerous contents
                dangerous_members = [n for n in names if n.endswith((".exe",".js",".vbs",".ps1",".lnk",".scr",".bat",".cmd",".hta"))]
                if dangerous_members:
                    findings.append(Finding("zip_dangerous_members", 70,
                                            "Archive contains potentially executable/script files.",
                                            evidence=", ".join(dangerous_members[:10])))

        except zipfile.BadZipFile:
            findings.append(Finding("zip_parse_fail", 15, "File claims to be a ZIP but could not be parsed (corrupt/obfuscated)."))

    # 5) HTML heuristics (treat HTML as a container)
    is_html = (
        last_ext in (".html",".htm",".xhtml",".mht",".mhtml")
        or (magic == "unknown" and b"<html" in data[:5000].lower())
        or (declared_mime and "text/html" in declared_mime.lower())
    )
    if is_html:
        text_raw = _html_sniff(data)
        lowered = text_raw.lower()

        # Existing checks (keep)
        if "<form" in lowered and ("password" in lowered or "passwd" in lowered):
            findings.append(Finding("html_credential_form", 55,
                                    "HTML content includes a form that references passwords, consistent with credential harvesting."))

        if "window.location" in lowered or "document.location" in lowered or 'meta http-equiv="refresh"' in lowered:
            findings.append(Finding("html_redirect", 20,
                                    "HTML content contains redirect behavior often used to route victims to phishing sites."))

        # New: scripts present at all
        if "<script" in lowered:
            findings.append(Finding("html_script", 15,
                                    "HTML attachment contains script tags (active content)."))

        # New: data URIs (often used to hide payloads)
        if "data:image/svg+xml" in lowered or "data:text/html" in lowered or "data:application" in lowered:
            findings.append(Finding("html_data_uri", 15,
                                    "HTML contains data: URIs, which are often used to embed hidden payloads."))

        # New: extract inline SVG blocks and analyze them
        svgs = _extract_inline_svgs(text_raw)
        if svgs:
            findings.append(Finding("html_inline_svg", 25,
                                    "HTML contains inline SVG content, which can embed active scripts.",
                                    evidence=f"count={len(svgs)}"))

            # analyze each SVG; pull worst indicators into top-level findings
            worst_weight_sum = 0
            worst_evidence = None

            for svg in svgs[:10]:  # cap to avoid abuse
                svg_lower = svg.lower()
                svg_findings = _svg_script_obfuscation_findings(svg_lower)
                weight_sum = sum(x.weight for x in svg_findings)

                if weight_sum > worst_weight_sum:
                    worst_weight_sum = weight_sum
                    # keep evidence short for CLI
                    worst_evidence = "; ".join(x.code for x in svg_findings[:6])

                # add detailed findings (optional: you can only add worst instead)
                findings.extend(svg_findings)

            if worst_weight_sum >= 55:
                findings.append(Finding("html_svg_weaponized", 40,
                                        "Embedded SVG shows active scripting + obfuscation patterns consistent with malicious loader behavior.",
                                        evidence=worst_evidence or ""))

    # 6) Script heuristics (very lightweight)
    if last_ext in (".ps1",".js",".jse",".vbs",".vbe",".wsf",".hta",".cmd",".bat"):
        text = data[:300_000].decode("utf-8", errors="ignore")
        lowered = text.lower()
        if "base64" in lowered or re.search(r"[A-Za-z0-9+/]{300,}={0,2}", text):
            findings.append(Finding("possible_obfuscation", 35,
                                    "Script contains long base64-like blobs, a common obfuscation technique."))
        if "invoke-expression" in lowered or "iex " in lowered:
            findings.append(Finding("ps_invoke_expression", 40,
                                    "PowerShell uses Invoke-Expression (IEX), frequently associated with malicious execution."))

    # 7) Entropy signal
    ent = shannon_entropy(data)
    if ent > 7.2:
        findings.append(Finding("high_entropy", 20,
                                "File content has high entropy, which can indicate packed or encrypted payloads.",
                                evidence=f"entropy={ent:.2f}"))

    # Score
    score = sum(f.weight for f in findings)
    score = max(0, min(100, score))
    return score, findings

def diagnose_eml(eml_file_path):
    """
    Examine the .eml file in multiple ways to understand its structure
    """
    print("="*70)
    print("EML FILE DIAGNOSTICS")
    print("="*70)
    print(f"File: {eml_file_path}\n")
    
    # Read as raw bytes
    with open(eml_file_path, 'rb') as f:
        raw_bytes = f.read()
    
    print(f"File size: {len(raw_bytes)} bytes\n")
    
    # Try different decodings
    decodings = []
    
    # UTF-8
    try:
        utf8_content = raw_bytes.decode('utf-8')
        decodings.append(('UTF-8', utf8_content))
        print("✓ UTF-8 decoding successful")
    except UnicodeDecodeError as e:
        print(f"✗ UTF-8 decoding failed: {e}")
    
    # Latin-1 (always works)
    latin1_content = raw_bytes.decode('latin-1')
    decodings.append(('Latin-1', latin1_content))
    print("✓ Latin-1 decoding successful")
    
    # ASCII with errors ignored
    ascii_content = raw_bytes.decode('ascii', errors='ignore')
    decodings.append(('ASCII (ignore)', ascii_content))
    print("✓ ASCII decoding successful\n")
    
    print("="*70)
    print("BOUNDARY ANALYSIS")
    print("="*70)
    
    for encoding_name, content in decodings:
        print(f"\n{encoding_name} encoding:")
        print("-" * 40)
        
        # Find all boundary-like strings
        boundaries = re.findall(r'--[=\w]+==--', content)
        if boundaries:
            print(f"  Closing boundaries found: {len(set(boundaries))}")
            for b in set(boundaries):
                count = content.count(b)
                print(f"    {b} (appears {count} time(s))")
        else:
            print("  No closing boundaries found")
        
        # Find boundary declarations
        boundary_decls = re.findall(r'boundary="?([^"\s]+)"?', content, re.IGNORECASE)
        if boundary_decls:
            print(f"\n  Boundary declarations: {len(set(boundary_decls))}")
            for b in set(boundary_decls):
                print(f"    {b}")
    
    print("\n" + "="*70)
    print("PDF CONTENT ANALYSIS")
    print("="*70)
    
    for encoding_name, content in decodings:
        print(f"\n{encoding_name} encoding:")
        print("-" * 40)
        
        # Look for PDF markers
        pdf_content_type = content.count('application/pdf')
        pdf_header = raw_bytes.count(b'%PDF')
        
        print(f"  'application/pdf' appears: {pdf_content_type} time(s)")
        print(f"  '%PDF' appears in raw bytes: {pdf_header} time(s)")
        
        # Find where PDF content is
        pdf_idx = content.find('application/pdf')
        if pdf_idx >= 0:
            # Show context around the PDF declaration
            start = max(0, pdf_idx - 200)
            end = min(len(content), pdf_idx + 400)
            snippet = content[start:end]
            
            print(f"\n  Context around 'application/pdf' (position {pdf_idx}):")
            print("  " + "─" * 66)
            for line in snippet.split('\n'):
                print(f"  {line[:66]}")
            print("  " + "─" * 66)
    
    print("\n" + "="*70)
    print("SEARCHING FOR PDF DATA AFTER LAST CLOSING BOUNDARY")
    print("="*70)
    
    # Use Latin-1 as it's most reliable
    content = latin1_content
    
    # Find all closing boundaries
    closing_boundaries = list(re.finditer(r'--[=\w]+==--', content))
    
    if closing_boundaries:
        last_boundary = closing_boundaries[-1]
        print(f"\nLast closing boundary: {last_boundary.group()}")
        print(f"Position: {last_boundary.start()} - {last_boundary.end()}")
        
        after_boundary = content[last_boundary.end():]
        print(f"\nContent after last boundary: {len(after_boundary)} characters")
        
        # Check if there's PDF content after it
        if 'application/pdf' in after_boundary:
            print("✓ Found 'application/pdf' after the last closing boundary!")
            
            pdf_idx = after_boundary.find('application/pdf')
            snippet_start = max(0, pdf_idx - 50)
            snippet_end = min(len(after_boundary), pdf_idx + 300)
            
            print("\nSnippet:")
            print("─" * 70)
            print(after_boundary[snippet_start:snippet_end])
            print("─" * 70)
        else:
            print("✗ No 'application/pdf' found after last closing boundary")
    else:
        print("\n✗ No closing boundaries found in file")
    
    print("\n" + "="*70)
    print("RAW BYTE SEARCH FOR PDF")
    print("="*70)
    
    # Search for %PDF in raw bytes
    pdf_magic = b'%PDF'
    pdf_positions = []
    pos = 0
    while True:
        pos = raw_bytes.find(pdf_magic, pos)
        if pos == -1:
            break
        pdf_positions.append(pos)
        pos += 1
    
    if pdf_positions:
        print(f"\n✓ Found {len(pdf_positions)} PDF header(s) at byte position(s):")
        for pos in pdf_positions:
            print(f"  Position {pos}: {raw_bytes[pos:pos+20]}")
    else:
        print("\n✗ No PDF headers found in raw bytes")

def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def audit_eml_bytes(eml_path: str, parser_input_bytes: bytes | None = None) -> dict:
    p = Path(eml_path)
    disk_size = p.stat().st_size
    disk_bytes = p.read_bytes()

    report = {
        "disk_size": disk_size,
        "read_size": len(disk_bytes),
        "disk_sha256": sha256(disk_bytes),
        "read_sha256": sha256(disk_bytes),  # same, but explicit
        "parser_input_size": len(parser_input_bytes) if parser_input_bytes is not None else None,
        "parser_input_sha256": sha256(parser_input_bytes) if parser_input_bytes is not None else None,
        "mismatch_disk_vs_read": disk_size != len(disk_bytes),
        "mismatch_read_vs_parser_input": (parser_input_bytes is not None and len(disk_bytes) != len(parser_input_bytes)),
        "contains_pdf_marker": (b"Content-Type: application/pdf" in disk_bytes) or (b"JVBERi0" in disk_bytes),
        "contains_nul_byte": (b"\x00" in disk_bytes),
        "first_nul_index": disk_bytes.find(b"\x00"),
    }
    return report

def detect_bad_epilogue(file_path):
    """
    Detect BadEpilogue attack - content hidden after MIME closing boundaries
    """
    print("="*70)
    print("BadEpilogue Attack Detector")
    print("="*70)
    print(f"Analyzing: {file_path}\n")
    
    # Read the raw file
    with open(file_path, 'rb') as f:
        raw_bytes = f.read()
    
    # Try to decode
    try:
        content = raw_bytes.decode('utf-8')
    except UnicodeDecodeError:
        content = raw_bytes.decode('latin-1', errors='ignore')
    
    print(f"File size: {len(raw_bytes):,} bytes\n")
    
    # Find all MIME boundaries (both opening and closing)
    # Closing boundaries end with --
    # Matches both formats: --boundary-- and --====boundary====--
    closing_boundaries = list(re.finditer(r'--([\w=]+)--', content))
    
    if not closing_boundaries:
        print("⚠ No MIME closing boundaries found")
        print("  This might not be a MIME email or boundaries use different format\n")
        return False
    
    print(f"Found {len(closing_boundaries)} closing MIME boundary/boundaries:\n")
    
    for i, match in enumerate(closing_boundaries, 1):
        boundary_str = match.group(0)
        position = match.end()
        
        print(f"  [{i}] {boundary_str}")
        print(f"      Position: {position:,} / {len(content):,} bytes")
        
        # Check what's after this boundary
        remaining = content[position:]
        remaining_stripped = remaining.strip()
        
        if remaining_stripped:
            print(f"      ⚠ WARNING: {len(remaining_stripped):,} bytes of content after this boundary!")
            
            # Check if it looks like another MIME part
            if 'Content-Type:' in remaining[:500]:
                print(f"      🚨 SUSPICIOUS: Contains 'Content-Type:' header!")
            
            if 'application/pdf' in remaining[:500].lower():
                print(f"      🚨 ALERT: Contains 'application/pdf' - likely BadEpilogue attack!")
            
            if 'base64' in remaining[:500].lower():
                print(f"      🚨 ALERT: Contains 'base64' encoding!")
            
            # Show a preview
            preview = remaining_stripped[:200].replace('\n', ' ')
            print(f"      Preview: {preview}...")
        else:
            print(f"      ✓ Clean - no content after boundary")
        
        print()
    
    # Find the LAST closing boundary
    if closing_boundaries:
        last_boundary = closing_boundaries[-1]
        epilogue_start = last_boundary.end()
        epilogue = content[epilogue_start:].strip()
        
        print("="*70)
        print("EPILOGUE ANALYSIS (content after last MIME boundary)")
        print("="*70)
        
        if epilogue:
            print(f"⚠ EPILOGUE DETECTED: {len(epilogue):,} bytes\n")
            
            # Analyze what's in the epilogue
            has_content_type = bool(re.search(r'Content-Type:', epilogue, re.IGNORECASE))
            has_pdf = bool(re.search(r'application/pdf', epilogue, re.IGNORECASE))
            has_base64 = bool(re.search(r'base64', epilogue, re.IGNORECASE))
            has_boundary = bool(re.search(r'--[=\w]+==[^-]', epilogue))
            
            threat_level = 0
            
            if has_content_type:
                print("🚨 Contains Content-Type header")
                threat_level += 2
            
            if has_pdf:
                print("🚨 Contains PDF content type")
                threat_level += 3
            
            if has_base64:
                print("🚨 Contains base64 encoding")
                threat_level += 2
            
            if has_boundary:
                print("🚨 Contains additional MIME boundaries")
                threat_level += 3
            
            print()
            
            if threat_level >= 5:
                print("🔴 THREAT LEVEL: HIGH - Likely BadEpilogue Attack!")
                print("    This email contains hidden content after the MIME structure.")
                print("    This is commonly used to bypass email security scanners.\n")
            elif threat_level >= 2:
                print("🟡 THREAT LEVEL: MEDIUM - Suspicious epilogue content")
            else:
                print("🟢 THREAT LEVEL: LOW - Epilogue may be benign")
            
            print("\nEpilogue Preview (first 500 chars):")
            print("-" * 70)
            print(epilogue[:500])
            print("-" * 70)
            
            return threat_level >= 5
        else:
            print("✓ No epilogue - email ends cleanly after last MIME boundary\n")
            return False
    
    return False

def run_analysis(file_path: str,
                 use_json: bool = False,
                 show_spinners: bool = True):

    print_banner()
    analysis_results = []

    # Load message for later
    message, raw = load_email(file_path)

    # Get file extension
    ext = get_file_extension(file_path)

    if ext == '.eml':
        print(BRIGHT_GREEN + "[+] Detected EML file" + RESET)

    else:
        print(YELLOW + "[*] Treating file as raw headers" + RESET)
    print()

    # --- MIME tree
    print(YELLOW + "[*] Analyzing MIME Data" + RESET)
    dump_mime_tree_plus(raw)
    print()

    # Extract attachments from the email file
    print(YELLOW + '[*] Attachment scanning...' + RESET)
    attachments = extract_attachments(message)

    if not attachments:
        print(YELLOW + '[*] No attachments found. Trying Advanced attachment scanning...' + RESET)
        salvaged = salvage_pdf_attachments_from_raw(raw)
        attachments.extend(salvaged)

        sig_hits = raw_attachment_signature_detected(raw)

        if sum(1 for v in sig_hits.values() if v) >= 3:
            print('Found raw attachment')
        else:
            print(YELLOW + '[*] Could not find any attachments' + RESET)

    if attachments:
            print(BRIGHT_GREEN + "[+] Email attachments detected" + RESET)
            for attachment in attachments:
                print(BRIGHT_WHITE + "-----------------------------------------------" + RESET)

                if show_spinners:
                    analyzeSpinner = Halo(text="Analyzing attachment...", spinner="dots")
                    analyzeSpinner.start()

                score, findings = analyze_attachment_bytes(
                    filename=attachment["filename"],
                    declared_mime=attachment.get("content_type", ""),
                    data=attachment["payload"],
                    risky_ext_reasons=RISKY_EXTENSION_REASONS
                )

                if show_spinners:
                    analyzeSpinner.stop()

                print(f"\nAttachment: {attachment['filename']}")
                print(f"Declared MIME: {attachment['content_type']}")
                print(f"Size: {attachment['size']} bytes")

                print()
                print()
                payload_preview = attachment["payload"][:1000]
                print(BRIGHT_BLUE + f"Payload (1000 chars): {payload_preview}" + RESET)
                print()
                print()

                print(BRIGHT_YELLOW + f"Total Findings: {len(findings)}" + RESET)
                for f in findings[:10]:
                    print(f"  - (+{f.weight}) {f.message}")
                    if f.evidence:
                        print(f"      evidence: {f.evidence}")
                print(BRIGHT_YELLOW + f"{len(findings) - 10} additional findings omitted from output" + RESET)
                print()
                print(YELLOW + f"Risk Score: {score}/100" + RESET)
                print()
                print(BRIGHT_WHITE + "-----------------------------------------------" + RESET)

            print()
    else:
        print(YELLOW + "[*] Running BadEpilogue Attack Detector")
        print()
        is_attack = detect_bad_epilogue(file_path)
        if is_attack:
            print('BadEpilogue Detected')
        else:
            print('BadEpilogue Not Detected')

    # ----------------------------------------------------------
    # Pull Headers from Headers Block
    # ----------------------------------------------------------

    #received_from_hdr = msg.get_all("Received") or []
    received_from_hdr = get_headers(file_path, "Received")

    from_hdr = get_header(file_path, "From")
    to_hdr = get_header(file_path, "To")
    reply_to_hdr = get_header(file_path, "Reply-To")
    return_path_hdr = get_header(file_path, "Return-Path")
    date_hdr = get_header(file_path, "Date")
    subject_hdr = get_header(file_path, "Subject")
    mime_version_hdr = get_header(file_path, "MIME-Version")
    content_language_hdr = get_header(file_path, "Content-Language")
    content_type_hdr = get_header(file_path, "Content-Type")
    content_transfer_encode_hdr = get_header(file_path, "Content-Transfer-Encoding")
    thread_topic_hdr = get_header(file_path, "Thread-Topic")
    org_authAs_hdr = get_header(file_path, "X-MS-Exchange-Organization-AuthAs")
    has_attachment_hdr = get_header(file_path, "X-MS-Has-Attach")
    origin_IP_hdr = get_header(file_path, "X-Originating-IP")

    auth_results_headers = get_headers(file_path,"authentication-results")
    has_auth_headers = bool(auth_results_headers)
    auth_spf = auth_dkim = auth_dmarc = None

    # ----------------------------------------------------------
    # END - Pull Headers from Headers Block
    # ----------------------------------------------------------

    # Check for file type .eml, .txt and parse message
    msg = parse_detected_filetype(ext, file_path)

    # Extract Email Body
    plain_body, html_body = extract_bodies(msg)

    # Extract URLs
    found_URLS = extract_urls_from_body(plain_body, html_body)
    url_analysis = [analyze_url(u, analysis_results) for u in found_URLS]

    if plain_body:
        print(CYAN + "\n=== Plain text body (first 400 chars) ===" + RESET)
        print(plain_body[:400])
    elif html_body:
        print(CYAN + "\n=== HTML body (first 400 chars) ===" + RESET)
        print(html_body[:400])
    else:
        print(RED + "\n[!] No body content found in this message." + RESET)

    if found_URLS:
        print()
        print(YELLOW + "[*] URLs Found in Body" + RESET)
        # print(CYAN + "\n=== URLs Found in Body ===" + RESET)
        # for url in found_URLS:
        #     print(" -", url)

        # Flag IP-literal URLs
        ip_literal_URLS = [u for u in found_URLS if is_ip_literal_url(u)]
        if ip_literal_URLS:
            print(RED + "\n[!] IP-literal URLs detected:" + RESET)
            for url in ip_literal_URLS:
                print("   -", url)

        if url_analysis:
            print(CYAN + "\n=== URL Analysis ===" + RESET)
            for item in url_analysis:
                url = item["url"]
                flags = item["flags"]
                if flags:
                    print(f" - {url}")
                    print(f"   Flags: {', '.join(flags)}")
                else:
                    print(f" - {url}")
                    print("   Flags: (none)")

    else:
        print(YELLOW + "\n[*] No URLs found in body." + RESET)

    print()

    if auth_results_headers:
        primary_auth = auth_results_headers[0]
        auth_parsed = parse_auth_results_header(primary_auth)
        auth_spf = auth_parsed.get("spf")
        auth_dkim = auth_parsed.get("dkim")
        auth_dmarc = auth_parsed.get("dmarc")

        if auth_dkim:
            add_finding(
                analysis_results,
                category=Category.AUTH_RESULTS,
                code=Code.DKIM_STATUS,
                severity=Severity.INFO if auth_dkim == "pass" else Severity.MEDIUM,
                message=f"DKIM status: {auth_dkim}",
                status=auth_dkim,
            )

        if auth_dmarc:
            add_finding(
                analysis_results,
                category=Category.AUTH_RESULTS,
                code=Code.DMARC_STATUS,
                severity=Severity.INFO if "pass" in auth_dmarc else Severity.MEDIUM,
                message=f"DMARC status: {auth_dmarc}",
                status=auth_dmarc,
            )


    # Parse received-spf
    received_spf_hdrs = get_headers(file_path,"received-spf")
    # Set "has SPF Headers" flag
    hasSPFHeaders = bool(received_spf_hdrs)

    # Rule:
    # - The first header is the most recent hop
    # - Earlier ones are historical and less relevant to final evaluation
    parsed_spf_hdr = None

    if received_spf_hdrs:
        primary_spf_header = received_spf_hdrs[0]
        parsed_spf_hdr = parse_received_spf(primary_spf_header) or None
        add_finding(
                analysis_results,
                category=Category.SPF,
                code=Code.SPF_STATUS,
                severity=Severity.INFO if "pass" in parsed_spf_hdr['result'] else Severity.HIGH,
                message=f"SPF status: {parsed_spf_hdr['result']}",
                status=parsed_spf_hdr['result'],
            )

    # Check for CrossTenant Headers
    cross_tenant = has_crosstenant_headers(msg)

    # Output Analysis
    print(f"{CYAN}=== Raw Header Values ==={RESET}")
    print(f"From:           {from_hdr!r}")
    print(f"To:             {to_hdr!r}")
    print(f"Reply-To:       {reply_to_hdr!r}")
    print(f"Return-Path:    {return_path_hdr!r}")
    print()
    if thread_topic_hdr:
        print(f"Thread-Topic:   {thread_topic_hdr!r}")
    print(f"Subject:        {subject_hdr!r}")
    print(f"Date:           {date_hdr!r}")
    if has_attachment_hdr:
        print(f"Has Attachment: {has_attachment_hdr!r}")
    print()
    if origin_IP_hdr:
        print(f"Origin IP:      {origin_IP_hdr!r}")
        print()
    if auth_results_headers:
        print(f"Auth-Results:   {auth_results_headers!r}")
        print()
    print(f"Content-Type:     {content_type_hdr!r}")
    if content_language_hdr:
        print(f"Content-Language: {content_language_hdr!r}")
    if content_transfer_encode_hdr:
        print(f"Content Transfer Encoding: {content_transfer_encode_hdr!r}")
    print()
    if hasSPFHeaders and parsed_spf_hdr['result'] == 'pass':
        print(f"{BRIGHT_GREEN}received-spf:{RESET}   {received_spf_hdrs[0]!r}")
    if hasSPFHeaders and parsed_spf_hdr['result'] == 'fail':
        print(f"{BRIGHT_RED}received-spf:{RESET}   {received_spf_hdrs[0]!r}")
    print()
    print(f"MIME-Version:   {mime_version_hdr!r}")
    print()

    for r in received_from_hdr:
        print(f"Received: {r}")

    print()

    print(f"{CYAN}=== Parsed Domains ==={RESET}")
    from_domain, from_display_name = get_domain_from_address(from_hdr)
    to_domain, to_display_name = get_domain_from_address(to_hdr)
    reply_to_domain, reply_to_display_name = get_domain_from_address(reply_to_hdr)
    return_path_domain, return_path_display_name = get_domain_from_address(return_path_hdr)

    if cross_tenant:
        add_finding(
            analysis_results,
            category=Category.HEADERS,
            code=Code.CROSSTENANT_PRESENT,
            severity=Severity.INFO if from_domain != to_domain else Severity.HIGH,
            message="Cross tenant headers detected for internal email.",
            status=cross_tenant,
        )

    print(f"From domain:            {from_domain}")
    if from_domain == None:
        print(f"{RED}[-] 'From' Headers missing!{RESET}")
        add_finding(
            analysis_results,
            category=Category.HEADERS,
            code=Code.MISSING_HEADER,
            severity=Severity.HIGH,
            message="From headers are missing! This is suspicious.",
            status=Code.MISSING_HEADER,
        )
    print(f"To domain:              {to_domain}")
    if from_domain != to_domain and cross_tenant:
        print(f"{BRIGHT_GREEN}Cross Tenant:           {cross_tenant}{RESET}")
    if from_domain == to_domain and cross_tenant:
        print(f"{BRIGHT_RED}Cross Tenant:           {cross_tenant}{RESET}")
    print(f"Reply-To domain:        {reply_to_domain}")
    print(f"Return-Path domain:     {return_path_domain}")
    print()

    WHITELIST_PATH = BASE_DIR / 'config' / 'domain-whitelist.txt'

    # Load up DNS whitelist for domains to skip WHOIS checks for: yourcompanydomain.com, etc.
    with open(WHITELIST_PATH, 'r') as f:
        lines = f.read().splitlines()

    if from_domain in lines:
        print(YELLOW + "[*] Domain is in whitelist, skipping unneccesary WHOIS & DNS Records lookup" + RESET)
        print()
    else:
        # -------------------------------------------
        # Analyze WHOIS for Sending Domain
        # -------------------------------------------
        print(f"{CYAN}=== Parsed Sender Domain WHOIS ==={RESET}")

        if show_spinners:
            whoisSpinner = Halo(text="Perfomring WHOIS lookup...", spinner="dots")
            whoisSpinner.start()

        whois_data = analyze_sender_rdap(from_domain, analysis_results)

        if show_spinners:
            whoisSpinner.stop()

        if whois_data:
            print(f"Domain:                 {whois_data['domain']}")
            print(f"Domain Registrar:       {whois_data['registrar']}")
            print(f"Domain Age:             {whois_data['domain_age_days']}")
            if whois_data['domain_age_days'] <= 180:
                print(RED + '[-] Domain is newly registered' + RESET)
            if whois_data['domain_age_days'] <= 365 and whois_data['domain_age_days'] > 180:
                print(YELLOW + '[*] Domain is young' + RESET)
            print(f"Creation Date:          {whois_data['creation_date']}")
            print(f"Expiration Date:        {whois_data['expiration_date']}")
            print(f"Updated Date:           {whois_data['updated_date']}")
            print()
            print(f"Nameserver:             {whois_data['name_servers']}")
        else:
            print(YELLOW + "[*] Could not lookup WHOIS information" + RESET)

        print()

        # ----------------------------------------------------------------------
        # Output DNS Records for Sending Domain
        # ----------------------------------------------------------------------
        print(f"{CYAN}=== Parsed Sender DNS Records ==={RESET}")

        if show_spinners:
            spinner = Halo(text="Querying DNS Records...", spinner="dots2")
            spinner.start()

        dns_results = extract_dns_records(from_domain)

        if show_spinners:
            spinner.stop()

        for r in dns_results:
            print(f"- {r}")

        print()

    # ----------------------------------------------------------------------
    # Output Authentication Header Results
    # ----------------------------------------------------------------------
    if auth_results_headers:
        print(f"{CYAN}=== Parsed Authentication Results ==={RESET}")
        print(f"spf: {auth_spf}")
        print(f"dkim: {auth_dkim}")
        print(f"dmarc: {auth_dmarc}")
        print()

    if auth_dmarc == 'fail':
        print(f"{RED}=== Email DMARC Failed Check ==={RESET}")
        print("Emails that fail DMARC checking are more likely phishing emails.")
        print()
        add_finding(
                analysis_results,
                category=Category.DMARC,
                code=Code.DMARC_FAIL,
                severity=Severity.HIGH,
                message="DMARC Failed Check",
                status=auth_dmarc,
            )

    if from_domain == to_domain and hasSPFHeaders:
        if parsed_spf_hdr['result'] == 'fail' or auth_spf == 'fail' or auth_dmarc == 'fail':
            print(f"{RED}=== Internal Spoofing evidence found ==={RESET}")
            if parsed_spf_hdr['result'] == "fail" or auth_spf == 'fail':
                print(f"SPF Failed -> Origin IP = {parsed_spf_hdr['client_ip']} for domain -> {from_domain}")
            if org_authAs_hdr == "Anonymous":
                print(f"AuthAs -> {org_authAs_hdr}")
            if auth_dmarc == 'fail':
                print(f"DMARC Check -> {auth_dmarc}")
            print()

    if from_domain != to_domain:
        if parsed_spf_hdr["result"] == "fail" or auth_spf == 'fail':
            print(f"{RED}=== External Spoofing evidence found ==={RESET}")
            print(f"SPF Failed -> Origin IP = {parsed_spf_hdr['client_ip']}")
        print()

    # Print if no From Headers are found
    if from_hdr is None:
        print(RED + '[-] No From Headers Found - Very suspicious!' + RESET)

    # Print if no Auth Headers are found
    if has_auth_headers is False:
        print(YELLOW + '[*] No Authentication Headers Found' + RESET)

    # Print if no SPF Headers are found
    if hasSPFHeaders is False:
        print(YELLOW + '[*] No SPF Headers Found' + RESET)

    # pretty-print JSON for now (CLI use)
    if use_json:
        print("\nJSON analysis results:")
        print(json.dumps({"analysis_results": analysis_results}, indent=2))

    print(rf"""{BRIGHT_GREEN}
==================================================
   Analysis Complete: Please perform manual
   investigation to verify findings
==================================================
{RESET}
""")

def run_analysis_and_pdf(file_path: str, pdf_path: str):
    analysis_results = []  # your existing findings list

    email_body = get_email_body(file_path)

    # ... run your usual logic to fill analysis_results and capture text_output ...
    text_output = run_analysis_capture_text(file_path, use_json=False, strip_ansi=False)

    hops = parse_received_hops(get_headers(file_path, "Received"))

    # Example badge: mark the last hop as "Delivered"
    if hops:
        hops[0]["badges"] = [{"text": "DELIVERED", "level": "pass"}]  # top Received is usually most recent
        hops[-1]["badges"] = [{"text": "SHIPPED", "level": ""}]

    metadata = {
        "file_name": file_path,
        "overall_verdict": "N/A",  # or whatever you compute
        "overall_score": "N/A",              # optional
        "analyzed_at": datetime.now(),
        "email_body": email_body,
        "received_hops": hops
    }

    generate_pdf_report(
        output_path=pdf_path,
        text_output=text_output,
        analysis_results=analysis_results,
        metadata=metadata,
        # email_body=email_body
    )

def run_analysis_capture_text(file_path: str,
                              use_json: bool = False,
                              strip_ansi: bool = True) -> str:
    """
    Run the analysis and capture the full terminal-style output
    as a single string, instead of printing it to the real terminal.
    """
    buffer = io.StringIO()
    # Redirect stdout into our buffer while run_analysis executes
    with contextlib.redirect_stdout(buffer):
        run_analysis(file_path, use_json=use_json, show_spinners=False)

    # Get everything that was printed
    output = buffer.getvalue()
    
    if strip_ansi and "\x1b" in output:
        output = ANSI_RE.sub("", output)

    return output

def analyze_sender_rdap(domain: str, analysis_results):
    rdap = lookup_rdap(domain)

    if not rdap["success"]:
        add_finding(
            analysis_results,
            category=Category.METADATA,
            code=Code.WHOIS_LOOKUP_FAILED,
            severity=Severity.LOW,
            message=f"WHOIS lookup failed for domain {domain}",
            error=rdap["error"],
        )
        return None

    add_finding(
        analysis_results,
        category=Category.METADATA,
        code=Code.WHOIS_BASIC_INFO,
        severity=Severity.INFO,
        message=f"WHOIS data for {domain}",
        registrar=rdap["registrar"],
        creation_date=rdap["creation_date"],
        expiration_date=rdap["expiration_date"],
    )

    return rdap
