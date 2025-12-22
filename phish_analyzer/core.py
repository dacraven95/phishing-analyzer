#!/usr/bin/env python3

"""
Core module for processing the email files for analysis
"""

import os
import re
import ipaddress
import json
import io
import contextlib

from email import message_from_string
from email.policy import default as default_policy
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse, urlunparse
from enum import Enum
from datetime import datetime
from typing import Any
from pathlib import Path

# Third party imports
from halo import Halo
import dns.resolver

# first party imports
from phish_analyzer.rdapHelper import lookup_rdap

# Local imports
from .colors import RED, GREEN, YELLOW, RESET, CYAN, BRIGHT_GREEN, BRIGHT_RED
from .pdfReport import generate_pdf_report

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

# optional: known-good company domains (can expand later)
TRUSTED_BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "office.com", "live.com"},
    "google": {"google.com", "accounts.google.com", "gmail.com"},
    "amazon": {"amazon.com"},
    # add domains here as needed
}

def print_banner():
    banner = r"""
==================================================
   PHISH ANALYZER - Email Header & Body Scanner
   Version: 0.4.5
==================================================
"""
    print(BRIGHT_GREEN + banner + RESET)

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
    lines = raw.splitlines()
    # Find the first "start" of a header: a line containing "Something:"
    # and then gather everything until the first blank line.
    header_started = False
    header_lines = []

    for line in lines:
        if not header_started:
            if ":" in line and "#" not in line:
                header_started = True
                header_lines.append(line)
        else:
            if line.strip() == "":    # blank line = end of headers
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

def parse_detected_filetype(ext, filename):
    if ext == ".eml":
        # Handle EML file
        return parse_full_eml(filename)
    else:
        # Handle as TXT file
        return parse_headers_from_file(filename)

def get_email_body(file_path):
    # Get file extension
    ext = get_file_extension(file_path)

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
    ext = get_file_extension(file_path)

    headers = parse_detected_filetype(ext, file_path)
    selected_hdr = headers.get_all(header) or []

    return selected_hdr

def get_header(file_path, header: str = None):
    
    # Check if header was passed in and cancel if not
    if header is None:
        return
    
    # Get file extension
    ext = get_file_extension(file_path)

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


def run_analysis(file_path: str,
                 use_json: bool = False,
                 show_spinners: bool = True):

    print_banner()

    analysis_results = []

    # Get file extension
    ext = get_file_extension(file_path)

    if ext == '.eml':
        print(GREEN + "[+] Detected EML file" + RESET)
        print()
    else:
        print(YELLOW + "[*] Treating file as raw headers" + RESET)
        print()

    # ----------------------------------------------------------
    # Pull Headers from Headers Block
    # ----------------------------------------------------------

    #received_from_hdr = msg.get_all("Received") or []
    received_from_hdr = get_headers(file_path, "Received")

    from_hdr = get_header(file_path, "From")
    to_hdr = get_header(file_path, "To")
    reply_to_hdr = get_header(file_path, "Reply-To")
    return_path_hdr = get_header("Return-Path")
    date_hdr = get_header("Date")
    subject_hdr = get_header("Subject")
    mime_version_hdr = get_header("MIME-Version")
    content_language_hdr = get_header("Content-Language")
    content_type_hdr = get_header("Content-Type")
    content_transfer_encode_hdr = get_header("Content-Transfer-Encoding")
    thread_topic_hdr = get_header("Thread-Topic")
    org_authAs_hdr = get_header("X-MS-Exchange-Organization-AuthAs")
    has_attachment_hdr = get_header("X-MS-Has-Attach")
    origin_IP_hdr = get_header("X-Originating-IP")

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
        print(YELLOW + "\n=== Plain text body (first 400 chars) ===" + RESET)
        print(plain_body[:400])
    elif html_body:
        print(YELLOW + "\n=== HTML body (first 400 chars) ===" + RESET)
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

    BASE_DIR = Path(__file__).resolve().parent
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

    ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

    # Get everything that was printed
    output = buffer.getvalue()
    return ANSI_RE.sub("", output) if strip_ansi else output

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
