#!/usr/bin/env python3

import os
import argparse
import re
import ipaddress
import json

from email import message_from_string
from email.policy import default as default_policy
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse, urlunparse
from colors import RED, GREEN, YELLOW, BLUE, RESET, CYAN, BRIGHT_GREEN, MAGENTA, BRIGHT_RED
from enum import Enum

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
===================================================================
   PHISH ANALYZER - Email Header & Body Scanner - Version: 0.2.3
===================================================================
"""
    print(BRIGHT_GREEN + banner + RESET)

def add_finding(results_list, category: Category, code: Code, severity: Severity, message: str, **data):
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
        # Single-part message
        ctype = msg.get_content_type()
        if ctype == "text/plain":
            plain_body = msg.get_content()
        elif ctype == "text/html":
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
        return None
    
    display_name, email_addr = parseaddr(header_value)
    if "@" not in email_addr:
        return None
    
    # Return lowercase domain name from email
    return email_addr.split("@", 1)[1].lower()

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

def main():
    analysis_results = []

    parser = argparse.ArgumentParser(
        description="Step 1: just parse and print basic email headers."
    )

    parser.add_argument(
        "-f", "--file",
        required=True,
        help="Path to a text file containing raw email headers.",
    )

    parser.add_argument(
        "-j", "--json",
        action="store_true",
        help="Include output of analysis_results as JSON"
    )

    args = parser.parse_args()

    # Get file extension
    filename = args.file
    _, ext = os.path.splitext(filename)
    ext = ext.lower()

    if ext == ".eml":
        # Handle EML file
        print(GREEN + "[+] Detected EML file" + RESET)
        print()
        msg = parse_full_eml(filename)

        # Where it was before

    else:
        # Handle as TXT file
        print(YELLOW + "[*] Treating file as raw headers" + RESET)
        print()
        msg = parse_headers_from_file(filename)


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
        print(CYAN + "\n=== URLs Found in Body ===" + RESET)
        for url in found_URLS:
            print(" -", url)

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

    from_hdr = msg["From"]
    to_hdr = msg["To"]
    reply_to_hdr = msg["Reply-To"]
    return_path_hdr = msg["Return-Path"]
    date_hdr = msg["Date"]
    subject_hdr = msg["Subject"]
    mime_version_hdr = msg["MIME-Version"]
    content_language_hdr = msg["Content-Language"]
    content_type_hdr = msg["Content-Type"]
    thread_topic_hdr = msg["Thread-Topic"]
    org_authAs_hdr = msg["X-MS-Exchange-Organization-AuthAs"]

    auth_results_headers = msg.get_all("authentication-results") or []
    auth_spf = auth_dkim = auth_dmarc = None

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
    received_spf_hdrs = msg.get_all("received-spf") or []

    # Rule:
    # - The first header is the most recent hop
    # - Earlier ones are historical and less relevant to final evaluation
    if received_spf_hdrs:
        primary_spf_header = received_spf_hdrs[0]
        parsed_spf_hdr = parse_received_spf(primary_spf_header)
        add_finding(
                analysis_results,
                category=Category.SPF,
                code=Code.SPF_STATUS,
                severity=Severity.INFO if "pass" in parsed_spf_hdr["result"] else Severity.HIGH,
                message=f"SPF status: {parsed_spf_hdr["result"]}",
                status=parsed_spf_hdr["result"],
            )
    
    # Check for CrossTenant Headers
    crossTenant = has_crosstenant_headers(msg)

    # Output Analysis
    print(f"{CYAN}=== Raw Header Values ==={RESET}")
    print(f"From:           {from_hdr!r}")
    print(f"To:             {to_hdr!r}")
    print(f"Reply-To:       {reply_to_hdr!r}")
    print(f"Return-Path:    {return_path_hdr!r}")
    print()
    print(f"Thread-Topic:   {thread_topic_hdr!r}")
    print(f"Subject:        {subject_hdr!r}")
    print(f"Date:           {date_hdr!r}")
    print()
    print(f"Auth-Results:   {auth_results_headers!r}")
    print()
    print(f"Content-Type:     {content_type_hdr!r}")
    print(f"Content-Language: {content_language_hdr!r}")
    print()
    if parsed_spf_hdr["result"] == 'pass':
        print(f"{BRIGHT_GREEN}received-spf:{RESET}   {received_spf_hdrs[0]!r}")
    if parsed_spf_hdr["result"] == 'fail':
        print(f"{BRIGHT_RED}received-spf:{RESET}   {received_spf_hdrs[0]!r}")
    print()
    print(f"MIME-Version:   {mime_version_hdr!r}")
    print()

    print(f"{CYAN}=== Parsed Domains ==={RESET}")
    from_domain = get_domain_from_address(from_hdr)
    to_domain = get_domain_from_address(to_hdr)
    reply_to_domain = get_domain_from_address(reply_to_hdr)
    return_path_domain = get_domain_from_address(return_path_hdr)

    if crossTenant:
        add_finding(
            analysis_results,
            category=Category.HEADERS,
            code=Code.CROSSTENANT_PRESENT,
            severity=Severity.INFO if from_domain != to_domain else Severity.HIGH,
            message=f"Cross tenant headers detected for internal email.",
            status=crossTenant,
        )

    print(f"From domain:            {from_domain}")
    print(f"To domain:              {to_domain}")
    if from_domain != to_domain and crossTenant:
        print(f"{BRIGHT_GREEN}Cross Tenant:           {crossTenant}{RESET}")
    if from_domain == to_domain and crossTenant:
        print(f"{BRIGHT_RED}Cross Tenant:           {crossTenant}{RESET}")
    print(f"Reply-To domain:        {reply_to_domain}")
    print(f"Return-Path domain:     {return_path_domain}")
    print()

    if auth_results_headers:
        print(f"{CYAN}=== Parsed Authentication Results ==={RESET}")
        print(f"spf: {auth_spf}")
        print(f"dkim: {auth_dkim}")
        print(f"dmarc: {auth_dmarc}")
        print()

    if auth_dmarc == 'fail':
        print(f"{RED}=== Email DMARC Failed Check ==={RESET}")
        print(f"Emails that fail DMARC checking are more likely phishing emails.")
        print()
        add_finding(
                analysis_results,
                category=Category.DMARC,
                code=Code.DMARC_FAIL,
                severity=Severity.HIGH,
                message=f"DMARC Failed Check",
                status=auth_dmarc,
            )

    if from_domain == to_domain and crossTenant:
        print(f"{RED}=== Internal Spoofing evidence found ==={RESET}")
        print(f"Cross Tenant -> {crossTenant} => Internal domain emailing shouldn't have Cross Tenant headers")
        if org_authAs_hdr == "Anonymous":
            print(f"AuthAs -> {org_authAs_hdr}")
        if parsed_spf_hdr["result"] == "fail" or auth_spf == 'fail':
            print(f"SPF Failed -> Origin IP = {parsed_spf_hdr["client_ip"]}")
        print()
    
    if from_domain != to_domain:
        if parsed_spf_hdr["result"] == "fail" or auth_spf == 'fail':
            print(f"{RED}=== External Spoofing evidence found ==={RESET}")
            print(f"SPF Failed -> Origin IP = {parsed_spf_hdr["client_ip"]}")
        print()

    # pretty-print JSON for now (CLI use)
    if args.json:
        print("\nJSON analysis results:")
        print(json.dumps({"analysis_results": analysis_results}, indent=2))

# Run main
if __name__ == "__main__":
    print_banner()
    main()

    print(rf"""{YELLOW}
===============================================================================
   Analysis Complete: Please perform manual investigation to verify findings
===============================================================================
{RESET}
""")