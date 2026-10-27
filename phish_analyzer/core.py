#!/usr/bin/env python3

"""
Core module for processing the email files for analysis
"""
from __future__ import annotations
import os, hashlib
import re
import json
import io
import base64
import quopri
from functools import lru_cache
from time import monotonic

from email import message_from_string, policy
from email.policy import default as default_policy
from email.message import Message
from email.parser import BytesParser
from urllib.parse import urlparse, parse_qs, unquote
from typing import Any, Union

from pathlib import Path

# Third party imports
from halo import Halo
import dns.resolver

# first party imports
from phish_analyzer.rdapHelper import lookup_rdap
from phish_analyzer.social_engineering import score_social_engineering, SEResult
from phish_analyzer.threat_intel import (
    initialize_database,
    save_analysis,
    extract_and_save_iocs,
    correlate_all,
    print_correlation_results,
)
from phish_analyzer.attack_mapping import format_attack_output
from phish_analyzer.yara_scanner import scan_email_components, format_yara_output

# Local imports
from .colors import RED, YELLOW, RESET, CYAN, BRIGHT_GREEN, BRIGHT_RED, BRIGHT_BLUE, BRIGHT_WHITE, BRIGHT_YELLOW
from .pdfReport import generate_pdf_report

# Detection implementations live in separate modules. Re-export existing names
# to preserve integrations importing helpers from phish_analyzer.core.
from .analysis_models import AnalysisResult, Category, Severity, Code, Finding, add_finding
from .url_analysis import (
    URL_REGEX, SUSPICIOUS_TLDS, SUSPICIOUS_PATH_KEYWORDS, CYRILLIC_RE, LATIN_RE,
    CYRILLIC_LOOKALIKES, TRUSTED_BRAND_DOMAINS, BRAND_ALIASES, SHORTENER_HOSTS,
    REDIRECT_PARAMETERS, contains_cyrillic, contains_latin, decode_idn,
    normalize_homoglyphs, highlight_homoglyphs, detect_cyrillic_homoglyph_domain,
    HrefExtractor, extract_urls_from_body, extract_hrefs_from_html, normalize_url,
    is_ip_literal_url, looks_random_segment, _host_matches_root, _normalized_host,
    _same_domain_family, _is_close_brand_label, _brand_spoof_targets, analyze_url,
    _VisibleLinkExtractor, analyze_displayed_links,
)
from .auth_analysis import (
    TRUSTED_AUTH_SERVERS, get_domain_from_address, parse_received_spf,
    parse_auth_results_header, _authserv_id, _auth_property, evaluate_authentication,
)
from .risk_scoring import _risk_label, build_risk_assessment, print_risk_assessment
from .attachment_analysis import (
    RISKY_EXTENSION_REASONS, RLO_CHARS, SVG_BLOCK_RE, SCRIPT_BLOCK_RE, BASE64_LONG_RE,
    analyze_attachment, shannon_entropy, detect_magic, _html_sniff,
    _extract_inline_svgs, _svg_script_obfuscation_findings, analyze_pdf_bytes,
    analyze_attachment_bytes, get_attachment_hashes,
)
from contextvars import ContextVar
from builtins import print as _builtin_print

# A per-request output stream, not a process-wide sys.stdout redirection.
_ANALYSIS_STREAM: ContextVar[io.StringIO | None] = ContextVar("phish_analysis_stream", default=None)

def print(*args: Any, **kwargs: Any) -> None:
    """Route legacy core diagnostics to this request's output when capturing."""
    stream = _ANALYSIS_STREAM.get()
    if stream is not None and kwargs.get("file") is None:
        kwargs["file"] = stream
    _builtin_print(*args, **kwargs)


# Enable/Disable Threat Intel DB functionality
THREAT_INTEL_ENABLED = os.getenv("THREAT_INTEL_ENABLED", "true").lower() == "true"

# Do not create or touch the database when threat intelligence is disabled.
if THREAT_INTEL_ENABLED:
    initialize_database()

BASE_DIR = Path(__file__).resolve().parent
ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')
MAX_DEEP_SCAN_BYTES = 12 * 1024 * 1024
MAX_EMAIL_BYTES = 25 * 1024 * 1024

# Emails can contain sensitive data and attachments. Do not retain parsed messages
# in a process-global cache beyond a request; run_analysis reuses its own Message.
def _get_cached_parsed_message(file_path: str) -> Message:
    """Compatibility helper; parse the requested message without global caching."""
    return parse_detected_filetype(get_file_extension(file_path), file_path)


SUSPICIOUS_MAILERS = [
    "the bat", "evolution", "mutt", "alpine",
    "phpmailer", "swiftmailer", "sendgrid",
    "mailchimp", "python", "php", "ruby",
    "curl", "libwww", "massmailer"
]

BRAND_KEYWORDS = [
    "paypal", "microsoft", "office365", "outlook", "apple", "google",
    "amazon", "bankofamerica", "chase", "wellsfargo"
]


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

# Unicode ranges

# Characters commonly used in Cyrillic homoglyph attacks


# Recognized corporate roots are exact host suffixes, not approval of actual URL safety.
# No network requests are made to any untrusted links during URL analysis.
# This must correspond to an upstream gateway that removes untrusted incoming
# Authentication-Results headers before inserting its own authoritative results.


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
        raw = f.read(MAX_EMAIL_BYTES + 1)
    if len(raw) > MAX_EMAIL_BYTES:
        raise ValueError("Email exceeds the 25 MiB analysis limit")
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    return msg, raw

def load_email_lenient_with_raw(path: str):
    with open(path, "rb") as f:
        raw = f.read(MAX_EMAIL_BYTES + 1)
    if len(raw) > MAX_EMAIL_BYTES:
        raise ValueError("Email exceeds the 25 MiB analysis limit")

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
        if len(b64_blob) > (MAX_DEEP_SCAN_BYTES * 4 // 3) + 16:
            continue

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
    # Parse original bytes so non-UTF-8 MIME data is not irreversibly replaced.
    with open(path, "rb") as f:
        raw = f.read(MAX_EMAIL_BYTES + 1)
    if len(raw) > MAX_EMAIL_BYTES:
        raise ValueError("Email exceeds the 25 MiB analysis limit")
    return BytesParser(policy=default_policy).parsebytes(raw)

def _read_text_part(part: Message) -> str:
    """Decode a text MIME part without aborting on malformed declared charsets."""
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
        if isinstance(content, bytes):
            return content.decode("utf-8", errors="replace")
    except (LookupError, UnicodeError, ValueError, TypeError):
        pass
    payload = part.get_payload(decode=True) or b""
    if isinstance(payload, bytes):
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except (LookupError, UnicodeError):
            return payload.decode("utf-8", errors="replace")
    return ""


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
                plain_body = _read_text_part(part)
            elif ctype == "text/html" and html_body is None:
                html_body = _read_text_part(part)
    else:

        content_str = _read_text_part(msg)

        # Single-part message
        ctype = msg.get_content_type()
        if ctype == "text/plain" and "<html" not in content_str.lower():
            plain_body = content_str
        elif ctype == "text/html" or "<html" in content_str.lower():
            html_body = content_str

    return plain_body, html_body


def parse_headers_from_file(path: str):
    """
    Read raw header text from a file and parse into an email Message object.

    :param path: Path to headers text file.
    :type path: str
    """
    if Path(path).stat().st_size > MAX_EMAIL_BYTES:
        raise ValueError("Email exceeds the 25 MiB analysis limit")
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()

    # Extract header block from text file
    header_block = extract_header_block(raw)

    msg = message_from_string(header_block, policy=default_policy)
    return msg


def has_crosstenant_headers(headers: dict) -> bool:
    """
    Returns True if any header name or value contains 'crosstenant'
    (case-insensitive).
    """
    for key, value in headers.items():
        if "crosstenant" in key.lower() or ("crosstenant" in value.lower() if value else False):
            return True
    return False

def _normalized_dns_domain(domain: str | None) -> str | None:
    """Accept only hostname-like DNS targets from untrusted message headers."""
    if not isinstance(domain, str):
        return None
    try:
        ascii_domain = domain.strip().rstrip(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None
    if not ascii_domain or len(ascii_domain) > 253:
        return None
    labels = ascii_domain.split(".")
    if len(labels) < 2 or any(
        not label or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        return None
    return ascii_domain


@lru_cache(maxsize=256)
def _cached_dns_query(domain: str, record_type: str, time_bucket: int) -> tuple[str, ...]:
    """Limit DNS latency and cache successes/failures for at most five minutes."""
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=3.0)
        return tuple(r.to_text() for r in answers)
    except (dns.exception.DNSException, OSError, ValueError):
        return ()


def safe_dns_query(domain: str, record_type: str):
    """Return DNS answers or None without raising for invalid/unresolvable domains."""
    normalized = _normalized_dns_domain(domain)
    record_type = record_type.upper()
    if normalized is None or record_type not in {"A", "MX", "CNAME", "TXT"}:
        return None
    records = _cached_dns_query(normalized, record_type, int(monotonic() // 300))
    return list(records) if records else None

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

def parse_detected_filetype(ext: str, file_path: Union[str, Path]):
    ext = (ext or "").lower()
    if ext and not ext.startswith("."):
        ext = "." + ext

    file_path = str(file_path)
    return parse_full_eml(file_path) if ext == ".eml" else parse_headers_from_file(file_path)

def get_email_body(file_path):
    # Parse the requested message and extract its bodies without retaining it.
    msg = _get_cached_parsed_message(file_path)
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

def get_header(file_path, header: str = None):
    
    # Check if header was passed in and cancel if not
    if header is None:
        return
    
    # Get file extension
    msg = _get_cached_parsed_message(file_path)
    return msg[header] or None

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
            return _read_text_part(part)
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
        if len(b64) > (MAX_DEEP_SCAN_BYTES * 4 // 3) + 16:
            continue
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


# crude but effective for embedded long base64 blobs


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

def _bounded_correlation_description(value: Any) -> str:
    """Fallback for external printer that has no injectable output stream."""
    if value is None:
        return "No threat-intelligence correlation data returned."
    if isinstance(value, dict):
        return "Correlation data: " + repr(list(value.items())[:12])[:2500]
    if isinstance(value, (list, tuple, set)):
        items = list(value)
        if not items:
            return "No historical correlations found."
        return f"Historical correlations ({len(items)}): " + repr(items[:8])[:2500]
    return "Correlation data: " + repr(value)[:2500]

def run_analysis(file_path: str,
                 use_json: bool = False,
                 show_spinners: bool = True,
                 show_mime: bool = False,
                 summary_out: dict[str, Any] | None = None,
                 details_out: dict[str, Any] | None = None):

    print_banner()

    analysis_results = []
    attachment_scores: list[int] = []
    analysis_limitations: list[str] = []

    # Track all finding codes for ATT&CK mapping at the end
    attack_finding_codes: list[str] = []

    # Load message for later
    message, raw = load_email(file_path)

    # Get file extension. The BytesParser result is reused for all EML header,
    # body, attachment, and authentication checks during this analysis.
    ext = get_file_extension(file_path)
    msg = message if ext == ".eml" else parse_headers_from_file(file_path)

    if ext == '.eml':
        print(BRIGHT_GREEN + "[+] Detected EML file" + RESET)

    else:
        print(YELLOW + "[*] Treating file as raw headers" + RESET)
    print()

    # --- MIME tree
    if show_mime:
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

    # A virtual PDF link is a URL artifact, not downloadable attachment bytes.
    # Only feed actual file payloads into hashing, deep inspection, and YARA.
    scannable_attachments = [
        att for att in attachments
        if isinstance(att.get("payload"), bytes) and bool(att["payload"])
    ]
    if any(att.get("virtual_kind") == "pdf_link" for att in attachments):
        analysis_limitations.append(
            "Linked PDF references were not downloaded or byte-scanned.")
    if attachments:
            print(BRIGHT_GREEN + "[+] Email attachments detected" + RESET)
            for attachment in attachments:
                print(BRIGHT_WHITE + "-----------------------------------------------" + RESET)

                if not isinstance(attachment.get("payload"), bytes) or not attachment["payload"]:
                    print(f"\nAttachment reference: {attachment['filename']}")
                    print("No attachment bytes available; scanning the linked URL instead.")
                    continue

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

                attachment_scores.append(score)
                if any(f.code in {"pdf_parser_unavailable", "pdf_deep_scan_skipped",
                                  "zip_scan_limited"} for f in findings):
                    analysis_limitations.append(
                        f"Deep inspection was unavailable or limited for {attachment['filename']}.")
                # Structured findings are also needed by JSON and PDF reporters.
                for finding in findings:
                    analysis_results.append({
                        "category": Category.CONTENT.value,
                        "code": finding.code,
                        "severity": (Severity.HIGH if finding.weight >= 40
                                     else Severity.MEDIUM if finding.weight >= 20
                                     else Severity.LOW if finding.weight > 0
                                     else Severity.INFO).value,
                        "message": finding.message,
                        "data": {"filename": attachment["filename"],
                                 "weight": finding.weight,
                                 "evidence": finding.evidence},
                    })

                print(f"\nAttachment: {attachment['filename']}")
                print(f"Declared MIME: {attachment['content_type']}")
                print(f"Size: {attachment['size']} bytes")
                print()
                print(f"Hashes: {get_attachment_hashes(attachment['payload'])}")

                print()
                print()
                # payload_preview = attachment['payload'][:500].decode('utf-8', errors='replace')
                # print(BRIGHT_BLUE + f"Payload Preview: {payload_preview}" + RESET)
                # print()
                # print()

                print(BRIGHT_YELLOW + f"Total Findings: {len(findings)}" + RESET)
                for f in findings[:10]:
                    print(f"  - (+{f.weight}) {f.message}")
                    if f.evidence:
                        print(f"      evidence: {f.evidence}")
                if len(findings) > 10:
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

    x_mailer_hdr = msg.get("X-Mailer")
    user_agent_hdr = msg.get("User-Agent")
    mailer_value = x_mailer_hdr or user_agent_hdr

    #received_from_hdr = msg.get_all("Received") or []
    received_from_hdr = (msg.get_all("Received") or [])

    from_hdr = msg.get("From")
    to_hdr = msg.get("To")
    reply_to_hdr = msg.get("Reply-To")
    return_path_hdr = msg.get("Return-Path")
    date_hdr = msg.get("Date")
    subject_hdr = msg.get("Subject")
    mime_version_hdr = msg.get("MIME-Version")
    content_language_hdr = msg.get("Content-Language")
    content_type_hdr = msg.get("Content-Type")
    content_transfer_encode_hdr = msg.get("Content-Transfer-Encoding")
    thread_topic_hdr = msg.get("Thread-Topic")
    org_authAs_hdr = msg.get("X-MS-Exchange-Organization-AuthAs")
    has_attachment_hdr = msg.get("X-MS-Has-Attach")
    origin_IP_hdr = msg.get("X-Originating-IP")

    auth_results_headers = (msg.get_all("authentication-results") or [])
    has_auth_headers = bool(auth_results_headers)

    # ----------------------------------------------------------
    # END - Pull Headers from Headers Block
    # ----------------------------------------------------------

    # ----------------------------------------------------------
    # Check for Mailer or User-Agent Headers
    # ----------------------------------------------------------

    if not mailer_value:
        print(f"{BRIGHT_YELLOW}[*] No X-Mailer or User-Agent header found{RESET}")
    else:
        lower = mailer_value.lower()
        matched = [m for m in SUSPICIOUS_MAILERS if m in lower]

        if matched:
            reason = f"{BRIGHT_RED}[!] Matched suspicious mailer pattern(s): {matched} {RESET}"
            print(reason)
        else:
            print(f"{BRIGHT_GREEN}[+] Mailer identified: {mailer_value}{RESET}")

    # ----------------------------------------------------------
    # END - Check for Mailer or User-Agent Headers
    # ----------------------------------------------------------

    # The message was already parsed above.

    # Extract Email Body
    plain_body, html_body = extract_bodies(msg)

    # Keep PDF/API metadata from this already-parsed message (no second parse).
    if details_out is not None:
        details_out["email_body"] = html_body or plain_body
        details_out["received_hops"] = parse_received_hops(
            [str(value) for value in msg.get_all("Received", [])])

    # Extract URLs
    found_URLS = extract_urls_from_body(plain_body, html_body)
    for attachment in attachments:
        if attachment.get("virtual_kind") == "pdf_link":
            linked_url = normalize_url(attachment.get("url", ""))
            if linked_url and linked_url not in found_URLS:
                found_URLS.append(linked_url)
    url_analysis = [analyze_url(u, analysis_results) for u in found_URLS]
    url_analysis.extend(analyze_displayed_links(html_body, analysis_results))
    if details_out is not None:
        details_out["urls"] = url_analysis

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

                for flag in flags:
                    if flag == "IP_LITERAL":
                        attack_finding_codes.append("URL_IP_LITERAL")
                    elif flag == "SUSPICIOUS_TLD":
                        attack_finding_codes.append("URL_SUSPICIOUS_TLD")
                    elif flag == "PUNYCODE_DOMAIN":
                        attack_finding_codes.append("URL_PUNYCODE")
                    elif flag == "OBFUSCATED_PATH":
                        attack_finding_codes.append("URL_OBFUSCATED_PATH")
                    elif flag.startswith("BRAND_IMPERSONATION"):
                        attack_finding_codes.append("URL_BRAND_IMPERSONATION")
                    elif flag in {"SUSPICIOUS_PATH_KEYWORDS"}:
                        attack_finding_codes.append("URL_SUSPICIOUS_PATH")


                if flags:
                    print(f" - {url}")
                    print(f"   Flags: {', '.join(flags)}")
                else:
                    print(f" - {url}")
                    print("   Flags: (none)")

    else:
        print(YELLOW + "\n[*] No URLs found in body." + RESET)

    print()

    # Authentication-Results are evaluated after we know the visible From domain.

    # Parse received-spf
    received_spf_hdrs = (msg.get_all("received-spf") or [])
    # Set "has SPF Headers" flag
    hasSPFHeaders = bool(received_spf_hdrs)

    # Rule:
    # - The first header is the most recent hop
    # - Earlier ones are historical and less relevant to final evaluation
    parsed_spf_hdr = None

    if received_spf_hdrs:
        primary_spf_header = received_spf_hdrs[0]
        parsed_spf_hdr = parse_received_spf(primary_spf_header)

    spf_result = parsed_spf_hdr.get("result") if parsed_spf_hdr else None
    spf_client_ip = parsed_spf_hdr.get("client_ip") if parsed_spf_hdr else None
    # Received-SPF is a claim in the message, never independently verified here.
    # It will only appear as descriptive context; scoring uses trusted A-R results.

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
    if spf_result == 'pass':
        print(f"{BRIGHT_GREEN}received-spf:{RESET}   {received_spf_hdrs[0]!r}")
    if spf_result == 'fail':
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
            severity=Severity.INFO,
            message="Cross-tenant header(s) present (informational; not proof of spoofing).",
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
    sender_risk = 0
    if from_domain and reply_to_domain and not _same_domain_family(from_domain, reply_to_domain):
        sender_risk = max(sender_risk, 42)
        add_finding(analysis_results, Category.HEADERS, Code.SENDER_REPLYTO_MISMATCH,
                    Severity.MEDIUM, "Reply-To domain differs from visible From domain",
                    from_domain=from_domain, reply_to_domain=reply_to_domain)
    if from_domain and return_path_domain and not _same_domain_family(from_domain, return_path_domain):
        # Common for legitimate ESPs and bounce handling: informational only.
        add_finding(analysis_results, Category.HEADERS, Code.FROM_RETURNPATH_MISMATCH,
                    Severity.INFO, "Return-Path differs from From (may be legitimate mailing service)",
                    from_domain=from_domain, return_path_domain=return_path_domain)
    if not from_domain:
        sender_risk = 80
    print()

    print(f"{CYAN}=== Cyrillic Detection ==={RESET}")
    cyrillic_from_domain = detect_cyrillic_homoglyph_domain(from_domain)
    if cyrillic_from_domain:
        for f in cyrillic_from_domain:
            attack_finding_codes.append(f.code)
            sender_risk = max(sender_risk, min(90, f.weight + 25))
            analysis_results.append({"category": Category.HEADERS.value,
                                     "code": f.code, "severity": Severity.HIGH.value,
                                     "message": f.message, "data": {"evidence": f.evidence}})
            print(YELLOW + f.message + RESET)
    else:
        print(f"{YELLOW}[*] No cyrillic characters detected for {from_domain}{RESET}")
    
    print()
    print()

    WHITELIST_PATH = BASE_DIR / 'config' / 'domain-whitelist.txt'

    # The whitelist is optional and can be absent in a fresh Docker volume.
    try:
        with open(WHITELIST_PATH, 'r', encoding='utf-8') as f:
            lines = {line.strip().lower() for line in f if line.strip() and not line.lstrip().startswith('#')}
    except OSError:
        lines = set()

    if not _normalized_dns_domain(from_domain):
        print(YELLOW + "[*] No valid sender domain; skipping WHOIS and DNS lookups" + RESET)
        print()
    elif from_domain.lower() in lines:
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
            print(f"Domain:                 {whois_data.get('domain', from_domain)}")
            print(f"Domain Registrar:       {whois_data.get('registrar')}")
            print(f"Domain Age:             {whois_data.get('domain_age_days')}")
            if isinstance(whois_data.get('domain_age_days'), (int, float)) and whois_data['domain_age_days'] <= 180:
                print(RED + '[-] Domain is newly registered' + RESET)
            if isinstance(whois_data.get('domain_age_days'), (int, float)) and 180 < whois_data['domain_age_days'] <= 365:
                print(YELLOW + '[*] Domain is young' + RESET)
            print(f"Creation Date:          {whois_data.get('creation_date')}")
            print(f"Expiration Date:        {whois_data.get('expiration_date')}")
            print(f"Updated Date:           {whois_data.get('updated_date')}")
            print()
            print(f"Nameserver:             {whois_data.get('name_servers')}")
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
    # Trusted authentication interpretation
    # ----------------------------------------------------------------------
    authentication = evaluate_authentication(
        [str(h) for h in auth_results_headers], from_domain)
    if details_out is not None:
        details_out["authentication"] = authentication
    print(f"{CYAN}=== Authentication Interpretation ==={RESET}")
    if authentication["trusted"]:
        print(f"Receiver: {authentication['authserv_id']} (configured trusted ingress)")
        print(f"SPF: {authentication['spf']}  smtp.mailfrom: {authentication['spf_domain']}")
        print(f"DKIM: {authentication['dkim']}  header.d: {authentication['dkim_domain']}")
        print(f"DMARC: {authentication['dmarc']}  Alignment: {authentication['alignment']}")
        for name, code in (("spf", Code.SPF_STATUS), ("dkim", Code.DKIM_STATUS),
                           ("dmarc", Code.DMARC_STATUS)):
            value = authentication.get(name)
            if value:
                add_finding(analysis_results, Category.AUTH_RESULTS, code,
                            Severity.HIGH if name == "dmarc" and value == "fail" else Severity.INFO,
                            f"Trusted receiver reports {name.upper()}: {value}", status=value,
                            authserv_id=authentication["authserv_id"])
        if authentication["dmarc"] == "fail":
            attack_finding_codes.append("DMARC_FAIL")
        if authentication["dkim"] == "fail" and authentication["dmarc"] != "pass":
            attack_finding_codes.append("DKIM_FAIL")
        if authentication["spf"] == "fail" and authentication["dmarc"] != "pass":
            attack_finding_codes.append("SPF_FAIL")
    else:
        print(YELLOW + "Unverified: no trusted Authentication-Results header selected." + RESET)
        if auth_results_headers:
            print("Authentication headers exist but cannot be trusted for scoring.")
        if received_spf_hdrs:
            print(f"Received-SPF claims: {spf_result} (unverified)")
    print("Trusted receiver IDs must only be enabled for sanitized gateway-provided headers.")
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


    # ----------------------------------------------------------
    # Social Engineering Scoring
    # ----------------------------------------------------------
    print(f"{CYAN}=== Social Engineering Analysis ==={RESET}")

    se_result = score_social_engineering(
        plain_body=plain_body,
        html_body=html_body,
        subject=subject_hdr,
    )

    # Pick a color based on grade
    SE_COLORS = {
        "CRITICAL": BRIGHT_RED,
        "HIGH":     RED,
        "MEDIUM":   YELLOW,
        "LOW":      BRIGHT_YELLOW,
        "MINIMAL":  BRIGHT_GREEN,
    }
    grade_color = SE_COLORS.get(se_result.grade, RESET)

    print(f"Social Engineering Score:  {grade_color}{se_result.score}/100 [{se_result.grade}]{RESET}")
    print(f"Summary: {se_result.summary}")
    if details_out is not None:
        details_out["social_engineering"] = {
            "score": se_result.score, "grade": se_result.grade,
            "summary": se_result.summary,
        }

    if se_result.triggers:
        # Group by cluster for cleaner output
        from itertools import groupby
        sorted_triggers = sorted(se_result.triggers, key=lambda t: t.cluster)
        
        for trigg in se_result.triggers:
            attack_finding_codes.append(f"SE_{trigg.cluster}")

        print()
        for cluster, group in groupby(sorted_triggers, key=lambda t: t.cluster):
            group_list = list(group)
            total_weight = sum(t.weight for t in group_list)
            print(f"  {YELLOW}[+{total_weight}] {cluster}{RESET}")
            for trigger in group_list[:3]:  # cap to 3 per cluster in CLI output
                print(f"      phrase:  \"{trigger.phrase}\"")
                print(f"      context: {trigger.context[:120]}")
    print()


    # ----------------------------------------------------------
    # Threat Intelligence Correlation
    # ----------------------------------------------------------
    if THREAT_INTEL_ENABLED:

        ti_matches = correlate_all(
            from_domain=from_domain,
            reply_domain=reply_to_domain,
            return_domain=return_path_domain,
            client_ip=spf_client_ip,
            urls=found_URLS if found_URLS else [],
            attachments=scannable_attachments,
        )

        if details_out is not None:
            details_out["threat_intelligence"] = ti_matches
        if _ANALYSIS_STREAM.get() is None:
            print_correlation_results(ti_matches, {
                "RED":          RED,
                "YELLOW":       YELLOW,
                "CYAN":         CYAN,
                "BRIGHT_RED":   BRIGHT_RED,
                "BRIGHT_GREEN": BRIGHT_GREEN,
                "RESET":        RESET,
            })
        else:
            # The existing threat_intel console formatter writes to global stdout.
            # Never redirect that global stream in a multi-request API worker.
            # Preserve the raw correlations on the structured result separately.
            print(CYAN + "=== Threat Intelligence Correlation ===" + RESET)
            print(_bounded_correlation_description(ti_matches))


    # ----------------------------------------------------------
    # YARA Rule Scanning
    # ----------------------------------------------------------
    yara_matches = scan_email_components(
        plain_body=plain_body,
        html_body=html_body,
        attachments=scannable_attachments,
    )

    if details_out is not None:
        details_out["yara"] = [
            {"rule_name": str(match.rule_name), "attack_ids": list(match.attack_ids)}
            for match in yara_matches
        ]
        details_out["attachments"] = [
            {"filename": att.get("filename"), "content_type": att.get("content_type"),
             "size": att.get("size"), "virtual": att.get("virtual", False)}
            for att in attachments
        ]

    print(format_yara_output(yara_matches, {
        "CYAN":         CYAN,
        "YELLOW":       YELLOW,
        "RED":          RED,
        "BRIGHT_RED":   BRIGHT_RED,
        "BRIGHT_GREEN": BRIGHT_GREEN,
        "RESET":        RESET,
    }))

    # Feed YARA findings into ATT&CK mapping and the structured PDF findings.
    for match in yara_matches:
        analysis_results.append({
            "category": Category.CONTENT.value,
            "code": f"YARA_{match.rule_name}",
            "severity": Severity.HIGH.value,
            "message": f"YARA rule matched: {match.rule_name}",
            "data": {"attack_ids": list(match.attack_ids)},
        })
        attack_finding_codes.append(f"YARA_{match.rule_name}")
        # Also feed the technique IDs directly since YARA rules declare them
        for attack_id in match.attack_ids:
            attack_finding_codes.append(attack_id)

    # ----------------------------------------------------------
    # Overall assessment: combine independent evidence, not every duplicate flag.
    # ----------------------------------------------------------
    risk = build_risk_assessment(
        findings=analysis_results, url_analysis=url_analysis,
        auth=authentication, se_score=se_result.score,
        attachment_scores=attachment_scores, yara_count=len(yara_matches),
        sender_score=sender_risk,
        limitations=analysis_limitations,
    )
    print_risk_assessment(risk, emit=print)
    if summary_out is not None:
        summary_out.clear()
        summary_out.update(risk)

    # Persist ONCE after correlation and full scoring. Current run does not match itself.
    if THREAT_INTEL_ENABLED:
        analysis_id = save_analysis(
            file_name=file_path, risk_score=risk["score"],
            se_score=se_result.score, verdict=risk["verdict"],
        )
        extract_and_save_iocs(
            analysis_id=analysis_id, from_domain=from_domain,
            reply_domain=reply_to_domain, return_domain=return_path_domain,
            client_ip=spf_client_ip, urls=found_URLS,
            attachments=scannable_attachments,
            mailer=msg.get("X-Mailer") or msg.get("User-Agent"),
        )

    # ----------------------------------------------------------
    # MITRE ATT&CK Coverage
    # ----------------------------------------------------------
    if details_out is not None:
        details_out["attack_finding_codes"] = list(dict.fromkeys(attack_finding_codes))
    print(format_attack_output(attack_finding_codes, {
        "CYAN":         CYAN,
        "YELLOW":       YELLOW,
        "BRIGHT_RED":   BRIGHT_RED,
        "BRIGHT_GREEN": BRIGHT_GREEN,
        "RESET":        RESET,
    }))

    # pretty-print JSON for now (CLI use)
    if use_json:
        print("\nJSON analysis results:")
        print(json.dumps({"analysis_results": analysis_results, "risk_assessment": risk}, indent=2))

    print(rf"""{BRIGHT_GREEN}
==================================================
   Analysis Complete: Please perform manual
   investigation to verify findings
==================================================
{RESET}
""")
    return analysis_results

def run_analysis_structured(
    file_path: str, *, strip_ansi: bool = True, show_mime: bool = False,
    display_filename: str | None = None,
) -> AnalysisResult:
    """Execute once and return structured findings, dashboard and legacy output.

    Each request captures only its own core output via ContextVar. No threads
    mutate sys.stdout; upstream legacy printer is handled separately.
    """
    findings: list[dict[str, Any]] = []
    risk: dict[str, Any] = {}
    details: dict[str, Any] = {}
    output = run_analysis_capture_text(
        file_path, strip_ansi=strip_ansi, show_mime=show_mime,
        findings_out=findings, summary_out=risk, details_out=details,
    )
    hops = details.get("received_hops") or []
    if hops:
        hops[0]["badges"] = [{"text": "DELIVERED", "level": "pass"}]
        hops[-1]["badges"] = [{"text": "SHIPPED", "level": ""}]
    # The external threat-intelligence implementation has no guaranteed JSON
    # schema; keep its raw objects out of HTTP responses until that contract is
    # verified, but retain a bounded human-readable summary.
    correlations = details.pop("threat_intelligence", None)
    if correlations is not None:
        details["threat_intelligence_summary"] = _bounded_correlation_description(correlations)
    return AnalysisResult(
        file_name=Path(display_filename or file_path).name,
        findings=findings, risk_assessment=risk, output=output,
        email_body=details.pop("email_body", None), received_hops=hops,
        details={key: value for key, value in details.items() if key != "received_hops"},
    )


def run_analysis_and_pdf(
    file_path: str, pdf_path: str, show_mime: bool = False,
    *, display_filename: str | None = None,
) -> None:
    """Render the existing PDF layout from a single structured analysis run."""
    result = run_analysis_structured(
        file_path, show_mime=show_mime, strip_ansi=False,
        display_filename=display_filename,
    )
    metadata = {
        "file_name": result.file_name,
        "overall_verdict": result.risk_assessment.get("verdict", "N/A"),
        "overall_score": result.risk_assessment.get("score"),
        "risk_assessment": result.risk_assessment,
        "analyzed_at": result.analyzed_at,
        "email_body": result.email_body,
        "received_hops": result.received_hops,
    }
    generate_pdf_report(
        output_path=pdf_path, text_output=result.output,
        analysis_results=result.findings, metadata=metadata,
    )


def run_analysis_capture_text(
    file_path: str, use_json: bool = False, strip_ansi: bool = True,
    show_mime: bool = False,
    findings_out: list[dict[str, Any]] | None = None,
    summary_out: dict[str, Any] | None = None,
    details_out: dict[str, Any] | None = None,
) -> str:
    """Backwards-compatible text output, captured without global redirection."""
    stream = io.StringIO()
    token = _ANALYSIS_STREAM.set(stream)
    try:
        findings = run_analysis(
            file_path, use_json=use_json, show_spinners=False,
            show_mime=show_mime, summary_out=summary_out,
            details_out=details_out,
        )
    finally:
        _ANALYSIS_STREAM.reset(token)
    if findings_out is not None:
        findings_out.extend(findings)
    output = stream.getvalue()
    return ANSI_RE.sub("", output) if strip_ansi else output

@lru_cache(maxsize=128)
def _cached_rdap_lookup(domain: str, time_bucket: int) -> dict:
    # Domain metadata is cached briefly; actual network timeouts are controlled
    # by rdapHelper.lookup_rdap and must be verified in that module.
    try:
        return lookup_rdap(domain)
    except Exception as exc:
        # Cache transient failures too, avoiding repeated lookups for the same host.
        return {"success": False, "error": str(exc)}


def analyze_sender_rdap(domain: str, analysis_results):
    normalized = _normalized_dns_domain(domain)
    if normalized is None:
        return None

    try:
        rdap = _cached_rdap_lookup(normalized, int(monotonic() // 300))
    except Exception as exc:
        rdap = {"success": False, "error": str(exc)}

    if not isinstance(rdap, dict) or not rdap.get("success"):
        add_finding(
            analysis_results,
            category=Category.METADATA,
            code=Code.WHOIS_LOOKUP_FAILED,
            severity=Severity.LOW,
            message=f"WHOIS lookup failed for domain {normalized}",
            error=rdap.get("error") if isinstance(rdap, dict) else "Invalid RDAP response",
        )
        return None

    add_finding(
        analysis_results,
        category=Category.METADATA,
        code=Code.WHOIS_BASIC_INFO,
        severity=Severity.INFO,
        message=f"WHOIS data for {normalized}",
        registrar=rdap.get("registrar"),
        creation_date=rdap.get("creation_date"),
        expiration_date=rdap.get("expiration_date"),
    )

    return rdap
