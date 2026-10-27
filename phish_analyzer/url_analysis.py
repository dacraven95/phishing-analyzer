"""Local-only URL and hostname analysis. No links are requested or followed."""
from __future__ import annotations
import ipaddress
import re
from html import unescape
from html.parser import HTMLParser
from urllib.parse import parse_qs, unquote, urlparse, urlunparse
from typing import List
from .analysis_models import Category, Severity, Code, Finding, add_finding

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

CYRILLIC_RE = re.compile(r'[\u0400-\u04FF]')

LATIN_RE = re.compile(r'[A-Za-z]')

CYRILLIC_LOOKALIKES = {
    'а': 'a',  # Cyrillic small a
    'А': 'A',
    'е': 'e',
    'Е': 'E',
    'о': 'o',
    'О': 'O',
    'р': 'p',
    'Р': 'P',
    'с': 'c',
    'С': 'C',
    'х': 'x',
    'Х': 'X',
    'у': 'y',
    'У': 'Y',
    'і': 'i',
    'І': 'I',
    'ј': 'j',
    'Ј': 'J',
    'ѕ': 's',
    'ԁ': 'd',
    'Ԍ': 'G',
    'գ': 'g',
    'ҡ': 'k',
    'Կ': 'K',
    'м': 'm',
    'М': 'M',
    'т': 't',
    'Т': 'T',
    'в': 'b',
    'В': 'B',
    'н': 'h',
    'Н': 'H',
    'к': 'k',
    'К': 'K',
}

TRUSTED_BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "office365.com",
                  "live.com", "outlook.com", "sharepoint.com", "onmicrosoft.com"},
    "google": {"google.com", "gmail.com", "googleusercontent.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazonaws.com"},
    "bankofamerica": {"bankofamerica.com"},
    "chase": {"chase.com", "jpmorganchase.com"},
    "wellsfargo": {"wellsfargo.com"},
}

BRAND_ALIASES = {"office365": "microsoft", "outlook": "microsoft"}

SHORTENER_HOSTS = frozenset({"bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd",
                            "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at"})

REDIRECT_PARAMETERS = frozenset({"redirect", "redirect_uri", "redirect_url", "url",
                                  "target", "destination", "dest", "continue", "next", "return_url"})

def contains_cyrillic(text: str) -> bool:
    return bool(CYRILLIC_RE.search(text))

def contains_latin(text: str) -> bool:
    return bool(LATIN_RE.search(text))

def decode_idn(domain: str) -> str:
    """
    Decode a punycode/IDN domain if possible.
    If decoding fails, return the original string.
    """
    try:
        return domain.encode("ascii").decode("idna")
    except Exception:
        return domain

def normalize_homoglyphs(text: str) -> str:
    """
    Replace known Cyrillic homoglyphs with Latin lookalikes.
    """
    return ''.join(CYRILLIC_LOOKALIKES.get(ch, ch) for ch in text)

def highlight_homoglyphs(domain: str) -> str:
    return ''.join(
        f"{ch}({CYRILLIC_LOOKALIKES.get(ch, '?')})"
        if ch in CYRILLIC_LOOKALIKES
        else ch
        for ch in domain
    )

def detect_cyrillic_homoglyph_domain(domain: str) -> List["Finding"]:
    findings: List["Finding"] = []

    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return findings

    try:
        decoded_domain = domain.encode("ascii").decode("idna")
    except Exception:
        decoded_domain = domain

    has_cyrillic = bool(CYRILLIC_RE.search(decoded_domain))
    has_latin = bool(LATIN_RE.search(decoded_domain))

    # 🔍 Extract exact Cyrillic characters found
    cyrillic_chars = sorted(set(ch for ch in decoded_domain if CYRILLIC_RE.match(ch)))

    # Map to Latin lookalikes if possible
    char_mappings = [
        f"{ch}→{CYRILLIC_LOOKALIKES.get(ch, '?')}"
        for ch in cyrillic_chars
    ]

    is_punycode = any(part.startswith("xn--") for part in domain.split("."))

    if is_punycode:
        findings.append(Finding(
            "punycode_domain",
            30,
            "Domain uses IDN/punycode encoding (possible spoofing)",
            evidence=f"{domain} -> {decoded_domain}"
        ))
    
    if has_cyrillic:
        highlighted = highlight_homoglyphs(decoded_domain)
        findings.append(Finding(
            "cyrillic_characters_detected",
            35 if has_latin else 20,
            "Domain contains Cyrillic characters",
            evidence=highlighted
        ))

    if has_cyrillic and has_latin:
        findings.append(Finding(
            "mixed_script_domain",
            40,
            "Domain contains mixed Latin and Cyrillic characters (possible homoglyph attack)",
            evidence=decoded_domain
        ))

    return findings

class HrefExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for name, value in attrs:
                if name.lower() == "href" and value:
                    self.hrefs.append(value)

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
    Normalize an HTTP(S) URL without treating relative paths or unsupported
    schemes as network destinations. Preserve its path and query for analysis.
    """
    if not isinstance(url, str) or not url:
        return None

    url = url.strip().rstrip(").,;\"'")
    # A terminal ']' may close a literal IPv6 host, not punctuation.
    if url.endswith("]") and not re.fullmatch(r"https?://\[[^]]+\]", url, re.IGNORECASE):
        url = url.rstrip("]")
    if not url or len(url) > 8192 or any(ord(ch) < 32 for ch in url):
        return None

    if url.startswith("//"):
        url = "https:" + url
    elif url.lower().startswith("www."):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return None
        if not parsed.hostname or parsed.port is not None and not 1 <= parsed.port <= 65535:
            return None
        # Guard against malformed host labels and invalid IPv6 bracket syntax.
        if any(ch.isspace() for ch in parsed.hostname):
            return None
    except ValueError:
        return None

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    return urlunparse((scheme, netloc, parsed.path or "/", parsed.params, parsed.query, ""))

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

def _host_matches_root(host: str, root: str) -> bool:
    """Label-boundary comparison; paypal.com.evil.test is never paypal.com."""
    return host == root or host.endswith("." + root)

def _normalized_host(host: str) -> str:
    try:
        return (host or "").rstrip(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return ""

def _same_domain_family(first: str | None, second: str | None) -> bool:
    """Conservative relationship; not an eTLD+1 or DMARC relaxed-alignment test."""
    left = _normalized_host(first or "")
    right = _normalized_host(second or "")
    return bool(left and right and (_host_matches_root(left, right) or _host_matches_root(right, left)))

def _is_close_brand_label(label: str, brand: str) -> bool:
    """Detect common single-character brand typos without broad fuzzy matching."""
    if len(brand) < 6 or abs(len(label) - len(brand)) > 1:
        return False
    if label == brand:
        return True
    if len(label) == len(brand):
        differences = [i for i, (a, b) in enumerate(zip(label, brand)) if a != b]
        if len(differences) == 1:
            return True
        if len(differences) == 2:
            a, b = differences
            return b == a + 1 and label[a] == brand[b] and label[b] == brand[a]
        return False
    # One added or removed character (e.g. microsofft.com).
    shorter, longer = sorted((label, brand), key=len)
    i = j = edits = 0
    while i < len(shorter) and j < len(longer):
        if shorter[i] == longer[j]:
            i += 1
        else:
            edits += 1
            if edits > 1:
                return False
        j += 1
    return True

def _brand_spoof_targets(host: str) -> list[str]:
    """Find brand labels on hosts that aren't under that brand's curated root."""
    ascii_host = _normalized_host(host)
    unicode_host = decode_idn(ascii_host).lower()
    labels = re.split(r"[.\-_]", unicode_host)
    joined = unicode_host.replace("-", "").replace("_", "")
    matches = []
    for brand, roots in TRUSTED_BRAND_DOMAINS.items():
        aliases = (brand,) + tuple(k for k, v in BRAND_ALIASES.items() if v == brand)
        if any(_host_matches_root(ascii_host, root) for root in roots):
            continue
        if any(alias in joined for alias in aliases) or any(
            (normalize_homoglyphs(label) in aliases or
             any(_is_close_brand_label(normalize_homoglyphs(label), alias) for alias in aliases))
            for label in labels
        ):
            matches.append(brand)
    return matches

def analyze_url(url: str, analysis_results) -> dict:
    """Assess a URL locally; do not connect to or resolve its destination."""
    normalized = normalize_url(url)
    if normalized is None:
        return {"url": url, "domain": "", "flags": ["INVALID_URL"], "score": 0}
    parsed = urlparse(normalized)
    host = _normalized_host(parsed.hostname or "")
    flags: list[str] = []
    signals: list[tuple[str, int]] = []

    def flag(name: str, points: int, code: Code | None = None,
             severity: Severity = Severity.MEDIUM, message: str = "") -> None:
        flags.append(name)
        if points:
            signals.append((name, points))
        if code is not None:
            add_finding(analysis_results, Category.URLs, code, severity,
                        message or name, url=normalized, signal_weight=points)

    if is_ip_literal_url(normalized):
        flag("IP_LITERAL", 42, Code.URL_IP_LITERAL, Severity.HIGH, "Link uses a literal IP address")
    if parsed.username is not None or parsed.password is not None:
        flag("URL_USERINFO", 55, Code.URL_USERINFO, Severity.HIGH,
             "Link contains an @-userinfo prefix that can hide its actual host")
    if parsed.port is not None and parsed.port not in {80, 443}:
        flag("UNUSUAL_PORT", 12, Code.URL_UNUSUAL_PORT, Severity.LOW,
             "Link uses a nonstandard web port")
    # TLD popularity is weak evidence, not proof of maliciousness.
    if host.split(".")[-1] in SUSPICIOUS_TLDS:
        flag("SUSPICIOUS_TLD", 6, Code.URL_SUSPICIOUS_TLD, Severity.LOW,
             "Link has a TLD sometimes abused in phishing; this alone is weak evidence")
    if any(label.startswith("xn--") for label in host.split(".")):
        decoded = decode_idn(host)
        flag("PUNYCODE_DOMAIN", 10, Code.URL_PUNYCODE, Severity.LOW,
             f"Internationalized domain encoding: {decoded}")
        if contains_cyrillic(decoded) and contains_latin(decoded):
            flag("MIXED_SCRIPT", 38, Code.URL_MIXED_SCRIPT, Severity.HIGH,
                 "Link mixes Latin and Cyrillic characters within its hostname")
    if parsed.scheme == "http":
        flag("PLAIN_HTTP", 3)
    path_query = unquote(parsed.path + "?" + parsed.query).lower()[:4096]
    found_keywords = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if re.search(
        r"(?<![a-z])" + re.escape(kw) + r"(?![a-z])", path_query)]
    if found_keywords:
        flag("SUSPICIOUS_PATH_KEYWORDS", 5, Code.URL_SUSPICIOUS_PATH, Severity.LOW,
             "Login/account vocabulary appears in URL path or query (weak signal)")
    if sum(looks_random_segment(segment) for segment in parsed.path.split("/") if segment) >= 2:
        flag("OBFUSCATED_PATH", 17, Code.URL_OBFUSCATED_PATH, Severity.MEDIUM,
             "URL contains multiple random-looking path segments")
    for brand in _brand_spoof_targets(host):
        flag(f"BRAND_IMPERSONATION_{brand.upper()}", 65, Code.URL_BRAND_IMPERSONATION,
             Severity.HIGH, f"Host appears to impersonate {brand}, but is not under its recognized domains")
    if host in SHORTENER_HOSTS:
        flag("URL_SHORTENER", 8, Code.URL_SHORTENER, Severity.LOW,
             "URL uses a known shortening service (destination not followed)")
    try:
        parameters = parse_qs(parsed.query, keep_blank_values=False, max_num_fields=100)
    except ValueError:
        # An oversized query is suspicious but must not crash the analysis.
        parameters = {}
        flag("EXCESSIVE_QUERY_PARAMS", 8)
    for parameter, values in parameters.items():
        if parameter.lower() not in REDIRECT_PARAMETERS:
            continue
        for value in values[:4]:
            candidate = normalize_url(unquote(value[:4096]))
            if candidate and not _same_domain_family(host, urlparse(candidate).hostname):
                flag("EXTERNAL_REDIRECT", 25, Code.URL_EXTERNAL_REDIRECT, Severity.MEDIUM,
                     "URL includes a redirect parameter pointing to another domain")
                break
        if "EXTERNAL_REDIRECT" in flags:
            break
    # Sum capped independent URL evidence; 3+ unrelated indicators increase confidence.
    score = min(100, max((weight for _, weight in signals), default=0)
                + min(32, sum(sorted((weight for _, weight in signals), reverse=True)[1:3]) // 2))
    return {"url": normalized, "domain": host, "flags": flags, "score": score}

class _VisibleLinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            self._href = next((v for k, v in attrs if k.lower() == "href" and v), None)
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None
            self._text = []

def analyze_displayed_links(html_body: str | None, analysis_results: list[dict]) -> list[dict]:
    """Compare a visible URL in anchor text with the actual href, never fetching either."""
    if not html_body:
        return []
    parser = _VisibleLinkExtractor()
    try:
        parser.feed(html_body[:1_000_000])
    except (ValueError, AssertionError):
        return []
    result: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for href, visible in parser.links[:500]:
        target = normalize_url(href)
        visible_text = unescape(visible).strip()
        candidate = URL_REGEX.search(visible_text)
        shown = normalize_url(candidate.group(1)) if candidate else None
        # Some phishing anchors show a bare domain without https:// or www.
        if shown is None and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,24}/?", visible_text):
            shown = normalize_url("https://" + visible_text)
        if not target or not shown:
            continue
        host = _normalized_host(urlparse(target).hostname or "")
        shown_host = _normalized_host(urlparse(shown).hostname or "")
        if not host or not shown_host or _same_domain_family(host, shown_host):
            continue
        key = (shown_host, host)
        if key in seen:
            continue
        seen.add(key)
        add_finding(analysis_results, Category.URLs, Code.URL_LINK_TEXT_MISMATCH,
                    Severity.HIGH, "Displayed link domain differs from actual destination",
                    displayed_domain=shown_host, actual_domain=host, url=target,
                    signal_weight=75)
        result.append({"url": target, "domain": host,
                       "flags": ["LINK_TEXT_MISMATCH"], "score": 75})
    return result

