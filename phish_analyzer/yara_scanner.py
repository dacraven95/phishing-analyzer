"""
YARA Rule Scanner
Loads and runs YARA rules against email bodies and attachments.
"""
from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, field

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

RULES_DIR = Path(__file__).resolve().parent / "yara_rules"


@dataclass
class YaraMatch:
    rule_name:    str
    severity:     str
    category:     str
    description:  str
    attack_ids:   List[str] = field(default_factory=list)
    kit_name:     Optional[str] = None
    matched_strings: List[str] = field(default_factory=list)
    target:       str = ""  # what was scanned: "html_body", "attachment:foo.pdf", etc.


# Cache compiled rules so we only compile once per process
_COMPILED_RULES = None


def _load_compiled_rules() -> Optional["yara.Rules"]:
    """
    Compile every .yar file in the rules directory into one ruleset.
    Safe to call many times — uses module-level cache.
    Returns None if YARA is not available or no rules were found.
    """
    global _COMPILED_RULES

    if not YARA_AVAILABLE:
        return None

    if _COMPILED_RULES is not None:
        return _COMPILED_RULES

    if not RULES_DIR.exists():
        return None

    rule_files = list(RULES_DIR.glob("*.yar")) + list(RULES_DIR.glob("*.yara"))
    if not rule_files:
        return None

    filepaths = {f.stem: str(f) for f in rule_files}

    try:
        _COMPILED_RULES = yara.compile(filepaths=filepaths)
    except yara.SyntaxError as e:
        print(f"[!] YARA rule compilation failed: {e}")
        return None

    return _COMPILED_RULES


def _parse_match_meta(match) -> dict:
    """Normalize a YARA match's metadata into a plain dict."""
    meta = {}
    for k, v in match.meta.items():
        meta[k] = v
    return meta


def scan_bytes(data: bytes, target_label: str = "unknown") -> List[YaraMatch]:
    """
    Scan a byte buffer against all compiled YARA rules.
    target_label is just a human-readable label for what was scanned
    (e.g. 'html_body', 'attachment:invoice.pdf').
    """
    if not YARA_AVAILABLE or not data:
        return []

    rules = _load_compiled_rules()
    if rules is None:
        return []

    try:
        raw_matches = rules.match(data=data, timeout=10)
    except Exception as e:
        print(f"[!] YARA scan error on {target_label}: {e}")
        return []

    results: List[YaraMatch] = []
    for m in raw_matches:
        meta = _parse_match_meta(m)
        attack_ids_str = meta.get("attack_ids", "")
        attack_ids = [a.strip() for a in attack_ids_str.split(",") if a.strip()] \
                     if attack_ids_str else []

        matched_strings = []
        for ms in m.strings[:5]:  # cap evidence to first 5 matches
            try:
                # yara-python 4.3+ returns StringMatch objects
                for instance in ms.instances[:2]:
                    snippet = instance.matched_data[:80]
                    matched_strings.append(
                        snippet.decode("utf-8", errors="replace")
                    )
            except AttributeError:
                # Older yara-python API
                matched_strings.append(str(ms)[:80])

        results.append(YaraMatch(
            rule_name=m.rule,
            severity=meta.get("severity", "medium"),
            category=meta.get("category", "uncategorized"),
            description=meta.get("description", ""),
            attack_ids=attack_ids,
            kit_name=meta.get("kit_name"),
            matched_strings=matched_strings,
            target=target_label,
        ))

    return results


def scan_email_components(
    plain_body:  Optional[str],
    html_body:   Optional[str],
    attachments: Optional[list],
) -> List[YaraMatch]:
    """
    Scan all the parts of an email against the YARA ruleset.
    Returns a combined list of matches.
    """
    all_matches: List[YaraMatch] = []

    if plain_body:
        all_matches.extend(
            scan_bytes(plain_body.encode("utf-8", errors="replace"), "plain_body")
        )

    if html_body:
        all_matches.extend(
            scan_bytes(html_body.encode("utf-8", errors="replace"), "html_body")
        )

    for att in (attachments or []):
        payload = att.get("payload")
        if not payload:
            continue
        label = f"attachment:{att.get('filename', 'unknown')}"
        all_matches.extend(scan_bytes(payload, label))

    return all_matches


def format_yara_output(matches: List[YaraMatch], colors: dict) -> str:
    """
    Generate terminal output block for YARA matches.
    """
    CYAN         = colors.get("CYAN", "")
    YELLOW       = colors.get("YELLOW", "")
    RED          = colors.get("RED", "")
    BRIGHT_RED   = colors.get("BRIGHT_RED", "")
    BRIGHT_GREEN = colors.get("BRIGHT_GREEN", "")
    RESET        = colors.get("RESET", "")

    lines = [f"{CYAN}=== YARA Rule Matches ==={RESET}"]

    if not YARA_AVAILABLE:
        lines.append(f"{YELLOW}[*] YARA not installed — skipping rule scanning{RESET}")
        lines.append(f"    Install with: pip install yara-python")
        lines.append("")
        return "\n".join(lines)

    if not matches:
        lines.append(f"{BRIGHT_GREEN}[+] No YARA rule matches{RESET}")
        lines.append("")
        return "\n".join(lines)

    # Group by severity for display
    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_matches = sorted(
        matches,
        key=lambda m: SEVERITY_ORDER.get(m.severity.lower(), 99)
    )

    lines.append(f"{BRIGHT_RED}[!] {len(matches)} YARA rule match(es){RESET}")
    lines.append("")

    for match in sorted_matches:
        sev_upper = match.severity.upper()
        sev_color = {
            "CRITICAL": BRIGHT_RED,
            "HIGH":     RED,
            "MEDIUM":   YELLOW,
            "LOW":      YELLOW,
        }.get(sev_upper, RESET)

        lines.append(f"  {sev_color}[{sev_upper}] {match.rule_name}{RESET}")
        lines.append(f"      Target:      {match.target}")
        lines.append(f"      Category:    {match.category}")
        if match.description:
            lines.append(f"      Description: {match.description}")
        if match.kit_name:
            lines.append(f"      Kit:         {match.kit_name}")
        if match.attack_ids:
            lines.append(f"      ATT&CK:      {', '.join(match.attack_ids)}")
        if match.matched_strings:
            preview = match.matched_strings[0]
            lines.append(f"      Evidence:    {preview[:100]}")
        lines.append("")

    return "\n".join(lines)