"""
MITRE ATT&CK Technique Mapping
Maps internal finding codes to MITRE ATT&CK techniques for SOC-friendly output.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List, Dict


@dataclass
class AttackTechnique:
    id:            str          # e.g. "T1566.002"
    name:          str          # e.g. "Spearphishing Link"
    tactic:        str          # e.g. "Initial Access"
    url:           str          # link to the MITRE page
    description:   str          # one-line description for output
    sub_technique: bool = False


# ---------------------------------------------------------------------------
# The technique catalog
# Each technique referenced below is defined here once and reused.
# ---------------------------------------------------------------------------

ATTACK_CATALOG: Dict[str, AttackTechnique] = {
    "T1566": AttackTechnique(
        id="T1566",
        name="Phishing",
        tactic="Initial Access",
        url="https://attack.mitre.org/techniques/T1566/",
        description="Adversaries send phishing messages to gain access to victim systems.",
    ),
    "T1566.001": AttackTechnique(
        id="T1566.001",
        name="Spearphishing Attachment",
        tactic="Initial Access",
        url="https://attack.mitre.org/techniques/T1566/001/",
        description="Phishing with a malicious file attachment.",
        sub_technique=True,
    ),
    "T1566.002": AttackTechnique(
        id="T1566.002",
        name="Spearphishing Link",
        tactic="Initial Access",
        url="https://attack.mitre.org/techniques/T1566/002/",
        description="Phishing with a malicious link in the email body.",
        sub_technique=True,
    ),
    "T1566.003": AttackTechnique(
        id="T1566.003",
        name="Spearphishing via Service",
        tactic="Initial Access",
        url="https://attack.mitre.org/techniques/T1566/003/",
        description="Phishing delivered through third-party services.",
        sub_technique=True,
    ),
    "T1598": AttackTechnique(
        id="T1598",
        name="Phishing for Information",
        tactic="Reconnaissance",
        url="https://attack.mitre.org/techniques/T1598/",
        description="Adversaries send messages to elicit sensitive information.",
    ),
    "T1598.002": AttackTechnique(
        id="T1598.002",
        name="Spearphishing Attachment",
        tactic="Reconnaissance",
        url="https://attack.mitre.org/techniques/T1598/002/",
        description="Credential/info harvesting via attachment.",
        sub_technique=True,
    ),
    "T1598.003": AttackTechnique(
        id="T1598.003",
        name="Spearphishing Link",
        tactic="Reconnaissance",
        url="https://attack.mitre.org/techniques/T1598/003/",
        description="Credential/info harvesting via link.",
        sub_technique=True,
    ),
    "T1204": AttackTechnique(
        id="T1204",
        name="User Execution",
        tactic="Execution",
        url="https://attack.mitre.org/techniques/T1204/",
        description="Adversaries rely on a user to open a file or follow a link.",
    ),
    "T1204.001": AttackTechnique(
        id="T1204.001",
        name="Malicious Link",
        tactic="Execution",
        url="https://attack.mitre.org/techniques/T1204/001/",
        description="User is tricked into clicking a malicious link.",
        sub_technique=True,
    ),
    "T1204.002": AttackTechnique(
        id="T1204.002",
        name="Malicious File",
        tactic="Execution",
        url="https://attack.mitre.org/techniques/T1204/002/",
        description="User is tricked into opening a malicious file.",
        sub_technique=True,
    ),
    "T1036": AttackTechnique(
        id="T1036",
        name="Masquerading",
        tactic="Defense Evasion",
        url="https://attack.mitre.org/techniques/T1036/",
        description="Adversaries disguise objects to appear legitimate.",
    ),
    "T1036.005": AttackTechnique(
        id="T1036.005",
        name="Match Legitimate Name or Location",
        tactic="Defense Evasion",
        url="https://attack.mitre.org/techniques/T1036/005/",
        description="Filenames, extensions, or paths mimic legitimate ones.",
        sub_technique=True,
    ),
    "T1027": AttackTechnique(
        id="T1027",
        name="Obfuscated Files or Information",
        tactic="Defense Evasion",
        url="https://attack.mitre.org/techniques/T1027/",
        description="Adversaries obfuscate content to hinder analysis.",
    ),
    "T1059": AttackTechnique(
        id="T1059",
        name="Command and Scripting Interpreter",
        tactic="Execution",
        url="https://attack.mitre.org/techniques/T1059/",
        description="Scripts used to execute commands and payloads.",
    ),
    "T1059.001": AttackTechnique(
        id="T1059.001",
        name="PowerShell",
        tactic="Execution",
        url="https://attack.mitre.org/techniques/T1059/001/",
        description="PowerShell scripts used for execution or payload delivery.",
        sub_technique=True,
    ),
    "T1059.005": AttackTechnique(
        id="T1059.005",
        name="Visual Basic",
        tactic="Execution",
        url="https://attack.mitre.org/techniques/T1059/005/",
        description="VBScript or VBA macros used for execution.",
        sub_technique=True,
    ),
    "T1059.007": AttackTechnique(
        id="T1059.007",
        name="JavaScript",
        tactic="Execution",
        url="https://attack.mitre.org/techniques/T1059/007/",
        description="JavaScript used for execution or payload staging.",
        sub_technique=True,
    ),
    "T1137": AttackTechnique(
        id="T1137",
        name="Office Application Startup",
        tactic="Persistence",
        url="https://attack.mitre.org/techniques/T1137/",
        description="Office macros abused for execution or persistence.",
    ),
    "T1137.001": AttackTechnique(
        id="T1137.001",
        name="Office Template Macros",
        tactic="Persistence",
        url="https://attack.mitre.org/techniques/T1137/001/",
        description="Malicious macros in Office documents.",
        sub_technique=True,
    ),
    "T1586": AttackTechnique(
        id="T1586",
        name="Compromise Accounts",
        tactic="Resource Development",
        url="https://attack.mitre.org/techniques/T1586/",
        description="Adversaries compromise legitimate accounts for operations.",
    ),
    "T1586.002": AttackTechnique(
        id="T1586.002",
        name="Email Accounts",
        tactic="Resource Development",
        url="https://attack.mitre.org/techniques/T1586/002/",
        description="Compromised email accounts used for phishing operations.",
        sub_technique=True,
    ),
    "T1656": AttackTechnique(
        id="T1656",
        name="Impersonation",
        tactic="Defense Evasion",
        url="https://attack.mitre.org/techniques/T1656/",
        description="Adversaries impersonate trusted entities to gain access.",
    ),
    "T1583.001": AttackTechnique(
        id="T1583.001",
        name="Acquire Infrastructure: Domains",
        tactic="Resource Development",
        url="https://attack.mitre.org/techniques/T1583/001/",
        description="Adversaries register domains to support operations (including lookalike domains).",
        sub_technique=True,
    ),
    "T1534": AttackTechnique(
        id="T1534",
        name="Internal Spearphishing",
        tactic="Lateral Movement",
        url="https://attack.mitre.org/techniques/T1534/",
        description="Adversaries use compromised internal accounts to phish colleagues.",
    ),
}


# ---------------------------------------------------------------------------
# The mapping layer
# Maps your internal finding codes (from Code enum + social engineering + 
# attachment findings) to MITRE technique IDs.
# ---------------------------------------------------------------------------

FINDING_TO_ATTACK: Dict[str, List[str]] = {
    # --- SPF / DKIM / DMARC failures — spoofing indicators ---
    "SPF_FAIL":                    ["T1566", "T1656"],
    "SPF_SOFTFAIL":                ["T1566", "T1656"],
    "DKIM_FAIL":                   ["T1566", "T1656"],
    "DKIM_MISSING":                ["T1566"],
    "DMARC_FAIL":                  ["T1566", "T1656"],
    "DMARC_NONE":                  ["T1566"],

    # --- Header anomalies ---
    "CROSSTENANT_PRESENT":         ["T1534"],
    "FROM_REPLYTO_MISMATCH":       ["T1656", "T1566"],
    "FROM_RETURNPATH_MISMATCH":    ["T1656", "T1566"],
    "MISSING_HEADER":              ["T1566"],

    # --- URL-based findings ---
    "URL_IP_LITERAL":              ["T1566.002", "T1204.001"],
    "URL_SUSPICIOUS_TLD":          ["T1566.002"],
    "URL_PUNYCODE":                ["T1566.002", "T1036"],
    "URL_BRAND_IMPERSONATION":     ["T1566.002", "T1656", "T1583.001"],
    "URL_OBFUSCATED_PATH":         ["T1566.002", "T1027"],
    "URL_SUSPICIOUS_PATH":         ["T1566.002", "T1598.003"],

    # --- Domain findings ---
    "cyrillic_characters_detected":["T1036", "T1583.001"],
    "mixed_script_domain":         ["T1036", "T1583.001"],
    "punycode_domain":             ["T1036", "T1583.001"],

    # --- Attachment findings (finding.code from analyze_attachment_bytes) ---
    "risky_extension":             ["T1566.001", "T1204.002"],
    "multi_extension":              ["T1566.001", "T1036.005", "T1204.002"],
    "unicode_direction_override":  ["T1036.005", "T1566.001"],
    "magic_type":                   [],  # informational
    "mime_mismatch":                ["T1036", "T1566.001"],
    "office_macro":                ["T1566.001", "T1204.002", "T1137.001", "T1059.005"],
    "zip_dangerous_members":       ["T1566.001", "T1204.002"],
    "zip_parse_fail":              ["T1027", "T1566.001"],
    "html_credential_form":        ["T1566.001", "T1598.002"],
    "html_redirect":               ["T1566.001", "T1204.001"],
    "html_script":                 ["T1566.001", "T1059.007"],
    "html_data_uri":               ["T1027", "T1566.001"],
    "html_inline_svg":             ["T1566.001"],
    "svg_script":                  ["T1566.001", "T1059.007"],
    "svg_base64_decode":           ["T1027"],
    "svg_eval":                    ["T1059.007", "T1027"],
    "svg_xor_decrypt":             ["T1027"],
    "svg_long_base64_blob":        ["T1027"],
    "html_svg_weaponized":         ["T1566.001", "T1059.007", "T1027"],
    "possible_obfuscation":        ["T1027"],
    "ps_invoke_expression":        ["T1059.001"],
    "high_entropy":                ["T1027"],
    "pdf_javascript_raw":          ["T1566.001", "T1059.007"],
    "pdf_javascript":              ["T1566.001", "T1059.007"],
    "pdf_auto_action":             ["T1566.001", "T1204.002"],
    "pdf_auto_action_raw":         ["T1566.001", "T1204.002"],
    "pdf_launch":                  ["T1566.001", "T1204.002"],
    "pdf_external_uri":            ["T1566.002", "T1204.001"],
    "pdf_embedded_file":           ["T1566.001", "T1027"],
    "pdf_forms":                   ["T1598.002"],
    "pdf_encrypted":               ["T1027"],
    "pdf_parse_fail":              ["T1027"],
    "pdf_urls_found":              ["T1566.002"],

    # --- Social engineering cluster mappings ---
    "SE_Urgency":                  ["T1566"],
    "SE_Fear":                     ["T1566"],
    "SE_Authority":                ["T1656", "T1566"],
    "SE_Artificial Deadline":      ["T1566"],
    "SE_Reward / Enticement":      ["T1566"],
    "SE_Credential Harvesting":    ["T1566.002", "T1598.003"],
    "SE_Secrecy / Isolation":      ["T1566"],
    "SE_Impersonation Signal":     ["T1656"],
    "SE_Psychological Pressure":   ["T1566"],
    "SE_Obfuscation / Evasion Language": ["T1566", "T1027"],
    "SE_Financial Manipulation":   ["T1566", "T1598"],
    "SE_Personal Information Harvesting": ["T1598", "T1566.002"],
    "SE_Technical Deception":      ["T1566", "T1656"],
}


# ---------------------------------------------------------------------------
# The main API
# ---------------------------------------------------------------------------

def map_finding_to_techniques(finding_code: str) -> List[AttackTechnique]:
    """
    Given an internal finding code, return the list of ATT&CK techniques
    it maps to. Returns empty list if the code is not mapped.
    """

    if finding_code in ATTACK_CATALOG:
        return [ATTACK_CATALOG[finding_code]]

    technique_ids = FINDING_TO_ATTACK.get(finding_code, [])
    return [ATTACK_CATALOG[tid] for tid in technique_ids if tid in ATTACK_CATALOG]


def summarize_attack_coverage(finding_codes: List[str]) -> Dict[str, List[str]]:
    """
    Given a list of finding codes from an analysis, return a dict of
    {tactic_name: [technique_id strings]} showing the overall ATT&CK
    coverage for this email.
    """
    tactic_map: Dict[str, set] = {}

    for code in finding_codes:
        for technique in map_finding_to_techniques(code):
            tactic_map.setdefault(technique.tactic, set()).add(
                f"{technique.id} ({technique.name})"
            )

    # Convert sets to sorted lists for stable output
    return {tactic: sorted(list(techs)) for tactic, techs in tactic_map.items()}


def format_attack_output(finding_codes: List[str], colors: dict) -> str:
    """
    Generate the terminal output block showing ATT&CK coverage.
    """
    CYAN         = colors.get("CYAN", "")
    YELLOW       = colors.get("YELLOW", "")
    BRIGHT_RED   = colors.get("BRIGHT_RED", "")
    BRIGHT_GREEN = colors.get("BRIGHT_GREEN", "")
    RESET        = colors.get("RESET", "")

    coverage = summarize_attack_coverage(finding_codes)

    lines = [f"{CYAN}=== MITRE ATT&CK Coverage ==={RESET}"]

    if not coverage:
        lines.append(f"{BRIGHT_GREEN}[+] No ATT&CK techniques identified from findings{RESET}")
        lines.append("")
        return "\n".join(lines)

    total_techniques = sum(len(techs) for techs in coverage.values())
    lines.append(
        f"{BRIGHT_RED}[!] {total_techniques} technique(s) across "
        f"{len(coverage)} tactic(s){RESET}"
    )
    lines.append("")

    # Sort tactics by ATT&CK kill chain order
    TACTIC_ORDER = [
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact",
    ]

    def tactic_sort_key(name: str) -> int:
        try:
            return TACTIC_ORDER.index(name)
        except ValueError:
            return 999

    for tactic in sorted(coverage.keys(), key=tactic_sort_key):
        lines.append(f"  {YELLOW}{tactic}{RESET}")
        for technique_str in coverage[tactic]:
            lines.append(f"      - {technique_str}")
        lines.append("")

    return "\n".join(lines)