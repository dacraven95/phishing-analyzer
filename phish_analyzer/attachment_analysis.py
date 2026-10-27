"""Attachment signature, PDF, archive, and script analysis."""
from __future__ import annotations
import hashlib
import io
import math
import mimetypes
import re
import zipfile
from pathlib import Path
from typing import Dict, List, Tuple
try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None
from .analysis_models import Finding
MAX_DEEP_SCAN_BYTES = 12 * 1024 * 1024

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

RLO_CHARS = {"\u202E", "\u202D", "\u2066", "\u2067", "\u2068", "\u2069"}

SVG_BLOCK_RE = re.compile(r"<svg\b.*?</svg>", flags=re.I | re.S)

SCRIPT_BLOCK_RE = re.compile(r"<script\b.*?</script>", flags=re.I | re.S)

BASE64_LONG_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")

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
    
    # Quick raw scan (cheap, catches many malicious PDFs even if parsing fails)
    raw_head = data[:500_000].lower()
    if b"/javascript" in raw_head or b"/js" in raw_head:
        findings.append(Finding("pdf_javascript_raw", 40,
                                "PDF contains JavaScript markers (raw scan), which may execute on open."))

    if b"/openaction" in raw_head or b"/aa" in raw_head:
        findings.append(Finding("pdf_auto_action_raw", 45,
                                "PDF contains auto-action markers (OpenAction/AA) that can trigger behavior on open."))

    # Deep parse is optional: missing pypdf is a scanner configuration issue,
    # not evidence that the attachment itself is suspicious.
    if PdfReader is None:
        findings.append(Finding("pdf_parser_unavailable", 0,
                                "PDF deep inspection unavailable: install the pypdf dependency."))
        return findings

    if len(data) > MAX_DEEP_SCAN_BYTES:
        findings.append(Finding("pdf_deep_scan_skipped", 0,
                                "PDF exceeds the deep-inspection size limit."))
        return findings

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

    visited_objects: set[int] = set()

    def walk_obj(obj, depth=0):
        # Limit cyclic references, recursion depth, and total traversal work.
        if depth > 20 or len(visited_objects) >= 2000:
            return
        obj_id = id(obj)
        if obj_id in visited_objects:
            return
        visited_objects.add(obj_id)
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
    if magic == "zip" and len(data) <= MAX_DEEP_SCAN_BYTES:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                names = []
                for idx, member in enumerate(z.infolist()):
                    if idx >= 2000:
                        findings.append(Finding("zip_scan_limited", 0,
                                                "ZIP contains more entries than the inspection limit."))
                        break
                    names.append(member.filename.lower())

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

        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError):
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

def get_attachment_hashes(file_bytes: bytes) -> dict:
    return {
        "md5":      hashlib.md5(file_bytes).hexdigest(),
        "sha1":     hashlib.sha1(file_bytes).hexdigest(),
        "sha256":   hashlib.sha256(file_bytes).hexdigest(),
    }

