"""Heuristic risk assessment, independent of output transports."""
from __future__ import annotations
from typing import Any, Callable
from .analysis_models import Code
from .colors import BRIGHT_RED, RED, YELLOW, BRIGHT_GREEN, CYAN, RESET

def _risk_label(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"

def build_risk_assessment(*, findings: list[dict[str, Any]], url_analysis: list[dict],
                          auth: dict[str, Any], se_score: int,
                          attachment_scores: list[int], yara_count: int,
                          sender_score: int, limitations: list[str]) -> dict[str, Any]:
    """Deterministic and conservative HEURISTIC, not a calibrated probability.

    Correlated evidence is capped per category. Never score unverified headers,
    benign WHOIS lookup failures, or mere re-observation of historical IOCs.
    """
    url_scores = sorted((int(item.get("score", 0)) for item in url_analysis), reverse=True)
    url_score = min(100, (url_scores[0] if url_scores else 0)
                    + min(15, sum(url_scores[1:3]) // 5))
    attachment_score = max(attachment_scores, default=0)
    if yara_count:
        attachment_score = max(attachment_score, min(100, 65 + 8 * min(yara_count, 4)))
    groups = [
        ("authentication", "Authentication", int(auth.get("score", 0)), 0.27),
        ("sender", "Sender identity", int(sender_score), 0.18),
        ("urls", "URLs & domains", url_score, 0.32),
        ("social", "Social engineering", int(se_score), 0.13),
        ("attachments", "Attachments & YARA", attachment_score, 0.10),
    ]
    components = [{"id": key, "label": label, "score": max(0, min(100, value))}
                  for key, label, value, _ in groups]
    raw = sum(max(0, min(100, value)) * weight for _, _, value, weight in groups)
    supporting = sum(value >= 50 for _, _, value, _ in groups)
    # Multiple independent types of evidence increase confidence.
    synergy = 15 if supporting >= 3 else 8 if supporting == 2 else 0
    overall = min(100, round(raw + synergy))
    # Explicit visual-link deception or brand spoofing is meaningful even in an
    # otherwise benign-looking message. DMARC fail alone remains MEDIUM unless
    # independent evidence corroborates it (legitimate misconfigurations occur).
    url_flags = {flag for item in url_analysis for flag in item.get("flags", [])}
    if ("LINK_TEXT_MISMATCH" in url_flags
            or any(flag.startswith("BRAND_IMPERSONATION_") for flag in url_flags)):
        overall = max(overall, 55)
    if auth.get("trusted") and auth.get("dmarc") == "fail":
        overall = max(overall, 30)

    notable = [f for f in findings if f.get("severity") in {"critical", "high", "medium"}
               and f.get("code") not in {Code.SPF_STATUS.value, Code.DKIM_STATUS.value,
                                          Code.DMARC_STATUS.value}]
    # Keep the report concise, while retaining full findings separately.
    unique: list[str] = []
    for item in notable:
        message = str(item.get("message", "")).strip()
        if message and message not in unique:
            unique.append(message)
        if len(unique) == 5:
            break
    if yara_count:
        unique.insert(0, f"YARA matched {yara_count} rule(s); investigate the actual matching patterns")
    warnings = list(dict.fromkeys([*auth.get("warnings", []), *limitations]))
    return {"score": overall, "verdict": _risk_label(overall),
            "method": "heuristic-v1", "components": components,
            "key_findings": unique[:5], "limitations": warnings,
            "completeness": "limited" if warnings else "standard"}

def print_risk_assessment(risk: dict[str, Any], emit: Callable[..., None] = print) -> None:
    color = (BRIGHT_RED if risk["score"] >= 75 else RED if risk["score"] >= 50
             else YELLOW if risk["score"] >= 25 else BRIGHT_GREEN)
    emit(CYAN + "\n=== Unified Risk Assessment ===" + RESET)
    emit(f"Overall risk: {color}{risk['score']}/100 [{risk['verdict']}]{RESET}")
    for item in risk["components"]:
        score = item["score"]
        bar = "#" * (score // 5) + "." * (20 - score // 5)
        emit(f"  {item['label']:<22} [{bar}] {score:3d}/100")
    if risk["key_findings"]:
        emit("Key evidence:")
        for finding in risk["key_findings"]:
            emit(f"  - {finding}")
    for warning in risk["limitations"][:3]:
        emit(YELLOW + f"  Note: {warning}" + RESET)
    emit("Scoring is heuristic, not a probability or a definitive verdict.\n")

