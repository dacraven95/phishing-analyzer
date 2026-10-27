"""Shared analyzer types and structured results."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

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
    URL_USERINFO = "URL_USERINFO"
    URL_UNUSUAL_PORT = "URL_UNUSUAL_PORT"
    URL_SHORTENER = "URL_SHORTENER"
    URL_EXTERNAL_REDIRECT = "URL_EXTERNAL_REDIRECT"
    URL_LINK_TEXT_MISMATCH = "URL_LINK_TEXT_MISMATCH"
    URL_MIXED_SCRIPT = "URL_MIXED_SCRIPT"

    # Headers
    CROSSTENANT_PRESENT = "CROSSTENANT_PRESENT"
    FROM_REPLYTO_MISMATCH = "FROM_REPLYTO_MISMATCH"
    FROM_RETURNPATH_MISMATCH = "FROM_RETURNPATH_MISMATCH"
    MISSING_HEADER = "MISSING_HEADER"
    AUTH_UNVERIFIED = "AUTH_UNVERIFIED"
    AUTH_TRUSTED = "AUTH_TRUSTED"
    SENDER_REPLYTO_MISMATCH = "SENDER_REPLYTO_MISMATCH"

    # Domain Related
    WHOIS_BASIC_INFO = "WHOIS_BASIC_INFO"
    WHOIS_LOOKUP_FAILED = "WHOIS_LOOKUP_FAILED"

@dataclass
class Finding:
    code: str
    weight: int
    message: str
    evidence: Optional[str] = None

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

@dataclass(slots=True)
class AnalysisResult:
    """One run's data, independent of CLI/PDF/HTTP formatting."""
    file_name: str
    findings: list[dict[str, Any]]
    risk_assessment: dict[str, Any]
    output: str
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    email_body: str | None = None
    received_hops: list[dict[str, Any]] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_api_dict(self) -> dict[str, Any]:
        return {
            "output": self.output,
            "risk_assessment": self.risk_assessment,
            "analysis_results": self.findings,
            "details": self.details,
            "metadata": {"file_name": self.file_name, "analyzed_at": self.analyzed_at.isoformat()},
        }

