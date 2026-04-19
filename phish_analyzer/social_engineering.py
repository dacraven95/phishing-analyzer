"""
Social Engineering Scorer
Analyzes email body text for manipulation, urgency, and psychological pressure tactics.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import List, Tuple, Optional


@dataclass
class SETrigger:
    """A matched social engineering trigger."""
    cluster:  str
    phrase:   str
    weight:   int
    context:  str  # surrounding text snippet for evidence


@dataclass 
class SEResult:
    score:    int
    grade:    str
    triggers: List[SETrigger] = field(default_factory=list)
    summary:  str = ""


# ---------------------------------------------------------------------------
# Cluster definitions
# Each cluster: (cluster_name, base_weight, [patterns])
# Patterns are plain strings (case-insensitive substring match) or
# regex strings prefixed with "re:" for more precise matching.
# ---------------------------------------------------------------------------

SE_CLUSTERS = [
    (
        "Urgency",
        12,
        [
            # Direct urgency commands
            "immediately", "urgent", "urgently", "as soon as possible",
            "asap", "right away", "without delay", "time-sensitive",
            "time sensitive", "don't wait", "do not wait",
            "act now", "act immediately", "respond immediately", "respond now",
            "reply immediately", "reply now", "reply urgently",
            "contact us immediately", "call us immediately",
            "must act", "must respond", "must reply", "must contact",
            "need to act", "need to respond", "need to verify",
            "required to act", "required to respond", "required to verify",

            # Deadline language
            "within 24 hours", "within 24hrs", "within the next 24",
            "within 48 hours", "within 48hrs", "within the next 48",
            "within 72 hours", "within 72hrs", "within the next 72",
            "within one hour", "within 1 hour", "within the hour",
            "in the next hour", "in the next 24", "in the next 48",
            "by end of day", "by eod", "by close of business", "by cob",
            "by tomorrow", "by monday", "by tuesday", "by wednesday",
            "by thursday", "by friday", "by the end of the week",
            "no later than", "deadline", "due date", "due immediately",
            "overdue", "past due", "delinquent",
            "today only", "today is the last", "today is your last",
            "expires today", "expiring today", "expiring soon", "expires in",
            "expires at midnight", "expires tonight", "expires this week",
            "last chance", "final notice", "final warning", "final reminder",
            "final opportunity", "final attempt", "last attempt",
            "last reminder", "last notification", "last warning",
            "limited time", "time is running out", "running out of time",
            "clock is ticking", "time is up", "time has expired",
            "before it's too late", "before its too late",
            "don't miss", "do not miss", "don't delay", "do not delay",
            "don't hesitate", "do not hesitate",
            "immediate action required", "immediate action needed",
            "immediate attention required", "immediate attention needed",
            "immediate response required", "immediate response needed",
            "immediate action is required", "immediate action is needed",
            "prompt action", "prompt response", "prompt attention",
            "swift action", "swift response",
            "48-hour", "24-hour", "72-hour",
            "48 hour", "24 hour", "72 hour",
            "re:", "re:e:",
        ],
    ),
    (
        "Fear",
        15,
        [
            # Account threats
            "suspended", "suspension", "your account has been",
            "account will be closed", "account has been locked",
            "account has been compromised", "account has been flagged",
            "account has been restricted", "account has been limited",
            "account has been blocked", "account has been banned",
            "account has been deactivated", "account has been disabled",
            "account has been terminated", "account has been suspended",
            "account will be locked", "account will be terminated",
            "account will be deactivated", "account will be disabled",
            "account will be deleted", "account will be suspended",
            "account will be banned", "account will be blocked",
            "account will be restricted", "account will be limited",
            "will be terminated", "will be deactivated", "will be disabled",
            "will be deleted", "will be suspended", "permanently closed",
            "permanently suspended", "permanently disabled",
            "permanently deleted", "permanently banned",
            "access will be", "access has been", "access revoked",
            "limited access", "restricted access",

            # Security threat language
            "unauthorized access", "unauthorized login", "unauthorized activity",
            "unusual activity", "unusual login", "unusual sign-in",
            "unusual sign in", "unusual access", "unusual behavior",
            "suspicious activity", "suspicious login", "suspicious sign-in",
            "suspicious sign in", "suspicious access", "suspicious behavior",
            "suspicious transaction", "suspicious purchase",
            "we have detected", "has been detected", "we detected",
            "our systems detected", "our system detected",
            "security alert", "security breach", "security warning",
            "security notice", "security issue", "security concern",
            "security violation", "security incident", "security threat",
            "your password has", "your credentials", "your information has",
            "your data has", "your account data", "your personal data",
            "data breach", "data leak", "data exposure",
            "compromised", "hacked", "breached", "leaked", "exposed",
            "identity theft", "fraud detected", "fraudulent activity",
            "fraudulent transaction", "fraudulent purchase",
            "failed login", "multiple failed", "multiple attempts",
            "login attempt", "sign-in attempt", "access attempt",

            # Legal / consequence threat
            "legal action", "legal proceedings", "legal consequences",
            "law enforcement", "authorities have been", "reported to",
            "prosecution", "criminal charges", "civil action",
            "warrant", "subpoena", "court order",
            "penalty", "penalties", "fine", "fines",
            "debt collection", "collections agency", "sent to collections",
            "negative impact", "affect your credit", "credit score",
            "credit report", "reported to credit",
        ],
    ),
    (
        "Authority",
        10,
        [
            # IT / Technical authority
            "it department", "it team", "it support", "it helpdesk",
            "it help desk", "it admin", "it administrator",
            "information technology", "technology department",
            "tech support", "technical support", "technical team",
            "helpdesk", "help desk", "service desk", "support desk",
            "network team", "network administrator", "network admin",
            "system administrator", "system admin", "sysadmin",
            "infrastructure team", "cloud team", "devops team",
            "cybersecurity team", "cyber security team",
            "security operations", "security operations center", "soc team",

            # HR / Corporate authority
            "hr department", "human resources", "hr team", "hr manager",
            "hr director", "people operations", "people team",
            "payroll department", "payroll team", "payroll notification",
            "payroll processing", "payroll update", "payroll alert",
            "benefits department", "benefits team", "benefits notification",
            "compliance team", "compliance department", "compliance officer",
            "legal department", "legal team", "general counsel",
            "finance department", "finance team", "accounts payable",
            "accounts receivable", "accounting department",

            # Executive impersonation
            "ceo", "chief executive", "president and ceo",
            "cfo", "chief financial officer",
            "cto", "chief technology officer",
            "ciso", "chief information security officer",
            "coo", "chief operating officer",
            "vp of", "vice president", "svp", "evp",
            "director of", "managing director",
            "board of directors", "executive team", "leadership team",
            "management team", "senior management", "upper management",
            "on behalf of the ceo", "on behalf of management",
            "on behalf of leadership",

            # Financial institution authority
            "your bank", "your financial institution",
            "banking team", "fraud department", "fraud team",
            "fraud prevention", "risk management", "risk team",
            "compliance officer", "account services",
            "customer relations", "member services",

            # Tech company impersonation
            "microsoft support", "microsoft security",
            "google support", "google security", "google team",
            "apple support", "apple security", "apple id team",
            "amazon support", "amazon security", "aws support",
            "facebook support", "meta support",
            "paypal support", "paypal security", "paypal team",
            "docusign support", "dropbox support",

            # Generic authority signals
            "official notice", "official notification", "official communication",
            "official message", "official alert", "official warning",
            "on behalf of", "acting on behalf",
            "customer support", "customer service", "customer care",
            "re: your account", "re: your request", "re: your inquiry",
            "management", "administration", "administrator",
        ],
    ),
    (
        "Artificial Deadline",
        18,
        [
            # Hour-based deadlines
            "within one hour", "within 1 hour", "within the hour",
            "in the next hour", "in the next 30 minutes",
            "within 30 minutes", "within 2 hours", "within 4 hours",
            "within 6 hours", "within 8 hours", "within 12 hours",
            "within 24 hours", "within 24hrs",
            "within 48 hours", "within 48hrs",
            "within 72 hours", "within 72hrs",
            "within the next 24", "within the next 48", "within the next 72",
            "48-hour", "24-hour", "72-hour",
            "48 hour", "24 hour", "72 hour",
            "1-hour", "2-hour", "12-hour",

            # Day-based deadlines
            "by end of day", "by eod", "by end of business",
            "by close of business", "by cob",
            "by tomorrow", "by tomorrow morning", "by tomorrow afternoon",
            "by tomorrow evening", "by tomorrow night",
            "by monday", "by tuesday", "by wednesday",
            "by thursday", "by friday",
            "by the end of the week", "by the end of this week",
            "by the end of the month", "by the end of this month",
            "in the next few days", "in the coming days",
            "within the next few days", "within the next 3 days",
            "within the next 5 days", "within the next 7 days",

            # Expiry language
            "expires today", "expiring today", "expiring soon",
            "expires in", "expires at", "expiration date",
            "expires at midnight", "expires tonight",
            "expires this week", "expires this month",
            "link will expire", "link expires",
            "this link is valid for", "valid for 24", "valid for 48",
            "valid for 72", "valid only for", "only valid for",
            "token will expire", "session will expire",
            "offer expires", "offer expiring",

            # Urgency countdown language
            "time is running out", "running out of time",
            "clock is ticking", "time is up", "time has expired",
            "before it's too late", "before its too late",
            "don't miss the deadline", "missing the deadline",
            "last chance", "final notice", "final warning",
            "final reminder", "final opportunity",
            "today only", "today is the last",
            "today is your last chance", "last day",
            "limited time", "limited time offer", "limited time only",
            "time-limited", "time limited",
        ],
    ),
    (
        "Reward / Enticement",
        8,
        [
            # Winner/selection language
            "you have been selected", "you've been selected",
            "you have been chosen", "you've been chosen",
            "you have been picked", "you've been picked",
            "you have been identified", "you've been identified",
            "congratulations", "congrats", "you are a winner",
            "you've won", "you have won", "you're a winner",
            "lucky winner", "prize winner", "selected winner",
            "random selection", "randomly selected",

            # Prize / reward language
            "claim your prize", "claim your reward", "claim your gift",
            "claim your winnings", "claim now", "claim today",
            "claim your", "unclaimed prize", "unclaimed reward",
            "unclaimed funds", "unclaimed money",
            "gift card", "gift cards", "amazon gift card",
            "google play gift card", "itunes gift card",
            "prize", "prizes", "grand prize", "jackpot",
            "reward", "rewards", "loyalty reward", "loyalty bonus",
            "bonus", "bonuses", "sign-up bonus", "signup bonus",
            "referral bonus", "referral reward",

            # Offer language
            "exclusive offer", "special offer", "limited offer",
            "exclusive deal", "special deal", "exclusive access",
            "exclusive invitation", "you are invited",
            "free offer", "free access", "free upgrade", "free trial",
            "free gift", "free subscription", "free membership",
            "at no cost", "at no charge", "complimentary",
            "no cost to you", "completely free", "totally free",
            "risk free", "risk-free", "no risk",
            "pre-approved", "pre approved", "already approved",
            "you qualify", "you are eligible", "you're eligible",
            "you have qualified", "you've qualified",

            # Financial enticement
            "refund", "refunds", "tax refund", "get your refund",
            "reimbursement", "compensation", "settlement",
            "unclaimed money", "unclaimed funds", "owed money",
            "money waiting", "funds waiting", "funds available",
            "inheritance", "lottery", "sweepstakes",
            "cash prize", "cash reward", "cash bonus",
            "bitcoin", "cryptocurrency", "crypto reward",
            "investment opportunity", "guaranteed return",
            "guaranteed profit", "high return",
        ],
    ),
    (
        "Credential Harvesting",
        20,
        [
            # Verify / confirm language
            "verify your identity", "verify your account",
            "verify your email", "verify your email address",
            "verify your information", "verify your details",
            "verify your credentials", "verify your password",
            "verify your phone", "verify your number",
            "confirm your identity", "confirm your account",
            "confirm your email", "confirm your email address",
            "confirm your information", "confirm your details",
            "confirm your credentials", "confirm your password",
            "validate your account", "validate your identity",
            "validate your email", "validate your information",
            "authenticate your account", "authenticate your identity",
            "authentication required", "verification required",
            "identity verification", "account verification",
            "email verification", "phone verification",

            # Update / re-enter language
            "update your information", "update your details",
            "update your account", "update your credentials",
            "update your password", "update your username",
            "update your email", "update your phone",
            "update your billing", "update your payment",
            "update your card", "update your credit card",
            "update your bank", "update your banking",
            "re-enter your", "re enter your", "re-confirm",
            "reconfirm your", "re-verify", "reverify your",
            "provide your credentials", "provide your information",
            "provide your details", "provide your password",
            "enter your password", "enter your username",
            "enter your email", "enter your credentials",
            "enter your information", "enter your details",
            "enter your card", "enter your credit card",
            "enter your bank", "enter your account number",
            "enter your social", "enter your ssn",
            "enter your date of birth", "enter your dob",

            # Click / link language
            "click to verify", "click here to verify",
            "click below to verify", "click the link below",
            "click here to confirm", "click below to confirm",
            "click here to update", "click below to update",
            "click here to validate", "click here to authenticate",
            "click here to restore", "click here to recover",
            "click here to unlock", "click here to reactivate",
            "click here to activate", "click here to complete",
            "follow the link", "follow the link below",
            "use the link below", "use the button below",
            "tap the link", "tap the button",
            "open the link", "open the attachment",
            "download the attachment", "open the file",

            # Login language
            "login to verify", "log in to verify",
            "sign in to verify", "sign in to confirm",
            "login to confirm", "log in to confirm",
            "login to update", "log in to update",
            "login to restore", "log in to restore",
            "login to recover", "log in to recover",
            "login to unlock", "log in to unlock",
            "login to reactivate", "log in to reactivate",
            "sign in to your account", "log into your account",
        ],
    ),
    (
        "Secrecy / Isolation",
        22,
        [
            # Do not share
            "do not share", "do not forward", "do not reply",
            "do not disclose", "do not distribute", "do not discuss",
            "do not tell", "tell no one", "tell nobody",
            "keep this confidential", "keep this private",
            "keep this secret", "keep this between us",
            "for your eyes only", "strictly confidential",
            "highly confidential", "private and confidential",
            "strictly private", "personal and confidential",
            "not for distribution", "internal use only",
            "do not contact", "do not call", "do not email",
            "do not reach out", "do not speak to",

            # Exclusive channel
            "contact only", "respond only to", "reply only to",
            "communicate only", "contact us only through",
            "only contact", "only respond to", "only reply to",
            "bypass", "do not go through", "do not contact your",
            "do not contact the", "do not contact our",
            "do not contact any other",

            # Message self-destruction
            "this message will expire", "this link will expire",
            "this email will self", "delete this email after",
            "destroy after reading", "delete after reading",
            "this message will be deleted", "this email will be deleted",
            "this message will self-destruct",

            # Unusual channel pressure
            "use this email only", "use only this email",
            "use this number only", "use only this number",
            "contact via this email only", "respond via this email only",
            "do not use any other", "avoid contacting",
            "do not involve", "without involving",
        ],
    ),
    (
        "Impersonation Signal",
        15,
        [
            # Automated message signals
            "this is an automated", "this is an automatic",
            "automated message", "automatic notification",
            "automated notification", "automated alert",
            "automated email", "automatic email",
            "automated system", "system generated",
            "system notification", "system alert", "system message",
            "generated automatically", "sent automatically",
            "this email was automatically", "automatically generated",

            # No-reply signals
            "do not reply to this email", "do not reply to this message",
            "please do not respond to this email",
            "please do not reply to this email",
            "sent from a notification-only address",
            "this email was sent from an unmonitored",
            "this mailbox is not monitored",
            "this inbox is not monitored",
            "noreply", "no-reply", "no_reply",
            "donotreply", "do-not-reply", "do_not_reply",

            # On behalf of language
            "on behalf of", "acting on behalf",
            "writing on behalf", "contacting on behalf",
            "reaching out on behalf", "emailing on behalf",
            "sent on behalf", "sent by", "sent from",

            # Brand impersonation signals
            "apple id", "apple account", "icloud account",
            "microsoft account", "outlook account", "office 365",
            "google account", "gmail account", "google workspace",
            "amazon account", "aws account", "amazon web services",
            "paypal account", "paypal transaction",
            "facebook account", "meta account", "instagram account",
            "linkedin account", "twitter account", "x account",
            "dropbox account", "docusign",
            "chase bank", "bank of america", "wells fargo",
            "citibank", "capital one", "american express",
            "your financial institution", "your bank account",
            "your credit union",

            # Formal impersonation language
            "this is an official", "this is an important",
            "this is a critical", "this is a mandatory",
            "required by policy", "required by law",
            "as per company policy", "per our records",
            "according to our records", "our records indicate",
            "our systems show", "our system shows",
            "our records show", "our database shows",
        ],
    ),
    (
        "Psychological Pressure",
        14,
        [
            # Personal responsibility pressure
            "you are responsible", "you will be held responsible",
            "you will be held liable", "you are liable",
            "failure to act", "failure to respond", "failure to comply",
            "failure to verify", "failure to confirm", "failure to update",
            "if you fail to", "if you do not", "if you don't",
            "unless you", "if you ignore", "ignoring this",
            "failure to complete", "failure to provide",
            "non-compliance", "non compliance",

            # Negative consequence framing
            "consequences", "serious consequences", "severe consequences",
            "immediate consequences", "significant consequences",
            "result in", "will result in", "may result in",
            "could result in", "leads to", "lead to",
            "loss of access", "loss of service", "loss of account",
            "lose access", "lose your account", "lose your data",
            "lose your files", "lose your information",

            # Trust manipulation
            "we value your", "we care about your", "for your protection",
            "for your security", "for your safety", "to protect you",
            "to protect your account", "to keep you safe",
            "your security is", "your safety is",
            "as a valued", "as a trusted", "as a loyal",
            "as our customer", "as our client", "as our member",
            "as our user", "as our subscriber",

            # Shame / embarrassment pressure
            "embarrassing", "you should be aware",
            "we are disappointed", "we are concerned",
            "we are worried", "we are alarmed",
            "this is unacceptable", "this cannot continue",
            "this must stop", "this needs to stop",

            # Scarcity pressure
            "limited spots", "limited seats", "limited availability",
            "limited quantity", "while supplies last",
            "only a few left", "only a few remaining",
            "few spots remaining", "spots are filling up",
            "space is limited", "capacity is limited",
            "only available to", "exclusively available",
        ],
    ),
    (
        "Obfuscation / Evasion Language",
        16,
        [
            # Unusual capitalization signals (lowercased for matching)
            "click h e r e", "c l i c k", "v e r i f y",
            "l o g i n", "s i g n i n",

            # Spelling evasion attempts
            "veryfy", "verfiy", "varify",
            "acccount", "acount", "acconut",
            "passw0rd", "passw@rd", "p@ssword",
            "securit y", "secur1ty",
            "l0gin", "l0g1n", "s1gn",
            "upd@te", "upd4te",

            # Link hiding language
            "click the button", "click the link",
            "click the image", "click the picture",
            "click the icon", "click the banner",
            "tap here", "tap below", "tap the button",
            "tap the link", "tap the image",
            "scan the qr", "scan the code", "scan the barcode",
            "scan qr code", "qr code below", "qr code above",

            # Shortened/obfuscated URL signals
            "bit.ly", "tinyurl", "t.co", "ow.ly",
            "is.gd", "buff.ly", "rebrand.ly", "short.io",
            "goo.gl", "tiny.cc", "bl.ink", "cutt.ly",
            "shorturl", "short url", "shortened link",
            "shortened url", "short link",

            # Attachment-based evasion
            "open the attachment", "open the document",
            "open the file", "see the attachment",
            "see the document", "see the file",
            "view the attachment", "view the document",
            "download the attachment", "download the document",
            "download and open", "download and run",
            "enable macros", "enable editing", "enable content",
            "allow macros", "allow editing", "allow content",
            "protected document", "protected file",
            "encrypted document", "encrypted file",
            "password protected", "password-protected",
        ],
    ),
    (
        "Financial Manipulation",
        17,
        [
            # Payment urgency
            "payment required", "payment due", "payment overdue",
            "payment past due", "payment is due", "payment is overdue",
            "outstanding balance", "outstanding payment", "outstanding invoice",
            "invoice attached", "invoice enclosed", "invoice due",
            "invoice overdue", "invoice past due",
            "unpaid invoice", "unpaid balance", "unpaid amount",
            "amount due", "amount owed", "balance due", "balance owed",
            "settle your", "clear your balance", "clear your debt",
            "pay now", "pay immediately", "pay today",
            "pay the balance", "pay the amount", "pay the invoice",
            "immediate payment", "payment immediately",
            "wire transfer", "wire funds", "bank transfer",
            "transfer funds", "transfer money", "transfer the amount",
            "send money", "send funds", "send payment",
            "send via", "send using",

            # Gift card / crypto payment (massive red flag)
            "pay with gift card", "pay using gift card",
            "purchase gift cards", "buy gift cards",
            "send gift card", "gift card payment",
            "itunes gift card", "google play gift card",
            "amazon gift card", "steam gift card",
            "gift card codes", "gift card numbers",
            "scratch off", "scratch the back",
            "bitcoin payment", "pay in bitcoin",
            "pay with bitcoin", "pay in crypto",
            "pay with crypto", "cryptocurrency payment",
            "send bitcoin", "send crypto", "wallet address",
            "crypto wallet", "bitcoin wallet",

            # Tax / refund scams
            "tax refund", "tax return", "irs refund",
            "hmrc refund", "tax rebate", "tax credit",
            "overpaid tax", "tax overpayment",
            "you are owed", "owed to you", "due to you",
            "claim your refund", "claim your tax",
            "unclaimed refund", "pending refund",
            "refund is waiting", "refund is ready",
            "refund has been processed", "refund initiated",
            "direct deposit", "direct payment",
        ],
    ),
    (
        "Personal Information Harvesting",
        19,
        [
            # Identity information requests
            "social security", "social security number", "ssn",
            "national insurance", "national id", "national identity",
            "driver's license", "drivers license", "driver license",
            "passport number", "passport details",
            "date of birth", "dob", "your birthday",
            "mother's maiden name", "maiden name",
            "place of birth", "birthplace",
            "your full name", "full legal name",
            "your address", "home address", "mailing address",
            "your phone number", "phone number", "mobile number",
            "your email address", "alternate email",

            # Financial information requests
            "credit card number", "card number", "card details",
            "debit card", "credit card", "card information",
            "cvv", "cvc", "security code", "card security",
            "expiration date", "expiry date", "card expiry",
            "bank account number", "account number",
            "routing number", "sort code",
            "bank details", "banking information", "banking details",
            "financial information", "financial details",
            "billing information", "billing details",
            "payment information", "payment details",
            "pin number", "your pin", "enter your pin",

            # Login credentials
            "username and password", "login credentials",
            "your credentials", "account credentials",
            "current password", "existing password",
            "old password", "new password",
            "create a new password", "reset your password",
            "password reset", "forgot password",
            "security question", "security answer",
            "secret question", "secret answer",
            "two-factor", "two factor", "2fa code",
            "authentication code", "verification code",
            "one-time password", "one time password", "otp",
            "sms code", "text code", "code sent to",
        ],
    ),
    (
        "Technical Deception",
        13,
        [
            # Fake technical problem language
            "your mailbox is full", "mailbox quota",
            "mailbox storage", "storage limit", "storage quota",
            "storage is full", "storage has been exceeded",
            "quota exceeded", "quota has been exceeded",
            "email quota", "email storage",
            "your inbox is full", "inbox storage",
            "your account storage", "account quota",
            "server maintenance", "scheduled maintenance",
            "system maintenance", "system upgrade",
            "system update required", "system update needed",
            "software update required", "software update needed",
            "critical update", "security update required",
            "security patch", "security update",
            "browser update", "plugin update", "java update",
            "adobe update", "flash update",
            "your computer has", "your device has",
            "your pc has", "your mac has",
            "virus detected", "malware detected",
            "your system is", "your device is",
            "computer is infected", "device is infected",
            "technical issue", "technical problem",
            "we are having trouble", "we are experiencing",
            "error detected", "error found",

            # Fake authentication language
            "session expired", "your session has expired",
            "session has timed out", "session timeout",
            "login session", "your login has",
            "token expired", "token has expired",
            "authentication failed", "authentication expired",
            "certificate expired", "ssl certificate",
            "connection not secure", "not secure",
            "your connection is", "unsecure connection",
        ],
    ),
]


def _extract_context(text: str, match_start: int, match_end: int, window: int = 60) -> str:
    """Pull a short snippet of surrounding text for evidence display."""
    start = max(0, match_start - window)
    end = min(len(text), match_end + window)
    snippet = text[start:end].replace("\n", " ").replace("\r", "")
    # Add ellipsis if truncated
    if start > 0:
        snippet = "..." + snippet
    if end < len(text):
        snippet = snippet + "..."
    return snippet.strip()


def _dedupe_triggers(triggers: List[SETrigger]) -> List[SETrigger]:
    """
    Remove triggers where a shorter phrase is a substring of an already-matched longer one
    in the same cluster, to avoid double-counting overlapping phrases.
    """
    seen_spans: dict[str, list[str]] = {}
    deduped = []
    for t in triggers:
        cluster_seen = seen_spans.setdefault(t.cluster, [])
        # Skip if this phrase is already covered by a longer match in same cluster
        if any(t.phrase in longer for longer in cluster_seen):
            continue
        cluster_seen.append(t.phrase)
        deduped.append(t)
    return deduped


def score_social_engineering(
    plain_body: Optional[str],
    html_body:  Optional[str],
    subject:    Optional[str] = None,
) -> SEResult:
    """
    Score the email content for social engineering indicators.

    Pass in whatever body content you have — plain text, HTML, or both.
    Subject line is analyzed separately with a small weight bonus since
    subject manipulation is a strong signal on its own.

    Returns an SEResult with score (0-100), grade, and matched triggers.
    """

    # Build a single normalized text blob for body analysis
    # HTML body: strip tags for text matching
    body_parts = []
    if plain_body:
        body_parts.append(plain_body)
    if html_body:
        # crude but effective tag stripper - avoids needing beautifulsoup
        clean_html = re.sub(r'<[^>]+>', ' ', html_body)
        clean_html = re.sub(r'&nbsp;', ' ', clean_html)
        clean_html = re.sub(r'&amp;', '&', clean_html)
        clean_html = re.sub(r'&lt;', '<', clean_html)
        clean_html = re.sub(r'&gt;', '>', clean_html)
        body_parts.append(clean_html)

    body_text = "\n".join(body_parts)
    body_lower = body_text.lower()

    # Subject gets its own analysis pass with a multiplier
    subject_lower = (subject or "").lower()

    triggers: List[SETrigger] = []
    raw_score = 0

    for cluster_name, base_weight, phrases in SE_CLUSTERS:
        cluster_hits = []

        for phrase in phrases:
            # Check body
            idx = body_lower.find(phrase)
            if idx != -1:
                context = _extract_context(body_lower, idx, idx + len(phrase))
                cluster_hits.append(SETrigger(
                    cluster=cluster_name,
                    phrase=phrase,
                    weight=base_weight,
                    context=context,
                ))

            # Check subject (subject hits worth 1.5x — manipulated subjects are a strong signal)
            if phrase in subject_lower:
                context = f"[SUBJECT] {subject_lower}"
                cluster_hits.append(SETrigger(
                    cluster=cluster_name,
                    phrase=phrase,
                    weight=int(base_weight * 1.5),
                    context=context,
                ))

        if not cluster_hits:
            continue

        # Dedupe within the cluster
        cluster_hits = _dedupe_triggers(cluster_hits)

        # Cap contribution per cluster: first hit = full weight, each extra = 50% diminishing
        # This prevents a single spammy cluster from dominating the score
        cluster_score = 0
        for i, trigger in enumerate(cluster_hits):
            if i == 0:
                contribution = trigger.weight
            else:
                contribution = max(1, int(trigger.weight * (0.5 ** i)))
            cluster_score += contribution
            triggers.append(trigger)

        raw_score += cluster_score

    # Multi-cluster bonus: if 3+ clusters are triggered, add a bonus
    # (a real phishing email typically weaponizes multiple tactics at once)
    triggered_clusters = set(t.cluster for t in triggers)
    if len(triggered_clusters) >= 3:
        raw_score += 10
    if len(triggered_clusters) >= 5:
        raw_score += 15

    # Normalize to 0-100
    score = max(0, min(100, raw_score))

    # Grade
    if score >= 75:
        grade = "CRITICAL"
    elif score >= 55:
        grade = "HIGH"
    elif score >= 35:
        grade = "MEDIUM"
    elif score >= 15:
        grade = "LOW"
    else:
        grade = "MINIMAL"

    # Build a plain-English summary
    cluster_names = sorted(triggered_clusters)
    if cluster_names:
        summary = (
            f"Detected {len(triggers)} social engineering indicator(s) across "
            f"{len(triggered_clusters)} tactic(s): {', '.join(cluster_names)}."
        )
    else:
        summary = "No social engineering indicators detected."

    return SEResult(
        score=score,
        grade=grade,
        triggers=triggers,
        summary=summary,
    )