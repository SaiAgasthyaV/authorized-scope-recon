"""Evidence-minimising heuristics for likely secrets in public text resources.

Regex matches are indicators only. Findings are deliberately redacted and marked
unverified; this module never attempts to use, validate, or transmit a value.
"""
from __future__ import annotations

import base64
import hashlib
import math
import re
from collections import Counter
from typing import Iterable


def redact_value(value: str) -> str:
    """Preserve a small recognisable prefix/suffix without storing the secret."""
    value = (value or "").strip()
    if len(value) <= 4:
        return "<redacted>"
    # Provider prefixes are useful when triaging, e.g. sk_live_****abcd.
    prefix_length = 8 if value.startswith(("sk_", "pk_", "ghp_", "xox", "AKIA", "ASIA", "SG.")) else 4
    if len(value) <= prefix_length + 4:
        return value[: min(2, len(value))] + "****"
    return f"{value[:prefix_length]}****{value[-4:]}"


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    size = len(value)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def is_placeholder(value: str) -> bool:
    normalized = value.strip().lower()
    markers = ("example", "sample", "placeholder", "changeme", "change_me", "your_", "<", "dummy", "not-a", "replace")
    return (not normalized or normalized in {"null", "undefined", "none", "true", "false", "password", "secret"}
            or any(marker in normalized for marker in markers) or set(normalized) == {"x"})


def _line_number(source: str, position: int) -> int:
    return source.count("\n", 0, position) + 1


def _finding_id(source_url: str, finding_type: str, pattern: str, line: int) -> str:
    value = f"{source_url}|{finding_type}|{pattern}|{line}".encode("utf-8")
    return "SF-" + hashlib.sha256(value).hexdigest()[:12].upper()


def _finding(source: str, start: int, source_url: str, host: str, file_type: str,
             finding_type: str, severity: str, confidence: str, pattern: str,
             value: str, context: str, original_js_url: str = "") -> dict:
    line = _line_number(source, start)
    return {
        "finding_id": _finding_id(source_url, finding_type, pattern, line),
        "host": host,
        "source_url": source_url,
        "original_js_url": original_js_url,
        "finding_type": finding_type,
        "severity": severity,
        "confidence": confidence,
        "file_type": file_type,
        "matched_pattern": pattern,
        "redacted_evidence": redact_value(value),
        # Never use raw source-line context here: it may contain additional secrets.
        "context": context,
        "line_number": line,
        "first_seen": "",  # populated by the resource analyser at retrieval time
        "status": "Unverified – pattern match only",
    }


PROVIDER_PATTERNS: tuple[tuple[str, re.Pattern[str], str, str, str], ...] = (
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "High", "High", "aws_access_key_id"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Medium", "Medium", "google_api_key"),
    ("GitHub token", re.compile(r"\b(?:ghp_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{30,255})\b"), "High", "High", "github_token"),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,255}\b"), "High", "High", "gitlab_token"),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b"), "High", "High", "slack_token"),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"), "High", "High", "sendgrid_api_key"),
    ("Stripe live secret key", re.compile(r"\bsk_live_[A-Za-z0-9]{12,}\b"), "High", "High", "stripe_live_secret"),
    ("Stripe test secret key", re.compile(r"\bsk_test_[A-Za-z0-9]{12,}\b"), "Low", "High", "stripe_test_secret"),
    # OpenAI issues only secret keys (no publishable variant); any occurrence client-side is a real finding.
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), "High", "High", "openai_api_key"),
    # Razorpay key IDs are the publishable half (like a Stripe publishable key) and are meant
    # to sit in checkout widgets; flag at a low severity for inventory purposes, not as a leak.
    ("Razorpay live key ID", re.compile(r"\brzp_live_[A-Za-z0-9]{10,}\b"), "Low", "High", "razorpay_live_key_id"),
    ("Razorpay test key ID", re.compile(r"\brzp_test_[A-Za-z0-9]{10,}\b"), "Informational", "High", "razorpay_test_key_id"),
    ("Twilio Account SID", re.compile(r"\bAC[0-9a-fA-F]{32}\b"), "Low", "Medium", "twilio_account_sid"),
    ("Mailgun API key", re.compile(r"\bkey-[0-9a-z]{32}\b"), "High", "High", "mailgun_api_key"),
    ("Mailchimp API key", re.compile(r"\b[0-9a-z]{32}-us\d{1,2}\b"), "High", "High", "mailchimp_api_key"),
    # Shopify's own admin/storefront/private-app token formats; especially relevant when the
    # authorized scope is itself made up of Shopify-owned or Shopify-hosted properties.
    ("Shopify Admin API access token", re.compile(r"\bshpat_[0-9a-fA-F]{32}\b"), "Critical", "High", "shopify_admin_token"),
    ("Shopify custom-app access token", re.compile(r"\bshpca_[0-9a-fA-F]{32}\b"), "Critical", "High", "shopify_custom_app_token"),
    ("Shopify private-app password", re.compile(r"\bshppa_[0-9a-fA-F]{32}\b"), "Critical", "High", "shopify_private_app_token"),
    ("Shopify shared secret", re.compile(r"\bshpss_[0-9a-fA-F]{32}\b"), "High", "High", "shopify_shared_secret"),
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
DATABASE_URI_RE = re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s/@:]+:[^\s/@]+@[^\s'\"`]+", re.IGNORECASE)
EMBEDDED_CREDENTIAL_URL_RE = re.compile(r"\bhttps?://[^\s/@:]+:[^\s/@]+@[^\s'\"`]+", re.IGNORECASE)
SLACK_WEBHOOK_RE = re.compile(r"\bhttps://hooks\.slack\.com/services/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+", re.IGNORECASE)
AZURE_STORAGE_KEY_RE = re.compile(r"\bAccountKey=[A-Za-z0-9+/=]{40,}\b", re.IGNORECASE)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
BEARER_RE = re.compile(r"\bBearer\s+([A-Za-z0-9._~+\-/=]{16,})", re.IGNORECASE)
ASSIGNMENT_RE = re.compile(
    r"(?im)(?P<key>[A-Za-z_][A-Za-z0-9_.-]*(?:api[_-]?key|secret|token|password|passwd|client[_-]?secret|access[_-]?key|authorization)[A-Za-z0-9_.-]*)"
    r"\s*[:=]\s*(?:[\"'](?P<quoted>[^\"'\r\n]{1,500})[\"']|(?P<bare>[^\s,;}]{8,500}))"
)
USERNAME_RE = re.compile(r"(?im)\b(?:user(?:name)?|login)\s*[:=]\s*[\"'][^\"'\r\n]{1,200}[\"']")


def _likely_jwt(value: str) -> bool:
    if is_placeholder(value) or shannon_entropy(value) < 3.2:
        return False
    try:
        # Decoding only its header verifies basic JWT shape; no signature checking.
        header = value.split(".", 1)[0] + "==="
        return b"{" in base64.urlsafe_b64decode(header.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        return False


def _deduplicate(findings: Iterable[dict]) -> list[dict]:
    result, seen = [], set()
    for finding in findings:
        key = (finding["source_url"], finding["finding_type"], finding["line_number"], finding["matched_pattern"])
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result


def find_secrets(source: str, source_url: str, host: str, file_type: str = "JavaScript",
                 original_js_url: str = "") -> list[dict]:
    """Return conservative, safely redacted *potential* secret findings."""
    findings: list[dict] = []
    for finding_type, pattern, severity, confidence, pattern_name in PROVIDER_PATTERNS:
        for match in pattern.finditer(source):
            value = match.group(0)
            if is_placeholder(value):
                continue
            severity_for_match, confidence_for_match, context = severity, confidence, f"Recognizable {finding_type.lower()} format; value redacted."
            if pattern_name == "google_api_key":
                # Google issues one key format across all Cloud APIs. Maps/Firebase-style keys
                # are commonly meant to be public and are restricted by HTTP referrer/quota
                # rather than secrecy, so a nearby Maps/Firebase reference downgrades this from
                # a suspected leak to an inventory note worth a restriction check.
                window = source[max(0, match.start() - 200): match.end() + 200].lower()
                if "maps.googleapis" in window or "maps_api" in window or "firebaseapp" in window:
                    severity_for_match, confidence_for_match = "Informational", "Low"
                    context = ("Google API key adjacent to a Maps/Firebase reference; these keys are commonly "
                               "public-by-design and restricted via HTTP referrer/quota rather than secrecy. "
                               "Verify referrer/API restrictions rather than treating this as a credential leak.")
            findings.append(_finding(source, match.start(), source_url, host, file_type, finding_type,
                severity_for_match, confidence_for_match, pattern_name, value, context, original_js_url))

    for match in PRIVATE_KEY_RE.finditer(source):
        findings.append(_finding(source, match.start(), source_url, host, file_type, "Private key material",
            "Critical", "High", "private_key_header", match.group(0),
            "A private-key PEM header was present; key material is not stored in this report.", original_js_url))

    for match in DATABASE_URI_RE.finditer(source):
        findings.append(_finding(source, match.start(), source_url, host, file_type, "Database connection string",
            "High", "High", "database_uri_with_credentials", match.group(0),
            "Database URI contains an embedded username/password; values redacted.", original_js_url))
    for match in EMBEDDED_CREDENTIAL_URL_RE.finditer(source):
        findings.append(_finding(source, match.start(), source_url, host, file_type, "URL with embedded credentials",
            "High", "High", "url_with_embedded_credentials", match.group(0),
            "HTTP(S) URL contains embedded credentials; values redacted.", original_js_url))
    for match in SLACK_WEBHOOK_RE.finditer(source):
        findings.append(_finding(source, match.start(), source_url, host, file_type, "Webhook secret",
            "High", "High", "slack_webhook_url", match.group(0),
            "Slack webhook URL format detected; the URL is redacted and not contacted.", original_js_url))
    for match in AZURE_STORAGE_KEY_RE.finditer(source):
        findings.append(_finding(source, match.start(), source_url, host, file_type, "Azure storage account key",
            "High", "High", "azure_storage_account_key", match.group(0),
            "Azure storage AccountKey assignment detected; value redacted and not tested.", original_js_url))

    for match in JWT_RE.finditer(source):
        value = match.group(0)
        if _likely_jwt(value):
            findings.append(_finding(source, match.start(), source_url, host, file_type, "JWT-like token",
                "Medium", "Medium", "jwt_like_token", value,
                "JWT-shaped value detected. It is unverified and may be an intentionally public/session artifact.", original_js_url))
    for match in BEARER_RE.finditer(source):
        value = match.group(1)
        if not is_placeholder(value) and shannon_entropy(value) >= 3.1:
            findings.append(_finding(source, match.start(1), source_url, host, file_type, "Bearer/access token",
                "Medium", "Medium", "bearer_token", value,
                "Bearer token assignment detected; value redacted and not tested.", original_js_url))

    for match in ASSIGNMENT_RE.finditer(source):
        key, value = match.group("key"), match.group("quoted") or match.group("bare")
        lower_key = key.lower()
        if is_placeholder(value) or value.lower().startswith(("http://", "https://")):
            continue
        # Do not flag familiar build-time public configuration as a secret. It is
        # retained as an informational distinction when it otherwise looks secret-like.
        public_prefix = lower_key.startswith(("next_public_", "react_app_", "vite_", "public_"))
        entropy = shannon_entropy(value)
        if entropy < 3.0 and not any(marker in lower_key for marker in ("password", "passwd")):
            continue
        if public_prefix:
            finding_type, severity, confidence = "Public frontend configuration", "Informational", "Low"
            context = "Public-prefixed frontend configuration resembles a credential field; review scope and provider controls."
        elif "password" in lower_key or "passwd" in lower_key:
            finding_type, severity, confidence = "Hardcoded password", "Medium", "Medium"
            context = "Password-like assignment detected; value redacted and not tested."
        elif "client" in lower_key and "secret" in lower_key:
            finding_type, severity, confidence = "OAuth/client secret", "High", "Medium"
            context = "Client-secret-like assignment detected; value redacted and not tested."
        elif "webhook" in lower_key:
            finding_type, severity, confidence = "Webhook secret", "High", "Medium"
            context = "Webhook-secret-like assignment detected; value redacted and not tested."
        else:
            finding_type, severity, confidence = "Generic secret/token assignment", "Medium", "Low"
            context = "Sensitive-keyword assignment with a non-placeholder, high-entropy value; unverified."
        findings.append(_finding(source, match.start("key"), source_url, host, file_type, finding_type,
            severity, confidence, "contextual_secret_assignment", value, context, original_js_url))

        if ("password" in lower_key or "passwd" in lower_key) and USERNAME_RE.search(source[max(0, match.start() - 500):match.end() + 500]):
            findings.append(_finding(source, match.start("key"), source_url, host, file_type, "Hardcoded username/password pair",
                "High", "Medium", "nearby_username_password_assignments", value,
                "Username and password assignments occur near one another; both values are redacted and untested.", original_js_url))
    return _deduplicate(findings)