"""Scope normalization and conservative web-target authorization helpers.

The input format intentionally uses column aliases rather than a platform-specific
schema. A record is only turned into a web target when both its inclusion state
and its domain/URL shape are clear. Everything else remains visible in the
normalized exclusion report.
"""
from __future__ import annotations

import csv
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)

# The aliases describe concepts, not any one platform's export format.
FIELD_ALIASES = {
    "identifier": ("identifier", "asset", "asset identifier", "target", "scope", "url", "hostname", "domain"),
    "asset_type": ("asset_type", "asset type", "type", "asset category", "target type"),
    "status": ("status", "scope status", "in scope", "in_scope", "included", "eligible", "state"),
    "bounty_eligible": ("eligible_for_bounty", "eligible for bounty", "bounty eligible", "bounty", "reward eligible"),
    "submission_eligible": ("eligible_for_submission", "eligible for submission", "submission eligible", "report eligible"),
    "instructions": ("instruction", "instructions", "notes", "note", "description", "guidance", "restrictions"),
    "platform": ("platform", "source platform", "program platform", "source"),
}

IN_SCOPE_VALUES = {"true", "yes", "y", "in scope", "in_scope", "included", "include", "active", "allowed"}
OUT_OF_SCOPE_VALUES = {"false", "no", "n", "out of scope", "out_of_scope", "excluded", "exclude", "not eligible", "disabled"}
WEB_TYPES = {"url", "website", "web", "domain", "hostname", "wildcard", "wildcard domain", "web application"}


def _normalise_key(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower().replace("_", " "))


def _row_value(row: dict[str, str], aliases: Iterable[str]) -> str:
    wanted = {_normalise_key(alias) for alias in aliases}
    for key, value in row.items():
        if _normalise_key(key) in wanted and value is not None:
            return str(value).strip()
    return ""


def infer_platform(headers: Iterable[str], explicit: str = "") -> str:
    """Return provenance without requiring a particular export schema."""
    if explicit:
        return explicit.strip()
    normalized = {_normalise_key(header) for header in headers}
    # These are provenance hints only; parsing remains alias-driven and generic.
    if {"eligible for submission", "eligible for bounty"} & normalized:
        return "HackerOne-compatible CSV"
    if "reward range" in normalized or "asset group" in normalized:
        return "Bugcrowd-compatible CSV"
    if "scope type" in normalized or "program id" in normalized:
        return "Intigriti-compatible CSV"
    if "program" in normalized and "asset" in normalized:
        return "YesWeHack-compatible CSV"
    return "Unknown CSV export"


def clean_identifier(identifier: str) -> tuple[str, bool] | None:
    """Return lower-case host and wildcard flag, or None for non-web identifiers."""
    raw = (identifier or "").strip()
    if not raw:
        return None
    wildcard = raw.startswith("*.")
    candidate = raw[2:] if wildcard else raw
    if "://" in candidate:
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        host = parsed.hostname
    else:
        # A slash, query, credential, or whitespace without a scheme is ambiguous.
        if any(char in candidate for char in "/?#@ "):
            return None
        host = candidate.split(":", 1)[0]
    host = host.rstrip(".").lower()
    if not DOMAIN_RE.fullmatch(host):
        return None
    return host, wildcard


def infer_asset_type(identifier: str, raw_type: str) -> str:
    if raw_type.strip():
        return raw_type.strip()
    if identifier.strip().startswith("*."):
        return "WILDCARD"
    if identifier.strip().lower().startswith(("http://", "https://")):
        return "URL"
    if clean_identifier(identifier):
        return "DOMAIN"
    return "UNKNOWN"


def resolve_inclusion(raw_status: str) -> tuple[bool, str]:
    """A missing status is accepted only as an unmarked row in a scope export."""
    value = _normalise_key(raw_status)
    if value in OUT_OF_SCOPE_VALUES or "out of scope" in value or "exclude" in value:
        return False, "explicitly marked out of scope"
    if not value or value in IN_SCOPE_VALUES or "in scope" in value:
        return True, ""
    return False, f"unrecognized inclusion status: {raw_status}"


@dataclass(frozen=True)
class NormalizedScopeRecord:
    identifier: str
    asset_type: str
    inclusion_status: str
    bounty_eligible: str
    submission_eligible: str
    instructions: str
    source_platform: str
    source_file: str
    source_row: int
    host: str = ""
    wildcard: bool = False
    web_target: bool = False
    exclusion_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_csv(path: str | Path, platform: str = "", bounty_only: bool = False) -> list[NormalizedScopeRecord]:
    records: list[NormalizedScopeRecord] = []
    path = Path(path)
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return records
        source_platform = infer_platform(reader.fieldnames, platform)
        for row_number, row in enumerate(reader, start=2):
            identifier = _row_value(row, FIELD_ALIASES["identifier"])
            asset_type = infer_asset_type(identifier, _row_value(row, FIELD_ALIASES["asset_type"]))
            inclusion_raw = _row_value(row, FIELD_ALIASES["status"])
            bounty = _row_value(row, FIELD_ALIASES["bounty_eligible"])
            submission = _row_value(row, FIELD_ALIASES["submission_eligible"])
            instructions = _row_value(row, FIELD_ALIASES["instructions"])
            platform_value = _row_value(row, FIELD_ALIASES["platform"]) or source_platform
            included, reason = resolve_inclusion(inclusion_raw)
            target = clean_identifier(identifier) if included else None

            type_is_web = _normalise_key(asset_type) in WEB_TYPES
            if included and not type_is_web:
                reason = "asset type is not a confidently mapped web target"
            elif included and not target:
                reason = "identifier is not a valid HTTP(S) domain or wildcard"
            elif bounty_only and _normalise_key(bounty) not in IN_SCOPE_VALUES and _normalise_key(submission) not in IN_SCOPE_VALUES:
                reason = "not bounty/submission eligible"

            web_target = included and type_is_web and target is not None and not reason
            host, wildcard = target if target else ("", False)
            records.append(NormalizedScopeRecord(
                identifier=identifier, asset_type=asset_type,
                inclusion_status="in_scope" if web_target else "excluded",
                bounty_eligible=bounty, submission_eligible=submission,
                instructions=instructions, source_platform=platform_value,
                source_file=str(path), source_row=row_number, host=host,
                wildcard=wildcard, web_target=web_target, exclusion_reason=reason,
            ))
    return records


def normalize_scope_files(paths: Iterable[str | Path], platform: str = "", bounty_only: bool = False) -> list[NormalizedScopeRecord]:
    records: list[NormalizedScopeRecord] = []
    for path in paths:
        records.extend(normalize_csv(path, platform=platform, bounty_only=bounty_only))
    return records


def allowed_hosts(records: Iterable[NormalizedScopeRecord]) -> tuple[set[str], set[str]]:
    exact, wildcards = set(), set()
    for record in records:
        if record.web_target:
            (wildcards if record.wildcard else exact).add(record.host)
    return exact, wildcards


def write_normalized_scope(records: Iterable[NormalizedScopeRecord], output: str | Path) -> None:
    data = {"version": 1, "records": [record.to_dict() for record in records]}
    with Path(output).open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def load_normalized_scope(path: str | Path) -> list[dict[str, Any]]:
    with Path(path).open(encoding="utf-8") as handle:
        data = json.load(handle)
    return data.get("records", data if isinstance(data, list) else [])


class ScopePolicy:
    """Host-only web policy: no non-HTTP schemes, credentials, or external hosts."""

    def __init__(self, records: Iterable[dict[str, Any] | NormalizedScopeRecord]):
        self.exact_hosts: set[str] = set()
        self.wildcard_roots: set[str] = set()
        for record in records:
            data = record.to_dict() if isinstance(record, NormalizedScopeRecord) else record
            if not data.get("web_target"):
                continue
            host = str(data.get("host") or "").lower().rstrip(".")
            if data.get("wildcard"):
                self.wildcard_roots.add(host)
            elif host:
                self.exact_hosts.add(host)

    @classmethod
    def from_file(cls, path: str | Path) -> "ScopePolicy":
        return cls(load_normalized_scope(path))

    def allows_host(self, host: str | None) -> bool:
        host = (host or "").lower().rstrip(".")
        return host in self.exact_hosts or host in self.wildcard_roots or any(
            host.endswith("." + root) for root in self.wildcard_roots
        )

    def allows_url(self, url: str) -> bool:
        try:
            parsed = urlsplit(url)
        except ValueError:
            return False
        return (parsed.scheme.lower() in {"http", "https"} and not parsed.username
                and not parsed.password and self.allows_host(parsed.hostname))
