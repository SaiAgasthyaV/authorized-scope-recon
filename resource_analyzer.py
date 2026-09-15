#!/usr/bin/env python3
"""Download discovered in-scope JavaScript and inspect it without using secrets."""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from secret_detection import find_secrets
from scope_normalization import ScopePolicy
from web_utils import SafeHttpClient, canonical_url, sha256_bytes

SOURCE_MAP_RE = re.compile(r"(?:/\*#?|//[#@])\s*sourceMappingURL\s*=\s*([^\s*]+)")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_jsonl(path: str) -> list[dict]:
    file_path = Path(path)
    if not file_path.exists():
        return []
    result = []
    for line in file_path.read_text(encoding="utf-8").splitlines():
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return result


def append_jsonl(path: Path, records: list[dict]) -> None:
    if not records:
        return
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def looks_like_javascript(content_type: str, url: str, body: bytes) -> bool:
    content_type = content_type.lower()
    head = body[:4096].decode("utf-8", errors="ignore")
    if "html" in content_type or "<html" in head.lower() or "<!doctype html" in head.lower():
        return False
    if any(value in content_type for value in ("javascript", "ecmascript")):
        return True
    if urlsplit(url).path.lower().endswith((".js", ".mjs", ".cjs", ".jsx")):
        return bool(re.search(r"\b(?:const|let|var|function|import|export|window|document)\b|=>", head))
    return False


def source_map_url(source: str, js_url: str) -> str:
    matches = SOURCE_MAP_RE.findall(source)
    return canonical_url(matches[-1].strip("'\""), js_url) if matches else ""


def analyse(args: argparse.Namespace) -> dict:
    policy = ScopePolicy.from_file(args.scope)
    client = SafeHttpClient(policy, args.timeout, args.max_response_size, args.rate_limit)
    output_dir = Path(args.output_dir)
    js_path = output_dir / "javascript_assets.jsonl"
    findings_path = output_dir / "secret_findings.jsonl"
    maps_path = output_dir / "source_maps.jsonl"
    for output in (js_path, findings_path, maps_path):
        output.write_text("", encoding="utf-8")
    all_resources = read_jsonl(args.resources)
    resources = [r for r in all_resources if r.get("resource_type") == "javascript"]
    # A map is considered only when the controlled crawler observed that exact
    # public URL in a page. This avoids speculative `name.js.map` requests.
    discovered_map_urls = {
        canonical_url(str(resource.get("url") or ""))
        for resource in all_resources if resource.get("resource_type") == "source_map"
    }
    seen_urls: set[str] = set()
    seen_map_urls: set[str] = set()
    stats = {"javascript_assets_analyzed": 0, "source_maps_discovered": 0, "source_maps_analyzed": 0,
             "findings_by_severity": Counter(), "findings_by_type": Counter(), "analysis_errors_timeouts": 0}

    def add_findings(source: str, source_url: str, host: str, file_type: str, original_js_url: str = "") -> list[dict]:
        records = find_secrets(source, source_url, host, file_type, original_js_url)
        now = utcnow()
        for record in records:
            record["first_seen"] = now
            stats["findings_by_severity"][record["severity"]] += 1
            stats["findings_by_type"][record["finding_type"]] += 1
        append_jsonl(findings_path, records)
        return records

    for resource in resources:
        url = canonical_url(str(resource.get("url") or ""))
        if not url or url in seen_urls or not policy.allows_url(url):
            continue
        seen_urls.add(url)
        result = client.fetch(url)
        content_type = result.headers.get("content-type", "")
        is_js = result.status >= 200 and result.status < 300 and not result.error and not result.skipped_reason and looks_like_javascript(content_type, result.final_url or url, result.body)
        js_record = {
            "url": result.final_url or url, "host": urlsplit(result.final_url or url).hostname or "",
            "parent_page": resource.get("parent_page", ""), "status_code": result.status,
            "content_type": content_type, "content_length": len(result.body),
            "hash": sha256_bytes(result.body) if result.body else "", "retrieved_at": utcnow(),
            "source_map": "", "in_scope": True, "is_javascript": is_js,
            "error": result.error or result.skipped_reason,
        }
        if result.error:
            stats["analysis_errors_timeouts"] += 1
        if not is_js:
            append_jsonl(js_path, [js_record])
            continue
        stats["javascript_assets_analyzed"] += 1
        source = result.body.decode("utf-8", errors="replace")
        add_findings(source, js_record["url"], js_record["host"], "JavaScript")
        map_url = source_map_url(source, js_record["url"])
        if not map_url:
            observed_map = canonical_url(js_record["url"] + ".map")
            map_url = observed_map if observed_map in discovered_map_urls else ""
        if args.source_maps and map_url and policy.allows_url(map_url):
            js_record["source_map"] = map_url
            if map_url in seen_map_urls:
                append_jsonl(js_path, [js_record])
                continue
            seen_map_urls.add(map_url)
            stats["source_maps_discovered"] += 1
            map_result = client.fetch(map_url)
            map_record = {
                "url": map_result.final_url or map_url, "original_js_url": js_record["url"],
                "host": urlsplit(map_result.final_url or map_url).hostname or "", "status_code": map_result.status,
                "content_type": map_result.headers.get("content-type", ""), "content_length": len(map_result.body),
                "hash": sha256_bytes(map_result.body) if map_result.body else "", "retrieved_at": utcnow(),
                "sources": 0, "error": map_result.error or map_result.skipped_reason,
            }
            try:
                mapping = json.loads(map_result.body.decode("utf-8", errors="replace"))
                sources = mapping.get("sources", [])
                contents = mapping.get("sourcesContent", [])
                map_record["sources"] = len(sources) if isinstance(sources, list) else 0
                if isinstance(sources, list) and isinstance(contents, list):
                    for index, source_content in enumerate(contents):
                        if not isinstance(source_content, str):
                            continue
                        source_name = str(sources[index]) if index < len(sources) else f"source-{index}"
                        add_findings(source_content, f"{map_record['url']}#{source_name}", map_record["host"], "Source map source", js_record["url"])
                stats["source_maps_analyzed"] += 1
            except (json.JSONDecodeError, UnicodeDecodeError):
                map_record["error"] = map_record["error"] or "invalid source map JSON"
            append_jsonl(maps_path, [map_record])
        append_jsonl(js_path, [js_record])

    stats["requests"] = client.request_count
    stats["findings_by_severity"] = dict(stats["findings_by_severity"])
    stats["findings_by_type"] = dict(stats["findings_by_type"])
    stats_path = output_dir / "analysis_statistics.json"
    stats_path.write_text(json.dumps(stats, indent=2, sort_keys=True), encoding="utf-8")
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze discovered in-scope JavaScript for possible exposed secrets")
    parser.add_argument("--scope", required=True)
    parser.add_argument("--resources", required=True, help="crawl_resources.jsonl from crawler.py")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--source-maps", action="store_true", help="Retrieve only explicitly referenced, in-scope maps")
    parser.add_argument("--max-response-size", type=int, default=2_000_000)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--rate-limit", type=float, default=1.0)
    args = parser.parse_args()
    if args.max_response_size <= 0 or args.timeout <= 0:
        parser.error("max-response-size and timeout must be positive")
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    stats = analyse(args)
    print(f"[+] Analyzed {stats['javascript_assets_analyzed']} JavaScript asset(s)")
    print(f"[+] Secret findings are unverified and safely redacted -> secret_findings.jsonl")


if __name__ == "__main__":
    main()
