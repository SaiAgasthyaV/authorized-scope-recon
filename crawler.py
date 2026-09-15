#!/usr/bin/env python3
"""Controlled, GET-only web crawler for in-scope page and JS discovery.

It is intentionally not a content discovery/fuzzing tool. It follows ordinary
HTML links only, stays in the supplied normalized scope, honours robots.txt by
default, and only records resource URLs for later analysis.
"""
from __future__ import annotations

import argparse
import json
import threading
from collections import Counter, deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit
from urllib.robotparser import RobotFileParser

from scope_normalization import ScopePolicy
from web_utils import SafeHttpClient, canonical_url


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_javascript_url(url: str) -> bool:
    return urlsplit(url).path.lower().endswith((".js", ".mjs", ".cjs", ".jsx"))


def classify_resource_url(url: str, script_reference: bool = False) -> str:
    path = urlsplit(url).path.lower()
    if script_reference or path.endswith((".js", ".mjs", ".cjs", ".jsx")):
        return "javascript"
    if path.endswith(".map"):
        return "source_map"
    if path.endswith(".json"):
        return "json"
    if path.endswith(".xml"):
        return "xml"
    if path.endswith((".txt", ".log")):
        return "text"
    if path.endswith((".config", ".conf", ".ini", ".yaml", ".yml")):
        return "configuration"
    return "other"


class _LinkExtractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.pages: set[str] = set()
        self.resources: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "script" and values.get("src"):
            url = canonical_url(values["src"], self.base_url)
            if url:
                self.resources.append((url, "javascript"))
        elif tag.lower() == "a" and values.get("href"):
            url = canonical_url(values["href"], self.base_url)
            if url:
                self.pages.add(url)
                kind = classify_resource_url(url)
                if kind != "other":
                    self.resources.append((url, kind))
        elif tag.lower() in {"link", "img", "source", "iframe"}:
            raw = values.get("href") or values.get("src")
            if raw:
                url = canonical_url(raw, self.base_url)
                if url:
                    kind = classify_resource_url(url, "module" in values.get("rel", "").lower())
                    if kind != "other":
                        self.resources.append((url, kind))


def extract_links_and_resources(html: str, base_url: str) -> tuple[set[str], list[tuple[str, str]]]:
    parser = _LinkExtractor(base_url)
    parser.feed(html)
    return parser.pages, parser.resources


def extract_javascript_urls(html: str, base_url: str) -> set[str]:
    """Public testable helper for script tags and normal page-resource JS links."""
    _, resources = extract_links_and_resources(html, base_url)
    return {url for url, kind in resources if kind == "javascript"}


def looks_like_html(content_type: str, body: bytes) -> bool:
    head = body[:4096].decode("utf-8", errors="ignore").lower()
    return "html" in content_type.lower() or "<html" in head or "<!doctype html" in head


def read_live_urls(path: str) -> list[str]:
    urls: set[str] = set()
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = value.get("final_url") or value.get("url")
            if isinstance(url, str) and canonical_url(url):
                urls.add(canonical_url(url))
    return sorted(urls)


class RobotsCache:
    def __init__(self, client: SafeHttpClient):
        self.client = client
        self.cache: dict[str, RobotFileParser | None] = {}
        self.origin_locks: dict[str, threading.Lock] = {}
        self.registry_lock = threading.Lock()

    def _lock_for(self, origin: str) -> threading.Lock:
        # A short-held lock just to hand out (or create) the per-origin lock.
        with self.registry_lock:
            lock = self.origin_locks.get(origin)
            if lock is None:
                lock = threading.Lock()
                self.origin_locks[origin] = lock
            return lock

    def allows(self, url: str) -> bool:
        parsed = urlsplit(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        with self.registry_lock:
            cached = origin in self.cache
        if not cached:
            # Hold only this origin's lock during the network fetch, so other
            # threads checking *different* origins are never blocked, and two
            # threads checking the *same* origin don't fetch it twice.
            with self._lock_for(origin):
                with self.registry_lock:
                    cached = origin in self.cache
                if not cached:
                    result = self.client.fetch(origin + "/robots.txt", max_redirects=1)
                    if result.status == 200 and result.body:
                        parser = RobotFileParser()
                        parser.set_url(origin + "/robots.txt")
                        parser.parse(result.body.decode("utf-8", errors="ignore").splitlines())
                    else:
                        # Missing/unreadable robots is not treated as a directive.
                        parser = None
                    with self.registry_lock:
                        self.cache[origin] = parser
        with self.registry_lock:
            parser = self.cache[origin]
        return parser.can_fetch("AuthorizedScopeInventoryCrawler", url) if parser else True


def append_jsonl(path: Path, records: Iterable[dict]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def crawl(args: argparse.Namespace) -> dict:
    policy = ScopePolicy.from_file(args.scope)
    client = SafeHttpClient(policy, args.timeout, args.max_response_size, args.rate_limit)
    robots = RobotsCache(client) if args.respect_robots else None
    seed_counts: Counter[str] = Counter()
    seeds = []
    for url in read_live_urls(args.live_urls):
        host = urlsplit(url).hostname or ""
        if policy.allows_url(url) and seed_counts[host] < args.max_pages:
            seeds.append(url)
            seed_counts[host] += 1
    stats: dict = {
        "started_at": utcnow(), "hosts_crawled": 0, "pages_visited": 0,
        "javascript_assets_discovered": 0, "resources_discovered": 0,
        "errors_timeouts": 0, "skipped_out_of_scope_urls": 0,
        "skipped_urls": Counter(), "requests": 0,
    }
    page_path = Path(args.output_dir) / "crawl_pages.jsonl"
    resource_path = Path(args.output_dir) / "crawl_resources.jsonl"
    for output in (page_path, resource_path):
        output.write_text("", encoding="utf-8")

    queue: deque[tuple[str, int, str]] = deque((url, 0, "") for url in seeds)
    queued = set(seeds)
    page_counts: Counter[str] = Counter(urlsplit(url).hostname or "" for url in seeds)
    js_counts: Counter[str] = Counter()
    seen_resources: set[str] = set()
    crawled_hosts: set[str] = set()

    def worker(url: str, depth: int, parent: str) -> tuple[dict, set[str], list[tuple[str, str, str]]]:
        if robots and not robots.allows(url):
            record = {
                "url": url, "requested_url": url, "host": urlsplit(url).hostname or "",
                "depth": depth, "parent_page": parent, "status_code": 0,
                "content_type": "", "content_length": 0, "retrieved_at": utcnow(),
                "error": "", "skipped_reason": "disallowed by robots.txt",
            }
            return (record, set(), [])
        result = client.fetch(url)
        record = {
            "url": result.final_url or url, "requested_url": url, "host": urlsplit(result.final_url or url).hostname or "",
            "depth": depth, "parent_page": parent, "status_code": result.status,
            "content_type": result.headers.get("content-type", ""), "content_length": len(result.body),
            "retrieved_at": utcnow(), "error": result.error, "skipped_reason": result.skipped_reason,
        }
        if result.error or result.skipped_reason or not looks_like_html(record["content_type"], result.body):
            return record, set(), []
        body = result.body.decode("utf-8", errors="replace")
        links, resources = extract_links_and_resources(body, record["url"])
        return record, links, [(resource_url, kind, record["url"]) for resource_url, kind in resources]

    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        in_flight: dict = {}

        def top_up() -> None:
            # Keep the pool saturated: submit new work the instant a slot frees up,
            # rather than waiting for an entire batch to finish (which lets a single
            # slow/unresponsive host stall every other worker in its batch).
            while queue and len(in_flight) < args.concurrency:
                url, depth, parent = queue.popleft()
                in_flight[executor.submit(worker, url, depth, parent)] = None

        top_up()
        while in_flight:
            done, _ = wait(in_flight.keys(), return_when=FIRST_COMPLETED)
            for future in done:
                del in_flight[future]
                page, links, resources = future.result()
                append_jsonl(page_path, [page])
                host = page["host"]
                if page["error"]:
                    stats["errors_timeouts"] += 1
                if page["skipped_reason"]:
                    stats["skipped_urls"][page["skipped_reason"]] += 1
                    if "scope" in page["skipped_reason"]:
                        stats["skipped_out_of_scope_urls"] += 1
                    continue
                stats["pages_visited"] += 1
                crawled_hosts.add(host)
                resource_records = []
                for resource_url, kind, parent_url in resources:
                    if not policy.allows_url(resource_url):
                        stats["skipped_out_of_scope_urls"] += 1
                        stats["skipped_urls"]["resource outside authorized scope"] += 1
                        continue
                    if resource_url in seen_resources:
                        continue
                    if kind == "javascript" and js_counts[urlsplit(resource_url).hostname] >= args.max_js:
                        stats["skipped_urls"]["per-host JavaScript limit"] += 1
                        continue
                    seen_resources.add(resource_url)
                    if kind == "javascript":
                        js_counts[urlsplit(resource_url).hostname] += 1
                    resource_records.append({
                        "url": resource_url, "host": urlsplit(resource_url).hostname or "", "parent_page": parent_url,
                        "resource_type": kind, "in_scope": True, "discovered_at": utcnow(),
                    })
                append_jsonl(resource_path, resource_records)
                stats["resources_discovered"] += len(resource_records)
                stats["javascript_assets_discovered"] = sum(js_counts.values())

                if page["depth"] >= args.max_depth:
                    continue
                for link in links:
                    if not policy.allows_url(link):
                        stats["skipped_out_of_scope_urls"] += 1
                        continue
                    link_host = urlsplit(link).hostname or ""
                    if link not in queued and page_counts[link_host] < args.max_pages:
                        queued.add(link)
                        page_counts[link_host] += 1
                        queue.append((link, page["depth"] + 1, page["url"]))
                    elif link not in queued:
                        stats["skipped_urls"]["per-host page limit"] += 1
            top_up()

    stats["hosts_crawled"] = len(crawled_hosts)
    stats["requests"] = client.request_count
    stats["completed_at"] = utcnow()
    stats["skipped_urls"] = dict(stats["skipped_urls"])
    with (Path(args.output_dir) / "crawl_statistics.json").open("w", encoding="utf-8") as handle:
        json.dump(stats, handle, indent=2, sort_keys=True)
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Crawl only authorized web pages to discover public resources")
    parser.add_argument("--scope", required=True, help="normalized_scope.json from parse_scope.py")
    parser.add_argument("--live-urls", required=True, help="httpx JSONL output")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--max-pages", type=int, default=25, help="Maximum pages scheduled per host")
    parser.add_argument("--max-js", type=int, default=50, help="Maximum JavaScript assets recorded per host")
    parser.add_argument("--max-response-size", type=int, default=2_000_000)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--rate-limit", type=float, default=1.0, help="Global GET requests per second")
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument("--respect-robots", action=argparse.BooleanOptionalAction, default=True)
    args = parser.parse_args()
    if min(args.max_depth, args.max_pages, args.max_js, args.max_response_size, args.concurrency) < 0 or args.timeout <= 0:
        parser.error("limits must be non-negative, and timeout must be positive")
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    stats = crawl(args)
    print(f"[+] Crawled {stats['pages_visited']} page(s) on {stats['hosts_crawled']} host(s)")
    print(f"[+] Discovered {stats['javascript_assets_discovered']} JavaScript asset(s) -> crawl_resources.jsonl")


if __name__ == "__main__":
    main()