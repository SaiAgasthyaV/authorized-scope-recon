"""Small stdlib-only HTTP primitives shared by crawler and resource analyser."""
from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass
from typing import Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from scope_normalization import ScopePolicy


def canonical_url(url: str, base: str | None = None) -> str:
    """Resolve a normal link and discard fragments so deduplication is stable."""
    try:
        parsed = urlsplit(urljoin(base or "", url))
        port = parsed.port  # Accessing it validates malformed port values.
    except ValueError:
        return ""
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    if not scheme or not host or parsed.username or parsed.password:
        return ""
    netloc = host if port is None or (scheme == "https" and port == 443) or (scheme == "http" and port == 80) else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    status: int
    headers: Mapping[str, str]
    body: bytes
    error: str = ""
    skipped_reason: str = ""


class RateLimiter:
    """A deliberately simple global limiter: rate is requests per second."""

    def __init__(self, rate_limit: float):
        self.interval = 1.0 / rate_limit if rate_limit > 0 else 0.0
        self.next_allowed = 0.0
        self.lock = threading.Lock()

    def wait(self) -> None:
        if not self.interval:
            return
        with self.lock:
            now = time.monotonic()
            delay = max(0.0, self.next_allowed - now)
            self.next_allowed = max(now, self.next_allowed) + self.interval
        if delay:
            time.sleep(delay)


class SafeHttpClient:
    """GET-only client which refuses redirects that leave the approved scope."""

    def __init__(self, policy: ScopePolicy, timeout: float, max_response_size: int, rate_limit: float):
        self.policy = policy
        self.timeout = timeout
        self.max_response_size = max_response_size
        self.rate_limiter = RateLimiter(rate_limit)
        self.opener = build_opener(_NoRedirect())
        self.request_count = 0
        self._request_lock = threading.Lock()

    def fetch(self, url: str, max_redirects: int = 3) -> FetchResult:
        current = canonical_url(url)
        if not current or not self.policy.allows_url(current):
            return FetchResult(url, current, 0, {}, b"", skipped_reason="out-of-scope URL")

        for _ in range(max_redirects + 1):
            self.rate_limiter.wait()
            request = Request(current, headers={
                "User-Agent": "AuthorizedScopeInventoryCrawler/1.0 (+passive-resource-inventory)",
                "Accept": "text/html,application/javascript,text/javascript,application/json,text/plain,*/*;q=0.1",
            })
            try:
                response = self.opener.open(request, timeout=self.timeout)
            except HTTPError as exc:
                response = exc
            except (URLError, OSError, ValueError) as exc:
                return FetchResult(url, current, 0, {}, b"", error=str(exc))

            with self._request_lock:
                self.request_count += 1
            headers = {key.lower(): value for key, value in response.headers.items()}
            status = int(getattr(response, "status", response.getcode()) or 0)
            location = headers.get("location")
            if status in {301, 302, 303, 307, 308} and location:
                redirected = canonical_url(location, current)
                if not redirected or not self.policy.allows_url(redirected):
                    return FetchResult(url, current, status, headers, b"", skipped_reason="redirect leaves authorized scope")
                current = redirected
                continue

            length_header = headers.get("content-length", "")
            try:
                if length_header and int(length_header) > self.max_response_size:
                    response.close()
                    return FetchResult(url, current, status, headers, b"", skipped_reason="response exceeds configured size")
            except ValueError:
                pass
            body = response.read(self.max_response_size + 1)
            response.close()
            if len(body) > self.max_response_size:
                return FetchResult(url, current, status, headers, b"", skipped_reason="response exceeds configured size")
            return FetchResult(url, current, status, headers, body)
        return FetchResult(url, current, 0, {}, b"", skipped_reason="redirect limit reached")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
