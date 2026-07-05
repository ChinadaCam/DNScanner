"""Shared, polite HTTP helper for external APIs.

Adds a User-Agent, a per-host minimum-interval throttle (to respect documented
rate limits), and clean timeouts. ``requests`` is imported lazily, so importing
this module needs no dependencies. Network failures return ``None`` from the
``*_or_none`` helpers rather than raising, so a check never crashes a scan.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse

DEFAULT_UA = "DNScanner/0.3 (+https://github.com/ChinadaCam/DNScanner)"

_last_call: Dict[str, float] = {}
_lock = threading.Lock()


def _throttle(host: str, min_interval: float) -> None:
    if min_interval <= 0:
        return
    with _lock:
        now = time.monotonic()
        wait = min_interval - (now - _last_call.get(host, 0.0))
        if wait > 0:
            time.sleep(wait)
        _last_call[host] = time.monotonic()


def http_get(url: str, timeout: float = 10.0, min_interval: float = 0.0,
             headers: Optional[Dict[str, str]] = None, **kwargs):
    """GET with a User-Agent and optional per-host throttle. May raise."""
    import requests  # lazy
    _throttle(urlparse(url).netloc, min_interval)
    hdrs = {"User-Agent": DEFAULT_UA}
    hdrs.update(headers or {})
    return requests.get(url, timeout=timeout, headers=hdrs, **kwargs)


def get_text_or_none(url: str, timeout: float = 10.0, min_interval: float = 0.0,
                     headers: Optional[Dict[str, str]] = None, **kwargs) -> Optional[str]:
    try:
        return http_get(url, timeout=timeout, min_interval=min_interval,
                        headers=headers, **kwargs).text
    except Exception:
        return None


def get_json_or_none(url: str, timeout: float = 10.0, min_interval: float = 0.0,
                     headers: Optional[Dict[str, str]] = None, **kwargs) -> Optional[Any]:
    try:
        return http_get(url, timeout=timeout, min_interval=min_interval,
                        headers=headers, **kwargs).json()
    except Exception:
        return None
