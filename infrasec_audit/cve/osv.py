from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import requests

from infrasec_audit.utils.cache import CacheConfig, FileCache


@dataclass
class OsvConfig:
    base_url: str = "https://api.osv.dev/v1/query"
    timeout_seconds: int = 10
    max_retries: int = 3
    backoff_seconds: float = 0.5
    rate_limit_per_second: float = 2.0


class OsvClient:
    def __init__(self, cache: FileCache, config: OsvConfig | None = None) -> None:
        self.cache = cache
        self.config = config or OsvConfig()
        self._last_call = 0.0

    def _throttle(self) -> None:
        interval = 1 / self.config.rate_limit_per_second
        elapsed = time.time() - self._last_call
        if elapsed < interval:
            time.sleep(interval - elapsed)
        self._last_call = time.time()

    def cached_lookup(self, package_name: str, version: str | None, ecosystem: str | None) -> dict[str, Any]:
        key = f"{ecosystem}:{package_name}:{version or 'unknown'}"
        cached = self.cache.get(key)
        return cached or {}

    def query(self, package_name: str, version: str | None, ecosystem: str | None) -> dict[str, Any]:
        key = f"{ecosystem}:{package_name}:{version or 'unknown'}"
        cached = self.cache.get(key)
        if cached:
            return cached

        payload = {"package": {"name": package_name}}
        if ecosystem:
            payload["package"]["ecosystem"] = ecosystem
        if version:
            payload["version"] = version

        for attempt in range(1, self.config.max_retries + 1):
            self._throttle()
            try:
                response = requests.post(
                    self.config.base_url,
                    json=payload,
                    timeout=self.config.timeout_seconds,
                )
                response.raise_for_status()
                data = response.json()
                self.cache.set(key, data)
                return data
            except requests.RequestException:
                if attempt >= self.config.max_retries:
                    break
                time.sleep(self.config.backoff_seconds * attempt)

        return {}


def default_cache(ttl_seconds: int) -> FileCache:
    cache_config = CacheConfig(ttl_seconds=ttl_seconds)
    from infrasec_audit.utils.cache import default_cache_dir

    return FileCache(default_cache_dir(), cache_config)
