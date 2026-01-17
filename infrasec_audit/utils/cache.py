from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CacheConfig:
    ttl_seconds: int = 60 * 60 * 24


class FileCache:
    def __init__(self, cache_dir: Path, config: CacheConfig | None = None) -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.config = config or CacheConfig()

    def _path_for(self, key: str) -> Path:
        safe_key = key.replace("/", "_")
        return self.cache_dir / f"{safe_key}.json"

    def get(self, key: str) -> dict | None:
        path = self._path_for(key)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
        if time.time() - payload.get("timestamp", 0) > self.config.ttl_seconds:
            return None
        return payload.get("data")

    def set(self, key: str, data: dict) -> None:
        payload = {"timestamp": time.time(), "data": data}
        self._path_for(key).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    if base:
        return Path(base) / "infrasec-audit"
    return Path.home() / ".cache" / "infrasec-audit"
