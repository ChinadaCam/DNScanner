"""User configuration + API-key management (persisted JSON).

API keys are read **env-first**, then the config file, and are never hardcoded.
Used by the Settings menu and by external-API checks (reputation, etc.).

Pure stdlib; safe to import anywhere.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

# provider -> environment variable that overrides the stored key
ENV_KEYS = {
    "virustotal": "DNSCANNER_VT_API_KEY",
    "safebrowsing": "DNSCANNER_GSB_API_KEY",
}

DEFAULT_CONFIG: Dict[str, Any] = {
    "disabled_checks": [],          # check keys the user has turned off
    "options": {
        "takeover_same_org_exclusion": False,   # opt-in (per user decision)
        "ct_default_in_extended": True,         # CT passive on in extended scans
        "warn_before_impactful": True,          # confirm AXFR/takeover/etc. in the menu
    },
    "api_keys": {},                 # provider -> key (fallback when no env var)
}

# Checks considered "impactful" enough to warrant a confirmation in the menu.
IMPACTFUL_CHECKS = {"axfr", "takeover", "reputation"}


def config_path() -> Path:
    """Resolve the config file path (override with $DNSCANNER_CONFIG)."""
    override = os.environ.get("DNSCANNER_CONFIG")
    if override:
        return Path(override)
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else (Path.home() / ".config")
    return root / "dnscanner" / "config.json"


class Config:
    """In-memory config backed by a JSON file. Never raises on load."""

    def __init__(self, data: Optional[Dict[str, Any]] = None, path: Optional[Path] = None):
        self.path = Path(path) if path else config_path()
        merged = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy of defaults
        for key, value in (data or {}).items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key].update(value)
            else:
                merged[key] = value
        self.data = merged

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Config":
        p = Path(path) if path else config_path()
        try:
            return cls(json.loads(p.read_text(encoding="utf-8")), path=p)
        except Exception:
            return cls(path=p)

    def save(self) -> str:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        return str(self.path)

    # ---- API keys (env first) -------------------------------------------
    def api_key(self, provider: str) -> Optional[str]:
        env = ENV_KEYS.get(provider)
        if env and os.environ.get(env):
            return os.environ[env]
        return (self.data.get("api_keys") or {}).get(provider)

    def set_api_key(self, provider: str, key: str) -> None:
        self.data.setdefault("api_keys", {})[provider] = key

    # ---- enable / disable checks ----------------------------------------
    def is_enabled(self, check: str) -> bool:
        return check not in (self.data.get("disabled_checks") or [])

    def set_enabled(self, check: str, enabled: bool) -> None:
        disabled = set(self.data.get("disabled_checks") or [])
        if enabled:
            disabled.discard(check)
        else:
            disabled.add(check)
        self.data["disabled_checks"] = sorted(disabled)

    # ---- options --------------------------------------------------------
    def option(self, name: str, default: Any = None) -> Any:
        return (self.data.get("options") or {}).get(name, default)

    def set_option(self, name: str, value: Any) -> None:
        self.data.setdefault("options", {})[name] = value
