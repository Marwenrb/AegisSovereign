"""AegisSovereign — defaults and type-safe environment parsers.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)
"""

from __future__ import annotations

import logging
import os
from typing import Mapping

logger = logging.getLogger(__name__)

DEFAULT_FAIL_OPEN_THRESHOLD = 0.02  # 2% of events stay open by default
DEFAULT_SECRET_KEY = "change-me-in-production--generate-with-secrets-token_urlsafe-48"

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}


def env_bool(src: Mapping[str, str], name: str, default: bool) -> bool:
    """Parse a boolean env var tolerantly; fall back to *default* on garbage."""
    raw = src.get(name, os.environ.get(name, "1" if default else "0"))
    if raw is None:
        return default
    text = str(raw).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    logger.warning("Bad boolean for %s=%r; using default %s", name, raw, default)
    return default


def env_int(src: Mapping[str, str], name: str, default: int) -> int:
    """Parse an integer env var; fall back to *default* on garbage."""
    raw = src.get(name, os.environ.get(name, str(default)))
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        logger.warning("Bad integer for %s; using default %s", name, default)
        return default


def env_float(src: Mapping[str, str], name: str, default: float) -> float:
    """Parse a float env var; fall back to *default* on garbage."""
    raw = src.get(name, os.environ.get(name, str(default)))
    try:
        return float(str(raw).strip())
    except (TypeError, ValueError):
        logger.warning("Bad float for %s; using default %s", name, default)
        return default


def env_str(src: Mapping[str, str], name: str, default: str) -> str:
    """Return a string env var (empty-string safe)."""
    raw = src.get(name, os.environ.get(name, default))
    if raw is None:
        return default
    return str(raw)


def env_str_list(src: Mapping[str, str], name: str, default: list[str]) -> list[str]:
    """Parse a comma-separated env var into a clean list of strings."""
    raw = src.get(name, os.environ.get(name))
    if raw is None or str(raw).strip() == "":
        return list(default)
    return [p.strip() for p in str(raw).split(",") if p.strip()]


# Backwards-compatible process-environment helpers (used by tests/scripts).
def _bool(name: str, default: bool) -> bool:
    return env_bool(os.environ, name, default)


def _int(name: str, default: int) -> int:
    return env_int(os.environ, name, default)


def _float(name: str, default: float) -> float:
    return env_float(os.environ, name, default)


def _str_list(name: str, default: list[str]) -> list[str]:
    return env_str_list(os.environ, name, default)
