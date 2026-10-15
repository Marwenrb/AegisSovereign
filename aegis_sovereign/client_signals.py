"""AegisSovereign P3 - signals bundle, fingerprint, coherence part 1."""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Tuple

logger = logging.getLogger(__name__)

POPULATION_SAMPLES = {"sample_size": 120_000, "fingerprint_collections": 1}
_APPLE_FONTS = {"sf pro", "san francisco", "helvetica neue", "menlo"}
_WINDOWS_CODECS = {"h264", "hevc", "aac", "mp3", "vp9", "av1"}
_HEADLESS = {"0x0", "0x0x0", "800x600x0", "1024x768x0"}
_LANG_TZ: Dict[str, Tuple[str, ...]] = {
    "fr": ("Europe/Paris",),
    "de": ("Europe/Berlin", "Europe/Vienna", "Europe/Zurich"),
    "es": ("Europe/Madrid", "America/Mexico_City"),
    "it": ("Europe/Rome",),
    "pt": ("Europe/Lisbon", "America/Sao_Paulo"),
    "en": ("America/New_York", "Europe/London"),
    "ar": ("Africa/Cairo", "Asia/Dubai"),
    "ja": ("Asia/Tokyo",),
    "zh": ("Asia/Shanghai",),
    "ko": ("Asia/Seoul",),
    "hi": ("Asia/Kolkata",),
}


@dataclass(slots=True)
class ClientSignals:
    """The evidence bundle that the coherence engine evaluates."""

    user_agent: str = ""
    platform: str = ""
    languages: List[str] = field(default_factory=list)
    timezone: str = ""
    screen_geometry: str = ""
    color_depth: str = ""
    fonts: Iterable[str] = ()
    gpu_renderers: Iterable[str] = ()
    codecs: Iterable[str] = ()
    webdriver: bool = False
    input_modality: str = ""
    navigator: Any = None
    js_available: bool = True

    def as_dict(self) -> Dict[str, Any]:
        return {
            "user_agent": self.user_agent,
            "platform": self.platform,
            "languages": list(self.languages),
            "timezone": self.timezone,
            "screen_geometry": self.screen_geometry,
            "color_depth": self.color_depth,
            "fonts": list(self.fonts),
            "gpu_renderers": list(self.gpu_renderers),
            "codecs": list(self.codecs),
            "webdriver": self.webdriver,
            "input_modality": self.input_modality,
        }


def fingerprint_hash(signals: ClientSignals) -> str:
    """Deterministic 64-bit fingerprint id from a client-signals bundle."""
    parts = [
        signals.user_agent[:80],
        signals.platform[:40],
        signals.timezone[:30],
        signals.screen_geometry,
        ",".join(sorted(signals.languages)),
        ",".join(sorted(signals.fonts))[:120],
        ",".join(sorted(signals.gpu_renderers))[:120],
        ",".join(sorted(signals.codecs))[:120],
        signals.input_modality,
        str(signals.webdriver),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


class CoherenceEngine:
    """Evaluates cross-signal agreement."""

    SCORES: Dict[str, float] = {
        "user_agent_platform": 0.20,
        "language_timezone": 0.15,
        "screen_geometry": 0.15,
        "font_codec_set": 0.20,
        "gpu_renderer": 0.15,
        "input_modality": 0.15,
    }

    def score(self, signals: ClientSignals) -> Dict[str, Any]:
        checks = {
            "user_agent_platform": self._ua_platform_agree(signals),
            "language_timezone": self._lang_tz_agree(signals),
            "screen_geometry": self._screen_agree(signals),
            "font_codec_set": self._font_codec_agree(signals),
            "gpu_renderer": self._gpu_agree(signals),
            "input_modality": self._input_agree(signals),
        }
        total = sum(self.SCORES.values()) or 1.0
        weighted = sum(self.SCORES[k] * float(v) for k, v in checks.items())
        comp = round(min(1.0, max(0.0, weighted / total)), 4)
        return {
            "per_signal": checks,
            "composite": comp,
            "all_checks_pass": all(v >= 0.5 for v in checks.values()),
        }

    @staticmethod
    def _ua_platform_agree(s: ClientSignals) -> float:
        ua = (s.user_agent or "").lower()
        plat = (s.platform or "").lower()
        if "webdriver" in ua or "headless" in ua or "cdp" in ua or s.webdriver:
            return 0.0
        if not plat:
            return 0.5
        if plat in ua:
            return 1.0
        if "win" in plat and "windows" in ua:
            return 1.0
        if "mac" in plat and ("macintosh" in ua or "mac os" in ua):
            return 1.0
        if "linux" in plat and ("linux" in ua or "x11" in ua):
            return 1.0
        return 0.2

    @staticmethod
    def _lang_tz_agree(s: ClientSignals) -> float:
        if not s.timezone or not s.languages:
            return 0.5
        tz = s.timezone
        langs = [str(x).lower().split("-")[0].split("_")[0] for x in s.languages]
        for lang in langs:
            zones = _LANG_TZ.get(lang)
            if not zones:
                continue
            for z in zones:
                if z.lower() in tz.lower() or tz.lower() in z.lower():
                    return 1.0
            if tz.split("/")[0].lower() in {z.split("/")[0].lower() for z in zones}:
                return 0.7
        if langs and langs[0] in _LANG_TZ:
            return 0.2
        return 0.5

    @staticmethod
    def _screen_agree(s: ClientSignals) -> float:
        geo = (s.screen_geometry or "").strip().lower().replace(" ", "")
        if not geo:
            return 0.5
        if geo in _HEADLESS:
            return 0.0
        m = re.match(r"(\d+)[x*,](\d+)(?:[x*,](\d+))?", geo)
        if not m:
            return 0.5
        try:
            w, h = int(m.group(1)), int(m.group(2))
            depth = int(m.group(3)) if m.group(3) else 24
        except ValueError:
            return 0.5
        if w <= 0 or h <= 0:
            return 0.0
        if w > 7680 or h > 4320 or depth not in {8, 16, 24, 30, 32}:
            return 0.2
        return 1.0

    @staticmethod
    def _font_codec_agree(s: ClientSignals) -> float:
        ua = (s.user_agent or "").lower()
        fonts = {str(f).lower() for f in (s.fonts or [])}
        codecs = {str(c).lower() for c in (s.codecs or [])}
        score = 1.0
        if ("windows" in ua or "linux" in ua) and fonts & _APPLE_FONTS:
            score -= 0.5
        if s.js_available and not codecs:
            score -= 0.4
        elif codecs and not (codecs & _WINDOWS_CODECS) and s.js_available:
            score -= 0.2
        return round(max(0.0, min(1.0, score)), 4)

    @staticmethod
    def _gpu_agree(s: ClientSignals) -> float:
        rs = [str(x).lower() for x in (s.gpu_renderers or [])]
        if not rs:
            return 0.5
        if any(r in {"swiftshader", "llvmpipe", "softpipe"} for r in rs):
            return 0.0
        ua_platform = f"{s.user_agent} {s.platform}".lower()
        if any("apple m3" in renderer or "m3 gpu" in renderer for renderer in rs) and (
                "linux" in ua_platform or "windows nt" in ua_platform):
            return 0.0
        if any("angle" in r or "metal" in r for r in rs):
            return 1.0
        return 0.6

    @staticmethod
    def _input_agree(s: ClientSignals) -> float:
        return 1.0 if s.input_modality in {"mouse", "keyboard", "touch"} else 0.5


class PopulationRarity:
    """Thread-safe fingerprint commonality scorer with sliding-window TTL."""

    def __init__(
        self,
        cohort_size: int = 120_000,
        anomaly_window: float = 30.0,
        max_entries: int = 50_000,
    ) -> None:
        import threading as _th

        self.cohort_size = cohort_size
        self.anomaly_window = anomaly_window
        self.max_entries = max_entries
        self._lock = _th.RLock()
        self._freq: Dict[str, int] = {}
        self._last_seen: Dict[str, float] = {}

    def register(self, fingerprint_id: str, now: float) -> None:
        with self._lock:
            self._freq[fingerprint_id] = self._freq.get(fingerprint_id, 0) + 1
            self._last_seen[fingerprint_id] = float(now)
            self._prune_locked(float(now))

    def score(self, fingerprint_id: str, now: float) -> float:
        with self._lock:
            self._prune_locked(float(now))
            count = self._freq.get(fingerprint_id, 0)
        if count == 0:
            return 0.75
        if count > 100:
            return 0.85
        if count < 5:
            return 0.45
        return 0.02 * (100 - count) / 100.0

    def _prune_locked(self, now: float) -> None:
        stale = [k for k, ts in self._last_seen.items() if now - ts > self.anomaly_window * 86400.0]
        for k in stale:
            self._freq.pop(k, None)
            self._last_seen.pop(k, None)
        if len(self._freq) > self.max_entries:
            ordered = sorted(self._last_seen.items(), key=lambda kv: kv[1])
            for k, _ in ordered[: len(self._freq) - self.max_entries]:
                self._freq.pop(k, None)
                self._last_seen.pop(k, None)
