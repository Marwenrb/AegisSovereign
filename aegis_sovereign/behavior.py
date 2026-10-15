"""Deterministic behavioural and human-kinematics feature extraction (P4/P6).

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple


def shannon_entropy(values: Sequence[float], bins: int = 16) -> float:
    """Compute Shannon entropy after fixed-width quantisation."""
    if not values:
        return 0.0
    low = min(values)
    high = max(values)
    if high <= low:
        return 0.0
    counts = [0] * max(2, bins)
    width = (high - low) / len(counts)
    for value in values:
        index = min(len(counts) - 1, int((value - low) / width))
        counts[index] += 1
    total = float(len(values))
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def dispersion_ratio(values: Sequence[float]) -> float:
    """Return variance/mean, robust for empty and constant timing series."""
    if not values:
        return 0.0
    mean = sum(values) / len(values)
    if mean <= 0.0:
        return 0.0
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    return variance / mean


def timing_risk(inter_arrivals: Sequence[float]) -> float:
    """Score fixed-interval and over-uniform jitter automation patterns."""
    if len(inter_arrivals) < 3:
        return 0.0
    entropy = shannon_entropy(inter_arrivals)
    dispersion = dispersion_ratio(inter_arrivals)
    fixed = 1.0 if entropy < 0.5 or dispersion < 0.02 else 0.0
    uniform_jitter = 1.0 if entropy > 3.0 and dispersion < 0.25 else 0.0
    return min(1.0, 0.6 * fixed + 0.4 * uniform_jitter)


class SurfaceTransitionGraph:
    """First-order Markov graph for natural navigation transitions."""

    DEFAULT_TRANSITIONS: Mapping[str, Tuple[str, ...]] = {
        "landing": ("registration.create", "signin", "browse"),
        "browse": ("product.view", "checkout", "signin"),
        "product.view": ("checkout", "browse"),
        "signin": ("account", "payout", "recovery"),
        "account": ("payout", "settings", "api.export"),
    }

    def __init__(self, transitions: Mapping[str, Iterable[str]] | None = None) -> None:
        raw = transitions or self.DEFAULT_TRANSITIONS
        self._transitions: Dict[str, Tuple[str, ...]] = {
            key: tuple(value) for key, value in raw.items()
        }

    def risk(self, history: Sequence[str], target: str) -> float:
        if not history:
            return 0.15 if target in {"landing", "browse", "signin"} else 0.65
        previous = history[-1]
        if target in self._transitions.get(previous, ()):
            return 0.0
        if target in {"payout", "checkout", "password_reset", "api.export"}:
            return 0.8
        return 0.25


def fitts_compliance(events: Sequence[Mapping[str, float]]) -> float:
    """Measure whether pointer movement times follow Fitts's law."""
    if len(events) < 3:
        return 0.5
    residuals: List[float] = []
    for event in events:
        distance = max(1.0, float(event.get("distance", 1.0)))
        target = max(1.0, float(event.get("target_width", 1.0)))
        duration = max(0.001, float(event.get("duration_ms", 1.0)))
        predicted = 80.0 + 110.0 * math.log2(distance / target + 1.0)
        residuals.append(abs(duration - predicted) / predicted)
    return max(0.0, min(1.0, 1.0 - sum(residuals) / len(residuals)))


def kinematics_risk(events: Sequence[Mapping[str, float]]) -> float:
    """Detect linear/Bézier synthetic pointer paths while preserving accessibility."""
    if not events:
        return 0.0
    angles = [float(event.get("angle", 0.0)) for event in events]
    tremor = [abs(float(event.get("micro_tremor", 0.0))) for event in events]
    angle_variance = dispersion_ratio([abs(angle) for angle in angles])
    tremor_mean = sum(tremor) / len(tremor)
    synthetic = angle_variance < 0.02 and tremor_mean < 0.01
    return 0.8 if synthetic else 0.0


def touch_risk(events: Sequence[Mapping[str, float]]) -> float:
    if len(events) < 2:
        return 0.0
    pressure = [float(event.get("pressure", 0.0)) for event in events]
    area = [float(event.get("area", 0.0)) for event in events]
    return 0.7 if shannon_entropy(pressure) < 0.5 and shannon_entropy(area) < 0.5 else 0.0


def keystroke_risk(events: Sequence[Mapping[str, float]]) -> float:
    if len(events) < 3:
        return 0.0
    dwell = [float(event.get("dwell_ms", 0.0)) for event in events]
    flight = [float(event.get("flight_ms", 0.0)) for event in events]
    return 0.75 if shannon_entropy(dwell) < 0.5 and shannon_entropy(flight) < 0.5 else 0.0


def behaviour_score(inter_arrivals: Sequence[float], history: Sequence[str], target: str,
                    pointer_events: Sequence[Mapping[str, float]] = (),
                    touch_events: Sequence[Mapping[str, float]] = (),
                    keystrokes: Sequence[Mapping[str, float]] = ()) -> Tuple[float, Dict[str, float]]:
    """Combine timing, transition and kinematic features into a bounded score."""
    features = {
        "timing_entropy": timing_risk(inter_arrivals),
        "surface_transition": SurfaceTransitionGraph().risk(history, target),
        "pointer_kinematics": kinematics_risk(pointer_events),
        "touch_dynamics": touch_risk(touch_events),
        "keystroke_dynamics": keystroke_risk(keystrokes),
    }
    return min(1.0, sum(features.values()) / len(features)), features
