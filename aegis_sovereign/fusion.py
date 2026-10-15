"""Log-odds fusion math for the calibrated ensemble (P7 - AegisSovereign).

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List

# Prior log-odds (b0). Slightly benign prior: most traffic is legitimate.
B0 = -0.35

# Default family weights (shadow-tuned; sum ~ 1.0 for stable calibration).
DEFAULT_FAMILY_WEIGHTS: Dict[str, float] = {
    "network": 0.22,
    "transport": 0.14,
    "client": 0.26,
    "identity": 0.18,
    "behaviour": 0.06,
    "graph": 0.14,
}

# Calibration: map a raw fused log-odds to a calibrated probability.
# Learned via Platt scaling in shadow mode.
PLATT_A = 1.0
PLATT_B = 0.0


def _log_odds(score: float) -> float:
    """Log-odds of a probability in (0,1)."""
    s = max(0.0001, min(0.9999, score))
    return math.log(s / (1.0 - s))


def _sigmoid(log_odds: float) -> float:
    return 1.0 / (1.0 + math.exp(-log_odds))


def _calibrated_probability(log_odds: float) -> float:
    """Platt-scaled calibrated probability."""
    calibrated = PLATT_A * log_odds + PLATT_B
    return min(0.9999, max(0.0001, _sigmoid(calibrated)))


def _family_log_odds(score: float, weight: float) -> float:
    """Convert a family score to a weighted log-odds contribution."""
    raw = _log_odds(score)
    return raw * weight


@dataclass(frozen=True, slots=True)
class FamilyEvidence:
    """A single evidence family's contribution to the fusion."""

    family: str
    score: float = 0.0
    features: Dict[str, float] = field(default_factory=dict)
    log_odds: float = 0.0
    weight: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "family": self.family,
            "score": self.score,
            "features": self.features,
            "log_odds": round(self.log_odds, 4),
            "weight": self.weight,
        }


class CalibratedEnsemble:
    """Log-odds fusion of independent evidence families."""

    def __init__(self, prior_b0: float = B0, base_weights: dict | None = None):
        self.b0 = prior_b0
        self.base_weights = dict(DEFAULT_FAMILY_WEIGHTS)
        if base_weights:
            self.base_weights.update(base_weights)

    def fuse(
        self,
        *families: FamilyEvidence,
        route: str = "",
    ) -> tuple[float, List[FamilyEvidence], float]:
        total_log_odds = self.b0
        resolved: List[FamilyEvidence] = []
        for fam in families:
            w = self.base_weights.get(fam.family, 0.0)
            contribution = _family_log_odds(fam.score, w)
            total_log_odds += contribution
            resolved.append(FamilyEvidence(fam.family, fam.score, dict(fam.features), contribution, w))
        calibrated = _calibrated_probability(total_log_odds)
        return calibrated, resolved, total_log_odds

    def make_family(self, name: str, score: float, features: dict | None = None) -> FamilyEvidence:
        return FamilyEvidence(family=name, score=score, features=features or {})
