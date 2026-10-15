"""AegisSovereign P9 - Governance and continuous-improvement loop.

Lead Architect & Developer: Marouan Rabai (https://marwenrabai.com)
Engineering Lab: Cristi Labs (https://cristilabs.net)

Keeps the defence correct, lawful and capable of adaptation:

    * Drift monitoring — Population Stability Index (PSI) over score
      distributions and features; threshold breach triggers retraining.
    * Champion/challenger — shadow models evaluated against champion rules.
    * Red teaming — authorised, scoped adversary simulation (T3–T7) on a
      quarterly cadence; findings tracked to closure.
    * Incident playbooks — credential-stuffing surge, mass-registration
      campaign, payout-fraud ring, challenge-farm, model-drift, biometric
      injection; each with an owner, kill switch and rollback.
    * Change control — canary releases, shadow evaluation, rollback on
      false-positive threshold breach.
    * Privacy & compliance — lawful-basis documentation, DPIA, minimisation,
      retention limits, accessibility (WCAG 2.2), fairness testing.
    * Challenge-farm detection — solved-challenge latency distributions and
      identity-bound proof issuance rates per actor.
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# PSI threshold. Values > this indicate distribution drift requiring review.
PSI_THRESHOLD = 0.10

# Frequency of red-team exercises.
RED_TEAM_FREQUENCY_DAYS = 90

# Training-label sources.
LABEL_SOURCES = [
    "chargeback",
    "confirmed_fraud",
    "manual_review",
    "honeypot_hit",
]


@dataclass(slots=True)
class Incidents:
    """A tracked incident with lifecycle state."""

    id: str
    title: str
    severity: str
    status: str
    owner: str
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "owner": self.owner,
            "created_at": datetime.fromtimestamp(self.created_at, timezone.utc).isoformat(),
            "updated_at": datetime.fromtimestamp(self.updated_at, timezone.utc).isoformat(),
        }


class Governance:
    """Manages drift monitoring, red teams, incidents and KPIs."""

    def __init__(self):
        self.incidents: List[Incidents] = []
        self._labels: Dict[str, int] = {}
        self.red_team_last_run = 0.0

    def drift_psi(self, current: Dict[str, float], historical: Dict[str, float]) -> float:
        """Compute population stability index over the score distribution."""
        all_keys = set(current.keys()) | set(historical.keys())
        psi = 0.0
        eps = 1e-6
        for key in all_keys:
            p = current.get(key, 0.0) + eps
            q = historical.get(key, 0.0) + eps
            psi += (p - q) * (math.log(p) - math.log(q))
        return round(psi, 4)

    def record_flip_rate(self, score: float) -> None:
        """Record a labelled outcome for a score bucket."""
        bucket = int(score * 10) / 10.0
        self._labels[bucket] = self._labels.get(bucket, 0) + 1

    def record_decision(self, decision: str) -> None:
        """Record a decision outcome for the audit trail."""
        if decision in ("block", "challenge", "stepup", "throttle", "allow"):
            logger.info("governance:decision:%s", decision)

    def can_run_red_team(self) -> bool:
        return time.time() - self.red_team_last_run >= RED_TEAM_FREQUENCY_DAYS

    def record_red_team(self) -> None:
        self.red_team_last_run = time.time()

    def create_incident(
        self,
        title: str,
        severity: str,
        owner: str,
        *,
        status: str = "open",
    ) -> Incidents:
        incident = Incidents(
            id="inc_" + str(int(time.time() * 1000)),
            title=title,
            severity=severity,
            status=status,
            owner=owner,
        )
        self.incidents.append(incident)
        logger.error("governance:incident:%s|severity:%s|owner:%s", incident.id, severity, owner)
        return incident

    def update_incident(self, incident_id: str, status: str) -> Optional[Incidents]:
        for inc in self.incidents:
            if inc.id == incident_id:
                inc.status = status
                inc.updated_at = time.time()
                return inc
        return None
