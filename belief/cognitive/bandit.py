"""
belief/cognitive/bandit.py — Thompson Sampling for arm (cwe, bridge) selection.

Fixes B-05 (deep version) from the audit: the old `_decide()` used a
constant novelty=0.8 for unseen beliefs. That meant the "exploration vs
exploitation" tradeoff collapsed to a noop.

This module replaces that hard-coded constant with a proper Thompson
sampling bandit. Each (cwe, bridge) pair is an arm with a Beta(α, β)
posterior over its success probability. At decision time we sample θ
from each posterior and pick the arm with the highest sample.

No external dependency (no scipy). Uses np.random.beta if numpy is
available, else falls back to Python's `random.betavariate` (stdlib).

Data is persisted inside the MemoryEngine's directory as `bandit.json`.
One entry per arm:
    {"arm": "CWE-89:bandit", "alpha": 3, "beta": 1, "pulls": 4, "rewards": 3}
"""
from __future__ import annotations

import json
import logging
import random
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("belief.cognitive.bandit")

try:
    import numpy as np
    _HAVE_NP = True
except Exception:
    _HAVE_NP = False


# ─────────────────────────────────────────────────────────────────

@dataclass
class Arm:
    """One (context_key, action) pair tracked by the bandit.

    α (alpha) and β (beta) are the pseudo-counts of the Beta posterior.
    Both start at 1 (uniform prior).
    """
    arm_id: str          # "CWE-89:bandit" or "CWE-22:path_traversal" etc.
    alpha: float = 1.0   # successes + 1
    beta: float = 1.0    # failures + 1
    pulls: int = 0
    rewards: int = 0

    def sample(self) -> float:
        """Draw θ from the Beta(α, β) posterior."""
        if _HAVE_NP:
            return float(np.random.beta(self.alpha, self.beta))
        return random.betavariate(self.alpha, self.beta)

    def update(self, reward: float) -> None:
        """Update the posterior given a reward in [0, 1].
        reward=1 → success bump, reward=0 → failure bump."""
        reward = max(0.0, min(1.0, reward))
        self.alpha += reward
        self.beta += 1.0 - reward
        self.pulls += 1
        if reward > 0.5:
            self.rewards += 1

    @property
    def mean(self) -> float:
        """Posterior mean (expected success probability)."""
        return self.alpha / (self.alpha + self.beta)

    @property
    def variance(self) -> float:
        """Posterior variance — a proxy for uncertainty."""
        s = self.alpha + self.beta
        return (self.alpha * self.beta) / (s * s * (s + 1))

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Arm":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ─────────────────────────────────────────────────────────────────

class ThompsonBandit:
    """Thompson-Sampling bandit for (cwe, bridge) selection.

    Usage:
        bandit = ThompsonBandit(persistence_dir="~/.belief/memory")
        bandit.load()

        # At decision time:
        score = bandit.sample_score(cwe="CWE-89", bridge="bandit")

        # After outcome is known (from _learn):
        bandit.update(cwe="CWE-89", bridge="bandit", reward=1.0)
        bandit.save()
    """

    def __init__(self, persistence_dir: Optional[str] = None):
        self._arms: Dict[str, Arm] = {}
        self._dir = Path(persistence_dir).expanduser() if persistence_dir else None

    # ── key scheme ──────────────────────────────────────────────

    @staticmethod
    def _arm_id(cwe: str, bridge: str = "") -> str:
        cwe = cwe or "UNKNOWN"
        return f"{cwe}:{bridge}" if bridge else cwe

    # ── sampling ────────────────────────────────────────────────

    def sample_score(self, cwe: str, bridge: str = "") -> float:
        """Return a Thompson-sampled score for this arm. Calling this is
        effectively 'how novel/promising is this arm right now?' in a
        bayesian sense — high variance (uncertain) arms get higher
        samples more often, driving exploration."""
        arm = self._arms.get(self._arm_id(cwe, bridge))
        if arm is None:
            arm = Arm(arm_id=self._arm_id(cwe, bridge))
            self._arms[arm.arm_id] = arm
        return arm.sample()

    def mean_score(self, cwe: str, bridge: str = "") -> float:
        """Return the posterior mean (no exploration)."""
        arm = self._arms.get(self._arm_id(cwe, bridge))
        return arm.mean if arm else 0.5

    def best_arm(self, candidates: List[Tuple[str, str]]) -> Tuple[str, str]:
        """Among (cwe, bridge) candidates, return the one with the
        highest Thompson sample."""
        if not candidates:
            return ("", "")
        best = max(candidates, key=lambda c: self.sample_score(*c))
        return best

    # ── update ──────────────────────────────────────────────────

    def update(self, cwe: str, bridge: str = "", reward: float = 0.0) -> None:
        arm_id = self._arm_id(cwe, bridge)
        arm = self._arms.setdefault(arm_id, Arm(arm_id=arm_id))
        arm.update(reward)

    # ── stats ────────────────────────────────────────────────────

    def stats(self) -> dict:
        if not self._arms:
            return {"arms": 0, "total_pulls": 0, "total_rewards": 0}
        pulls = sum(a.pulls for a in self._arms.values())
        rewards = sum(a.rewards for a in self._arms.values())
        top = sorted(
            self._arms.values(), key=lambda a: a.mean, reverse=True
        )[:5]
        return {
            "arms": len(self._arms),
            "total_pulls": pulls,
            "total_rewards": rewards,
            "overall_success_rate": rewards / pulls if pulls else 0.0,
            "top_arms": [
                {"arm": a.arm_id, "mean": round(a.mean, 3),
                 "pulls": a.pulls, "rewards": a.rewards}
                for a in top
            ],
        }

    # ── persistence ─────────────────────────────────────────────

    def save(self) -> None:
        if not self._dir:
            return
        self._dir.mkdir(parents=True, exist_ok=True)
        path = self._dir / "bandit.json"
        data = {
            "version": 1,
            "arms": {aid: a.to_dict() for aid, a in self._arms.items()},
        }
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.replace(path)

    def load(self) -> None:
        if not self._dir:
            return
        path = self._dir / "bandit.json"
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
            for aid, adict in data.get("arms", {}).items():
                self._arms[aid] = Arm.from_dict(adict)
            logger.info(f"Bandit loaded: {len(self._arms)} arms")
        except Exception as e:
            logger.warning(f"Bandit load failed: {e}")


__all__ = ["Arm", "ThompsonBandit"]
