"""Named reportability presets.

The MVP exposes one conservative preset and keeps room for future tuning
without changing CLI flags.
"""

from __future__ import annotations


CONSERVATIVE_PRESET = {
    "reportable_candidate": 80,
    "needs_manual_validation": 50,
    "weak_signal": 20,
}


__all__ = ["CONSERVATIVE_PRESET"]
