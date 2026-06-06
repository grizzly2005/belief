"""Target classification for local BELIEF orchestration."""

from .classifier import classify_target
from .models import TargetProfile

__all__ = ["TargetProfile", "classify_target"]
