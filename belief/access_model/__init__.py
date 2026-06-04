"""Conservative access-control hypothesis model for BELIEF."""

from .heuristics import infer_access_hypotheses_from_source_tree
from .models import (
    AccessHypothesis,
    Actor,
    AuthorizationEvidence,
    ObjectAction,
    ProtectedObject,
)

__all__ = [
    "AccessHypothesis",
    "Actor",
    "AuthorizationEvidence",
    "ObjectAction",
    "ProtectedObject",
    "infer_access_hypotheses_from_source_tree",
]
