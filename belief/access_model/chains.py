"""Convert access hypotheses into lightweight validation chains."""

from __future__ import annotations

from belief.tools.schemas import AttackPath, RequestStep

from .models import AccessHypothesis


def hypotheses_to_attack_paths(hypotheses: list[AccessHypothesis]) -> list[AttackPath]:
    paths = []
    for hyp in hypotheses:
        route = hyp.route or "/"
        paths.append(AttackPath(
            source_tool="belief_access_model",
            title=hyp.title,
            steps=[
                RequestStep(method="SETUP", path=route, actor="User A", produces=["object_id"]),
                RequestStep(method="REPLAY", path=route, actor="User B", consumes=["object_id"]),
            ],
            hypothesis="Same-privilege actor may access another actor's object unless owner/tenant scope exists.",
            evidence_needed=list(hyp.validation_steps),
            risk=hyp.confidence,
        ))
    return paths


__all__ = ["hypotheses_to_attack_paths"]
