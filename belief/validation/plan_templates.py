"""Safe strategy templates for evidence-guided validation plans."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .plan_models import ValidationOracle, ValidationStimulus

BASE_PREREQUISITES = (
    "Confirm explicit authorization for the pinned target revision.",
    "Use an isolated fixture with rollback and no production data.",
    "Record baseline functional behavior before security counterfactuals.",
)

STOP_CONDITIONS = (
    "Stop when one benign marker proves a policy bypass in isolation.",
    "Return inconclusive when the entrypoint or fixture cannot be reproduced.",
    "Stop at the configured case budget without automatic scope expansion.",
)


def _stimulus(
    kind: str,
    description: str,
    hint: str = "",
    transforms: Sequence[str] = (),
) -> ValidationStimulus:
    return ValidationStimulus(kind, description, hint, tuple(transforms))


def _oracle(
    kind: str,
    expected: str,
    failure: str,
    evidence: Sequence[str],
) -> ValidationOracle:
    return ValidationOracle(kind, expected, failure, tuple(evidence))


def _functional_oracle() -> ValidationOracle:
    return _oracle(
        "functional_baseline",
        "The valid baseline remains functionally correct.",
        "The validation setup breaks or changes the valid baseline behavior.",
        ("baseline_input", "baseline_result", "expected_result"),
    )


def strategy_spec(case_type: str, status: str) -> dict[str, Any]:
    """Return the bounded validation strategy for one audit case family."""

    if status in {"protected", "false_positive_likely"}:
        return {
            "strategy": "defensive_regression",
            "objective": (
                "Verify that the mined guard dominates the same value and "
                "sink at runtime."
            ),
            "prerequisites": BASE_PREREQUISITES,
            "stimuli": (
                _stimulus("valid_baseline", "Exercise valid behavior."),
                _stimulus(
                    "guard_counterfactual",
                    "Exercise a benign unsafe-equivalent input.",
                ),
            ),
            "oracles": (
                _oracle(
                    "guard_enforcement",
                    (
                        "The same-value guard precedes and blocks the "
                        "sensitive sink."
                    ),
                    (
                        "The sink is reached through a bypass, late guard, "
                        "or different value."
                    ),
                    (
                        "guard_line",
                        "guarded_value",
                        "sink_line",
                        "sink_reached",
                    ),
                ),
                _oracle(
                    "functional_non_regression",
                    (
                        "Valid behavior remains functional while the "
                        "counterfactual is blocked."
                    ),
                    (
                        "The guard is absent, bypassed, or blocks every "
                        "valid baseline."
                    ),
                    ("baseline_result", "counterfactual_result"),
                ),
            ),
        }

    specs = {
        "path_traversal_possible": (
            "property_guided_path_boundary",
            "Determine whether controlled path material can escape the allowed root.",
            (
                _stimulus(
                    "baseline",
                    "Use an in-bound sentinel path.",
                    "nested/marker.txt",
                ),
                _stimulus(
                    "boundary_counterfactual",
                    "Apply benign normalization and boundary forms.",
                    "../marker.txt",
                    (
                        "dot_segment",
                        "encoded_separator",
                        "absolute_path",
                        "symlink_fixture",
                    ),
                ),
            ),
            (
                _oracle(
                    "path_boundary_invariant",
                    (
                        "Every accepted resolved path remains under the "
                        "allowed root."
                    ),
                    (
                        "A sentinel outside the root is read, written, "
                        "listed, or disclosed."
                    ),
                    (
                        "raw_input",
                        "resolved_path",
                        "allowed_root",
                        "sink_invocation",
                    ),
                ),
            ),
        ),
        "idor_bola_possible": (
            "stateful_authorization_differential",
            (
                "Keep the principal fixed and vary only resource or tenant "
                "identity."
            ),
            (
                _stimulus(
                    "owned_resource_baseline",
                    "Access a resource owned by principal A.",
                ),
                _stimulus(
                    "ownership_counterfactual",
                    "Substitute a foreign resource identifier.",
                    transforms=(
                        "same_tenant",
                        "cross_tenant",
                        "alternate_identifier",
                    ),
                ),
            ),
            (
                _oracle(
                    "authorization_differential",
                    "Foreign resources are denied before the sensitive sink.",
                    (
                        "A foreign resource is returned, changed, deleted, "
                        "or disclosed."
                    ),
                    (
                        "principal_id",
                        "tenant_id",
                        "resource_id",
                        "response_status",
                    ),
                ),
                _oracle(
                    "state_invariant",
                    "Denied operations leave foreign state unchanged.",
                    "Any unauthorized state transition is observed.",
                    ("state_before", "state_after", "audit_log_entry"),
                ),
            ),
        ),
        "command_injection_possible": (
            "argument_boundary_differential",
            "Verify that controlled command data remains one inert argument.",
            (
                _stimulus(
                    "argument_baseline",
                    "Record a normal argument with spaces.",
                ),
                _stimulus(
                    "argument_counterfactual",
                    "Apply inert quoting and metacharacter sentinels.",
                    transforms=(
                        "quote_boundary",
                        "metacharacter",
                        "newline",
                    ),
                ),
            ),
            (
                _oracle(
                    "process_invocation_shape",
                    (
                        "Executable, argv structure, and shell mode remain "
                        "fixed."
                    ),
                    (
                        "Input changes executable, argv count, shell mode, "
                        "or starts another operation."
                    ),
                    (
                        "executable",
                        "argv",
                        "shell_flag",
                        "side_effect_attempts",
                    ),
                ),
            ),
        ),
        "ssrf_possible": (
            "mocked_network_policy_differential",
            (
                "Test post-parse and post-resolution destination policy "
                "using recording fakes."
            ),
            (
                _stimulus(
                    "allowed_destination_baseline",
                    "Use an allowlisted .invalid host.",
                ),
                _stimulus(
                    "destination_counterfactual",
                    "Apply denied address classes and parser differentials.",
                    transforms=(
                        "redirect",
                        "userinfo",
                        "alternate_ip",
                        "rebinding",
                    ),
                ),
            ),
            (
                _oracle(
                    "network_policy",
                    (
                        "Only allowed resolved destinations reach the "
                        "mocked transport."
                    ),
                    "A denied address or redirect reaches the transport.",
                    (
                        "raw_url",
                        "parsed_url",
                        "resolved_addresses",
                        "redirect_chain",
                    ),
                ),
            ),
        ),
        "sql_injection_possible": (
            "query_parameterization_differential",
            (
                "Verify that controlled values remain bound data and do not "
                "alter query structure."
            ),
            (
                _stimulus(
                    "bound_value_baseline",
                    "Record a normal bound value.",
                ),
                _stimulus(
                    "syntax_counterfactual",
                    "Apply inert quote, wildcard, and comment-like sentinels.",
                    transforms=(
                        "quote",
                        "wildcard",
                        "comment",
                        "unicode_equivalent",
                    ),
                ),
            ),
            (
                _oracle(
                    "query_shape_invariant",
                    (
                        "The query template stays fixed and untrusted values "
                        "remain parameters."
                    ),
                    (
                        "A mutation changes syntax, operator structure, rows, "
                        "or statement count."
                    ),
                    (
                        "query_template",
                        "bound_parameters",
                        "statement_count",
                        "row_ids",
                    ),
                ),
            ),
        ),
        "xss_possible": (
            "contextual_output_encoding",
            (
                "Verify encoding for the actual HTML, attribute, URL, or "
                "script context."
            ),
            (
                _stimulus(
                    "context_marker",
                    "Insert inert tag-like and quote-boundary markers.",
                    transforms=(
                        "html_text",
                        "attribute",
                        "url_component",
                        "script_string",
                    ),
                ),
            ),
            (
                _oracle(
                    "output_context",
                    (
                        "The marker remains data and creates no executable "
                        "context."
                    ),
                    (
                        "The marker creates a node, attribute, URL target, or "
                        "executable context."
                    ),
                    ("rendered_fragment", "parsed_nodes", "output_context"),
                ),
            ),
        ),
        "unsafe_deserialization_possible": (
            "safe_deserialization_policy",
            (
                "Verify authentication, type restrictions, and absence of "
                "side effects."
            ),
            (
                _stimulus(
                    "trusted_baseline",
                    "Load an allowlisted local fixture.",
                ),
                _stimulus(
                    "policy_counterfactual",
                    "Use unsigned, wrong-type, and extra-field fixtures.",
                    transforms=(
                        "unsigned",
                        "wrong_type",
                        "unexpected_field",
                    ),
                ),
            ),
            (
                _oracle(
                    "deserialization_policy",
                    (
                        "Only authenticated allowlisted types are "
                        "materialized without side effects."
                    ),
                    (
                        "An untrusted type or file, process, or network side "
                        "effect is observed."
                    ),
                    (
                        "signature_result",
                        "materialized_type",
                        "side_effect_attempts",
                    ),
                ),
            ),
        ),
        "hardcoded_secret_possible": (
            "secret_provenance_verification",
            (
                "Classify the literal locally without contacting an external "
                "service."
            ),
            (
                _stimulus(
                    "provenance_review",
                    "Trace declaration and runtime use by redacted hash.",
                ),
            ),
            (
                _oracle(
                    "secret_provenance",
                    (
                        "The report distinguishes active, placeholder, test, "
                        "and inconclusive values."
                    ),
                    (
                        "Production-reachable secret material is embedded "
                        "outside an approved store."
                    ),
                    (
                        "redacted_hash",
                        "declaration_site",
                        "runtime_use",
                        "override_source",
                    ),
                ),
            ),
        ),
    }

    selected = specs.get(case_type)
    if selected is None:
        return {
            "strategy": "manual_evidence_collection",
            "objective": (
                "Collect missing runtime and provenance evidence for this "
                "audit case."
            ),
            "prerequisites": BASE_PREREQUISITES,
            "stimuli": (
                _stimulus(
                    "baseline",
                    "Reproduce the normal path with local fixtures.",
                ),
            ),
            "oracles": (
                _oracle(
                    "reachability",
                    "Source, guards, and sink are recorded in causal order.",
                    (
                        "The sink receives controlled data without an "
                        "effective guard."
                    ),
                    ("entrypoint", "source", "guards", "sink", "result"),
                ),
            ),
        }

    strategy, objective, stimuli, oracles = selected
    extra = ()
    if case_type == "ssrf_possible":
        extra = ("Replace DNS and HTTP transports with recording fakes.",)
    elif case_type == "command_injection_possible":
        extra = ("Replace process execution with a recording stub.",)

    return {
        "strategy": strategy,
        "objective": objective,
        "prerequisites": (*BASE_PREREQUISITES, *extra),
        "stimuli": stimuli,
        "oracles": (*oracles, _functional_oracle()),
    }


def safety_contract(case_type: str) -> dict[str, Any]:
    """Return non-negotiable execution boundaries for a future adapter."""

    return {
        "authorized_scope_required": True,
        "network_mode": (
            "mocked_only" if case_type == "ssrf_possible" else "forbidden"
        ),
        "destructive_actions_allowed": False,
        "production_data_allowed": False,
        "real_secrets_allowed": False,
        "payload_policy": "benign_markers_only",
        "automatic_scope_expansion": False,
    }


__all__ = [
    "BASE_PREREQUISITES",
    "STOP_CONDITIONS",
    "safety_contract",
    "strategy_spec",
]
