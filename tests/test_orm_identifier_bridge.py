from __future__ import annotations

import pytest

from belief.bridges.orm_identifier_bridge import RULE_ID, scan_source


pytestmark = pytest.mark.security


def _generic_source(*, guard: str = "", sink_first: bool = False) -> str:
    sink = "    selected = [item.apply_func(func) for item in descriptors]\n"
    check = f"{guard}\n" if guard else ""
    ordered = sink + check if sink_first else check + sink
    return (
        "async def aggregate(self, operation, requested_fields):\n"
        "    func = getattr(query_namespace.func, operation)\n"
        "    descriptors = [\n"
        "        FieldAction(select_str=field, model_cls=self.model)\n"
        "        for field in requested_fields\n"
        "    ]\n"
        f"{ordered}"
        "    return selected\n"
    )


def test_flags_external_descriptor_collection_reaching_orm_operation() -> None:
    findings = scan_source(_generic_source(), "query.py")

    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == RULE_ID
    assert finding["cwe"] == "CWE-89"
    assert finding["line"] == 7
    assert finding["sink"] == "apply_func"
    assert finding["variables"] == ["descriptors"]


def test_accepts_fail_closed_membership_check_on_target_model() -> None:
    guard = (
        "    if any(item.field_name not in item.target_model.model_fields "
        "for item in descriptors):\n"
        "        raise ValueError('unknown field')"
    )

    assert scan_source(_generic_source(guard=guard), "query.py") == []


def test_guard_against_wrong_model_does_not_clear_flow() -> None:
    guard = (
        "    if any(item.field_name not in self.model.model_fields "
        "for item in descriptors):\n"
        "        raise ValueError('unknown field')"
    )

    assert len(scan_source(_generic_source(guard=guard), "query.py")) == 1


def test_guard_on_wrong_descriptor_attribute_does_not_clear_flow() -> None:
    guard = (
        "    if any(item.label not in item.target_model.model_fields "
        "for item in descriptors):\n"
        "        raise ValueError('unknown field')"
    )

    assert len(scan_source(_generic_source(guard=guard), "query.py")) == 1


def test_property_check_without_membership_does_not_clear_flow() -> None:
    guard = (
        "    if any(not item.is_numeric for item in descriptors):\n"
        "        raise ValueError('numeric fields required')"
    )

    assert len(scan_source(_generic_source(guard=guard), "query.py")) == 1


def test_membership_check_after_sink_does_not_retroactively_protect() -> None:
    guard = (
        "    if any(item.field_name not in item.target_model.model_fields "
        "for item in descriptors):\n"
        "        raise ValueError('unknown field')"
    )

    findings = scan_source(
        _generic_source(guard=guard, sink_first=True),
        "query.py",
    )

    assert len(findings) == 1


def test_optional_membership_branch_does_not_establish_global_guard() -> None:
    source = '''
def aggregate(self, requested_fields, strict):
    descriptors = [
        FieldAction(field_name=value, model=self.model)
        for value in requested_fields
    ]
    if strict:
        if any(
            item.field_name not in item.target_model.model_fields
            for item in descriptors
        ):
            raise ValueError("unknown field")
    return [item.apply_func(sum) for item in descriptors]
'''

    assert len(scan_source(source, "query.py")) == 1


def test_constant_descriptor_collection_is_not_external() -> None:
    source = '''
def aggregate(self):
    descriptors = [
        FieldAction(field_name=value, model=self.model)
        for value in ("total", "count")
    ]
    return [item.apply_func(sum) for item in descriptors]
'''

    assert scan_source(source, "query.py") == []


@pytest.mark.parametrize(
    ("parameter", "collection", "item"),
    [
        ("requested_fields", "descriptors", "item"),
        ("columns", "actions", "action"),
        ("attributes", "projections", "projection"),
    ],
)
def test_alpha_renaming_preserves_detection(
    parameter: str,
    collection: str,
    item: str,
) -> None:
    source = f'''
def aggregate(self, {parameter}):
    {collection} = [
        FieldAction(column_name=value, model=self.model)
        for value in {parameter}
    ]
    return [{item}.apply_func(sum) for {item} in {collection}]
'''

    assert len(scan_source(source, "query.py")) == 1


def test_invalid_python_produces_no_claim() -> None:
    assert scan_source("def broken(:", "query.py") == []


def test_tracks_alias_of_external_identifier_collection() -> None:
    source = '''
def aggregate(self, requested_fields):
    fields = requested_fields
    actions = [
        FieldAction(field_name=value, model=self.model)
        for value in fields
    ]
    return [action.apply_func(sum) for action in actions]
'''

    findings = scan_source(source, "alias.py")

    assert len(findings) == 1
    assert findings[0]["source_line"] == 2


def test_guard_does_not_hide_sink_executed_before_rejection() -> None:
    source = '''
def aggregate(self, fields):
    actions = [
        FieldAction(field_name=value, model=self.model)
        for value in fields
    ]
    if any(
        action.field_name not in action.target_model.model_fields
        for action in actions
    ):
        leaked = [action.apply_func(sum) for action in actions]
        raise ValueError(leaked)
    return [action.apply_func(sum) for action in actions]
'''

    findings = scan_source(source, "ordered_guard.py")

    assert [finding["line"] for finding in findings] == [11]
