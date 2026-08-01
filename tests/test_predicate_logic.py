"""Structured predicate negation regressions."""

from __future__ import annotations

import pytest

from belief.predicate_logic import (
    PredicateLogicError,
    negate_expression,
    parse_logical_expression,
    render_logical_expression,
)


@pytest.mark.parametrize(
    ("expression", "expected"),
    (
        ("x not in y", "x in y"),
        ("x in y", "x not in y"),
        ("a < b < c", "a >= b or b >= c"),
        ("ptr is None", "ptr is not None"),
        ("ptr is not None", "ptr is None"),
        ("x == None", "x != None"),
        (
            "a < b and (c == d or x not in y)",
            "a >= b or c != d and x in y",
        ),
        (
            "a < b or c == d",
            "a >= b and c != d",
        ),
        ("not not active", "not active"),
        ("not (a < b and c == d)", "a < b and c == d"),
        ("len(data) <= limit", "len(data) > limit"),
    ),
)
def test_structured_negation(expression, expected):
    assert negate_expression(expression) == expected


def test_parse_render_round_trip_preserves_membership():
    node = parse_logical_expression("role in {'admin', 'owner'}")

    assert render_logical_expression(node) == (
        "role in {'admin', 'owner'}"
    )


@pytest.mark.parametrize(
    "expression",
    (
        "some_complex_thing()",
        "lambda x: x",
        "a if condition else b",
        "await result",
        "obj.mutate() == 1",
    ),
)
def test_unsupported_predicate_abstains(expression):
    with pytest.raises(PredicateLogicError):
        negate_expression(expression)
