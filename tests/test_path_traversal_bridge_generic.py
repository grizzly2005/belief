from __future__ import annotations

import pytest

from belief.bridges.path_traversal_bridge import scan_source


pytestmark = pytest.mark.security


def _lines(source: str) -> list[int]:
    return [int(item["line"]) for item in scan_source(source, "paths.py")]


def test_flags_tainted_helper_return_after_tuple_unpacking() -> None:
    source = '''
def destination(requested_url, storage_root):
    leaf, fragment = derive_leaf(requested_url)
    if leaf:
        leaf = leaf.replace("..", ".")
    candidate = os.path.join(storage_root, leaf)
    return candidate
'''

    findings = scan_source(source, "paths.py")

    assert len(findings) == 1
    assert findings[0]["line"] == 7
    assert findings[0]["cwe"] == "CWE-22"
    assert findings[0]["rule_id"] == "path_traversal_user_input_to_boundary"


def test_accepts_prior_fail_closed_containment_guard() -> None:
    source = '''
def destination(input_value, trusted_root):
    leaf, fragment = derive_leaf(input_value)
    candidate = (Path(trusted_root) / leaf).resolve()
    if not candidate.is_relative_to(trusted_root):
        raise ValueError("outside root")
    return candidate
'''

    assert scan_source(source, "paths.py") == []


def test_accepts_basename_style_leaf_sanitizer() -> None:
    source = '''
def destination(input_value, trusted_root):
    leaf = os.path.basename(input_value)
    return os.path.join(trusted_root, leaf)
'''

    assert scan_source(source, "paths.py") == []


def test_normalization_without_containment_remains_risky() -> None:
    source = '''
def destination(input_value, trusted_root):
    candidate = os.path.realpath(os.path.join(trusted_root, input_value))
    return candidate
'''

    assert _lines(source) == [4]


def test_guard_on_wrong_value_does_not_clear_candidate() -> None:
    source = '''
def destination(input_value, trusted_root, unrelated):
    candidate = os.path.join(trusted_root, input_value)
    if not unrelated.startswith(str(trusted_root)):
        raise ValueError("outside root")
    return candidate
'''

    assert _lines(source) == [6]


@pytest.mark.parametrize(
    "guard_argument",
    ['"trusted"', "str(other_root)"],
)
def test_guard_must_compare_candidate_to_its_own_join_root(
    guard_argument: str,
) -> None:
    source = f'''
def destination(input_value, trusted_root, other_root):
    candidate = os.path.join(trusted_root, input_value)
    if not candidate.startswith({guard_argument}):
        raise ValueError("outside root")
    return candidate
'''

    assert _lines(source) == [6]


def test_non_terminating_check_does_not_establish_containment() -> None:
    source = '''
def destination(input_value, trusted_root):
    candidate = os.path.join(trusted_root, input_value)
    if not candidate.startswith(str(trusted_root)):
        log_problem(candidate)
    return candidate
'''

    assert _lines(source) == [6]


def test_unused_sanitizer_result_does_not_clear_original_value() -> None:
    source = '''
def destination(input_value, trusted_root):
    os.path.basename(input_value)
    return os.path.join(trusted_root, input_value)
'''

    assert _lines(source) == [4]


def test_string_join_is_not_treated_as_a_filesystem_path_join() -> None:
    source = '''
def render(input_value, separator):
    output = separator.join(["prefix", input_value])
    return output
'''

    assert scan_source(source, "paths.py") == []


def test_safe_reassignment_clears_an_earlier_tainted_path() -> None:
    source = '''
def destination(input_value, trusted_root):
    candidate = os.path.join(trusted_root, input_value)
    candidate = os.path.join(trusted_root, "generated.bin")
    return candidate
'''

    assert scan_source(source, "paths.py") == []


def test_flags_path_method_receiver_instead_of_write_content() -> None:
    unsafe_receiver = '''
def persist(input_value, trusted_root, content):
    candidate = Path(trusted_root) / input_value
    candidate.write_bytes(content)
'''
    safe_receiver = '''
def persist(input_value, safe_path):
    safe_path.write_text(input_value)
'''

    findings = scan_source(unsafe_receiver, "paths.py")

    assert len(findings) == 1
    assert findings[0]["sink"] == "file sink"
    assert findings[0]["variables"] == ["candidate"]
    assert scan_source(safe_receiver, "paths.py") == []


def test_guard_after_file_sink_does_not_retroactively_protect_it() -> None:
    source = '''
def persist(input_value, trusted_root):
    candidate = os.path.join(trusted_root, input_value)
    open(candidate, "wb")
    if not candidate.startswith(str(trusted_root)):
        raise ValueError("outside root")
'''

    assert _lines(source) == [4]


@pytest.mark.parametrize(
    ("argument", "root", "local"),
    [
        ("requested_name", "storage_root", "candidate"),
        ("object_key", "base_folder", "resolved_path"),
        ("payload", "workspace", "output_path"),
    ],
)
def test_alpha_renaming_preserves_detection(
    argument: str,
    root: str,
    local: str,
) -> None:
    source = f'''
def build({argument}, {root}):
    {local} = os.path.join({root}, {argument})
    return {local}
'''

    assert _lines(source) == [4]


def test_positional_only_parameters_are_tracked() -> None:
    source = '''
def build(input_value, trusted_root, /):
    candidate = os.path.join(trusted_root, input_value)
    return candidate
'''

    assert _lines(source) == [4]


def test_module_level_conditionals_do_not_corrupt_scope_tracking() -> None:
    source = '''
if FEATURE_ENABLED:
    def build(input_value, trusted_root):
        candidate = os.path.join(trusted_root, input_value)
        return candidate
'''

    assert _lines(source) == [5]


@pytest.mark.parametrize("receiver", ["self", "cls"])
def test_method_receiver_is_not_treated_as_attacker_input(receiver: str) -> None:
    source = f'''
class Cache:
    def destination({receiver}, trusted_root):
        return os.path.join(trusted_root, {receiver}.cache_name)
'''

    assert scan_source(source, "paths.py") == []


def test_method_argument_remains_tainted_when_receiver_is_clean() -> None:
    source = '''
class Cache:
    def destination(self, input_value, trusted_root):
        return os.path.join(trusted_root, input_value)
'''

    findings = scan_source(source, "paths.py")

    assert _lines(source) == [4]
    assert findings[0]["variables"] == ["input_value"]


@pytest.mark.parametrize(
    "definition",
    [
        "def destination(self, trusted_root):",
        "@staticmethod\n    def destination(self, trusted_root):",
    ],
)
def test_self_named_non_receiver_remains_tainted(definition: str) -> None:
    if definition.startswith("@"):
        source = f'''
class Cache:
    {definition}
        return os.path.join(trusted_root, self)
'''
    else:
        source = f'''
{definition}
    return os.path.join(trusted_root, self)
'''

    findings = scan_source(source, "paths.py")

    assert len(findings) == 1
    assert findings[0]["variables"] == ["self"]


@pytest.mark.parametrize(
    "expression",
    [
        "left + right",
        "left / right",
        "'prefix-' + left",
    ],
)
def test_arithmetic_and_non_path_string_operations_are_not_paths(
    expression: str,
) -> None:
    source = f'''
def calculate(left, right):
    return {expression}
'''

    assert scan_source(source, "paths.py") == []


@pytest.mark.parametrize(
    "expression",
    [
        "'/srv/uploads/' + input_value",
        "f'/srv/uploads/{input_value}'",
        "Path(trusted_root) / input_value",
    ],
)
def test_explicit_path_construction_forms_remain_detectable(
    expression: str,
) -> None:
    source = f'''
def destination(input_value, trusted_root):
    return {expression}
'''

    assert _lines(source) == [3]


def test_nested_path_argument_does_not_turn_a_handle_into_a_path() -> None:
    source = '''
def load(input_value, trusted_root):
    handle = open(os.path.join(trusted_root, input_value), "rb")
    return handle
'''

    findings = scan_source(source, "paths.py")

    assert len(findings) == 1
    assert findings[0]["line"] == 3
    assert findings[0]["sink"] == "file sink"


def test_unqualified_object_open_is_not_assumed_to_be_a_file_sink() -> None:
    source = '''
def retry(client, url, host):
    new_url = "https://" + host
    return client.open(new_url)
'''

    assert scan_source(source, "paths.py") == []


def test_parameter_only_taint_is_not_claimed_at_high_confidence() -> None:
    source = '''
def destination(input_value, trusted_root):
    return os.path.join(trusted_root, input_value)
'''

    findings = scan_source(source, "paths.py")

    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["confidence"] < 0.8


def test_invalid_python_produces_no_claim() -> None:
    assert scan_source("def broken(:", "paths.py") == []


@pytest.mark.parametrize("check", ["startswith(str(trusted_root))", "is_relative_to(trusted_root)"])
def test_lexical_check_without_resolution_does_not_establish_containment(check) -> None:
    source = f'''
def destination(input_value, trusted_root):
    candidate = Path(trusted_root) / input_value
    if not candidate.{check}:
        raise ValueError("outside root")
    return candidate
'''
    assert _lines(source) == [6]


def test_resolved_string_prefix_check_still_allows_sibling_prefixes() -> None:
    source = '''
def destination(input_value, trusted_root):
    candidate = os.path.realpath(os.path.join(trusted_root, input_value))
    if not candidate.startswith(str(trusted_root)):
        raise ValueError("outside root")
    return candidate
'''
    assert _lines(source) == [6]


@pytest.mark.parametrize("label", ["allowed/", "tenant/"])
def test_relative_path_label_return_is_not_a_file_operation(label) -> None:
    source = f'''
def render(candidate, root):
    if candidate.is_relative_to(root):
        return {label!r} + candidate.relative_to(root).as_posix()
'''
    assert scan_source(source, "paths.py") == []


def test_relative_path_rendering_does_not_sanitize_an_actual_file_sink() -> None:
    source = '''
def read(candidate, root):
    return open('allowed/' + candidate.relative_to(root).as_posix()).read()
'''
    assert _lines(source) == [3]
