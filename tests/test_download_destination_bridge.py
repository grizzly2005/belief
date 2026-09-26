from __future__ import annotations

import pytest

from belief.bridges.download_destination_bridge import RULE_ID, scan_source


pytestmark = pytest.mark.security


def test_flags_external_filename_flowing_to_download_destination() -> None:
    source = '''
async def fetch_blob(self, record, destination_name=""):
    folder, destination_name = os.path.split(destination_name)
    supplied_name = getattr(record, "filename", "")
    destination_name = destination_name or supplied_name
    job = self.queue_download((record, folder, destination_name))
    return await job
'''

    findings = scan_source(source, "worker.py")

    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == RULE_ID
    assert finding["cwe"] == "CWE-22"
    assert finding["severity"] == "high"
    assert finding["file"] == "worker.py"
    assert finding["line"] == 6
    assert finding["source_line"] == 4
    assert finding["sink"] == "queue_download"


def test_flags_generated_fallback_without_losing_unsafe_nonempty_branch() -> None:
    source = '''
def retrieve(asset, folder):
    output_name = asset.suggested_filename
    if not output_name:
        output_name = "generated.bin"
    return start_download((folder, output_name))
'''

    findings = scan_source(source, "retrieval.py")

    assert [finding["line"] for finding in findings] == [6]


def test_flags_null_byte_filter_because_it_does_not_remove_path_components() -> None:
    source = '''
def persist_attachment(item, destination_dir):
    target_name = getattr(item, "original_filename", "")
    target_name = target_name.replace("\\x00", "")
    return save_download(destination_dir, target_name)
'''

    findings = scan_source(source, "attachments.py")

    assert len(findings) == 1
    assert findings[0]["source_line"] == 3


def test_flags_explicit_destination_keyword_without_positional_directory() -> None:
    source = '''
def cache_resource(resource):
    local_name = resource.original_file_name
    return store_download(filename=local_name)
'''

    findings = scan_source(source, "cache.py")

    assert len(findings) == 1
    assert findings[0]["variables"] == ["local_name"]


@pytest.mark.parametrize(
    "sanitized_expression",
    [
        "os.path.basename(remote_name)",
        "Path(remote_name).name",
        "secure_filename(remote_name)",
        "os.path.split(remote_name)[1]",
    ],
)
def test_accepts_leaf_sanitizers(sanitized_expression: str) -> None:
    source = f'''
def cache_attachment(payload, output_dir):
    remote_name = getattr(payload, "filename", "")
    local_name = {sanitized_expression}
    return persist_download((output_dir, local_name))
'''

    assert scan_source(source, "safe_cache.py") == []


def test_accepts_truthiness_guard_that_sanitizes_every_dangerous_value() -> None:
    source = '''
def transfer(asset, target_dir):
    target_name = asset.filename
    if target_name:
        target_name = os.path.basename(target_name)
    if not target_name:
        target_name = "generated.bin"
    return queue_download((target_dir, target_name))
'''

    assert scan_source(source, "safe_transfer.py") == []


def test_flags_alpha_renamed_minimal_filename_flow() -> None:
    source = '''
def f(r, d):
    n = r.filename
    return save_download(d, destination=n)
'''

    findings = scan_source(source, "alpha_renamed.py")

    assert len(findings) == 1
    assert findings[0]["source_line"] == 3
    assert findings[0]["sink"] == "save_download"
    assert findings[0]["variables"] == ["n"]


def test_ignores_download_log_call_with_path_shaped_arguments() -> None:
    source = '''
def report(record, directory):
    remote_name = record.filename
    return log_download_started(directory, remote_name)
'''

    assert scan_source(source, "download_log.py") == []


def test_ignores_orm_save_method_with_path_shaped_arguments() -> None:
    source = '''
def persist(row, record, directory):
    remote_name = record.filename
    return row.save(directory, remote_name)
'''

    assert scan_source(source, "orm_save.py") == []


def test_accepts_two_step_path_name_sanitization() -> None:
    source = '''
def transfer(record, directory):
    remote_name = record.filename
    remote_path = Path(remote_name)
    local_name = remote_path.name
    return queue_download(directory, local_name)
'''

    assert scan_source(source, "path_name.py") == []


@pytest.mark.parametrize(
    "path_type",
    ["PurePath", "PurePosixPath", "PureWindowsPath"],
)
def test_accepts_pure_path_name_sanitization(path_type: str) -> None:
    source = f'''
def transfer(record, directory):
    remote_name = record.filename
    local_name = {path_type}(remote_name).name
    return queue_download(directory, local_name)
'''

    assert scan_source(source, "pure_path_name.py") == []


def test_flags_string_split_because_it_does_not_prove_a_leaf() -> None:
    source = '''
def transfer(record, directory):
    remote_name = record.filename
    local_name = remote_name.split("/")[-1]
    return save_download(directory, local_name)
'''

    findings = scan_source(source, "string_split.py")

    assert len(findings) == 1
    assert findings[0]["variables"] == ["local_name"]


def test_flags_joined_path_variable_passed_to_open() -> None:
    source = '''
def persist(record, directory):
    remote_name = record.filename
    destination = os.path.join(directory, remote_name)
    return open(destination, "wb")
'''

    findings = scan_source(source, "joined_open.py")

    assert len(findings) == 1
    assert findings[0]["sink"] == "open"
    assert findings[0]["variables"] == ["destination"]


def test_flags_unsafe_receiver_of_write_bytes() -> None:
    source = '''
def persist(record, directory, content):
    remote_name = record.filename
    return (Path(directory) / remote_name).write_bytes(content)
'''

    findings = scan_source(source, "receiver_write.py")

    assert len(findings) == 1
    assert findings[0]["sink"] == "write_bytes"
    assert findings[0]["variables"] == ["remote_name"]


def test_ignores_unsafe_content_written_to_a_safe_receiver() -> None:
    source = '''
def persist(record, safe_path):
    content = record.filename
    return safe_path.write_bytes(content.encode())
'''

    assert scan_source(source, "safe_receiver.py") == []


def test_ignores_archive_member_open_that_does_not_write_a_local_path() -> None:
    source = '''
def read_member(archive, record):
    remote_name = record.filename
    return archive.open(remote_name)
'''

    assert scan_source(source, "archive_member.py") == []


def test_flags_unsafe_copy_destination_but_not_unsafe_copy_source() -> None:
    unsafe_destination = '''
def persist(record, safe_source, directory):
    remote_name = record.filename
    destination = os.path.join(directory, remote_name)
    return shutil.copy(safe_source, destination)
'''
    unsafe_source_only = '''
def copy_existing(record, safe_destination):
    remote_name = record.filename
    return shutil.copy(remote_name, safe_destination)
'''

    findings = scan_source(unsafe_destination, "copy_destination.py")

    assert len(findings) == 1
    assert findings[0]["sink"] == "copy"
    assert scan_source(unsafe_source_only, "copy_source.py") == []


def test_accepts_fail_closed_basename_guard() -> None:
    source = '''
def persist(record, directory):
    remote_name = record.filename
    if remote_name != os.path.basename(remote_name):
        raise ValueError("filename must be a leaf")
    return save_download(directory, remote_name)
'''

    assert scan_source(source, "basename_guard.py") == []


def test_accepts_fail_closed_containment_guard() -> None:
    source = '''
def persist(record, root):
    remote_name = record.filename
    candidate = os.path.realpath(os.path.join(root, remote_name))
    if not candidate.startswith(root + os.sep):
        raise ValueError("destination escapes root")
    return open(candidate, "wb")
'''

    assert scan_source(source, "containment_guard.py") == []


@pytest.mark.parametrize(
    "guard",
    [
        'if not candidate.startswith("report"):\n        raise ValueError("bad")',
        'if not candidate.startswith(root + os.sep):\n        raise ValueError("bad")',
        'if not candidate.is_relative_to(root):\n        raise ValueError("bad")',
    ],
)
def test_rejects_unproven_or_unresolved_containment_guards(guard: str) -> None:
    source = f'''
def persist(record, root):
    remote_name = record.filename
    candidate = os.path.join(root, remote_name)
    {guard}
    return open(candidate, "wb")
'''

    assert len(scan_source(source, "weak_guard.py")) == 1


def test_accepts_resolved_path_is_relative_to_its_own_root() -> None:
    source = '''
def persist(record, root):
    remote_name = record.filename
    candidate = (Path(root) / remote_name).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("destination escapes root")
    return candidate.open("wb")
'''

    assert scan_source(source, "relative_guard.py") == []


def test_tuple_coassignment_tracks_each_value_independently() -> None:
    source = '''
def persist(record, directory):
    remote_name, size = record.filename, record.size
    return save_download(directory, size)
'''

    assert scan_source(source, "tuple_values.py") == []


def test_path_object_alias_preserves_name_sanitization() -> None:
    source = '''
def persist(record, directory):
    remote_name = record.filename
    candidate = Path(remote_name)
    chosen = candidate
    local_name = chosen.name
    return save_download(directory, local_name)
'''

    assert scan_source(source, "path_alias.py") == []


def test_custom_download_requires_destination_context_not_arity() -> None:
    source = '''
def report(record, retries):
    remote_name = record.filename
    return queue_download(remote_name, retries)
'''

    assert scan_source(source, "download_arity.py") == []


def test_exact_file_sink_evidence_does_not_claim_directory_context() -> None:
    source = '''
def read(record):
    remote_name = record.filename
    return open(remote_name, "rb")
'''

    findings = scan_source(source, "direct_open.py")

    assert len(findings) == 1
    assert "directory context" not in findings[0]["description"]


@pytest.mark.parametrize(
    "unused_sanitizer",
    [
        "safe_name = os.path.basename(remote_name)",
        "safe_name = os.path.basename(other_name)",
    ],
)
def test_flags_when_sanitizer_does_not_protect_the_sink_value(
    unused_sanitizer: str,
) -> None:
    source = f'''
def persist(record, directory, other_name):
    remote_name = record.filename
    {unused_sanitizer}
    return save_download(directory, remote_name)
'''

    findings = scan_source(source, "unused_sanitizer.py")

    assert len(findings) == 1
    assert findings[0]["variables"] == ["remote_name"]


def test_ignores_caller_selected_destination_without_remote_filename_source() -> None:
    source = '''
def retrieve(identifier, output_dir, output_name):
    return queue_download((identifier, output_dir, output_name))
'''

    assert scan_source(source, "caller_destination.py") == []


def test_ignores_remote_filename_without_destination_evidence() -> None:
    source = '''
def describe(record):
    supplied_name = getattr(record, "filename", "")
    return download_metadata(supplied_name)
'''

    assert scan_source(source, "metadata.py") == []


def test_ignores_non_sink_use_even_with_directory_context() -> None:
    source = '''
def inspect_upload(upload, base_dir):
    remote_filename = upload.filename
    return audit_metadata(base_dir, remote_filename)
'''

    assert scan_source(source, "inspection.py") == []


def test_invalid_python_produces_no_claim() -> None:
    assert scan_source("def broken(:", "broken.py") == []
