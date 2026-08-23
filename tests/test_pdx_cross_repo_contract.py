from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from belief.json_contracts import strict_json_dumps


_PDX_PREFLIGHT_SCRIPT = """
import jsonschema
import pytest
import pypdx.observation_attestation
import pypdx.observation_store
"""
_SUBPROCESS_TIMEOUT_SECONDS = 30

_PDX_FIXTURE_SCRIPT = textwrap.dedent(
    """
    import json
    import runpy
    import sys
    from pathlib import Path

    from pypdx.observation_identity import ObservationIdentityConfig
    from pypdx.observation_store import ObservationStore, ObservationStoreConfig

    pdx_runtime = Path(sys.argv[1])
    store_root = Path(sys.argv[2])
    metadata_path = Path(sys.argv[3])
    fixture_module = runpy.run_path(str(pdx_runtime / "tests" / "conftest.py"))
    cases = json.loads(
        (
            pdx_runtime
            / "tests"
            / "fixtures"
            / "http_observation_v2"
            / "round_trip_cases.json"
        ).read_text(encoding="utf-8")
    )
    document = fixture_module["build_observation"](cases[0])
    identity = ObservationIdentityConfig(
        engagement="engagement-alpha",
        session="session-alpha",
        actor="actor-alpha",
        role="role-user",
        tenant="tenant-alpha",
        workflow="workflow-download",
        workflow_step="step-1",
    )
    store = ObservationStore(
        ObservationStoreConfig(root=store_root),
        identity_config=identity,
    )
    receipt = store.persist_dict(document)
    if receipt.status != "created":
        raise RuntimeError(f"PDX fixture persistence failed: {receipt.to_dict()}")
    verified = store.verify(document["capture_id"])
    metadata_path.write_text(
        json.dumps(
            {
                "capture_id": document["capture_id"],
                "target_id": verified["target_id"],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    """
).strip()


@pytest.mark.integration
def test_real_pdx_cli_attestation_imports_and_replays_through_belief_cli(tmp_path):
    """Exercise the passive F3 boundary against a real adjacent PDX checkout."""

    configured = os.environ.get("PDX_REPO", "")
    if not configured:
        pytest.skip("set PDX_REPO to run the cross-repository PDX/BELIEF contract test")
    pdx_repo = Path(configured).expanduser().resolve()
    pdx_runtime = pdx_repo / "pdx"
    required = [
        pdx_runtime / "pdx_cli.py",
        pdx_runtime / "tests" / "conftest.py",
        pdx_runtime / "tests" / "fixtures" / "http_observation_v2" / "round_trip_cases.json",
        pdx_repo / "schemas" / "pdx-observation-attestation-v1.schema.json",
    ]
    missing = [str(path) for path in required if not path.is_file()]
    assert not missing, f"PDX_REPO is not the expected PDX checkout: {missing}"

    pdx_python = os.environ.get("PDX_PYTHON") or sys.executable
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try:
        preflight = subprocess.run(
            [pdx_python, "-c", _PDX_PREFLIGHT_SCRIPT],
            cwd=pdx_runtime,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT_SECONDS,
        )
    except OSError as exc:
        pytest.fail(
            f"PDX_PYTHON={pdx_python!r} could not be executed: {exc}. "
            "Set PDX_PYTHON to a Python executable with the PDX and test dependencies.",
            pytrace=False,
        )
    if preflight.returncode != 0:
        pytest.fail(
            f"PDX runtime preflight failed for PDX_PYTHON={pdx_python!r}. "
            "Set PDX_PYTHON to a Python executable with the PDX and test dependencies "
            f"installed.\nstdout:\n{preflight.stdout}\nstderr:\n{preflight.stderr}",
            pytrace=False,
        )

    pdx_store = tmp_path / "pdx-store"
    metadata_path = tmp_path / "pdx-fixture-metadata.json"
    generated = subprocess.run(
        [
            pdx_python,
            "-c",
            _PDX_FIXTURE_SCRIPT,
            str(pdx_runtime),
            str(pdx_store),
            str(metadata_path),
        ],
        cwd=pdx_runtime,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT_SECONDS,
    )
    assert generated.returncode == 0, generated.stderr
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

    attestation_path = tmp_path / "attestation.json"
    exported = subprocess.run(
        [
            pdx_python,
            str(pdx_runtime / "pdx_cli.py"),
            "observations",
            "attest",
            "--store-dir",
            str(pdx_store),
            "--capture",
            metadata["capture_id"],
            "--engagement-id",
            "engagement-alpha",
            "--engagement-version",
            "3",
            "--scope-ref",
            "scope:alpha:v3",
            "--scope-sha256",
            "e" * 64,
            "--authorization-ref",
            "authorization:alpha:v3",
            "--output",
            str(attestation_path),
        ],
        cwd=pdx_runtime,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT_SECONDS,
    )
    assert exported.returncode == 0, exported.stderr

    engagement = {
        "schema_version": "belief.pdx_engagement.v1",
        "engagement_id": "engagement-alpha",
        "engagement_version": 3,
        "status": "active",
        "owner_ref": "owner:alpha",
        "scope_ref": "scope:alpha:v3",
        "scope_sha256": "e" * 64,
        "authorization_ref": "authorization:alpha:v3",
        "policy_ref": "policy:alpha:v3",
        "budget_ref": "budget:alpha:v3",
        "valid_from": "2026-08-01T00:00:00Z",
        "valid_until": "2026-09-01T00:00:00Z",
        "target_ids": [metadata["target_id"]],
    }
    engagement_path = tmp_path / "engagement.json"
    engagement_path.write_text(strict_json_dumps(engagement), encoding="utf-8")
    journal = tmp_path / "belief-store"
    belief_repo = Path(__file__).resolve().parents[1]

    registered = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "pdx",
            "register-engagement",
            str(engagement_path),
            "--store-dir",
            str(journal),
        ],
        cwd=belief_repo,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT_SECONDS,
    )
    assert registered.returncode == 0, registered.stderr

    import_command = [
        sys.executable,
        "-m",
        "belief",
        "pdx",
        "import-attestation",
        str(attestation_path),
        "--store-dir",
        str(journal),
    ]
    imported = subprocess.run(
        import_command,
        cwd=belief_repo,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT_SECONDS,
    )
    replayed = subprocess.run(
        import_command,
        cwd=belief_repo,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT_SECONDS,
    )
    assert imported.returncode == 0, imported.stderr
    assert replayed.returncode == 0, replayed.stderr
    first = json.loads(imported.stdout)
    second = json.loads(replayed.stdout)
    assert first["receipt"]["status"] == "ACCEPT"
    assert first["receipt"]["observation_refs"][0]["proof_state"] == (
        "signal_only_no_belief_attempt_result_evidence"
    )
    assert second["replayed"] is True
    assert second["receipt"]["receipt_id"] == first["receipt"]["receipt_id"]
    pdx_schema = (
        pdx_repo / "schemas" / "pdx-observation-attestation-v1.schema.json"
    ).read_bytes().replace(b"\r\n", b"\n")
    belief_schema = (
        belief_repo / "schemas" / "pdx-observation-attestation-v1.schema.json"
    ).read_bytes().replace(b"\r\n", b"\n")
    assert pdx_schema == belief_schema
