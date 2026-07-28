"""Security tests for the one closed, abstaining real-project pilot."""

from __future__ import annotations

from pathlib import Path

import pytest

from belief.mcp import authorized_project as pilot
from belief.mcp.tools import BeliefMCPError, BeliefMCPTools

pytestmark = pytest.mark.security

_AUTHORIZATION_ID = "auth_" + ("a" * 64)
_REVISION = "1" * 40


def _write_test_project(root: Path) -> Path:
    git_ref = root / ".git" / "refs" / "heads"
    git_ref.mkdir(parents=True)
    (root / ".git" / "HEAD").write_text(
        "ref: refs/heads/main\n",
        encoding="ascii",
    )
    (git_ref / "main").write_text(_REVISION + "\n", encoding="ascii")
    app = root / "app.py"
    app.write_text(
        '''
from pathlib import Path
from flask import Flask, request

Path(__file__).with_name("IMPORTED").write_text("target was imported")
app = Flask(__name__)

@app.get("/download")
def download():
    user_path = request.args["path"]
    return open(user_path).read()
'''.lstrip(),
        encoding="utf-8",
    )
    return app


def _pin_test_project(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    count, total_bytes, digest = pilot._source_inventory(root)
    monkeypatch.setattr(pilot, "FLASKJWT_PILOT_SOURCE_REVISION", _REVISION)
    monkeypatch.setattr(pilot, "FLASKJWT_PILOT_SOURCE_DIGEST", digest)
    monkeypatch.setattr(pilot, "FLASKJWT_PILOT_SOURCE_FILE_COUNT", count)
    monkeypatch.setattr(
        pilot,
        "FLASKJWT_PILOT_SOURCE_TOTAL_BYTES",
        total_bytes,
    )


def _request() -> dict:
    return {
        "adapter_id": pilot.FLASKJWT_PILOT_ADAPTER_ID,
        "authorization_id": _AUTHORIZATION_ID,
        "source_revision": pilot.FLASKJWT_PILOT_SOURCE_REVISION,
        "source_digest": pilot.FLASKJWT_PILOT_SOURCE_DIGEST,
        "acknowledge_authorized_project_access": True,
    }


def _service(
    root: Path,
    *,
    grant: pilot.AuthorizedProjectGrant | None = None,
) -> BeliefMCPTools:
    return BeliefMCPTools(
        workspace_root=root,
        authorized_project_grant=grant,
    )


def test_pilot_tool_schema_has_no_dispatch_surface(tmp_path):
    service = _service(tmp_path)
    definition = next(
        item
        for item in service.list_tools()
        if item["name"] == "belief_prepare_authorized_project_pilot"
    )

    assert set(definition["inputSchema"]["properties"]) == {
        "adapter_id",
        "authorization_id",
        "source_revision",
        "source_digest",
        "acknowledge_authorized_project_access",
    }
    assert definition["inputSchema"]["additionalProperties"] is False
    assert definition["annotations"] == {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
    rendered = repr(definition["inputSchema"]).casefold()
    for forbidden in (
        "path",
        "module",
        "callable",
        "command",
        "url",
        "host",
        "port",
        "source_code",
    ):
        assert f"'{forbidden}'" not in rendered


@pytest.mark.parametrize("forbidden", ["path", "module", "callable"])
def test_pilot_rejects_arbitrary_dispatch_arguments(
    tmp_path,
    forbidden,
):
    service = _service(tmp_path)
    request = _request()
    request[forbidden] = "attacker-controlled"

    with pytest.raises(BeliefMCPError, match="unsupported argument"):
        service.call_tool(
            "belief_prepare_authorized_project_pilot",
            request,
        )


def test_pilot_requires_distinct_startup_authorization(
    tmp_path,
    monkeypatch,
):
    _write_test_project(tmp_path)
    _pin_test_project(monkeypatch, tmp_path)
    service = _service(tmp_path)

    with pytest.raises(BeliefMCPError, match="separate local-operator"):
        service.call_tool(
            "belief_prepare_authorized_project_pilot",
            _request(),
        )


def test_pilot_requires_literal_access_acknowledgement(
    tmp_path,
    monkeypatch,
):
    _write_test_project(tmp_path)
    _pin_test_project(monkeypatch, tmp_path)
    grant = pilot.make_authorized_project_grant(_AUTHORIZATION_ID)
    service = _service(tmp_path, grant=grant)
    request = _request()
    request["acknowledge_authorized_project_access"] = False

    with pytest.raises(BeliefMCPError, match="JSON boolean true"):
        service.call_tool(
            "belief_prepare_authorized_project_pilot",
            request,
        )


def test_pilot_rejects_wrong_authorization_id(
    tmp_path,
    monkeypatch,
):
    _write_test_project(tmp_path)
    _pin_test_project(monkeypatch, tmp_path)
    grant = pilot.make_authorized_project_grant(_AUTHORIZATION_ID)
    service = _service(tmp_path, grant=grant)
    request = _request()
    request["authorization_id"] = "auth_" + ("b" * 64)

    with pytest.raises(BeliefMCPError, match="authorization does not match"):
        service.call_tool(
            "belief_prepare_authorized_project_pilot",
            request,
        )


def test_pilot_rejects_revision_or_digest_mismatch(
    tmp_path,
    monkeypatch,
):
    _write_test_project(tmp_path)
    _pin_test_project(monkeypatch, tmp_path)
    grant = pilot.make_authorized_project_grant(_AUTHORIZATION_ID)
    service = _service(tmp_path, grant=grant)

    wrong_revision = _request()
    wrong_revision["source_revision"] = "2" * 40
    with pytest.raises(BeliefMCPError, match="revision does not match"):
        service.call_tool(
            "belief_prepare_authorized_project_pilot",
            wrong_revision,
        )

    wrong_digest = _request()
    wrong_digest["source_digest"] = "2" * 64
    with pytest.raises(BeliefMCPError, match="digest does not match"):
        service.call_tool(
            "belief_prepare_authorized_project_pilot",
            wrong_digest,
        )


def test_pilot_rejects_changed_workspace_revision(
    tmp_path,
    monkeypatch,
):
    _write_test_project(tmp_path)
    _pin_test_project(monkeypatch, tmp_path)
    grant = pilot.make_authorized_project_grant(_AUTHORIZATION_ID)
    service = _service(tmp_path, grant=grant)
    (tmp_path / ".git" / "refs" / "heads" / "main").write_text(
        ("2" * 40) + "\n",
        encoding="ascii",
    )

    with pytest.raises(BeliefMCPError, match="exact authorized revision"):
        service.call_tool(
            "belief_prepare_authorized_project_pilot",
            _request(),
        )


def test_pilot_rejects_changed_source_inventory(
    tmp_path,
    monkeypatch,
):
    app = _write_test_project(tmp_path)
    _pin_test_project(monkeypatch, tmp_path)
    grant = pilot.make_authorized_project_grant(_AUTHORIZATION_ID)
    service = _service(tmp_path, grant=grant)
    app.write_text(
        app.read_text(encoding="utf-8") + "\n# changed after authorization\n",
        encoding="utf-8",
    )

    with pytest.raises(BeliefMCPError, match="exact authorized revision"):
        service.call_tool(
            "belief_prepare_authorized_project_pilot",
            _request(),
        )


def test_pilot_rechecks_source_after_static_analysis(
    tmp_path,
    monkeypatch,
):
    app = _write_test_project(tmp_path)
    _pin_test_project(monkeypatch, tmp_path)
    grant = pilot.make_authorized_project_grant(_AUTHORIZATION_ID)
    service = _service(tmp_path, grant=grant)
    analyze = pilot.analyze_static_target

    def analyze_then_change(root, options):
        result = analyze(root, options)
        app.write_text(
            app.read_text(encoding="utf-8") + "\n# changed during scan\n",
            encoding="utf-8",
        )
        return result

    monkeypatch.setattr(pilot, "analyze_static_target", analyze_then_change)

    with pytest.raises(BeliefMCPError, match="exact authorized revision"):
        service.call_tool(
            "belief_prepare_authorized_project_pilot",
            _request(),
        )


def test_pilot_binds_exact_source_and_always_abstains(
    tmp_path,
    monkeypatch,
):
    _write_test_project(tmp_path)
    _pin_test_project(monkeypatch, tmp_path)
    grant = pilot.make_authorized_project_grant(_AUTHORIZATION_ID)
    service = _service(tmp_path, grant=grant)

    payload = service.call_tool(
        "belief_prepare_authorized_project_pilot",
        _request(),
    )

    assert payload["outcome"] == "inconclusive"
    assert payload["execution_status"] == "abstained"
    assert payload["source_attestation"] == {
        "adapter_id": pilot.FLASKJWT_PILOT_ADAPTER_ID,
        "project_id": pilot.FLASKJWT_PILOT_PROJECT_ID,
        "source_revision": pilot.FLASKJWT_PILOT_SOURCE_REVISION,
        "source_digest": pilot.FLASKJWT_PILOT_SOURCE_DIGEST,
        "source_file_count": pilot.FLASKJWT_PILOT_SOURCE_FILE_COUNT,
        "source_total_bytes": pilot.FLASKJWT_PILOT_SOURCE_TOTAL_BYTES,
    }
    assert payload["plan_count"] > 0
    assert len(payload["bindings"]) == payload["plan_count"]
    assert len(payload["abstentions"]) == payload["plan_count"]
    assert all(
        item["outcome"] == "inconclusive"
        and item["execution_status"] == "abstained"
        and item["target_vulnerability_confirmed"] is False
        and item["human_confirmation_required"] is True
        and item["boundaries"]["target_executed"] is False
        for item in payload["abstentions"]
    )
    assert not (tmp_path / "IMPORTED").exists()

    plans, mime_type = service.read_resource(
        f"belief://runs/{payload['run_id']}/validation-plans"
    )
    assert mime_type == "application/json"
    assert plans["execution_enabled"] is False
    assert plans["authorized_project_dynamic_execution_enabled"] is False
    assert (
        plans["authorized_project_scope"]
        == pilot.AUTHORIZED_PROJECT_EXECUTION_SCOPE
    )
    assert all(
        row["authorized_project_binding"]["dynamic_execution_authorized"]
        is False
        for row in plans["validation_plans"]
    )

    results, _ = service.read_resource(
        f"belief://runs/{payload['run_id']}/validation-results"
    )
    assert results["count"] == 0

    first_plan = plans["validation_plans"][0]
    with pytest.raises(BeliefMCPError, match="unbound"):
        service.call_tool(
            "belief_validate_plan",
            {
                "run_id": payload["run_id"],
                "plan_id": first_plan["plan_id"],
                "fixture_id": "flask_path_traversal_vulnerable_v1",
                "timeout_ms": 1000,
                "acknowledge_local_execution": True,
            },
        )


def test_pilot_environment_authorization_is_explicit():
    assert pilot.authorized_project_grant_from_environment({}) is None

    with pytest.raises(pilot.AuthorizedProjectError, match="exactly true"):
        pilot.authorized_project_grant_from_environment(
            {
                pilot.FLASKJWT_PILOT_AUTHORIZED_ENV: "1",
                pilot.FLASKJWT_PILOT_AUTHORIZATION_ID_ENV: _AUTHORIZATION_ID,
            }
        )

    grant = pilot.authorized_project_grant_from_environment(
        {
            pilot.FLASKJWT_PILOT_AUTHORIZED_ENV: "true",
            pilot.FLASKJWT_PILOT_AUTHORIZATION_ID_ENV: _AUTHORIZATION_ID,
        }
    )
    assert grant is not None
    assert grant.authorization_id == _AUTHORIZATION_ID
    assert grant.source_revision == pilot.FLASKJWT_PILOT_SOURCE_REVISION
    assert grant.source_digest == pilot.FLASKJWT_PILOT_SOURCE_DIGEST


def test_bounded_git_reader_rejects_path_outside_git_directory(tmp_path):
    git_root = tmp_path / "project" / ".git"
    git_root.mkdir(parents=True)
    outside = tmp_path / "outside-ref"
    outside.write_text(_REVISION + "\n", encoding="ascii")

    with pytest.raises(pilot.AuthorizedProjectError, match="unreadable"):
        pilot._read_small_git_text(
            outside,
            git_root=git_root,
            context="test Git ref",
        )
