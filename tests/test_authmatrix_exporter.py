from belief.exporters.authmatrix import export_authmatrix_state
from belief.tools.schemas import AccessObservation


def test_access_observation_exports_to_authmatrix_like_json():
    state = export_authmatrix_state([
        AccessObservation(
            source_tool="test",
            actor="alice",
            role="user",
            method="GET",
            path="/invoices/1",
            object_type="invoice",
            object_id_source="invoice_id",
            action="read",
            expected_guard="owner_or_tenant_scope",
            missing_guards=["owner_or_tenant_scoped_lookup"],
            evidence=["fixture"],
        )
    ])
    assert state["schema"] == "belief.authmatrix.v1"
    assert state["roles"] == ["user"]
    assert state["requests"][0]["path"] == "/invoices/1"
    assert state["secrets"] == "not_exported"
