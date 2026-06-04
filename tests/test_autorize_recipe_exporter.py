from belief.access_model.models import AccessHypothesis, ObjectAction, ProtectedObject
from belief.exporters.autorize_recipe import export_autorize_recipes


def test_autorize_recipe_exporter_uses_placeholders_not_secrets():
    hypothesis = AccessHypothesis(
        title="Candidate object authorization gap",
        actor=None,
        object=ProtectedObject("invoice", "invoice_id"),
        action=ObjectAction("read", mutates_state=False, reads_sensitive_data=True),
        route="/invoices/<invoice_id>",
        missing_guards=["owner_or_tenant_scoped_lookup"],
        validation_steps=["Replay as same-privilege user."],
    )

    payload = export_autorize_recipes([hypothesis])
    recipe = payload["recipes"][0]
    assert payload["secrets"] == "not_exported"
    assert recipe["high_privileged_context"] == "<provide manually outside repo>"
    assert recipe["low_privileged_context"] == "<provide manually outside repo>"
    assert "cookie" not in str(payload).lower()
