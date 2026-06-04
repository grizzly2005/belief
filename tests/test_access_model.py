from pathlib import Path

from belief.access_model import infer_access_hypotheses_from_source_tree


def test_raw_object_lookup_without_owner_check_produces_hypothesis(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(
        """
from flask_login import login_required, current_user

@app.route('/users/<user_id>')
@login_required
def get_user(user_id):
    user = User.query.get(user_id)
    return jsonify(user.email)
""",
        encoding="utf-8",
    )

    hypotheses = infer_access_hypotheses_from_source_tree(tmp_path)
    assert len(hypotheses) == 1
    assert "owner_or_tenant_scoped_lookup" in hypotheses[0].missing_guards
    assert hypotheses[0].object.id_name == "user_id"
    assert hypotheses[0].detected_guards[0].strength == "weak"


def test_strong_owner_filter_suppresses_hypothesis(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(
        """
from flask_login import login_required, current_user

@app.route('/users/<user_id>')
@login_required
def get_user(user_id):
    user = User.query.filter_by(user_id=current_user.id).first()
    return jsonify(user.email)
""",
        encoding="utf-8",
    )

    assert infer_access_hypotheses_from_source_tree(tmp_path) == []


def test_admin_decorator_is_strong_for_admin_action(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(
        """
@app.route('/admin/users/<user_id>/delete')
@admin_required
def delete_user(user_id):
    User.query.get(user_id).delete()
    return 'ok'
""",
        encoding="utf-8",
    )

    assert infer_access_hypotheses_from_source_tree(tmp_path) == []


def test_validation_steps_are_report_language_not_exploits(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(
        """
def download_invoice(invoice_id):
    return Invoice.query.get(invoice_id).pdf
""",
        encoding="utf-8",
    )
    hypotheses = infer_access_hypotheses_from_source_tree(Path(tmp_path))
    assert hypotheses
    assert "Expected secure behavior" in hypotheses[0].validation_steps[3]
