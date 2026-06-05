from belief.access_model import infer_access_hypotheses_from_source_tree


def test_include_protected_returns_guarded_access_case_without_changing_default(tmp_path):
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

    protected = infer_access_hypotheses_from_source_tree(tmp_path, include_protected=True)

    assert len(protected) == 1
    assert protected[0].missing_guards == []
    assert protected[0].detected_guards
    assert "Likely protected" in protected[0].title
