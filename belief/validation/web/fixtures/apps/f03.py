"""Fixed Flask resource application for opaque fixture fx_2f6b10_v1."""

from ...flask_adapter import prepare_flask_idor_app


def prepare(temporary_root, parameters):
    del parameters
    return prepare_flask_idor_app(
        temporary_root,
        application_id="app_2f6b10",
        policy_name="alpha",
    )
