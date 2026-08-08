"""Fixed Flask resource application for opaque fixture fx_3c8d57_v1."""

from ...flask_adapter import prepare_flask_idor_app


def prepare(temporary_root, parameters):
    del parameters
    return prepare_flask_idor_app(
        temporary_root,
        application_id="app_3c8d57",
        policy_name="beta",
    )
