"""Fixed Flask path application for opaque fixture fx_18a4e9_v1."""

from ...flask_adapter import prepare_flask_path_app


def prepare(temporary_root, parameters):
    return prepare_flask_path_app(
        temporary_root,
        parameters,
        application_id="app_18a4e9",
        policy_name="beta",
    )
