"""Fixed FastAPI path application for opaque fixture fx_47e1a3_v1."""

from ...fastapi_adapter import prepare_fastapi_path_app


def prepare(temporary_root, parameters):
    return prepare_fastapi_path_app(
        temporary_root,
        parameters,
        application_id="app_47e1a3",
        policy_name="alpha",
    )
