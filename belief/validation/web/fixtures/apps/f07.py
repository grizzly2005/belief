"""Fixed FastAPI resource application for opaque fixture fx_6d04f8_v1."""

from ...fastapi_adapter import prepare_fastapi_idor_app


def prepare(temporary_root, parameters):
    del temporary_root, parameters
    return prepare_fastapi_idor_app(
        application_id="app_6d04f8",
        policy_name="alpha",
    )
