"""Route inventory extraction tests for common Python web frameworks."""

from __future__ import annotations

from pathlib import Path

from belief.routes import extract_routes_from_file, extract_routes_from_files


def test_extracts_flask_decorated_route_with_auth(tmp_path: Path):
    app = tmp_path / "app.py"
    app.write_text(
        """
from flask import Flask
from auth import login_required

app = Flask(__name__)

@app.route("/submit/<item_id>", methods=["POST"])
@login_required
def submit(item_id):
    return item_id
""",
        encoding="utf-8",
    )

    routes = extract_routes_from_files([app], target_root=tmp_path)

    assert len(routes) == 1
    route = routes[0]
    assert route.framework == "flask"
    assert route.file == "app.py"
    assert route.route == "/submit/<item_id>"
    assert route.methods == ("POST",)
    assert route.handler == "submit"
    assert route.params == ("item_id",)
    assert "route.requires_login == true" in route.auth_guarantees


def test_extracts_fastapi_route_params_and_dependency_guard(tmp_path: Path):
    api = tmp_path / "api.py"
    api.write_text(
        """
from fastapi import APIRouter, Depends

router = APIRouter()

@router.get("/items/{item_id}")
async def get_item(item_id: str, user = Depends(require_user)):
    return {"item_id": item_id}
""",
        encoding="utf-8",
    )

    route = extract_routes_from_file(api)[0]

    assert route.framework == "fastapi"
    assert route.route == "/items/{item_id}"
    assert route.methods == ("GET",)
    assert route.params == ("item_id",)
    assert "route.has_dependency_guard == true" in route.auth_guarantees


def test_extracts_django_path_route(tmp_path: Path):
    urls = tmp_path / "urls.py"
    urls.write_text(
        """
from django.urls import path
from . import views

urlpatterns = [
    path("items/<int:item_id>/", views.detail, name="detail"),
]
""",
        encoding="utf-8",
    )

    route = extract_routes_from_file(urls)[0]

    assert route.framework == "django"
    assert route.route == "items/<int:item_id>/"
    assert route.handler == "views.detail"
    assert route.params == ("item_id",)


def test_route_output_is_deterministic(tmp_path: Path):
    first = tmp_path / "a.py"
    second = tmp_path / "b.py"
    first.write_text('@app.get("/a")\ndef a(): pass\n', encoding="utf-8")
    second.write_text('@app.get("/b")\ndef b(): pass\n', encoding="utf-8")

    routes_a = [route.to_dict() for route in extract_routes_from_files([second, first], target_root=tmp_path)]
    routes_b = [route.to_dict() for route in extract_routes_from_files([first, second], target_root=tmp_path)]

    assert routes_a == routes_b
