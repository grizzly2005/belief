"""API entrypoint. User-controlled filename accepted without validation."""
from flask import Flask, request
from generators.report import build_report

app = Flask(__name__)


@app.route("/report", methods=["POST"])
def generate():
    # Source of taint
    data = request.get_json(force=True) or {}
    filename = data.get("filename", "out.pdf")
    # Pass to business logic — no sanitation
    path = build_report(filename)
    return {"path": path}
