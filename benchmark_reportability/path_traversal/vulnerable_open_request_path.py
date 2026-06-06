"""Synthetic path traversal candidate: opens a request-controlled relative path."""

from pathlib import Path


def read_named_report(request, report_root):
    requested_name = request.params.get("name", "")
    report_path = Path(report_root) / requested_name
    return report_path.read_text(encoding="utf-8")
