"""Synthetic protected path case: basename and root containment guard."""

from pathlib import Path


def read_named_report_safely(request, report_root):
    requested_name = Path(request.params.get("name", "")).name
    root = Path(report_root).resolve()
    report_path = (root / requested_name).resolve()
    if root not in report_path.parents and report_path != root:
        return ""
    return report_path.read_text(encoding="utf-8")
