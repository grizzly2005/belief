"""Compatibility wrapper for reportability scoring of imported tool results."""

from __future__ import annotations

from belief.reportability.scoring import assess_audit_case_reportability, assess_many

__all__ = ["assess_audit_case_reportability", "assess_many"]
