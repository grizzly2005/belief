"""
BELIEF — Export Formats.

Generate analysis reports in multiple formats:
- SARIF 2.1.0 (GitHub Security, Azure DevOps compatible)
- Markdown (human-readable reports)
- JSON (machine-readable, enhanced)
- HTML (standalone, no external dependencies)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from ..models import AnalysisReport, Belief, Conflict, ConflictSeverity

logger = logging.getLogger("belief.export")


class SARIFExporter:
    """
    Export BELIEF results as SARIF 2.1.0.

    SARIF (Static Analysis Results Interchange Format) is the standard
    for GitHub Code Scanning, Azure DevOps, and other CI platforms.
    """

    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def export(self, report: AnalysisReport) -> dict:
        """Generate SARIF JSON structure."""
        rules = []
        results = []
        rule_ids = set()

        # Generate rules and results from conflicts
        for conflict in report.conflicts:
            rule_id = self._conflict_to_rule_id(conflict)
            if rule_id not in rule_ids:
                rules.append(self._make_rule(conflict, rule_id))
                rule_ids.add(rule_id)
            results.append(self._make_result(conflict, rule_id))

        # Generate results from high-risk beliefs without conflicts
        for belief in report.beliefs:
            if belief.confidence_score >= 0.85 and belief.fragility >= 0.7:
                rule_id = self._belief_to_rule_id(belief)
                if rule_id not in rule_ids:
                    rules.append(self._make_belief_rule(belief, rule_id))
                    rule_ids.add(rule_id)
                results.append(self._make_belief_result(belief, rule_id))

        return {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "BELIEF",
                        "version": "0.4.0",
                        "informationUri": "https://github.com/belief-sec/belief",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                }],
            }],
        }

    def export_json(self, report: AnalysisReport) -> str:
        return json.dumps(self.export(report), indent=2)

    def _conflict_to_rule_id(self, conflict: Conflict) -> str:
        return f"BELIEF-C-{conflict.belief_a.id[:6]}"

    def _belief_to_rule_id(self, belief: Belief) -> str:
        return f"BELIEF-B-{belief.id[:6]}"

    def _severity_to_sarif(self, severity: ConflictSeverity) -> str:
        return {
            ConflictSeverity.CRITICAL: "error",
            ConflictSeverity.HIGH: "error",
            ConflictSeverity.MEDIUM: "warning",
            ConflictSeverity.LOW: "note",
        }.get(severity, "warning")

    def _make_rule(self, conflict: Conflict, rule_id: str) -> dict:
        return {
            "id": rule_id,
            "name": "BeliefConflict",
            "shortDescription": {"text": conflict.description[:200] if conflict.description else "Belief conflict detected"},
            "fullDescription": {"text": (
                f"Conflict between '{conflict.belief_a.predicate.expression}' "
                f"and '{conflict.belief_b.predicate.expression}'"
            )},
            "defaultConfiguration": {
                "level": self._severity_to_sarif(conflict.severity),
            },
            "properties": {
                "tags": ["security", "belief-conflict"],
            },
        }

    def _make_result(self, conflict: Conflict, rule_id: str) -> dict:
        belief = conflict.belief_a
        return {
            "ruleId": rule_id,
            "level": self._severity_to_sarif(conflict.severity),
            "message": {"text": conflict.description or "Belief conflict"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": belief.scope.file_path or "unknown"},
                    "region": {
                        "startLine": belief.scope.line_start or 1,
                        "endLine": belief.scope.line_end or 1,
                    },
                }
            }],
            "properties": {
                "severity": conflict.severity.value,
                "verified_by": conflict.verified_by,
                "belief_a": belief.predicate.expression,
                "belief_b": conflict.belief_b.predicate.expression,
            },
        }

    def _make_belief_rule(self, belief: Belief, rule_id: str) -> dict:
        return {
            "id": rule_id,
            "name": "FragileBelief",
            "shortDescription": {"text": f"Fragile implicit belief: {belief.predicate.expression[:100]}"},
            "defaultConfiguration": {"level": "warning"},
            "properties": {"tags": ["belief", "implicit-assumption"]},
        }

    def _make_belief_result(self, belief: Belief, rule_id: str) -> dict:
        return {
            "ruleId": rule_id,
            "level": "warning",
            "message": {"text": belief.predicate.natural_language or belief.predicate.expression},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": belief.scope.file_path or "unknown"},
                    "region": {
                        "startLine": belief.scope.line_start or 1,
                    },
                }
            }],
            "properties": {
                "justification": belief.justification.value,
                "confidence": belief.confidence_score,
                "fragility": belief.fragility,
            },
        }


class MarkdownExporter:
    """Export BELIEF results as a Markdown report."""

    def export(self, report: AnalysisReport) -> str:
        lines = [
            f"# BELIEF Analysis Report: {report.project_name}",
            "",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "",
            "## Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total beliefs | {len(report.beliefs)} |",
            f"| Conflicts found | {len(report.conflicts)} |",
            f"| Cognitive Debt | {report.cognitive_debt:.2f} |",
            f"| Epistemic Health | {report.cognitive_debt:.2f} |",
            f"| Mean Fragility | {report.mean_fragility:.2f} |",
            "",
        ]

        # Conflicts section
        if report.conflicts:
            lines.append("## Conflicts")
            lines.append("")
            for i, c in enumerate(sorted(report.conflicts,
                                          key=lambda x: x.severity.value, reverse=True), 1):
                lines.append(f"### {i}. [{c.severity.value.upper()}] {c.description[:100]}")
                lines.append("")
                lines.append(f"- **Belief A:** `{c.belief_a.predicate.expression}`")
                lines.append(f"  - File: {c.belief_a.scope.file_path}:{c.belief_a.scope.line_start or '?'}")
                lines.append(f"  - Justification: {c.belief_a.justification.value}")
                lines.append(f"- **Belief B:** `{c.belief_b.predicate.expression}`")
                lines.append(f"  - File: {c.belief_b.scope.file_path}:{c.belief_b.scope.line_start or '?'}")
                lines.append(f"- **Verified by:** {c.verified_by}")
                lines.append("")

        # High-fragility beliefs
        fragile = sorted(
            [b for b in report.beliefs if b.fragility >= 0.7],
            key=lambda b: b.fragility, reverse=True,
        )[:20]

        if fragile:
            lines.append("## Top Fragile Beliefs")
            lines.append("")
            lines.append("| # | Expression | File | Fragility | Justification |")
            lines.append("|---|-----------|------|-----------|---------------|")
            for i, b in enumerate(fragile, 1):
                expr = b.predicate.expression[:60]
                fp = b.scope.file_path.split("/")[-1] if b.scope.file_path else "?"
                lines.append(f"| {i} | `{expr}` | {fp} | {b.fragility:.2f} | {b.justification.value} |")
            lines.append("")

        return "\n".join(lines)


class HTMLExporter:
    """Export BELIEF results as a standalone HTML report."""

    def export(self, report: AnalysisReport) -> str:
        conflicts_html = ""
        for c in sorted(report.conflicts, key=lambda x: x.severity.value, reverse=True):
            sev_color = {"critical": "#dc3545", "high": "#fd7e14",
                         "medium": "#ffc107", "low": "#28a745"}.get(c.severity.value, "#6c757d")
            conflicts_html += f"""
            <div style="border-left:4px solid {sev_color};padding:12px;margin:8px 0;background:#f8f9fa;border-radius:4px">
                <strong style="color:{sev_color}">[{c.severity.value.upper()}]</strong>
                {c.description or 'Belief conflict'}
                <div style="margin-top:8px;font-size:0.9em;color:#555">
                    <code>{c.belief_a.predicate.expression}</code> vs
                    <code>{c.belief_b.predicate.expression}</code>
                </div>
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>BELIEF Report: {report.project_name}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #333; }}
h1 {{ color: #1a1a2e; border-bottom: 2px solid #16213e; padding-bottom: 10px; }}
.metric {{ display: inline-block; background: #e8f4fd; padding: 12px 20px; margin: 5px; border-radius: 8px; text-align: center; }}
.metric .value {{ font-size: 1.8em; font-weight: bold; color: #16213e; }}
.metric .label {{ font-size: 0.8em; color: #666; }}
table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
th {{ background: #16213e; color: white; }}
tr:nth-child(even) {{ background: #f8f9fa; }}
code {{ background: #e9ecef; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }}
</style>
</head>
<body>
<h1>BELIEF Analysis Report</h1>
<p><strong>Project:</strong> {report.project_name} | <strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>

<div>
<div class="metric"><div class="value">{len(report.beliefs)}</div><div class="label">Beliefs</div></div>
<div class="metric"><div class="value">{len(report.conflicts)}</div><div class="label">Conflicts</div></div>
<div class="metric"><div class="value">{report.cognitive_debt:.0%}</div><div class="label">Cognitive Debt</div></div>
<div class="metric"><div class="value">{(1.0 - report.cognitive_debt):.0%}</div><div class="label">Health</div></div>
</div>

<h2>Conflicts ({len(report.conflicts)})</h2>
{conflicts_html if conflicts_html else '<p>No conflicts detected.</p>'}

</body>
</html>"""


class JSONExporter:
    """Enhanced JSON export with full analysis metadata."""

    def export(self, report: AnalysisReport) -> str:
        return json.dumps({
            "belief_version": "0.4.0",
            "project": report.project_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_beliefs": len(report.beliefs),
                "total_conflicts": len(report.conflicts),
                "cognitive_debt": report.cognitive_debt,
                "epistemic_health": report.epistemic_health,
                "mean_fragility": report.mean_fragility,
            },
            "beliefs": [b.to_dict() for b in report.beliefs],
            "conflicts": [
                {
                    "belief_a": c.belief_a.to_dict(),
                    "belief_b": c.belief_b.to_dict(),
                    "severity": c.severity.value,
                    "description": c.description,
                    "verified_by": c.verified_by,
                }
                for c in report.conflicts
            ],
        }, indent=2)
