"""
BELIEF — BELIEF-Bench Evaluation Framework.

Provides ground truth datasets and automated evaluation for measuring
BELIEF's effectiveness compared to existing tools.

Supports:
- Retrospective evaluation (does BELIEF find known bugs pre-patch?)
- Prospective evaluation (does BELIEF find new issues?)
- Comparative evaluation (BELIEF vs CodeQL vs Semgrep vs Bandit)
- Ablation studies (remove components, measure impact)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field


from ..models import AnalysisReport, Belief

logger = logging.getLogger("belief.bench")


@dataclass
class GroundTruthEntry:
    """A known vulnerability with belief annotation."""
    id: str
    cve: str                    # CVE ID or empty for silent fixes
    description: str
    file_path: str
    line_start: int
    line_end: int
    cwe: str                    # CWE category
    severity: str               # critical, high, medium, low
    belief_expression: str      # the implicit belief that was violated
    belief_justification: str   # C1-C6
    fix_commit: str             # commit hash that fixed it
    project: str
    language: str


@dataclass
class EvalResult:
    """Result of evaluating BELIEF against a ground truth entry."""
    entry_id: str
    found: bool                 # did BELIEF detect this vulnerability?
    matched_belief_id: str = ""
    matched_conflict_id: str = ""
    detection_method: str = ""  # z3, heuristic, llm_semantic, structural
    false_positive: bool = False


@dataclass
class BenchmarkResult:
    """Aggregate evaluation results."""
    tool_name: str
    entries_tested: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    results: list[EvalResult] = field(default_factory=list)

    @property
    def precision(self) -> float:
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)

    @property
    def recall(self) -> float:
        if self.true_positives + self.false_negatives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        if p + r == 0:
            return 0.0
        return 2 * p * r / (p + r)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool_name,
            "entries_tested": self.entries_tested,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1_score": round(self.f1, 3),
        }


# ─── Built-in Ground Truth (LLM Agent Vulnerabilities) ───

BUILTIN_GROUND_TRUTH = [
    GroundTruthEntry(
        id="GT-001", cve="", project="langchain",
        description="PythonREPL executes LLM-generated code without sandboxing",
        file_path="langchain/tools/python/tool.py",
        line_start=1, line_end=50,
        cwe="CWE-94", severity="critical",
        belief_expression="llm_output.is_safe_code == True",
        belief_justification="C5",
        fix_commit="", language="python",
    ),
    GroundTruthEntry(
        id="GT-002", cve="", project="langchain",
        description="ConversationBufferMemory trusts all stored content",
        file_path="langchain/memory/buffer.py",
        line_start=1, line_end=100,
        cwe="CWE-74", severity="high",
        belief_expression="memory.contents in TRUSTED_DATA",
        belief_justification="C5",
        fix_commit="", language="python",
    ),
    GroundTruthEntry(
        id="GT-003", cve="", project="langchain",
        description="Web content fetched by agent can contain prompt injection",
        file_path="langchain/tools/requests/tool.py",
        line_start=1, line_end=50,
        cwe="CWE-74", severity="high",
        belief_expression="web_response.content_type == 'passive_data'",
        belief_justification="C5",
        fix_commit="", language="python",
    ),
    GroundTruthEntry(
        id="GT-004", cve="", project="langchain",
        description="SQL chain generates queries from untrusted LLM output",
        file_path="langchain/chains/sql_database/query.py",
        line_start=1, line_end=80,
        cwe="CWE-89", severity="high",
        belief_expression="sql_query in SAFE_QUERIES",
        belief_justification="C5",
        fix_commit="", language="python",
    ),
    GroundTruthEntry(
        id="GT-005", cve="CVE-2023-36189", project="langchain",
        description="Arbitrary code execution via PALChain",
        file_path="langchain/chains/pal/base.py",
        line_start=1, line_end=100,
        cwe="CWE-94", severity="critical",
        belief_expression="generated_code.is_safe == True",
        belief_justification="C5",
        fix_commit="", language="python",
    ),
    GroundTruthEntry(
        id="GT-006", cve="", project="langchain",
        description="Vector store retrieval trusts all document content",
        file_path="langchain/vectorstores/base.py",
        line_start=1, line_end=50,
        cwe="CWE-74", severity="medium",
        belief_expression="vectorstore.documents in CLEAN_DATA",
        belief_justification="C5",
        fix_commit="", language="python",
    ),
    GroundTruthEntry(
        id="GT-007", cve="", project="langchain",
        description="Chain output format assumed but not validated",
        file_path="langchain/chains/sequential.py",
        line_start=1, line_end=50,
        cwe="CWE-20", severity="medium",
        belief_expression="chain_output.format == expected_format",
        belief_justification="C4",
        fix_commit="", language="python",
    ),
    GroundTruthEntry(
        id="GT-008", cve="", project="langchain",
        description="Callbacks can access agent state without permission checks",
        file_path="langchain/callbacks/manager.py",
        line_start=1, line_end=100,
        cwe="CWE-862", severity="medium",
        belief_expression="callback.is_trusted == True",
        belief_justification="C5",
        fix_commit="", language="python",
    ),
]


class BenchmarkRunner:
    """
    Run evaluation benchmarks against ground truth.
    """

    def __init__(self, ground_truth: list[GroundTruthEntry] | None = None):
        self.ground_truth = ground_truth or BUILTIN_GROUND_TRUTH

    def evaluate_report(
        self,
        report: AnalysisReport,
        tool_name: str = "BELIEF",
    ) -> BenchmarkResult:
        """Evaluate a BELIEF report against ground truth."""
        result = BenchmarkResult(tool_name=tool_name)
        result.entries_tested = len(self.ground_truth)

        for entry in self.ground_truth:
            eval_result = self._check_entry(entry, report)
            result.results.append(eval_result)
            if eval_result.found:
                result.true_positives += 1
            else:
                result.false_negatives += 1

        # Count false positives: conflicts not matching any ground truth
        matched_belief_ids = {r.matched_belief_id for r in result.results if r.found}
        for conflict in report.conflicts:
            if (conflict.belief_a.id not in matched_belief_ids and
                    conflict.belief_b.id not in matched_belief_ids):
                result.false_positives += 1

        return result

    def _check_entry(
        self,
        entry: GroundTruthEntry,
        report: AnalysisReport,
    ) -> EvalResult:
        """Check if a ground truth entry was detected."""
        # Try matching by predicate expression similarity
        for belief in report.beliefs:
            if self._beliefs_match(entry, belief):
                return EvalResult(
                    entry_id=entry.id,
                    found=True,
                    matched_belief_id=belief.id,
                    detection_method="belief_match",
                )

        # Try matching by conflict
        for conflict in report.conflicts:
            if (self._beliefs_match(entry, conflict.belief_a) or
                    self._beliefs_match(entry, conflict.belief_b)):
                return EvalResult(
                    entry_id=entry.id,
                    found=True,
                    matched_conflict_id=f"{conflict.belief_a.id}-{conflict.belief_b.id}",
                    detection_method=conflict.verified_by,
                )

        return EvalResult(entry_id=entry.id, found=False)

    def _beliefs_match(self, entry: GroundTruthEntry, belief: Belief) -> bool:
        """Check if a belief matches a ground truth entry."""
        entry_expr = entry.belief_expression.lower().strip()
        belief_expr = belief.predicate.expression.lower().strip()

        # Exact match
        if entry_expr == belief_expr:
            return True

        # Keyword overlap (at least 2 significant words match)
        noise = {"is", "not", "in", "true", "false", "none", "the", "a", "an", "=="}
        entry_words = set(entry_expr.split()) - noise
        belief_words = set(belief_expr.split()) - noise
        overlap = entry_words & belief_words
        if len(overlap) >= 2:
            return True

        # CWE match + same file
        if entry.file_path and belief.scope.file_path:
            if (entry.cwe.lower() in belief.predicate.natural_language.lower() and
                    entry.file_path.split("/")[-1] in belief.scope.file_path):
                return True

        return False

    def save_results(self, result: BenchmarkResult, path: str):
        with open(path, "w") as f:
            json.dump(result.to_dict(), f, indent=2)

    def comparison_table(self, results: list[BenchmarkResult]) -> str:
        """Generate a markdown comparison table."""
        lines = [
            "| Tool | Precision | Recall | F1 | TP | FP | FN |",
            "|------|-----------|--------|----|----|----|-----|",
        ]
        for r in results:
            lines.append(
                f"| {r.tool_name} | {r.precision:.3f} | {r.recall:.3f} | "
                f"{r.f1:.3f} | {r.true_positives} | {r.false_positives} | "
                f"{r.false_negatives} |"
            )
        return "\n".join(lines)
