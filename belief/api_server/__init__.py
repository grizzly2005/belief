"""
BELIEF — REST API Server.

Provides HTTP endpoints for BELIEF analysis:
- POST /analyze    — run analysis on uploaded code
- GET  /report/:id — get analysis report
- GET  /beliefs    — list beliefs with filtering
- GET  /health     — health check
- GET  /stats      — system statistics

Uses Python's built-in http.server — zero external dependencies.
"""

from __future__ import annotations

import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from ..models import AnalysisReport
from ..structural import StructuralExtractor
from ..security_patterns import SecurityPatternExtractor
from ..taint import TaintEngine

logger = logging.getLogger("belief.api_server")


class BeliefAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for BELIEF API."""

    # Shared state (set by APIServer before starting)
    reports: dict[str, AnalysisReport] = {}
    structural = StructuralExtractor()
    security = SecurityPatternExtractor()
    taint = TaintEngine()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)

        if path == "/health":
            self._json_response({"status": "ok", "version": "0.5.0"})
        elif path == "/stats":
            self._json_response(self._get_stats())
        elif path == "/beliefs":
            self._json_response(self._list_beliefs(params))
        elif path.startswith("/report/"):
            report_id = path.split("/report/")[-1]
            self._get_report(report_id)
        else:
            self._json_response({"error": "Not found", "endpoints": [
                "GET /health", "GET /stats", "GET /beliefs",
                "GET /report/:id", "POST /analyze",
            ]}, status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/analyze":
            self._handle_analyze()
        else:
            self._json_response({"error": "Not found"}, status=404)

    def _handle_analyze(self):
        """Handle POST /analyze with source code in body."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")

            try:
                data = json.loads(body)
                source_code = data.get("code", "")
                file_path = data.get("file_path", "uploaded.py")
                project_name = data.get("project", "api_upload")
            except json.JSONDecodeError:
                # Treat raw body as source code
                source_code = body
                file_path = "uploaded.py"
                project_name = "api_upload"

            if not source_code:
                self._json_response({"error": "No code provided"}, status=400)
                return

            # Run analysis
            all_beliefs = []
            all_beliefs.extend(self.structural.extract(source_code, file_path))
            all_beliefs.extend(self.security.extract(source_code, file_path))
            all_beliefs.extend(self.taint.analyze_to_beliefs(source_code, file_path))

            report = AnalysisReport(
                project_name=project_name,
                beliefs=all_beliefs,
            )

            # Store report
            import hashlib
            report_id = hashlib.sha256(source_code.encode()).hexdigest()[:12]
            self.reports[report_id] = report

            self._json_response({
                "report_id": report_id,
                "total_beliefs": len(all_beliefs),
                "cognitive_debt": report.cognitive_debt,
                "beliefs": [b.to_dict() for b in all_beliefs[:50]],
            })

        except Exception as e:
            logger.error(f"Analysis error: {e}")
            self._json_response({"error": str(e)}, status=500)

    def _get_report(self, report_id: str):
        report = self.reports.get(report_id)
        if not report:
            self._json_response({"error": "Report not found"}, status=404)
            return

        self._json_response({
            "report_id": report_id,
            "project": report.project_name,
            "total_beliefs": len(report.beliefs),
            "total_conflicts": len(report.conflicts),
            "cognitive_debt": report.cognitive_debt,
            "beliefs": [b.to_dict() for b in report.beliefs],
            "conflicts": [
                {
                    "belief_a": c.belief_a.predicate.expression,
                    "belief_b": c.belief_b.predicate.expression,
                    "severity": c.severity.value,
                }
                for c in report.conflicts
            ],
        })

    def _list_beliefs(self, params: dict) -> dict:
        """List beliefs across all reports with optional filtering."""
        all_beliefs = []
        for rid, report in self.reports.items():
            for b in report.beliefs:
                all_beliefs.append({
                    "report_id": rid,
                    **b.to_dict(),
                })

        # Filter by justification
        just_filter = params.get("justification", [None])[0]
        if just_filter:
            all_beliefs = [b for b in all_beliefs
                          if b.get("justification") == just_filter]

        # Limit
        limit = int(params.get("limit", [100])[0])
        return {
            "total": len(all_beliefs),
            "beliefs": all_beliefs[:limit],
        }

    def _get_stats(self) -> dict:
        total_beliefs = sum(len(r.beliefs) for r in self.reports.values())
        total_conflicts = sum(len(r.conflicts) for r in self.reports.values())
        return {
            "total_reports": len(self.reports),
            "total_beliefs": total_beliefs,
            "total_conflicts": total_conflicts,
        }

    def _json_response(self, data: dict, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode("utf-8"))

    def log_message(self, format, *args):
        logger.info(f"API: {args[0] if args else ''}")


class APIServer:
    """BELIEF REST API server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8420):
        self.host = host
        self.port = port
        self.server: HTTPServer | None = None

    def start(self):
        """Start the API server (blocking)."""
        self.server = HTTPServer((self.host, self.port), BeliefAPIHandler)
        logger.info(f"BELIEF API server running on http://{self.host}:{self.port}")
        print(f"BELIEF API server running on http://{self.host}:{self.port}")
        print("Endpoints: GET /health, POST /analyze, GET /beliefs, GET /report/:id")
        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        if self.server:
            self.server.shutdown()
            logger.info("API server stopped")
