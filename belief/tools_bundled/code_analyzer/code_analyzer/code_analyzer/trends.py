"""Trend analysis and historical tracking."""

import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict

from .models import AnalysisResult


@dataclass
class TrendPoint:
    """Single point in trend analysis."""
    timestamp: datetime
    total_issues: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    avg_complexity: float
    max_complexity: int
    total_files: int
    total_lines: int
    total_functions: int


class TrendsDatabase:
    """SQLite database for historical analysis data."""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                project_path TEXT NOT NULL,
                total_issues INTEGER,
                critical_issues INTEGER,
                high_issues INTEGER,
                medium_issues INTEGER,
                low_issues INTEGER,
                avg_complexity REAL,
                max_complexity INTEGER,
                total_files INTEGER,
                total_lines INTEGER,
                total_functions INTEGER,
                total_classes INTEGER,
                branch_name TEXT,
                commit_hash TEXT,
                raw_data TEXT
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp 
            ON analysis_history(timestamp DESC)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_project 
            ON analysis_history(project_path, timestamp DESC)
        """)
        
        conn.commit()
        conn.close()
    
    def store_analysis(self, result: AnalysisResult, branch: str = "", commit: str = ""):
        """Store analysis result in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO analysis_history (
                timestamp, project_path, total_issues,
                critical_issues, high_issues, medium_issues, low_issues,
                avg_complexity, max_complexity,
                total_files, total_lines, total_functions, total_classes,
                branch_name, commit_hash, raw_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.analysis_date.isoformat(),
            result.project_path,
            result.metrics.total_issues,
            result.metrics.issues_by_severity.get('critical', 0),
            result.metrics.issues_by_severity.get('high', 0),
            result.metrics.issues_by_severity.get('medium', 0),
            result.metrics.issues_by_severity.get('low', 0),
            result.metrics.average_complexity,
            result.metrics.max_complexity,
            result.metrics.total_files,
            result.metrics.total_lines,
            result.metrics.total_functions,
            result.metrics.total_classes,
            branch,
            commit,
            json.dumps({
                'issues_by_type': result.metrics.issues_by_type,
                'entry_points': result.entry_points
            })
        ))
        
        conn.commit()
        conn.close()
    
    def get_trends(self, project_path: str, days: int = 30) -> List[TrendPoint]:
        """Get trend data for a project."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT timestamp, total_issues, critical_issues, high_issues,
                   medium_issues, low_issues, avg_complexity, max_complexity,
                   total_files, total_lines, total_functions
            FROM analysis_history
            WHERE project_path = ?
              AND datetime(timestamp) >= datetime('now', ?)
            ORDER BY timestamp ASC
        """, (project_path, f'-{days} days'))
        
        trends = []
        for row in cursor.fetchall():
            trends.append(TrendPoint(
                timestamp=datetime.fromisoformat(row[0]),
                total_issues=row[1],
                critical_issues=row[2],
                high_issues=row[3],
                medium_issues=row[4],
                low_issues=row[5],
                avg_complexity=row[6],
                max_complexity=row[7],
                total_files=row[8],
                total_lines=row[9],
                total_functions=row[10]
            ))
        
        conn.close()
        return trends
    
    def get_latest(self, project_path: str) -> Optional[TrendPoint]:
        """Get most recent analysis."""
        trends = self.get_trends(project_path, days=365)
        return trends[-1] if trends else None
    
    def calculate_change(self, project_path: str, metric: str) -> Optional[float]:
        """Calculate percentage change for a metric."""
        trends = self.get_trends(project_path, days=30)
        
        if len(trends) < 2:
            return None
        
        first = getattr(trends[0], metric, 0)
        last = getattr(trends[-1], metric, 0)
        
        if first == 0:
            return None
        
        return ((last - first) / first) * 100


def generate_trend_markdown(trends: List[TrendPoint], project_name: str) -> str:
    """Generate markdown report for trends."""
    if not trends:
        return "No historical data available."
    
    latest = trends[-1]
    first = trends[0]
    
    # Calculate changes
    def change(attr):
        f = getattr(first, attr, 0)
        l = getattr(latest, attr, 0)
        if f == 0:
            return "N/A"
        pct = ((l - f) / f) * 100
        emoji = "📈" if pct > 0 else "📉" if pct < 0 else "➡️"
        return f"{emoji} {pct:+.1f}%"
    
    content = f"""# 📊 Trend Analysis: {project_name}

## Overview
- **Analysis Period**: {first.timestamp.strftime('%Y-%m-%d')} to {latest.timestamp.strftime('%Y-%m-%d')}
- **Data Points**: {len(trends)}

## Key Metrics Trends

### Issues
| Metric | Current | Change |
|--------|---------|--------|
| Total Issues | {latest.total_issues} | {change('total_issues')} |
| Critical | {latest.critical_issues} | {change('critical_issues')} |
| High | {latest.high_issues} | {change('high_issues')} |
| Medium | {latest.medium_issues} | {change('medium_issues')} |
| Low | {latest.low_issues} | {change('low_issues')} |

### Code Quality
| Metric | Current | Change |
|--------|---------|--------|
| Avg Complexity | {latest.avg_complexity:.2f} | {change('avg_complexity')} |
| Max Complexity | {latest.max_complexity} | {change('max_complexity')} |

### Codebase Size
| Metric | Current | Change |
|--------|---------|--------|
| Total Files | {latest.total_files} | {change('total_files')} |
| Total Lines | {latest.total_lines:,} | {change('total_lines')} |
| Total Functions | {latest.total_functions} | {change('total_functions')} |

## Sparkline Trends

"""
    
    # Generate simple ASCII sparklines
    if len(trends) >= 3:
        issues = [t.total_issues for t in trends]
        complexity = [t.avg_complexity for t in trends]
        
        content += f"**Issues**: {_sparkline(issues)}\n"
        content += f"**Complexity**: {_sparkline(complexity)}\n"
    
    return content


def _sparkline(data: List[float]) -> str:
    """Generate ASCII sparkline."""
    if not data or len(data) < 2:
        return "—"
    
    chars = "▁▂▃▄▅▆▇█"
    min_val = min(data)
    max_val = max(data)
    
    if max_val == min_val:
        return chars[3] * len(data)
    
    normalized = [(v - min_val) / (max_val - min_val) for v in data]
    return ''.join(chars[min(int(v * len(chars)), len(chars) - 1)] for v in normalized)
