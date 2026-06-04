"""Enhanced code quality trends with detailed insights and visualizations."""

from typing import List, Dict, Tuple, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass
from .trends import TrendPoint, TrendsDatabase


@dataclass
class QualityInsight:
    """Insight about code quality trend."""
    category: str  # 'improvement', 'regression', 'stable', 'warning'
    title: str
    description: str
    metrics: Dict[str, float]
    recommendation: str


class QualityTrendsAnalyzer:
    """Analyzes quality trends and generates insights."""
    
    def __init__(self, trends_db: TrendsDatabase):
        self.db = trends_db
    
    def analyze_quality_trends(self, project_path: str, days: int = 90) -> List[QualityInsight]:
        """Analyze quality trends and generate insights."""
        trends = self.db.get_trends(project_path, days=days)
        
        if len(trends) < 2:
            return []
        
        insights = []
        
        # Issue trends
        insights.extend(self._analyze_issue_trends(trends))
        
        # Complexity trends
        insights.extend(self._analyze_complexity_trends(trends))
        
        # Growth trends
        insights.extend(self._analyze_growth_trends(trends))
        
        # Velocity insights
        insights.extend(self._analyze_velocity(trends))
        
        return insights
    
    def _analyze_issue_trends(self, trends: List[TrendPoint]) -> List[QualityInsight]:
        """Analyze issue count trends."""
        insights = []
        
        first = trends[0]
        last = trends[-1]
        
        # Total issues trend
        issue_change = self._percent_change(first.total_issues, last.total_issues)
        
        if issue_change < -20:
            insights.append(QualityInsight(
                category='improvement',
                title='Significant Issue Reduction',
                description=f'Total issues decreased by {abs(issue_change):.1f}% ({first.total_issues} → {last.total_issues})',
                metrics={'change_percent': issue_change, 'issues_fixed': first.total_issues - last.total_issues},
                recommendation='Great progress! Continue addressing remaining issues systematically.'
            ))
        elif issue_change > 20:
            insights.append(QualityInsight(
                category='regression',
                title='Rising Issue Count',
                description=f'Total issues increased by {issue_change:.1f}% ({first.total_issues} → {last.total_issues})',
                metrics={'change_percent': issue_change, 'new_issues': last.total_issues - first.total_issues},
                recommendation='Consider dedicating time to address accumulating technical debt.'
            ))
        
        # Critical issues trend
        critical_change = self._percent_change(first.critical_issues, last.critical_issues)
        
        if last.critical_issues > 0 and critical_change > 0:
            insights.append(QualityInsight(
                category='warning',
                title='Critical Issues Increasing',
                description=f'Critical issues grew from {first.critical_issues} to {last.critical_issues}',
                metrics={'critical_count': last.critical_issues, 'change': critical_change},
                recommendation='Prioritize critical issues immediately - they pose significant risk.'
            ))
        elif first.critical_issues > 0 and last.critical_issues == 0:
            insights.append(QualityInsight(
                category='improvement',
                title='All Critical Issues Resolved',
                description='Successfully eliminated all critical issues',
                metrics={'issues_resolved': first.critical_issues},
                recommendation='Excellent work! Maintain this quality standard going forward.'
            ))
        
        return insights
    
    def _analyze_complexity_trends(self, trends: List[TrendPoint]) -> List[QualityInsight]:
        """Analyze complexity trends."""
        insights = []
        
        first = trends[0]
        last = trends[-1]
        
        # Average complexity
        complexity_change = self._percent_change(first.avg_complexity, last.avg_complexity)
        
        if complexity_change > 15:
            insights.append(QualityInsight(
                category='regression',
                title='Complexity Increasing',
                description=f'Average complexity grew from {first.avg_complexity:.2f} to {last.avg_complexity:.2f}',
                metrics={'avg_complexity': last.avg_complexity, 'change': complexity_change},
                recommendation='Consider refactoring: break down complex functions, extract methods.'
            ))
        elif complexity_change < -15:
            insights.append(QualityInsight(
                category='improvement',
                title='Complexity Reduced',
                description=f'Average complexity decreased from {first.avg_complexity:.2f} to {last.avg_complexity:.2f}',
                metrics={'avg_complexity': last.avg_complexity, 'change': complexity_change},
                recommendation='Great refactoring! Code is becoming more maintainable.'
            ))
        
        # Max complexity
        if last.max_complexity > 20:
            insights.append(QualityInsight(
                category='warning',
                title='High Maximum Complexity',
                description=f'Most complex function has complexity of {last.max_complexity}',
                metrics={'max_complexity': last.max_complexity},
                recommendation='Target functions with complexity >15 for refactoring.'
            ))
        
        return insights
    
    def _analyze_growth_trends(self, trends: List[TrendPoint]) -> List[QualityInsight]:
        """Analyze codebase growth."""
        insights = []
        
        first = trends[0]
        last = trends[-1]
        
        lines_change = self._percent_change(first.total_lines, last.total_lines)
        issues_per_loc = (last.total_issues / max(last.total_lines, 1)) * 1000
        
        # Growth without quality degradation
        if lines_change > 10 and self._percent_change(first.total_issues, last.total_issues) < 10:
            insights.append(QualityInsight(
                category='improvement',
                title='Healthy Growth',
                description=f'Codebase grew {lines_change:.1f}% while maintaining quality',
                metrics={'lines_added': last.total_lines - first.total_lines, 'issues_per_kloc': issues_per_loc},
                recommendation='Maintaining quality during growth is excellent discipline.'
            ))
        
        # Issue density
        if issues_per_loc > 5:
            insights.append(QualityInsight(
                category='warning',
                title='High Issue Density',
                description=f'{issues_per_loc:.1f} issues per 1000 lines of code',
                metrics={'issues_per_kloc': issues_per_loc},
                recommendation='Target issue density below 3 per 1000 lines for production code.'
            ))
        elif issues_per_loc < 2:
            insights.append(QualityInsight(
                category='improvement',
                title='Low Issue Density',
                description=f'Only {issues_per_loc:.1f} issues per 1000 lines - excellent quality',
                metrics={'issues_per_kloc': issues_per_loc},
                recommendation='Quality metrics are strong. Continue current practices.'
            ))
        
        return insights
    
    def _analyze_velocity(self, trends: List[TrendPoint]) -> List[QualityInsight]:
        """Analyze improvement velocity."""
        if len(trends) < 3:
            return []
        
        insights = []
        
        # Recent vs older trend
        mid_point = len(trends) // 2
        older = trends[:mid_point]
        recent = trends[mid_point:]
        
        older_avg_issues = sum(t.total_issues for t in older) / len(older)
        recent_avg_issues = sum(t.total_issues for t in recent) / len(recent)
        
        velocity = self._percent_change(older_avg_issues, recent_avg_issues)
        
        if velocity < -10:
            insights.append(QualityInsight(
                category='improvement',
                title='Accelerating Improvement',
                description='Issue resolution is accelerating in recent period',
                metrics={'velocity': abs(velocity)},
                recommendation='Current velocity is strong. Keep momentum going.'
            ))
        elif velocity > 10:
            insights.append(QualityInsight(
                category='warning',
                title='Quality Degrading Faster',
                description='Issues are accumulating at increasing rate',
                metrics={'velocity': velocity},
                recommendation='Intervention needed to reverse negative trend.'
            ))
        
        return insights
    
    def _percent_change(self, old: float, new: float) -> float:
        """Calculate percentage change."""
        if old == 0:
            return 0 if new == 0 else 100
        return ((new - old) / old) * 100
    
    def generate_trend_chart(self, trends: List[TrendPoint], metric: str) -> str:
        """Generate ASCII trend chart."""
        if len(trends) < 2:
            return ""
        
        values = [getattr(t, metric) for t in trends]
        
        # Determine scale
        min_val = min(values)
        max_val = max(values)
        range_val = max_val - min_val
        
        if range_val == 0:
            return "█" * len(values) + " (stable)"
        
        # Create chart
        height = 10
        chart_lines = []
        
        for h in range(height, 0, -1):
            threshold = min_val + (range_val * h / height)
            line = ""
            for v in values:
                if v >= threshold:
                    line += "█"
                else:
                    line += " "
            chart_lines.append(line)
        
        # Add labels
        chart = "\n".join(chart_lines)
        chart += "\n" + "─" * len(values)
        chart += f"\n{min_val:.1f}" + " " * (len(values) - 10) + f"{max_val:.1f}"
        
        return chart


def format_quality_trends(project_path: str, trends_db: TrendsDatabase, days: int = 90) -> str:
    """Format quality trends report."""
    analyzer = QualityTrendsAnalyzer(trends_db)
    insights = analyzer.analyze_quality_trends(project_path, days)
    trends = trends_db.get_trends(project_path, days)
    
    if not trends:
        return ""
    
    output = []
    output.append("# 📈 CODE QUALITY TRENDS")
    output.append("=" * 80)
    output.append("")
    
    first = trends[0]
    last = trends[-1]
    
    output.append(f"**Analysis Period**: {first.timestamp.strftime('%Y-%m-%d')} to {last.timestamp.strftime('%Y-%m-%d')}")
    output.append(f"**Data Points**: {len(trends)} snapshots")
    output.append("")
    
    # Key insights
    if insights:
        output.append("## 🔍 Key Insights")
        output.append("")
        
        # Group by category
        for category in ['improvement', 'warning', 'regression', 'stable']:
            category_insights = [i for i in insights if i.category == category]
            if not category_insights:
                continue
            
            emoji = {'improvement': '✅', 'warning': '⚠️', 'regression': '❌', 'stable': '➡️'}[category]
            
            for insight in category_insights:
                output.append(f"### {emoji} {insight.title}")
                output.append(f"{insight.description}")
                output.append("")
                output.append(f"**Recommendation**: {insight.recommendation}")
                output.append("")
    
    # Trend charts
    output.append("## 📊 Metric Trends")
    output.append("")
    
    if len(trends) >= 3:
        output.append("### Issues Over Time")
        output.append("```")
        output.append(analyzer.generate_trend_chart(trends, 'total_issues'))
        output.append("```")
        output.append("")
        
        output.append("### Average Complexity")
        output.append("```")
        output.append(analyzer.generate_trend_chart(trends, 'avg_complexity'))
        output.append("```")
        output.append("")
    
    # Summary table
    output.append("## 📋 Summary")
    output.append("")
    output.append("| Metric | First | Latest | Change |")
    output.append("|--------|-------|--------|--------|")
    
    def change_str(attr):
        f = getattr(first, attr)
        l = getattr(last, attr)
        pct = analyzer._percent_change(f, l)
        emoji = "📈" if pct > 0 else "📉" if pct < 0 else "➡️"
        return f"{emoji} {pct:+.1f}%"
    
    output.append(f"| Total Issues | {first.total_issues} | {last.total_issues} | {change_str('total_issues')} |")
    output.append(f"| Critical | {first.critical_issues} | {last.critical_issues} | {change_str('critical_issues')} |")
    output.append(f"| Avg Complexity | {first.avg_complexity:.2f} | {last.avg_complexity:.2f} | {change_str('avg_complexity')} |")
    output.append(f"| Total Lines | {first.total_lines:,} | {last.total_lines:,} | {change_str('total_lines')} |")
    output.append("")
    
    return "\n".join(output)
