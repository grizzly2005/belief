"""Generates top N most important findings summary."""

from typing import List, Dict
from dataclasses import dataclass


@dataclass  
class TopFinding:
    """A top finding to highlight."""
    rank: int
    title: str
    category: str
    importance: str
    location: str
    description: str
    action_required: str


class TopFindingsGenerator:
    """Generates summary of top N most important findings."""
    
    def generate_top_findings(self, result, n: int = 10) -> List[TopFinding]:
        """
        Generate top N most important findings.
        
        Args:
            result: AnalysisResult object
            n: Number of top findings to return
            
        Returns:
            List of top findings
        """
        all_findings = []
        
        # Add critical issues
        critical_issues = result.get_issues_by_severity(result.issues[0].severity.__class__.CRITICAL) if result.issues else []
        for issue in critical_issues[:5]:  # Max 5 critical issues
            all_findings.append({
                'score': 100,  # Highest priority
                'title': f"CRITICAL ISSUE: {issue.title}",
                'category': 'security_issue',
                'importance': 'critical',
                'location': str(issue.location),
                'description': issue.description,
                'action': issue.recommendation or "Immediate fix required"
            })
        
        # Add critical sections
        for cs in result.critical_sections[:5]:
            score = 90 if cs.risk_level.value == 'high' else 80
            all_findings.append({
                'score': score,
                'title': f"Critical Code Section: {cs.name}",
                'category': 'critical_section',
                'importance': cs.risk_level.value,
                'location': str(cs.location),
                'description': cs.reason,
                'action': f"Review and potentially refactor - impacts {', '.join(cs.impact_areas) if cs.impact_areas else 'multiple areas'}"
            })
        
        # Add important sections (entry points, patterns, APIs)
        for section in result.important_sections[:10]:
            score_map = {'critical': 85, 'high': 75, 'medium': 60}
            score = score_map.get(section.importance, 50)
            
            # Boost score for certain categories
            if section.category in ['entry_point', 'api', 'data_model']:
                score += 10
            
            all_findings.append({
                'score': score,
                'title': f"{section.category.replace('_', ' ').title()}: {section.name}",
                'category': section.category,
                'importance': section.importance,
                'location': str(section.location),
                'description': section.description,
                'action': f"Document and ensure proper {section.category.replace('_', ' ')}"
            })
        
        # Add high-priority improvements
        for imp in result.improvements[:15]:
            score_map = {'critical': 95, 'high': 70, 'medium': 50, 'low': 30}
            score = score_map.get(imp.priority, 30)
            
            # Boost for quick wins (small effort, high impact)
            if imp.effort == 'small' and imp.impact == 'high':
                score += 15
            
            all_findings.append({
                'score': score,
                'title': f"Improvement: {imp.issue}",
                'category': imp.category,
                'importance': imp.priority,
                'location': str(imp.location),
                'description': f"{imp.issue} at {imp.name}",
                'action': f"{imp.suggestion} (Effort: {imp.effort}, Impact: {imp.impact})"
            })
        
        # Sort by score and take top N
        all_findings.sort(key=lambda x: x['score'], reverse=True)
        top_findings = all_findings[:n]
        
        # Convert to TopFinding objects
        result_findings = []
        for rank, finding in enumerate(top_findings, 1):
            result_findings.append(TopFinding(
                rank=rank,
                title=finding['title'],
                category=finding['category'],
                importance=finding['importance'],
                location=finding['location'],
                description=finding['description'],
                action_required=finding['action']
            ))
        
        return result_findings
    
    def generate_summary_markdown(self, top_findings: List[TopFinding], project_name: str) -> str:
        """Generate markdown summary of top findings."""
        md = [f"# 🎯 Top {len(top_findings)} Most Important Findings: {project_name}\n\n"]
        md.append("These are the most critical items requiring attention, ranked by importance and impact.\n\n")
        md.append("---\n\n")
        
        for finding in top_findings:
            # Emoji for importance
            emoji_map = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🔵'
            }
            emoji = emoji_map.get(finding.importance, '⚪')
            
            md.append(f"## {finding.rank}. {emoji} {finding.title}\n\n")
            md.append(f"**Category**: {finding.category.replace('_', ' ').title()}\n\n")
            md.append(f"**Importance**: {finding.importance.upper()}\n\n")
            md.append(f"**Location**: `{finding.location}`\n\n")
            md.append(f"**Description**: {finding.description}\n\n")
            md.append(f"**Action Required**: {finding.action_required}\n\n")
            md.append("---\n\n")
        
        return ''.join(md)
    
    def generate_quick_wins(self, improvements: List) -> List[Dict]:
        """Generate list of quick wins (small effort, high impact)."""
        quick_wins = []
        
        for imp in improvements:
            if imp.effort == 'small' and imp.impact in ['high', 'medium']:
                quick_wins.append({
                    'name': imp.name,
                    'issue': imp.issue,
                    'suggestion': imp.suggestion,
                    'effort': imp.effort,
                    'impact': imp.impact,
                    'location': str(imp.location)
                })
        
        # Sort by impact (high first)
        quick_wins.sort(key=lambda x: 0 if x['impact'] == 'high' else 1)
        
        return quick_wins[:10]  # Top 10 quick wins
