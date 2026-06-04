"""Technical debt tracking and scoring."""

from typing import List, Dict, Tuple
from dataclasses import dataclass
from pathlib import Path
from .models import ModuleInfo, Issue


@dataclass
class DebtItem:
    """Single technical debt item."""
    location: str
    category: str  # 'complexity', 'duplication', 'design', 'documentation', 'testing'
    severity: str  # 'high', 'medium', 'low'
    description: str
    effort_hours: float  # Estimated remediation effort
    impact: str  # Business/technical impact


class TechDebtCalculator:
    """Calculates technical debt metrics."""
    
    # Effort estimates in hours
    EFFORT_ESTIMATES = {
        'high_complexity': 4.0,  # Refactor complex function
        'god_class': 8.0,  # Break down large class
        'duplicate_code': 2.0,  # Extract common code
        'missing_docs': 0.5,  # Add docstring
        'missing_tests': 3.0,  # Write tests
        'design_smell': 6.0,  # Fix design issue
        'security_issue': 8.0,  # Fix security problem
    }
    
    def calculate_debt(self, modules: List[ModuleInfo], issues: List[Issue]) -> Tuple[float, List[DebtItem]]:
        """Calculate total technical debt score and itemize debt."""
        debt_items = []
        
        # Debt from high complexity
        debt_items.extend(self._debt_from_complexity(modules))
        
        # Debt from issues
        debt_items.extend(self._debt_from_issues(issues))
        
        # Debt from missing documentation
        debt_items.extend(self._debt_from_docs(modules))
        
        # Debt from size/design
        debt_items.extend(self._debt_from_design(modules))
        
        # Calculate total effort
        total_hours = sum(item.effort_hours for item in debt_items)
        
        return total_hours, debt_items
    
    def _debt_from_complexity(self, modules: List[ModuleInfo]) -> List[DebtItem]:
        """Identify debt from high complexity."""
        items = []
        
        for module in modules:
            for func in module.functions:
                if func.complexity > 15:
                    items.append(DebtItem(
                        location=f"{module.name}.{func.name}",
                        category='complexity',
                        severity='high' if func.complexity > 20 else 'medium',
                        description=f"High cyclomatic complexity ({func.complexity})",
                        effort_hours=self.EFFORT_ESTIMATES['high_complexity'],
                        impact="Difficult to understand, test, and maintain"
                    ))
            
            for cls in module.classes:
                for method in cls.methods:
                    if method.complexity > 15:
                        items.append(DebtItem(
                            location=f"{module.name}.{cls.name}.{method.name}",
                            category='complexity',
                            severity='high' if method.complexity > 20 else 'medium',
                            description=f"High method complexity ({method.complexity})",
                            effort_hours=self.EFFORT_ESTIMATES['high_complexity'],
                            impact="Increases bug risk and maintenance cost"
                        ))
        
        return items
    
    def _debt_from_issues(self, issues: List[Issue]) -> List[DebtItem]:
        """Convert issues to debt items."""
        items = []
        
        for issue in issues:
            category = self._categorize_issue(issue.description)
            effort_key = self._estimate_key_from_issue(issue.description)
            effort = self.EFFORT_ESTIMATES.get(effort_key, 2.0)
            
            items.append(DebtItem(
                location=issue.location,
                category=category,
                severity=str(issue.severity.name).lower() if hasattr(issue.severity, 'name') else str(issue.severity).lower(),
                description=issue.description,
                effort_hours=effort,
                impact=self._impact_from_severity(str(issue.severity.name) if hasattr(issue.severity, 'name') else str(issue.severity))
            ))
        
        return items
    
    def _debt_from_docs(self, modules: List[ModuleInfo]) -> List[DebtItem]:
        """Identify debt from missing documentation."""
        items = []
        
        for module in modules:
            # Module docstring
            if not module.docstring and len(module.classes) + len(module.functions) > 3:
                items.append(DebtItem(
                    location=module.name,
                    category='documentation',
                    severity='low',
                    description="Module missing docstring",
                    effort_hours=self.EFFORT_ESTIMATES['missing_docs'],
                    impact="Reduces code discoverability"
                ))
            
            # Function docstrings (sample)
            undocumented = [f for f in module.functions if not f.docstring and not f.name.startswith('_')]
            if len(undocumented) > 2:
                items.append(DebtItem(
                    location=module.name,
                    category='documentation',
                    severity='low',
                    description=f"{len(undocumented)} public functions lack docstrings",
                    effort_hours=self.EFFORT_ESTIMATES['missing_docs'] * min(len(undocumented), 5),
                    impact="Harder for new developers to understand"
                ))
        
        return items[:10]  # Limit documentation debt items
    
    def _debt_from_design(self, modules: List[ModuleInfo]) -> List[DebtItem]:
        """Identify debt from design issues."""
        items = []
        
        for module in modules:
            # God classes
            for cls in module.classes:
                if len(cls.methods) > 20:
                    items.append(DebtItem(
                        location=f"{module.name}.{cls.name}",
                        category='design',
                        severity='high',
                        description=f"God class with {len(cls.methods)} methods",
                        effort_hours=self.EFFORT_ESTIMATES['god_class'],
                        impact="Violates single responsibility, hard to maintain"
                    ))
                
                # Long parameter lists
                long_param_methods = [m for m in cls.methods if len(m.parameters) > 5]
                if long_param_methods:
                    items.append(DebtItem(
                        location=f"{module.name}.{cls.name}",
                        category='design',
                        severity='medium',
                        description=f"{len(long_param_methods)} methods with >5 parameters",
                        effort_hours=2.0,
                        impact="Increased coupling, harder to test"
                    ))
            
            # Large functions/methods (language-agnostic)
            for func in module.functions:
                if func.lines_of_code and func.lines_of_code > 100:
                    items.append(DebtItem(
                        location=f"{module.name}.{func.name}",
                        category='design',
                        severity='medium',
                        description=f"Large function ({func.lines_of_code} lines)",
                        effort_hours=4.0,
                        impact="Hard to understand and test"
                    ))
            
            # JS/TS specific: Check for missing error handling in async functions
            if module.file_path.endswith(('.js', '.ts', '.jsx', '.tsx')):
                async_funcs_no_try = [
                    f for f in module.functions 
                    if f.is_async and 'try' not in (f.source_code or '').lower()
                ]
                if async_funcs_no_try and len(async_funcs_no_try) > 0:
                    items.append(DebtItem(
                        location=module.name,
                        category='design',
                        severity='medium',
                        description=f"{len(async_funcs_no_try)} async functions lack error handling",
                        effort_hours=1.0 * len(async_funcs_no_try),
                        impact="Unhandled promise rejections"
                    ))
        
        return items
    
    def _categorize_issue(self, description: str) -> str:
        """Categorize issue by description."""
        desc_lower = description.lower()
        if 'complexity' in desc_lower:
            return 'complexity'
        elif 'duplicate' in desc_lower or 'similar' in desc_lower:
            return 'duplication'
        elif 'security' in desc_lower:
            return 'design'
        elif 'god class' in desc_lower or 'design' in desc_lower:
            return 'design'
        else:
            return 'other'
    
    def _estimate_key_from_issue(self, description: str) -> str:
        """Get effort estimate key from issue description."""
        desc_lower = description.lower()
        if 'security' in desc_lower:
            return 'security_issue'
        elif 'complexity' in desc_lower:
            return 'high_complexity'
        elif 'god class' in desc_lower:
            return 'god_class'
        elif 'duplicate' in desc_lower:
            return 'duplicate_code'
        else:
            return 'design_smell'
    
    def _impact_from_severity(self, severity: str) -> str:
        """Get impact description from severity."""
        impacts = {
            'critical': 'Critical risk to system stability/security',
            'high': 'Significant maintenance burden and bug risk',
            'medium': 'Moderate impact on code quality',
            'low': 'Minor quality concern'
        }
        return impacts.get(severity.lower(), 'Unknown impact')


def format_tech_debt_report(modules: List[ModuleInfo], issues: List[Issue]) -> str:
    """Format technical debt report."""
    calculator = TechDebtCalculator()
    total_hours, debt_items = calculator.calculate_debt(modules, issues)
    
    if total_hours == 0:
        return ""
    
    output = []
    output.append("# 💳 TECHNICAL DEBT ANALYSIS")
    output.append("=" * 80)
    output.append("")
    
    # Summary
    total_days = total_hours / 8
    total_weeks = total_days / 5
    
    output.append("## 📊 Debt Summary")
    output.append("")
    output.append(f"**Total Estimated Effort**: {total_hours:.1f} hours ({total_days:.1f} days, {total_weeks:.1f} weeks)")
    output.append(f"**Total Debt Items**: {len(debt_items)}")
    output.append("")
    
    # Breakdown by category
    by_category = {}
    for item in debt_items:
        by_category.setdefault(item.category, []).append(item)
    
    output.append("## 🏷️  Debt by Category")
    output.append("")
    output.append("| Category | Items | Hours | % of Total |")
    output.append("|----------|-------|-------|------------|")
    
    for category, items in sorted(by_category.items(), key=lambda x: sum(i.effort_hours for i in x[1]), reverse=True):
        cat_hours = sum(i.effort_hours for i in items)
        pct = (cat_hours / total_hours * 100) if total_hours > 0 else 0
        output.append(f"| {category.title()} | {len(items)} | {cat_hours:.1f}h | {pct:.1f}% |")
    
    output.append("")
    
    # Top debt items
    output.append("## 🔝 Top Debt Items (by effort)")
    output.append("")
    
    sorted_items = sorted(debt_items, key=lambda x: x.effort_hours, reverse=True)[:15]
    
    for i, item in enumerate(sorted_items, 1):
        severity_emoji = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}.get(item.severity, '⚪')
        output.append(f"### {i}. {severity_emoji} {item.location}")
        output.append(f"**Category**: {item.category.title()} | **Effort**: {item.effort_hours:.1f}h")
        output.append(f"**Issue**: {item.description}")
        output.append(f"**Impact**: {item.impact}")
        output.append("")
    
    # Recommendations
    output.append("## 💡 Remediation Strategy")
    output.append("")
    output.append("### Quick Wins (< 2 hours each)")
    quick_wins = [item for item in debt_items if item.effort_hours < 2.0]
    if quick_wins:
        output.append(f"- {len(quick_wins)} items totaling {sum(i.effort_hours for i in quick_wins):.1f} hours")
        output.append("- Start here for momentum and immediate quality improvement")
    else:
        output.append("- No quick wins identified")
    output.append("")
    
    output.append("### High-Impact Fixes")
    high_impact = [item for item in debt_items if item.severity == 'high']
    if high_impact:
        output.append(f"- {len(high_impact)} high-severity items requiring {sum(i.effort_hours for i in high_impact):.1f} hours")
        output.append("- Prioritize these to reduce system risk")
    else:
        output.append("- No high-severity debt identified")
    output.append("")
    
    output.append("### Debt Reduction Plan")
    output.append("1. **Week 1-2**: Address quick wins and critical items")
    output.append("2. **Week 3-4**: Tackle high-complexity refactoring")
    output.append("3. **Ongoing**: Prevent new debt through code review standards")
    output.append("")
    
    return "\n".join(output)
