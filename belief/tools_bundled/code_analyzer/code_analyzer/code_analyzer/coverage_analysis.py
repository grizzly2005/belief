"""Test coverage analysis and integration."""

from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import xml.etree.ElementTree as ET
import json


@dataclass
class CoverageInfo:
    """Coverage information for a module."""
    module_name: str
    file_path: str
    line_coverage: float  # Percentage
    branch_coverage: float  # Percentage
    lines_covered: int
    lines_total: int
    uncovered_lines: List[int]


class CoverageAnalyzer:
    """Analyzes test coverage from coverage reports."""
    
    def __init__(self, project_path: Path):
        self.project_path = project_path
    
    def parse_coverage_report(self) -> Optional[Dict[str, CoverageInfo]]:
        """Parse coverage report from various formats."""
        # Try coverage.xml (most common)
        coverage_xml = self.project_path / 'coverage.xml'
        if coverage_xml.exists():
            return self._parse_coverage_xml(coverage_xml)
        
        # Try .coverage (SQLite)
        coverage_db = self.project_path / '.coverage'
        if coverage_db.exists():
            return self._parse_coverage_db(coverage_db)
        
        # Try htmlcov/index.html
        htmlcov = self.project_path / 'htmlcov' / 'index.html'
        if htmlcov.exists():
            return self._parse_coverage_html(htmlcov)
        
        return None
    
    def _parse_coverage_xml(self, xml_path: Path) -> Dict[str, CoverageInfo]:
        """Parse coverage.xml file (Cobertura format)."""
        coverage_data = {}
        
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            # Find all classes (files)
            for cls in root.findall('.//class'):
                filename = cls.get('filename', '')
                name = cls.get('name', Path(filename).stem)
                
                lines = cls.findall('.//line')
                total_lines = len(lines)
                covered_lines = sum(1 for line in lines if line.get('hits', '0') != '0')
                uncovered = [int(line.get('number')) for line in lines if line.get('hits', '0') == '0']
                
                line_rate = float(cls.get('line-rate', 0)) * 100
                branch_rate = float(cls.get('branch-rate', 0)) * 100
                
                coverage_data[name] = CoverageInfo(
                    module_name=name,
                    file_path=filename,
                    line_coverage=line_rate,
                    branch_coverage=branch_rate,
                    lines_covered=covered_lines,
                    lines_total=total_lines,
                    uncovered_lines=uncovered[:20]  # Limit to first 20
                )
        except Exception:
            pass
        
        return coverage_data
    
    def _parse_coverage_db(self, db_path: Path) -> Dict[str, CoverageInfo]:
        """Parse .coverage SQLite database (requires coverage module)."""
        coverage_data = {}
        
        try:
            import coverage
            cov = coverage.Coverage(data_file=str(db_path))
            cov.load()
            
            for file_path in cov.get_data().measured_files():
                analysis = cov.analysis2(file_path)
                name = Path(file_path).stem
                
                executed = analysis[1]
                missing = analysis[2]
                total = len(executed) + len(missing)
                
                if total > 0:
                    line_rate = (len(executed) / total) * 100
                else:
                    line_rate = 0
                
                coverage_data[name] = CoverageInfo(
                    module_name=name,
                    file_path=file_path,
                    line_coverage=line_rate,
                    branch_coverage=0,  # Not available from this format
                    lines_covered=len(executed),
                    lines_total=total,
                    uncovered_lines=list(missing)[:20]
                )
        except Exception:
            pass
        
        return coverage_data
    
    def _parse_coverage_html(self, html_path: Path) -> Dict[str, CoverageInfo]:
        """Parse htmlcov/index.html (simplified)."""
        # This is complex without proper HTML parsing, return empty for now
        return {}
    
    def identify_critical_uncovered(self, coverage_data: Dict[str, CoverageInfo], 
                                    module_complexity: Dict[str, int]) -> List[Tuple[str, str]]:
        """Identify critical code that lacks test coverage."""
        critical = []
        
        for name, cov_info in coverage_data.items():
            # Low coverage on complex modules is critical
            complexity = module_complexity.get(name, 0)
            
            if cov_info.line_coverage < 50 and complexity > 10:
                critical.append((
                    name,
                    f"Only {cov_info.line_coverage:.1f}% covered with complexity {complexity}"
                ))
            elif cov_info.line_coverage < 30:
                critical.append((
                    name,
                    f"Very low coverage: {cov_info.line_coverage:.1f}%"
                ))
        
        return critical


def format_coverage_report(project_path: Path, module_complexity: Optional[Dict[str, int]] = None) -> str:
    """Format test coverage report."""
    analyzer = CoverageAnalyzer(project_path)
    coverage_data = analyzer.parse_coverage_report()
    
    if not coverage_data:
        output = []
        output.append("# 🧪 TEST COVERAGE ANALYSIS")
        output.append("=" * 80)
        output.append("")
        output.append("⚠️  No coverage report found.")
        output.append("")
        output.append("## 📋 How to Generate Coverage")
        output.append("")
        output.append("```bash")
        output.append("# Install coverage.py")
        output.append("pip install coverage")
        output.append("")
        output.append("# Run tests with coverage")
        output.append("coverage run -m pytest")
        output.append("")
        output.append("# Generate XML report")
        output.append("coverage xml")
        output.append("")
        output.append("# Or HTML report")
        output.append("coverage html")
        output.append("```")
        output.append("")
        output.append("## 💡 Testing Best Practices")
        output.append("")
        output.append("1. **Aim for 80%+ coverage** on critical business logic")
        output.append("2. **Test edge cases** not just happy paths")
        output.append("3. **Use pytest fixtures** for test setup")
        output.append("4. **Mock external dependencies** for unit tests")
        output.append("5. **Add integration tests** for complex workflows")
        output.append("")
        return "\n".join(output)
    
    output = []
    output.append("# 🧪 TEST COVERAGE ANALYSIS")
    output.append("=" * 80)
    output.append("")
    
    # Calculate overall stats
    total_lines = sum(cov.lines_total for cov in coverage_data.values())
    total_covered = sum(cov.lines_covered for cov in coverage_data.values())
    overall_coverage = (total_covered / total_lines * 100) if total_lines > 0 else 0
    
    output.append(f"**Overall Coverage**: {overall_coverage:.1f}%")
    output.append(f"**Modules Analyzed**: {len(coverage_data)}")
    output.append(f"**Lines Covered**: {total_covered:,} / {total_lines:,}")
    output.append("")
    
    # Coverage by module (sorted by coverage)
    output.append("## 📊 Coverage by Module")
    output.append("")
    output.append("| Module | Coverage | Lines | Uncovered |")
    output.append("|--------|----------|-------|-----------|")
    
    sorted_modules = sorted(coverage_data.values(), key=lambda x: x.line_coverage)
    
    for cov in sorted_modules[:20]:  # Top 20 lowest coverage
        emoji = "🔴" if cov.line_coverage < 50 else "🟡" if cov.line_coverage < 80 else "🟢"
        uncovered_count = len(cov.uncovered_lines)
        output.append(f"| {emoji} `{cov.module_name}` | {cov.line_coverage:.1f}% | {cov.lines_covered}/{cov.lines_total} | {uncovered_count} lines |")
    
    output.append("")
    
    # Critical gaps
    if module_complexity:
        critical = analyzer.identify_critical_uncovered(coverage_data, module_complexity)
        if critical:
            output.append("## ⚠️  Critical Coverage Gaps")
            output.append("")
            output.append("High-complexity modules with low test coverage:")
            output.append("")
            
            for name, reason in critical[:10]:
                output.append(f"- **`{name}`**: {reason}")
            output.append("")
    
    # Recommendations
    output.append("## 💡 Recommendations")
    output.append("")
    
    low_coverage = [cov for cov in coverage_data.values() if cov.line_coverage < 70]
    if low_coverage:
        output.append(f"### Priority: {len(low_coverage)} modules below 70% coverage")
        output.append("")
        for cov in low_coverage[:5]:
            output.append(f"1. **`{cov.module_name}`** ({cov.line_coverage:.1f}%)")
            if cov.uncovered_lines:
                lines_str = ', '.join(str(l) for l in cov.uncovered_lines[:5])
                output.append(f"   - Uncovered lines: {lines_str}...")
        output.append("")
    
    output.append("### General Improvements")
    output.append("- Add tests for edge cases and error conditions")
    output.append("- Increase coverage of complex functions (complexity > 10)")
    output.append("- Add integration tests for critical workflows")
    output.append("- Set up coverage gates in CI/CD (e.g., minimum 80%)")
    output.append("")
    
    return "\n".join(output)
