"""Dependency vulnerability scanning and security analysis."""

from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from pathlib import Path
import subprocess
import json


@dataclass
class VulnerabilityInfo:
    """Security vulnerability information."""
    package: str
    installed_version: str
    vulnerability_id: str
    severity: str
    description: str
    fixed_version: Optional[str]


@dataclass
class DependencyIssue:
    """Dependency-related issue."""
    package: str
    current_version: str
    issue_type: str  # 'vulnerable', 'outdated', 'deprecated'
    severity: str
    details: str
    recommendation: str


class SecurityAnalyzer:
    """Analyzes dependencies for security issues."""
    
    def __init__(self, project_path: Path):
        self.project_path = project_path
    
    def scan_dependencies(self) -> List[DependencyIssue]:
        """Scan dependencies for vulnerabilities and issues."""
        issues = []
        
        # Try to find requirements file
        req_files = ['requirements.txt', 'pyproject.toml', 'setup.py', 'Pipfile']
        dependencies = self._extract_dependencies(req_files)
        
        if not dependencies:
            return issues
        
        # Check for known vulnerable patterns
        issues.extend(self._check_known_vulnerabilities(dependencies))
        
        # Check for outdated packages (simplified)
        issues.extend(self._check_outdated(dependencies))
        
        return issues
    
    def _extract_dependencies(self, req_files: List[str]) -> Dict[str, str]:
        """Extract dependencies from project files."""
        deps = {}
        
        for req_file in req_files:
            file_path = self.project_path / req_file
            if not file_path.exists():
                continue
            
            try:
                if req_file == 'requirements.txt':
                    with open(file_path) as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                # Parse "package==version" or "package>=version"
                                if '==' in line:
                                    pkg, ver = line.split('==')
                                    deps[pkg.strip()] = ver.strip()
                                elif '>=' in line:
                                    pkg = line.split('>=')[0].strip()
                                    deps[pkg] = 'unknown'
                                else:
                                    deps[line] = 'unknown'
            except Exception:
                continue
        
        return deps
    
    def _check_known_vulnerabilities(self, dependencies: Dict[str, str]) -> List[DependencyIssue]:
        """Check for known vulnerable packages (simplified)."""
        issues = []
        
        # Known vulnerable patterns (simplified - real implementation would use CVE database)
        KNOWN_ISSUES = {
            'requests': {
                'vulnerable_versions': ['2.6.0', '2.5.0'],
                'issue': 'Known SSL verification bypass',
                'fixed': '2.20.0'
            },
            'urllib3': {
                'vulnerable_versions': ['1.24', '1.23'],
                'issue': 'CRLF injection vulnerability',
                'fixed': '1.24.2'
            },
            'pyyaml': {
                'vulnerable_versions': ['3.12', '3.13'],
                'issue': 'Arbitrary code execution',
                'fixed': '5.1'
            }
        }
        
        for pkg, version in dependencies.items():
            pkg_lower = pkg.lower()
            if pkg_lower in KNOWN_ISSUES:
                vuln_info = KNOWN_ISSUES[pkg_lower]
                if version in vuln_info['vulnerable_versions']:
                    issues.append(DependencyIssue(
                        package=pkg,
                        current_version=version,
                        issue_type='vulnerable',
                        severity='high',
                        details=vuln_info['issue'],
                        recommendation=f"Upgrade to {vuln_info['fixed']} or later"
                    ))
        
        return issues
    
    def _check_outdated(self, dependencies: Dict[str, str]) -> List[DependencyIssue]:
        """Check for outdated packages."""
        issues = []
        
        # Try using pip list --outdated (if available)
        try:
            result = subprocess.run(
                ['pip', 'list', '--outdated', '--format=json'],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=str(self.project_path)
            )
            
            if result.returncode == 0:
                outdated = json.loads(result.stdout)
                for item in outdated:
                    pkg_name = item.get('name', '')
                    if pkg_name in dependencies:
                        issues.append(DependencyIssue(
                            package=pkg_name,
                            current_version=item.get('version', 'unknown'),
                            issue_type='outdated',
                            severity='medium',
                            details=f"Latest version: {item.get('latest_version', 'unknown')}",
                            recommendation="Consider upgrading to benefit from bug fixes and improvements"
                        ))
        except Exception:
            pass  # pip not available or error
        
        return issues


def format_security_report(project_path: Path) -> str:
    """Format security analysis report."""
    analyzer = SecurityAnalyzer(project_path)
    issues = analyzer.scan_dependencies()
    
    if not issues:
        output = []
        output.append("# 🔒 SECURITY & DEPENDENCY ANALYSIS")
        output.append("=" * 80)
        output.append("")
        output.append("✅ No known security vulnerabilities detected in dependencies.")
        output.append("")
        output.append("## 🛡️ Security Best Practices")
        output.append("")
        output.append("1. **Keep dependencies updated**: Run `pip list --outdated` regularly")
        output.append("2. **Use vulnerability scanners**: Consider `safety` or `pip-audit`")
        output.append("3. **Pin versions**: Use `requirements.txt` with exact versions")
        output.append("4. **Review new dependencies**: Audit before adding to project")
        output.append("5. **Use virtual environments**: Isolate project dependencies")
        output.append("")
        return "\n".join(output)
    
    output = []
    output.append("# 🔒 SECURITY & DEPENDENCY ANALYSIS")
    output.append("=" * 80)
    output.append("")
    
    output.append(f"⚠️ **Found {len(issues)} dependency issues**")
    output.append("")
    
    # Group by severity
    by_severity = {'high': [], 'medium': [], 'low': []}
    for issue in issues:
        by_severity[issue.severity].append(issue)
    
    # Critical vulnerabilities
    if by_severity['high']:
        output.append("## 🚨 Critical Issues (Immediate Action Required)")
        output.append("")
        
        for issue in by_severity['high']:
            output.append(f"### `{issue.package}` v{issue.current_version}")
            output.append(f"**Type**: {issue.issue_type.title()}")
            output.append(f"**Issue**: {issue.details}")
            output.append(f"**Action**: {issue.recommendation}")
            output.append("")
    
    # Medium priority
    if by_severity['medium']:
        output.append("## ⚠️  Medium Priority Issues")
        output.append("")
        
        for issue in by_severity['medium'][:10]:  # Limit to 10
            output.append(f"- **`{issue.package}`** v{issue.current_version}: {issue.details}")
            output.append(f"  → {issue.recommendation}")
        
        if len(by_severity['medium']) > 10:
            output.append(f"  ... and {len(by_severity['medium']) - 10} more")
        output.append("")
    
    # Recommendations
    output.append("## 💡 Security Recommendations")
    output.append("")
    output.append("### Immediate Actions")
    output.append("```bash")
    output.append("# Check for vulnerabilities")
    output.append("pip install safety")
    output.append("safety check")
    output.append("")
    output.append("# Or use pip-audit")
    output.append("pip install pip-audit")
    output.append("pip-audit")
    output.append("```")
    output.append("")
    
    output.append("### Prevention")
    output.append("1. Add security scanning to CI/CD pipeline")
    output.append("2. Enable Dependabot/Renovate for automated updates")
    output.append("3. Review security advisories for dependencies")
    output.append("4. Use `pip freeze > requirements.txt` to pin versions")
    output.append("")
    
    return "\n".join(output)
