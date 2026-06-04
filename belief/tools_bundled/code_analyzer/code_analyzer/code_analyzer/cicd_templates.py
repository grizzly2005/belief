"""Generate CI/CD configurations and workflows."""

from pathlib import Path
from typing import List


GITHUB_ACTIONS_WORKFLOW = """name: Code Analysis

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  analyze:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
      with:
        fetch-depth: 0  # Full history for trend analysis
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install code-analyzer
      run: |
        pip install code-analyzer
    
    - name: Run Analysis
      run: |
        code-analyzer analyze . --depth deep --output .code-analyzer
    
    - name: Check for Critical Issues
      run: |
        # Fail if critical issues found
        python -c "
import json
with open('.code-analyzer/analysis.json') as f:
    data = json.load(f)
    critical = data['metrics']['issues_by_severity'].get('critical', 0)
    high = data['metrics']['issues_by_severity'].get('high', 0)
    if critical > 0:
        print(f'❌ Found {critical} critical issues')
        exit(1)
    if high > 5:
        print(f'⚠️  Found {high} high severity issues (threshold: 5)')
        exit(1)
    print('✅ Quality checks passed')
"
    
    - name: Upload Analysis Results
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: code-analysis
        path: .code-analyzer/
    
    - name: Comment on PR
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          const analysis = JSON.parse(fs.readFileSync('.code-analyzer/analysis.json', 'utf8'));
          const metrics = analysis.metrics;
          
          const comment = `## 📊 Code Analysis Results
          
**Quality Metrics:**
- Total Issues: ${metrics.total_issues}
- Critical: ${metrics.issues_by_severity.critical || 0}
- High: ${metrics.issues_by_severity.high || 0}
- Medium: ${metrics.issues_by_severity.medium || 0}
- Low: ${metrics.issues_by_severity.low || 0}

**Code Metrics:**
- Average Complexity: ${metrics.average_complexity.toFixed(2)}
- Max Complexity: ${metrics.max_complexity}
- Total Files: ${metrics.total_files}
- Total Lines: ${metrics.total_lines.toLocaleString()}

[View Full Report](${{github.server_url}}/${{github.repository}}/actions/runs/${{github.run_id}})
          `;
          
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: comment
          });
"""


PRE_COMMIT_CONFIG = """# See https://pre-commit.com for more information
repos:
  - repo: local
    hooks:
      - id: code-analyzer
        name: Code Quality Analysis
        entry: code-analyzer analyze . --depth shallow
        language: system
        pass_filenames: false
        always_run: true
        stages: [commit]
"""


GITLAB_CI = """stages:
  - analyze
  - quality-gate

code-analysis:
  stage: analyze
  image: python:3.9
  script:
    - pip install code-analyzer
    - code-analyzer analyze . --depth deep --output .code-analyzer
  artifacts:
    paths:
      - .code-analyzer/
    expire_in: 30 days
    reports:
      codequality: .code-analyzer/analysis.json

quality-gate:
  stage: quality-gate
  image: python:3.9
  dependencies:
    - code-analysis
  script:
    - python -c "
import json
with open('.code-analyzer/analysis.json') as f:
    data = json.load(f)
    critical = data['metrics']['issues_by_severity'].get('critical', 0)
    if critical > 0:
        print(f'Quality gate failed: {critical} critical issues')
        exit(1)
    print('Quality gate passed')
"
"""


def generate_github_workflow(output_dir: Path):
    """Generate GitHub Actions workflow file."""
    workflow_dir = output_dir / ".github" / "workflows"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    
    workflow_file = workflow_dir / "code-analysis.yml"
    workflow_file.write_text(GITHUB_ACTIONS_WORKFLOW)
    
    return workflow_file


def generate_pre_commit_config(output_dir: Path):
    """Generate pre-commit configuration."""
    config_file = output_dir / ".pre-commit-config.yaml"
    config_file.write_text(PRE_COMMIT_CONFIG)
    
    return config_file


def generate_gitlab_ci(output_dir: Path):
    """Generate GitLab CI configuration."""
    ci_file = output_dir / ".gitlab-ci.yml"
    ci_file.write_text(GITLAB_CI)
    
    return ci_file


def generate_all_cicd(output_dir: Path, ci_type: str = "github") -> List[Path]:
    """Generate all CI/CD configurations."""
    files = []
    
    if ci_type == "github":
        files.append(generate_github_workflow(output_dir))
        files.append(generate_pre_commit_config(output_dir))
    elif ci_type == "gitlab":
        files.append(generate_gitlab_ci(output_dir))
        files.append(generate_pre_commit_config(output_dir))
    elif ci_type == "all":
        files.append(generate_github_workflow(output_dir))
        files.append(generate_gitlab_ci(output_dir))
        files.append(generate_pre_commit_config(output_dir))
    
    return files
