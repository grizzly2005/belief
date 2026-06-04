"""Enhanced onboarding report formatting with editor integrations."""

from pathlib import Path
from typing import List
from .onboarding import OnboardingInsights, CodeSnapshot
from .call_graph import CallGraphBuilder
from .why_docs import WhyDocsExtractor, format_why_section
from .interactive_examples import InteractiveExamplesGenerator, format_example
from .workflows import WorkflowsGenerator, format_workflow
from .architecture_diagrams import format_architecture_diagrams
from .troubleshooting import format_troubleshooting_playbook
from .glossary import format_glossary
from .edge_cases import format_edge_cases


def generate_editor_links(file_path: str, line: int, project_root: str = None) -> dict:
    """Generate editor protocol links for major editors."""
    # Convert to absolute path if project_root provided
    if project_root:
        abs_path = str(Path(project_root) / file_path)
    else:
        abs_path = file_path
    
    return {
        'vscode': f"vscode://file/{abs_path}:{line}",
        'idea': f"idea://open?file={abs_path}&line={line}",
        'sublime': f"subl://open?url=file://{abs_path}&line={line}",
        'atom': f"atom://core/open/file?filename={abs_path}&line={line}",
        'nvim': f"nvim://open?file={abs_path}&line={line}",
        'vim': f"vim://open?file={abs_path}&line={line}",
        'emacs': f"emacs://open?url=file://{abs_path}&line={line}",
        'textmate': f"txmt://open?url=file://{abs_path}&line={line}"
    }


def format_code_snapshot(snapshot: CodeSnapshot, project_root: str = None, show_links: bool = True) -> str:
    """Format a code snapshot with syntax highlighting and editor links."""
    output = []
    
    # Title
    output.append(f"### {snapshot.entity_type.title()}: `{snapshot.entity_name}`")
    output.append(f"**Purpose**: {snapshot.context}")
    output.append(f"**Location**: `{snapshot.file_path}:{snapshot.line_start}-{snapshot.line_end}`")
    
    # Editor links
    if show_links:
        links = generate_editor_links(snapshot.file_path, snapshot.line_start, project_root)
        output.append("")
        output.append("**Open in Editor**:")
        output.append(f"- [VS Code]({links['vscode']}) | [IntelliJ]({links['idea']}) | [Sublime]({links['sublime']})")
        output.append(f"- [Neovim/Vim](nvim://open?file={snapshot.file_path}&line={snapshot.line_start})")
        output.append(f"- [Emacs]({links['emacs']}) | [Atom]({links['atom']})")
    
    # Code block
    output.append("")
    output.append("```python")
    output.append(snapshot.code.rstrip())
    output.append("```")
    output.append("")
    
    return "\n".join(output)


def format_architecture_section(insights: OnboardingInsights) -> str:
    """Format detailed architecture section."""
    output = []
    
    output.append("# 🏗️  ARCHITECTURE DEEP DIVE")
    output.append("=" * 80)
    output.append("")
    
    # Architectural style
    output.append("## Architectural Pattern")
    output.append(f"**Style**: {insights.key_concepts.architectural_style}")
    output.append("")
    
    # Module interactions
    if insights.key_concepts.module_interactions:
        output.append("## Module Interactions")
        output.append("```")
        for from_mod, to_mod, purpose in insights.key_concepts.module_interactions[:10]:
            output.append(f"{from_mod} --> {to_mod}: {purpose}")
        output.append("```")
        output.append("")
    
    # Architecture diagram
    if insights.key_concepts.architecture_diagram:
        output.append("## System Overview")
        output.append("```")
        for line in insights.key_concepts.architecture_diagram:
            output.append(line)
        output.append("```")
        output.append("")
    
    # Data flow
    if insights.key_concepts.data_flow:
        output.append("## Data Flow")
        for flow in insights.key_concepts.data_flow:
            output.append(f"- {flow}")
        output.append("")
    
    # Design patterns
    if insights.key_concepts.design_patterns:
        output.append("## Design Patterns Used")
        for pattern in insights.key_concepts.design_patterns:
            output.append(f"- {pattern}")
        output.append("")
    
    return "\n".join(output)


def format_code_examples_section(insights: OnboardingInsights, project_root: str = None) -> str:
    """Format section with actual code examples."""
    output = []
    
    output.append("# 💻 CODE EXAMPLES")
    output.append("=" * 80)
    output.append("")
    
    # Main classes with code
    if insights.key_concepts.main_classes:
        output.append("## Key Classes to Understand")
        output.append("")
        output.append("These are the core classes that drive the application:")
        output.append("")
        
        for item in insights.key_concepts.main_classes[:5]:
            # Handle both old format (class, purpose) and new format (class, purpose, snapshot)
            if len(item) == 3:
                class_name, purpose, snapshot = item
                output.append(format_code_snapshot(snapshot, project_root))
            else:
                class_name, purpose = item
                output.append(f"### Class: `{class_name}`")
                output.append(f"**Purpose**: {purpose}")
                output.append("")
    
    # Core functions with code
    if insights.key_concepts.core_functions:
        output.append("")
        output.append("## Important Functions")
        output.append("")
        output.append("Critical functions you should understand:")
        output.append("")
        
        for item in insights.key_concepts.core_functions[:3]:
            # Handle both formats
            if len(item) == 3:
                func_name, role, snapshot = item
                output.append(format_code_snapshot(snapshot, project_root))
            else:
                func_name, role = item
                output.append(f"### Function: `{func_name}`")
                output.append(f"**Role**: {role}")
                output.append("")
    
    return "\n".join(output)


def format_learning_roadmap(insights: OnboardingInsights) -> str:
    """Format a detailed learning roadmap with time estimates."""
    output = []
    
    output.append("# 🗺️  LEARNING ROADMAP")
    output.append("=" * 80)
    output.append("")
    
    output.append("## Phase 1: Setup & Overview (30-60 minutes)")
    output.append("")
    output.append("### Prerequisites")
    output.append("- Python 3.8+ installed")
    output.append("- Familiarity with: " + ", ".join(insights.overview.main_technologies[:3]) if insights.overview.main_technologies else "- Basic Python knowledge")
    output.append("")
    
    output.append("### Tasks")
    output.append("1. **Clone and setup environment**")
    output.append("   ```bash")
    output.append("   git clone <repository>")
    output.append("   cd " + insights.overview.name)
    output.append("   pip install -r requirements.txt  # or pip install -e .")
    output.append("   ```")
    output.append("")
    
    output.append("2. **Verify installation**")
    output.append("   ```bash")
    output.append("   python -m pytest  # Run tests")
    output.append("   ```")
    output.append("")
    
    output.append("3. **Explore project structure**")
    output.append("   ```bash")
    output.append("   tree -L 2 -I '__pycache__|*.pyc|.git'")
    output.append("   ```")
    output.append("")
    
    output.append("## Phase 2: Entry Points (1-2 hours)")
    output.append("")
    if insights.learning_path.entry_points:
        for i, (file_path, reason) in enumerate(insights.learning_path.entry_points[:3], 1):
            output.append(f"{i}. **{file_path}**")
            output.append(f"   - {reason}")
            output.append(f"   - Open: `nvim +1 {file_path}` or click: [VS Code](vscode://file/{file_path}:1)")
            output.append("")
    
    output.append("## Phase 3: Core Modules (3-5 hours)")
    output.append("")
    output.append("Study these modules in order:")
    output.append("")
    if insights.learning_path.core_modules:
        for i, (file_path, purpose) in enumerate(insights.learning_path.core_modules[:5], 1):
            output.append(f"{i}. **{file_path}** - {purpose}")
            output.append(f"   - nvim: `nvim {file_path}`")
            output.append(f"   - Focus on main classes and their public methods")
            output.append("")
    
    output.append("## Phase 4: Testing & Validation (1-2 hours)")
    output.append("")
    output.append("- Read test files to understand expected behavior")
    output.append("- Run tests and see what breaks when you change things")
    output.append("- Write a simple test for a new feature")
    output.append("")
    
    output.append("## Phase 5: Making Changes (ongoing)")
    output.append("")
    output.append("- Start with small bug fixes or documentation improvements")
    output.append("- Use git blame to see change history: `git blame <file>`")
    output.append("- Ask questions in code reviews")
    output.append("")
    
    return "\n".join(output)


def format_call_graph_section(insights: OnboardingInsights, modules: list) -> str:
    """Format call graph visualization section."""
    output = []
    
    output.append("# 🔄 CALL GRAPH & DATA FLOW")
    output.append("=" * 80)
    output.append("")
    output.append("Understanding how functions call each other helps you navigate the codebase.")
    output.append("")
    
    # Build call graph from modules
    if not modules:
        output.append("_No call graph data available_")
        return "\n".join(output)
    
    try:
        builder = CallGraphBuilder(modules)
        
        # System flow diagram
        output.append("## System Flow Overview")
        output.append("")
        output.append("```")
        flow_diagram = builder.generate_flow_diagram()
        output.extend(flow_diagram)
        output.append("```")
        output.append("")
        
        # Data flow
        output.append("## Data Transformation Pipeline")
        output.append("")
        output.append("```")
        data_flow = builder.generate_data_flow_diagram()
        output.extend(data_flow)
        output.append("```")
        output.append("")
        
        # Entry point call trees
        output.append("## Entry Points & Call Trees")
        output.append("")
        output.append("Start here to understand execution flow:")
        output.append("")
        
        entry_points = ['main', 'analyze', 'run', 'execute', 'process', 'start']
        found_entries = [ep for ep in entry_points if ep in builder.call_map]
        
        if found_entries:
            for entry in found_entries[:3]:  # Show top 3
                output.append(f"### {entry}()")
                output.append("```")
                call_tree = builder.generate_call_tree(entry, max_depth=3)
                output.extend(call_tree)
                output.append("```")
                output.append("")
        else:
            output.append("_No standard entry points detected_")
            output.append("")
        
        # Hot paths
        output.append("## Most-Called Functions (Hot Paths)")
        output.append("")
        output.append("These functions are called frequently - understand them well:")
        output.append("")
        
        hot_paths = builder.find_hot_paths(top_n=8)
        if hot_paths:
            for func, count in hot_paths:
                output.append(f"- **`{func}()`** - called by {count} different functions")
        else:
            output.append("_No hot paths detected_")
        output.append("")
        
        # Module dependencies
        output.append("## Module Dependencies")
        output.append("")
        output.append("How modules depend on each other:")
        output.append("")
        output.append("```")
        module_deps = builder.generate_module_dependencies()
        output.extend(module_deps[:15])  # Show top 15
        output.append("```")
        output.append("")
        
    except Exception as e:
        output.append(f"_Call graph generation failed: {e}_")
        output.append("")
    
    return "\n".join(output)


def format_why_documentation(insights: OnboardingInsights, project_root: str = None) -> str:
    """Format 'Why This Exists' documentation from git history."""
    output = []
    
    output.append("# 🎯 WHY THIS EXISTS")
    output.append("=" * 80)
    output.append("")
    output.append("Understanding WHY code exists is as important as knowing WHAT it does.")
    output.append("This section explains the rationale behind key components.")
    output.append("")
    
    if not project_root:
        output.append("_Git history unavailable - cannot extract component rationale_")
        return "\n".join(output)
    
    try:
        extractor = WhyDocsExtractor(Path(project_root))
        
        # Extract history for key modules
        components_to_analyze = []
        
        # Get core modules from insights
        if insights.learning_path.core_modules:
            for file_path, _ in insights.learning_path.core_modules[:5]:
                components_to_analyze.append(file_path)
        
        # Get entry points
        if insights.learning_path.entry_points:
            for file_path, _ in insights.learning_path.entry_points[:2]:
                if file_path not in components_to_analyze:
                    components_to_analyze.append(file_path)
        
        if not components_to_analyze:
            output.append("_No key components identified for analysis_")
            return "\n".join(output)
        
        output.append("## Core Components")
        output.append("")
        
        histories_found = 0
        for file_path in components_to_analyze[:6]:  # Top 6 components
            history = extractor.extract_component_history(file_path)
            if history:
                why_section = format_why_section(history)
                output.extend(why_section)
                histories_found += 1
        
        if histories_found == 0:
            output.append("_Git history not available for these components_")
            output.append("")
        
    except Exception as e:
        output.append(f"_Could not extract git history: {str(e)}_")
        output.append("")
    
    return "\n".join(output)


def format_interactive_examples(insights: OnboardingInsights, project_name: str = None, modules: list = None) -> str:
    """Format interactive code examples section."""
    output = []
    
    output.append("# 🎨 INTERACTIVE EXAMPLES")
    output.append("=" * 80)
    output.append("")
    output.append("Copy-paste these examples to quickly understand how components work.")
    output.append("")
    
    if not modules or not project_name:
        output.append("_No examples available_")
        return "\n".join(output)
    
    try:
        generator = InteractiveExamplesGenerator(project_name, modules)
        examples = generator.generate_examples()
        
        if not examples:
            output.append("_No runnable examples could be generated_")
            return "\n".join(output)
        
        for example in examples:
            example_lines = format_example(example)
            output.extend(example_lines)
        
    except Exception as e:
        output.append(f"_Could not generate examples: {str(e)}_")
        output.append("")
    
    return "\n".join(output)


def format_common_workflows(insights: OnboardingInsights, modules: list = None) -> str:
    """Format common developer workflows section."""
    output = []
    
    output.append("# 🔧 COMMON WORKFLOWS")
    output.append("=" * 80)
    output.append("")
    output.append("Step-by-step guides for common developer tasks.")
    output.append("")
    
    if not modules:
        output.append("_No workflows available_")
        return "\n".join(output)
    
    try:
        generator = WorkflowsGenerator(insights.overview.name, modules)
        workflows = generator.generate_workflows()
        
        if not workflows:
            output.append("_No workflows could be generated_")
            return "\n".join(output)
        
        for workflow in workflows:
            workflow_lines = format_workflow(workflow)
            output.extend(workflow_lines)
        
    except Exception as e:
        output.append(f"_Could not generate workflows: {str(e)}_")
        output.append("")
    
    return "\n".join(output)


def format_debugging_guide(insights: OnboardingInsights) -> str:
    """Format debugging and troubleshooting guide."""
    output = []
    
    output.append("# 🐛 DEBUGGING GUIDE")
    output.append("=" * 80)
    output.append("")
    
    output.append("## Quick Debugging Commands")
    output.append("")
    output.append("### Set up debugging in your editor")
    output.append("")
    output.append("**VS Code (launch.json):**")
    output.append("```json")
    output.append('{')
    output.append('  "version": "0.2.0",')
    output.append('  "configurations": [')
    output.append('    {')
    output.append('      "name": "Python: Current File",')
    output.append('      "type": "python",')
    output.append('      "request": "launch",')
    output.append('      "program": "${file}",')
    output.append('      "console": "integratedTerminal"')
    output.append('    }')
    output.append('  ]')
    output.append('}')
    output.append("```")
    output.append("")
    
    output.append("**Neovim (using nvim-dap):**")
    output.append("```lua")
    output.append("require('dap-python').setup('python')")
    output.append("-- Set breakpoint: <leader>db")
    output.append("-- Continue: <leader>dc")
    output.append("-- Step over: <leader>ds")
    output.append("```")
    output.append("")
    
    output.append("### Command-line debugging")
    output.append("```bash")
    output.append("# Add breakpoint in code:")
    output.append("import pdb; pdb.set_trace()")
    output.append("")
    output.append("# Or use ipdb for better experience:")
    output.append("import ipdb; ipdb.set_trace()")
    output.append("```")
    output.append("")
    
    output.append("## Common Issues & Solutions")
    output.append("")
    for pitfall in insights.common_pitfalls[:5]:
        output.append(f"- **Issue**: {pitfall}")
        output.append(f"  - **Solution**: Review simpler modules first, use debugger to step through")
        output.append("")
    
    return "\n".join(output)


def format_enhanced_onboarding(insights: OnboardingInsights, project_root: str = None, modules: list = None, issues: list = None) -> str:
    """Generate enhanced onboarding report with code snapshots and editor links."""
    sections = []
    
    # Header
    sections.append("=" * 80)
    sections.append(f"ENGINEERING ONBOARDING: {insights.overview.name}")
    sections.append("=" * 80)
    sections.append("")
    sections.append(f"**Project Size**: {insights.overview.total_files} files, {insights.overview.total_lines:,} lines")
    sections.append(f"**Complexity**: {insights.overview.estimated_complexity}")
    if insights.overview.description:
        sections.append(f"**Description**: {insights.overview.description}")
    sections.append("")
    
    # Architecture deep dive
    sections.append(format_architecture_section(insights))
    sections.append("")
    
    # Call graph visualization (NEW)
    if modules:
        sections.append(format_call_graph_section(insights, modules))
        sections.append("")
    
    # Learning roadmap
    sections.append(format_learning_roadmap(insights))
    sections.append("")
    
    # Code examples
    sections.append(format_code_examples_section(insights, project_root))
    sections.append("")
    
    # Why this exists (git history)
    if project_root:
        sections.append(format_why_documentation(insights, project_root))
        sections.append("")
    
    # Interactive examples
    if modules:
        sections.append(format_interactive_examples(insights, insights.overview.name, modules))
        sections.append("")
    
    # Architecture diagrams (Phase 2)
    if modules:
        sections.append(format_architecture_diagrams(modules))
        sections.append("")
    
    # Troubleshooting playbook (Phase 2)
    if issues:
        sections.append(format_troubleshooting_playbook(issues))
        sections.append("")
    
    # Glossary (Phase 2)
    if modules:
        glossary_section = format_glossary(modules, insights.overview.name)
        if glossary_section:
            sections.append(glossary_section)
            sections.append("")
    
    # Edge cases (Phase 2)
    if modules:
        edge_cases_section = format_edge_cases(modules)
        if edge_cases_section:
            sections.append(edge_cases_section)
            sections.append("")
    
    # Common workflows
    if modules:
        sections.append(format_common_workflows(insights, modules))
        sections.append("")
    
    # Debugging guide
    sections.append(format_debugging_guide(insights))
    sections.append("")
    
    # Quick reference
    sections.append("# 📚 QUICK REFERENCE")
    sections.append("=" * 80)
    sections.append("")
    sections.append("## Key Dependencies")
    for dep in insights.overview.key_dependencies[:10]:
        sections.append(f"- `{dep}`")
    sections.append("")
    
    sections.append("## Helpful Commands")
    for cmd, purpose in insights.helpful_commands:
        sections.append(f"```bash")
        sections.append(f"{cmd}")
        sections.append(f"```")
        sections.append(f"→ {purpose}")
        sections.append("")
    
    sections.append("=" * 80)
    sections.append("**Pro Tips**:")
    sections.append("- Use `git log --follow <file>` to see file history")
    sections.append("- Use `git blame -L <start>,<end> <file>` to see who wrote what")
    sections.append("- Set up editor to jump to definitions (Ctrl+Click or gd in vim)")
    sections.append("- Install language server (pyright/pylsp) for better autocomplete")
    sections.append("=" * 80)
    
    return "\n\n".join(sections)

