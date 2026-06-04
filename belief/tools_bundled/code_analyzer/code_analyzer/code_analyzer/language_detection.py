"""Language detection for multi-language projects."""

from pathlib import Path
from typing import Dict, List, Set
from collections import Counter
from dataclasses import dataclass


@dataclass
class LanguageStats:
    """Statistics about languages in a project."""
    language: str
    file_count: int
    line_count: int
    percentage: float
    extensions: Set[str]


class LanguageDetector:
    """Detect programming languages in a project."""
    
    # Extension to language mapping
    LANGUAGE_MAP = {
        # Python
        '.py': 'python',
        '.pyw': 'python',
        '.pyx': 'python',
        
        # JavaScript/TypeScript
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.mjs': 'javascript',
        '.cjs': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        
        # Go
        '.go': 'go',
        
        # Java
        '.java': 'java',
        
        # Ruby
        '.rb': 'ruby',
        '.rake': 'ruby',
        
        # C/C++
        '.c': 'c',
        '.h': 'c',
        '.cpp': 'cpp',
        '.cc': 'cpp',
        '.cxx': 'cpp',
        '.hpp': 'cpp',
        
        # C#
        '.cs': 'csharp',
        
        # PHP
        '.php': 'php',
        
        # Rust
        '.rs': 'rust',
        
        # Swift
        '.swift': 'swift',
        
        # Kotlin
        '.kt': 'kotlin',
        '.kts': 'kotlin',
    }
    
    # Default ignore patterns
    IGNORE_DIRS = {
        'node_modules', '.git', '.svn', '__pycache__', '.venv', 'venv',
        'build', 'dist', 'target', '.idea', '.vscode', 'vendor'
    }
    
    def detect_languages(self, project_path: Path) -> List[LanguageStats]:
        """
        Detect all languages in a project.
        
        Returns sorted list by file count (most files first).
        """
        language_files: Dict[str, Set[Path]] = {}
        
        # Scan all files
        for file_path in project_path.rglob('*'):
            # Skip if in ignore directory
            if any(ignore_dir in file_path.parts for ignore_dir in self.IGNORE_DIRS):
                continue
            
            if not file_path.is_file():
                continue
            
            # Get language from extension
            ext = file_path.suffix.lower()
            language = self.LANGUAGE_MAP.get(ext)
            
            if language:
                if language not in language_files:
                    language_files[language] = set()
                language_files[language].add(file_path)
        
        # Calculate statistics
        total_files = sum(len(files) for files in language_files.values())
        stats = []
        
        for language, files in language_files.items():
            # Count lines
            line_count = 0
            extensions = set()
            
            for file_path in files:
                extensions.add(file_path.suffix.lower())
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        line_count += sum(1 for _ in f)
                except Exception:
                    continue
            
            percentage = (len(files) / total_files * 100) if total_files > 0 else 0
            
            stats.append(LanguageStats(
                language=language,
                file_count=len(files),
                line_count=line_count,
                percentage=percentage,
                extensions=extensions
            ))
        
        # Sort by file count descending
        stats.sort(key=lambda s: s.file_count, reverse=True)
        
        return stats
    
    def get_primary_language(self, project_path: Path) -> str:
        """Get the primary (most common) language in the project."""
        stats = self.detect_languages(project_path)
        return stats[0].language if stats else 'unknown'
    
    def is_multi_language(self, project_path: Path, threshold: float = 10.0) -> bool:
        """
        Check if project is multi-language.
        
        A project is considered multi-language if it has 2+ languages
        where each has at least `threshold` percent of files.
        """
        stats = self.detect_languages(project_path)
        significant_languages = [s for s in stats if s.percentage >= threshold]
        return len(significant_languages) >= 2
    
    def get_language_for_file(self, file_path: Path) -> str:
        """Get language for a specific file."""
        ext = file_path.suffix.lower()
        return self.LANGUAGE_MAP.get(ext, 'unknown')


def format_language_stats(stats: List[LanguageStats]) -> str:
    """Format language statistics for display."""
    if not stats:
        return "No programming languages detected."
    
    output = []
    output.append("# 🌍 Language Statistics")
    output.append("")
    output.append("| Language | Files | Lines | % | Extensions |")
    output.append("|----------|-------|-------|---|------------|")
    
    for stat in stats:
        exts = ', '.join(sorted(stat.extensions))
        output.append(
            f"| **{stat.language.title()}** | {stat.file_count} | "
            f"{stat.line_count:,} | {stat.percentage:.1f}% | {exts} |"
        )
    
    output.append("")
    
    # Summary
    total_files = sum(s.file_count for s in stats)
    total_lines = sum(s.line_count for s in stats)
    
    output.append(f"**Total**: {len(stats)} languages, {total_files} files, {total_lines:,} lines")
    output.append("")
    
    return "\n".join(output)
