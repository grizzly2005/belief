"""Base interface for language-specific analyzers."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional

from .models import ModuleInfo


class LanguageAnalyzer(ABC):
    """Abstract base class for language-specific code analyzers."""
    
    @abstractmethod
    def analyze_file(self, file_path: Path) -> Optional[ModuleInfo]:
        """
        Analyze a single file and return module information.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            ModuleInfo object or None if analysis fails
        """
        pass
    
    @abstractmethod
    def get_supported_extensions(self) -> List[str]:
        """
        Return list of file extensions this analyzer supports.
        
        Returns:
            List of file extensions (e.g., ['.py', '.pyi'])
        """
        pass
    
    @abstractmethod
    def get_language_name(self) -> str:
        """
        Return the name of the language this analyzer handles.
        
        Returns:
            Language name (e.g., 'Python', 'JavaScript')
        """
        pass


class PythonAnalyzerAdapter(LanguageAnalyzer):
    """Adapter for existing Python analyzer to match LanguageAnalyzer interface."""
    
    def __init__(self, analyzer_instance):
        """
        Initialize with existing CodeAnalyzer instance.
        
        Args:
            analyzer_instance: Instance of CodeAnalyzer
        """
        self.analyzer = analyzer_instance
    
    def analyze_file(self, file_path: Path) -> Optional[ModuleInfo]:
        """Analyze a Python file."""
        return self.analyzer._analyze_file(file_path)
    
    def get_supported_extensions(self) -> List[str]:
        """Return Python file extensions."""
        return ['.py', '.pyi']
    
    def get_language_name(self) -> str:
        """Return language name."""
        return 'Python'
