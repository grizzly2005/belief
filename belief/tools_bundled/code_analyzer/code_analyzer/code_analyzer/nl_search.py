"""Natural language search over codebase."""

from typing import List, Dict, Tuple
from dataclasses import dataclass
import re
from .models import ModuleInfo, FunctionInfo, ClassInfo


@dataclass
class SearchResult:
    """Search result with relevance score."""
    entity_type: str  # 'function', 'class', 'module'
    name: str
    location: str
    description: str
    score: float
    code_snippet: str


class NaturalLanguageSearch:
    """Search codebase using natural language queries."""
    
    def __init__(self, modules: List[ModuleInfo]):
        self.modules = modules
        self._build_index()
    
    def _build_index(self):
        """Build searchable index from modules."""
        self.index = {
            'functions': [],
            'classes': [],
            'modules': []
        }
        
        for module in self.modules:
            # Index functions
            for func in module.functions:
                self.index['functions'].append({
                    'name': func.name,
                    'module': module.name,
                    'location': f"{module.name}.{func.name}",
                    'docstring': func.docstring or '',
                    'parameters': func.parameters,
                    'complexity': func.complexity
                })
            
            # Index classes
            for cls in module.classes:
                methods_text = ' '.join(m.name for m in cls.methods)
                self.index['classes'].append({
                    'name': cls.name,
                    'module': module.name,
                    'location': f"{module.name}.{cls.name}",
                    'docstring': cls.docstring or '',
                    'methods': methods_text
                })
            
            # Index modules
            self.index['modules'].append({
                'name': module.name,
                'location': module.file_path,
                'docstring': module.docstring or '',
                'imports': ' '.join(module.imports)
            })
    
    def search(self, query: str, limit: int = 10) -> List[SearchResult]:
        """
        Search codebase with natural language query.
        
        Examples:
        - "functions that handle HTTP requests"
        - "database connection classes"
        - "validation logic"
        - "error handling"
        """
        query_lower = query.lower()
        results = []
        
        # Extract keywords from query
        keywords = self._extract_keywords(query_lower)
        
        # Search functions
        for func in self.index['functions']:
            score = self._score_function(func, keywords, query_lower)
            if score > 0:
                results.append(SearchResult(
                    entity_type='function',
                    name=func['name'],
                    location=func['location'],
                    description=func['docstring'][:200] if func['docstring'] else f"Function with {len(func['parameters'])} parameters",
                    score=score,
                    code_snippet=f"def {func['name']}({', '.join(func['parameters'])})"
                ))
        
        # Search classes
        for cls in self.index['classes']:
            score = self._score_class(cls, keywords, query_lower)
            if score > 0:
                results.append(SearchResult(
                    entity_type='class',
                    name=cls['name'],
                    location=cls['location'],
                    description=cls['docstring'][:200] if cls['docstring'] else f"Class in {cls['module']}",
                    score=score,
                    code_snippet=f"class {cls['name']}"
                ))
        
        # Search modules
        for mod in self.index['modules']:
            score = self._score_module(mod, keywords, query_lower)
            if score > 0:
                results.append(SearchResult(
                    entity_type='module',
                    name=mod['name'],
                    location=mod['location'],
                    description=mod['docstring'][:200] if mod['docstring'] else f"Module at {mod['location']}",
                    score=score,
                    code_snippet=f"# {mod['name']}"
                ))
        
        # Sort by score descending
        results.sort(key=lambda r: r.score, reverse=True)
        
        return results[:limit]
    
    def _extract_keywords(self, query: str) -> List[str]:
        """Extract meaningful keywords from query."""
        # Remove common words
        stopwords = {'the', 'a', 'an', 'that', 'this', 'with', 'for', 'in', 'on', 'at', 'to', 'from'}
        words = re.findall(r'\w+', query)
        return [w for w in words if w not in stopwords and len(w) > 2]
    
    def _score_function(self, func: Dict, keywords: List[str], query: str) -> float:
        """Score function relevance to query."""
        score = 0.0
        
        name_lower = func['name'].lower()
        doc_lower = func['docstring'].lower()
        
        # Exact name match
        if query in name_lower:
            score += 10.0
        
        # Keyword matches in name (high weight)
        for keyword in keywords:
            if keyword in name_lower:
                score += 5.0
        
        # Keyword matches in docstring (medium weight)
        for keyword in keywords:
            if keyword in doc_lower:
                score += 2.0
        
        # Pattern matching
        if 'http' in query or 'request' in query or 'api' in query:
            if any(term in name_lower for term in ['request', 'response', 'api', 'endpoint', 'handler']):
                score += 3.0
        
        if 'database' in query or 'db' in query or 'sql' in query:
            if any(term in name_lower for term in ['db', 'database', 'query', 'connection', 'fetch', 'save']):
                score += 3.0
        
        if 'validation' in query or 'validate' in query:
            if any(term in name_lower for term in ['valid', 'check', 'verify']):
                score += 3.0
        
        if 'error' in query or 'exception' in query:
            if any(term in name_lower for term in ['error', 'exception', 'handle', 'catch']):
                score += 3.0
        
        return score
    
    def _score_class(self, cls: Dict, keywords: List[str], query: str) -> float:
        """Score class relevance to query."""
        score = 0.0
        
        name_lower = cls['name'].lower()
        doc_lower = cls['docstring'].lower()
        methods_lower = cls['methods'].lower()
        
        # Exact name match
        if query in name_lower:
            score += 10.0
        
        # Keyword matches in name
        for keyword in keywords:
            if keyword in name_lower:
                score += 5.0
        
        # Keyword matches in docstring
        for keyword in keywords:
            if keyword in doc_lower:
                score += 2.0
        
        # Keyword matches in method names
        for keyword in keywords:
            if keyword in methods_lower:
                score += 1.0
        
        return score
    
    def _score_module(self, mod: Dict, keywords: List[str], query: str) -> float:
        """Score module relevance to query."""
        score = 0.0
        
        name_lower = mod['name'].lower()
        doc_lower = mod['docstring'].lower()
        
        # Keyword matches
        for keyword in keywords:
            if keyword in name_lower:
                score += 3.0
            if keyword in doc_lower:
                score += 1.0
        
        return score


def format_search_results(results: List[SearchResult]) -> str:
    """Format search results for display."""
    if not results:
        return "No results found."
    
    output = []
    output.append(f"Found {len(results)} results:\n")
    
    for i, result in enumerate(results, 1):
        emoji = {'function': '🔧', 'class': '🏛️', 'module': '📄'}[result.entity_type]
        output.append(f"{i}. {emoji} **{result.name}** ({result.entity_type})")
        output.append(f"   Location: `{result.location}`")
        output.append(f"   Score: {result.score:.1f}")
        if result.description:
            output.append(f"   {result.description[:100]}...")
        output.append(f"   ```python\n   {result.code_snippet}\n   ```")
        output.append("")
    
    return "\n".join(output)
