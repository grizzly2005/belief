"""LLM integration for code analysis and explanation."""

import os
from typing import List, Dict, Optional
from dataclasses import dataclass
from .models import ModuleInfo, Issue


@dataclass
class LLMResponse:
    """Response from LLM analysis."""
    query: str
    response: str
    model: str
    tokens_used: int


class LLMAnalyzer:
    """Analyze code using LLMs (OpenAI/Anthropic)."""
    
    def __init__(self, api_key: Optional[str] = None, provider: str = "openai"):
        """
        Initialize LLM analyzer.
        
        Args:
            api_key: API key (or read from env: OPENAI_API_KEY/ANTHROPIC_API_KEY)
            provider: 'openai' or 'anthropic'
        """
        self.provider = provider
        self.api_key = api_key or self._get_api_key()
        
        if not self.api_key:
            raise ValueError(f"No API key found. Set {self._env_var_name()} environment variable")
        
        self._init_client()
    
    def _env_var_name(self) -> str:
        """Get environment variable name for provider."""
        return {
            'openai': 'OPENAI_API_KEY',
            'anthropic': 'ANTHROPIC_API_KEY'
        }.get(self.provider, 'OPENAI_API_KEY')
    
    def _get_api_key(self) -> Optional[str]:
        """Get API key from environment."""
        return os.getenv(self._env_var_name())
    
    def _init_client(self):
        """Initialize API client."""
        try:
            if self.provider == 'openai':
                import openai
                self.client = openai.OpenAI(api_key=self.api_key)
                self.model = "gpt-4o-mini"
            elif self.provider == 'anthropic':
                import anthropic
                self.client = anthropic.Anthropic(api_key=self.api_key)
                self.model = "claude-3-5-sonnet-20241022"
        except ImportError:
            raise ImportError(f"Install {self.provider} package: pip install {self.provider}")
    
    def explain_code(self, code: str, context: str = "") -> LLMResponse:
        """
        Explain what code does in plain English.
        
        Args:
            code: Code snippet to explain
            context: Additional context (module name, purpose, etc.)
        """
        prompt = f"""Explain what this Python code does in clear, concise terms.

{f"Context: {context}" if context else ""}

Code:
```python
{code}
```

Provide:
1. High-level purpose (1-2 sentences)
2. Key operations
3. Potential issues or improvements"""
        
        return self._query(prompt)
    
    def summarize_module(self, module: ModuleInfo) -> LLMResponse:
        """Generate a concise summary of a module."""
        content = f"""Module: {module.name}
Location: {module.file_path}
Lines: {module.lines_of_code}
Classes: {len(module.classes)}
Functions: {len(module.functions)}

{f"Docstring: {module.docstring}" if module.docstring else ""}

Classes: {', '.join(c.name for c in module.classes[:10])}
Functions: {', '.join(f.name for f in module.functions[:10])}
"""
        
        prompt = f"""Summarize this Python module in 2-3 sentences. Focus on its purpose and main responsibilities.

{content}"""
        
        return self._query(prompt)
    
    def suggest_improvements(self, code: str, issues: List[Issue] = None) -> LLMResponse:
        """Suggest improvements for code."""
        issues_text = ""
        if issues:
            issues_text = "\n\nKnown issues:\n" + "\n".join(f"- {i.description}" for i in issues[:5])
        
        prompt = f"""Review this Python code and suggest specific improvements.

Code:
```python
{code}
```
{issues_text}

Provide:
1. Top 3 improvements (prioritized)
2. Code examples for each improvement
3. Expected impact"""
        
        return self._query(prompt)
    
    def answer_question(self, question: str, codebase_context: str) -> LLMResponse:
        """Answer questions about the codebase."""
        prompt = f"""Answer this question about a Python codebase:

Question: {question}

Codebase context:
{codebase_context}

Provide a clear, specific answer with examples if relevant."""
        
        return self._query(prompt)
    
    def generate_documentation(self, modules: List[ModuleInfo], project_name: str) -> LLMResponse:
        """Generate high-level documentation for project."""
        modules_summary = "\n".join([
            f"- {m.name}: {m.lines_of_code} lines, {len(m.classes)} classes, {len(m.functions)} functions"
            for m in modules[:20]
        ])
        
        prompt = f"""Generate comprehensive documentation for this Python project.

Project: {project_name}
Total modules: {len(modules)}

Key modules:
{modules_summary}

Generate:
1. Project overview (2-3 paragraphs)
2. Architecture summary
3. Key components and their roles
4. Getting started guide

Format in Markdown."""
        
        return self._query(prompt, max_tokens=2000)
    
    def _query(self, prompt: str, max_tokens: int = 1000) -> LLMResponse:
        """Send query to LLM."""
        try:
            if self.provider == 'openai':
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are an expert Python developer and code analyst."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=max_tokens,
                    temperature=0.3
                )
                
                return LLMResponse(
                    query=prompt[:200],
                    response=response.choices[0].message.content,
                    model=self.model,
                    tokens_used=response.usage.total_tokens
                )
            
            elif self.provider == 'anthropic':
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    messages=[
                        {"role": "user", "content": prompt}
                    ],
                    system="You are an expert Python developer and code analyst.",
                    temperature=0.3
                )
                
                return LLMResponse(
                    query=prompt[:200],
                    response=response.content[0].text,
                    model=self.model,
                    tokens_used=response.usage.input_tokens + response.usage.output_tokens
                )
        
        except Exception as e:
            return LLMResponse(
                query=prompt[:200],
                response=f"Error: {str(e)}",
                model=self.model,
                tokens_used=0
            )


def format_llm_response(response: LLMResponse) -> str:
    """Format LLM response for display."""
    output = []
    output.append("# 🤖 LLM Analysis")
    output.append("=" * 80)
    output.append("")
    output.append(f"**Model**: {response.model}")
    output.append(f"**Tokens Used**: {response.tokens_used:,}")
    output.append("")
    output.append("## Response")
    output.append("")
    output.append(response.response)
    output.append("")
    
    return "\n".join(output)
