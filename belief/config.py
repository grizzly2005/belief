"""
BELIEF — Configuration management.

v2 changes:
- LLMProvider gains `context_window` and `num_predict` so each backend
  declares its real limits (Ollama, Groq, Gemini, OpenRouter all differ).
- BeliefConfig gains a `prompt_budget_ratio` knob: max fraction of the
  context window we let a single prompt consume (rest is reserved for
  the JSON answer).
- Defaults bumped to qwen2.5:14b for the local model (better belief
  extraction quality without huge VRAM cost on a 4090).
"""

from __future__ import annotations
import os

from dataclasses import dataclass, field


@dataclass
class LLMProvider:
    """Configuration for a single LLM provider."""

    name: str
    base_url: str
    model: str
    api_key: str = field(default="", repr=False)  # hidden from repr
    rate_limit_per_min: int = 30
    priority: int = 1       # lower = preferred
    role: str = "primary"   # primary | verification | fallback

    # ── v2: context-window awareness ──
    context_window: int = 32768       # total tokens the model accepts
    num_predict: int = 4096           # max tokens for the *answer*
    supports_json_mode: bool = True   # Ollama, Groq, OpenAI: yes; some local: no
    is_ollama: bool = False           # toggles Ollama-specific options

    @property
    def headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            if "anthropic" in self.base_url:
                h["x-api-key"] = self.api_key
                h["anthropic-version"] = "2023-06-01"
            elif "groq" in self.base_url or "openrouter" in self.base_url:
                h["Authorization"] = f"Bearer {self.api_key}"
            elif "generativelanguage" in self.base_url:
                pass  # Google uses query param
            else:
                h["Authorization"] = f"Bearer {self.api_key}"
        return h

    @property
    def prompt_budget_tokens(self) -> int:
        """How many tokens we may spend on the prompt (system + user)."""
        # Reserve num_predict for answer + 256 for safety overhead
        return max(512, self.context_window - self.num_predict - 256)


@dataclass
class BeliefConfig:
    """Global configuration for BELIEF."""

    # ── LLM Providers ──
    providers: list[LLMProvider] = field(default_factory=list)

    # ── Analysis Settings ──
    max_beliefs_per_function: int = 30
    min_confidence_threshold: float = 0.3
    max_frontiers_per_run: int = 200
    enable_cross_verification: bool = True
    include_cycles: bool = False
    max_cycles: int = 100

    # Below this confidence, a belief's scope is flagged as an
    # "incomprehensible zone" in the AnalysisReport. v4: was hard-coded to 0.3.
    low_confidence_threshold: float = 0.3

    # ── Verifier Settings ──
    z3_timeout_ms: int = 30000
    enable_temporal_verification: bool = False  # requires Spin
    enable_information_flow: bool = False         # requires Joern
    enable_behavioral_testing: bool = True        # Hypothesis

    # ── v2: extraction quality knobs ──
    enable_kb_grounding: bool = True       # inject taint sources/sinks pre-LLM
    enable_z3_repair_loop: bool = True     # 1-shot retry on Z3 translation failure
    enable_self_consistency: bool = False  # multi-sample voting for high-severity beliefs
    self_consistency_samples: int = 3
    self_consistency_min_agreement: int = 2

    # ── v2: chunking / budget ──
    prompt_budget_ratio: float = 0.6   # cap user-content at 60% of prompt budget
    max_code_chars_per_call: int = 16000  # hard ceiling on code chunk size
    chunk_overlap_lines: int = 3       # overlap when splitting big functions

    # ── Output ──
    output_dir: str = "./belief_output"
    save_intermediate: bool = True
    verbose: bool = True

    @classmethod
    def default(cls) -> "BeliefConfig":
        """Sensible defaults for a local 4090 setup, all-free providers."""
        providers: list[LLMProvider] = []

        # Local Ollama (always available if running)
        providers.append(LLMProvider(
            name="ollama_local",
            base_url=os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/") + "/v1",
            model=os.environ.get("BELIEF_OLLAMA_MODEL", "qwen2.5-coder:14b-instruct-q4_K_M"),
            api_key="ollama",
            rate_limit_per_min=9999,
            priority=1,
            role="primary",
            context_window=32768,
            num_predict=4096,
            supports_json_mode=True,
            is_ollama=True,
        ))

        # Groq free tier (large context, very fast)
        groq_key = os.environ.get("GROQ_API_KEY", "")
        if groq_key:
            providers.append(LLMProvider(
                name="groq",
                base_url="https://api.groq.com/openai/v1",
                model="llama-3.3-70b-versatile",
                api_key=groq_key,
                rate_limit_per_min=30,
                priority=2,
                role="verification",
                context_window=131072,
                num_predict=8192,
                supports_json_mode=True,
            ))

        # Google AI Studio free tier (massive context)
        google_key = os.environ.get("GOOGLE_AI_KEY", "")
        if google_key:
            providers.append(LLMProvider(
                name="google",
                base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
                model="gemini-2.0-flash",
                api_key=google_key,
                rate_limit_per_min=60,
                priority=3,
                role="verification",
                context_window=1048576,
                num_predict=8192,
                supports_json_mode=True,
            ))

        # Cerebras free tier
        cerebras_key = os.environ.get("CEREBRAS_API_KEY", "")
        if cerebras_key:
            providers.append(LLMProvider(
                name="cerebras",
                base_url="https://api.cerebras.ai/v1",
                model="llama3.3-70b",
                api_key=cerebras_key,
                rate_limit_per_min=30,
                priority=4,
                role="fallback",
                context_window=8192,
                num_predict=2048,
                supports_json_mode=True,
            ))

        # OpenRouter free models
        openrouter_key = os.environ.get("OPENROUTER_API_KEY", "")
        if openrouter_key:
            providers.append(LLMProvider(
                name="openrouter",
                base_url="https://openrouter.ai/api/v1",
                model="qwen/qwen-2.5-coder-32b-instruct:free",
                api_key=openrouter_key,
                rate_limit_per_min=20,
                priority=5,
                role="fallback",
                context_window=32768,
                num_predict=4096,
                supports_json_mode=True,
            ))

        return cls(providers=providers)

    @classmethod
    def from_env(cls) -> "BeliefConfig":
        """Load configuration from environment variables."""
        config = cls.default()
        config.output_dir = os.environ.get("BELIEF_OUTPUT_DIR", "./belief_output")
        config.verbose = os.environ.get("BELIEF_VERBOSE", "1") == "1"
        return config

    @property
    def primary_provider(self) -> LLMProvider | None:
        primary = [p for p in self.providers if p.role == "primary"]
        return min(primary, key=lambda p: p.priority) if primary else None

    @property
    def verification_providers(self) -> list[LLMProvider]:
        return sorted(
            [p for p in self.providers if p.role == "verification"],
            key=lambda p: p.priority,
        )
