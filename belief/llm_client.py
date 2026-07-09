"""
BELIEF — Multi-provider LLM client (v3, with Groq key rotation pool).

v3 changes over v2 (pool integration only — no behavioral change for
non-groq providers):

1. **Groq key rotation** — when `belief.llm_key_pool` is importable and at
   least one GROQ_API_KEY* env var is set, groq calls automatically rotate
   across keys on HTTP 429 (rate limit) or 401/403 (auth). The key used
   for each call is picked by the pool; keys hitting a rate limit are
   cooled down for `retry_after` seconds parsed from the 429 message.
   Non-groq providers are untouched.

2. **Groq JSON mode prompt fix** — groq requires the literal word "JSON"
   to appear in the system or user prompt when `response_format={"type":
   "json_object"}` is used, otherwise it returns HTTP 400
   "Failed to generate JSON". When the caller requests json_mode for a
   groq call and neither prompt mentions JSON, we auto-append a short
   directive to the system prompt.

v2 fixes still active: num_ctx for Ollama, JSON-mode forcing,
token budgeting, tolerant JSON parsing.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections import deque
try:
    import httpx
except ImportError:  # The static/offline CLI must not require an LLM transport.
    httpx = None

from .config import BeliefConfig, LLMProvider

logger = logging.getLogger("belief.llm")


# ─────────────────────────────────────────────────────────────────────────────
#  Key pool (optional — graceful fallback if module missing or no keys)
# ─────────────────────────────────────────────────────────────────────────────

try:
    from .llm_key_pool import GroqKeyPool  # noqa: F401
    _HAS_KEYPOOL = True
except ImportError:
    _HAS_KEYPOOL = False
    logger.debug("llm_key_pool unavailable — groq will use single-key mode")

_groq_pool = None  # lazily initialized on first groq call
_groq_pool_tried = False


def _get_groq_pool():
    """Lazy singleton. Returns the pool instance, or None if disabled/unavailable."""
    global _groq_pool, _groq_pool_tried
    if _groq_pool is not None:
        return _groq_pool
    if _groq_pool_tried or not _HAS_KEYPOOL:
        return None
    _groq_pool_tried = True
    try:
        pool = GroqKeyPool()
        if pool.size() >= 2:
            logger.info(
                "Groq key rotation enabled: %d keys available", pool.size()
            )
            _groq_pool = pool
            return pool
        logger.info(
            "Groq key pool found 1 key — rotation disabled "
            "(add GROQ_API_KEY_2/_3/... to enable)"
        )
        return None
    except RuntimeError as e:
        logger.info("Groq key pool disabled: %s", e)
        return None


_groq_patch_banner_shown = False


def _show_groq_patch_banner_once():
    """Emit a single INFO banner confirming the v3 patch is active. Makes it
    obvious to the user that the new llm_client.py is really loaded."""
    global _groq_patch_banner_shown
    if not _groq_patch_banner_shown:
        _groq_patch_banner_shown = True
        logger.info(
            "llm_client v3 active: groq json_mode auto-prefix + key rotation"
        )


_RETRY_AFTER_RE = re.compile(r"try again in\s+([\d.]+)\s*s", re.IGNORECASE)


# ─────────────────────────────────────────────────────────────────────────────
#  Token counting
# ─────────────────────────────────────────────────────────────────────────────

def estimate_tokens(text: str) -> int:
    """Pessimistic char→token estimate. ~3 chars/token works for qwen, llama,
    gemini in practice (they all use similar BPE vocab sizes). We round up
    to leave headroom."""
    if not text:
        return 0
    return (len(text) // 3) + 1


# ─────────────────────────────────────────────────────────────────────────────
#  Rate limiting
# ─────────────────────────────────────────────────────────────────────────────

class RateLimiter:
    """Simple sliding-window rate limiter."""

    def __init__(self, max_per_minute: int):
        self.max = max_per_minute
        self.timestamps: deque[float] = deque()

    def acquire(self) -> None:
        now = time.time()
        while self.timestamps and now - self.timestamps[0] > 60:
            self.timestamps.popleft()
        if len(self.timestamps) >= self.max:
            wait = 60 - (now - self.timestamps[0])
            if wait > 0:
                logger.debug(f"Rate limit reached, waiting {wait:.1f}s")
                time.sleep(wait)
        self.timestamps.append(time.time())


# ─────────────────────────────────────────────────────────────────────────────
#  JSON parsing — tolerant of common LLM glitches
# ─────────────────────────────────────────────────────────────────────────────

_FENCE_RE = re.compile(r"^```(?:json|JSON)?\s*\n?|\n?```\s*$", re.MULTILINE)


def _parse_json_tolerant(raw: str) -> list | dict:
    """Parse JSON from LLM output. Recovers from:
    - markdown fences ``` ```json
    - leading/trailing prose
    - trailing commas before } or ]
    - unclosed arrays (truncated output): keeps complete objects up to the cut
    """
    if not raw:
        raise ValueError("Empty LLM response")

    text = raw.strip()
    text = _FENCE_RE.sub("", text).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    array_start = text.find("[")
    object_start = text.find("{")
    if array_start == -1 and object_start == -1:
        raise ValueError(f"No JSON structure found in:\n{text[:300]}")

    if array_start != -1 and (object_start == -1 or array_start < object_start):
        start, open_ch, close_ch = array_start, "[", "]"
    else:
        start, open_ch, close_ch = object_start, "{", "}"

    end = text.rfind(close_ch)
    if end != -1 and end > start:
        candidate = text[start:end + 1]
        cleaned = re.sub(r",(\s*[}\]])", r"\1", candidate)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

    if open_ch == "[":
        return _salvage_partial_array(text[start:])

    raise ValueError(f"Could not parse JSON from LLM output:\n{text[:500]}")


def _salvage_partial_array(text: str) -> list:
    """When the model got cut off in the middle of an array, recover the
    objects that *did* finish. We walk the string with a tiny brace
    counter that respects strings."""
    if not text.startswith("["):
        return []

    objects: list = []
    i = 1
    n = len(text)
    while i < n:
        while i < n and text[i] in " \t\n\r,":
            i += 1
        if i >= n or text[i] == "]":
            break
        if text[i] != "{":
            break

        depth = 0
        in_str = False
        esc = False
        start = i
        while i < n:
            c = text[i]
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = not in_str
            elif not in_str:
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
            i += 1

        if depth != 0:
            break

        chunk = text[start:i]
        cleaned = re.sub(r",(\s*[}\]])", r"\1", chunk)
        try:
            objects.append(json.loads(cleaned))
        except json.JSONDecodeError:
            break

    if objects:
        logger.warning(f"Recovered {len(objects)} objects from truncated JSON array")
    return objects


# ─────────────────────────────────────────────────────────────────────────────
#  LLM Client
# ─────────────────────────────────────────────────────────────────────────────

class PromptTooLargeError(Exception):
    """Raised when the prompt exceeds a provider's budget. The caller is
    expected to chunk and retry; this is *not* an LLM failure."""


class LLMDependencyError(RuntimeError):
    """Raised when an LLM feature is requested without its HTTP transport."""


def _require_httpx():
    if httpx is None:
        raise LLMDependencyError(
            "LLM features require the optional 'httpx' dependency. "
            "Install BELIEF's project dependencies in the active environment."
        )
    return httpx


def _is_groq(provider: LLMProvider) -> bool:
    """Detect a groq provider regardless of config naming conventions."""
    if getattr(provider, "name", "").lower() == "groq":
        return True
    base = getattr(provider, "base_url", "") or ""
    return "groq.com" in base.lower()


class LLMClient:
    """Multi-provider LLM client for BELIEF."""

    def __init__(self, config: BeliefConfig):
        self.config = config
        self.limiters: dict[str, RateLimiter] = {}
        self.http = _require_httpx().Client(timeout=180.0)
        for p in config.providers:
            self.limiters[p.name] = RateLimiter(p.rate_limit_per_min)

    # ── Public API ──

    def complete(
        self,
        prompt: str,
        system: str = "",
        provider_name: str | None = None,
        temperature: float = 0.1,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> str:
        providers = self._resolve_providers(provider_name)

        last_error: Exception | None = None
        for provider in providers:
            try:
                self._check_budget(provider, system, prompt)
                return self._call_provider(
                    provider, prompt, system, temperature,
                    max_tokens or provider.num_predict,
                    json_mode=json_mode,
                )
            except PromptTooLargeError as e:
                logger.warning(f"Prompt too large for {provider.name}: {e}")
                last_error = e
                continue
            except Exception as e:
                logger.warning(f"Provider {provider.name} failed: {e}")
                last_error = e
                continue

        raise RuntimeError(f"All LLM providers failed. Last error: {last_error}")

    def complete_json(
        self,
        prompt: str,
        system: str = "",
        provider_name: str | None = None,
        temperature: float = 0.1,
        max_tokens: int | None = None,
    ) -> list | dict:
        raw = self.complete(
            prompt, system, provider_name, temperature, max_tokens, json_mode=True
        )
        try:
            return _parse_json_tolerant(raw)
        except Exception as e:
            logger.error(f"JSON parse failed for output: {raw[:300]}...")
            raise ValueError(f"LLM returned unparseable JSON: {e}") from e

    def complete_with_repair(
        self,
        prompt: str,
        system: str = "",
        repair_instruction: str = "",
        provider_name: str | None = None,
        max_repair_attempts: int = 1,
    ) -> list | dict:
        try:
            return self.complete_json(prompt, system, provider_name)
        except Exception as first_err:
            if max_repair_attempts <= 0:
                raise
            logger.info(f"Initial call failed ({first_err}), attempting repair")
            repair_prompt = (
                f"{prompt}\n\n"
                f"## Previous attempt failed\n"
                f"Error: {first_err}\n"
                f"{repair_instruction}\n"
                f"Output ONLY valid JSON this time. No prose."
            )
            return self.complete_json(repair_prompt, system, provider_name)

    def cross_verify(
        self,
        prompt: str,
        system: str = "",
    ) -> list[dict]:
        results: list[dict] = []

        primary = self.config.primary_provider
        if primary:
            try:
                resp = self.complete_json(prompt, system, primary.name)
                results.append({"provider": primary.name, "response": resp})
            except Exception as e:
                logger.warning(f"Primary {primary.name} failed in cross-verify: {e}")

        for vp in self.config.verification_providers:
            try:
                resp = self.complete_json(prompt, system, vp.name)
                results.append({"provider": vp.name, "response": resp})
            except Exception as e:
                logger.warning(f"Verifier {vp.name} failed: {e}")

        return results

    def self_consistency(
        self,
        prompt: str,
        system: str = "",
        provider_name: str | None = None,
        n_samples: int = 3,
        temperature: float = 0.4,
    ) -> list[list | dict]:
        outputs: list[list | dict] = []
        for i in range(n_samples):
            try:
                out = self.complete_json(
                    prompt, system, provider_name,
                    temperature=temperature,
                )
                outputs.append(out)
            except Exception as e:
                logger.warning(f"Self-consistency sample {i + 1}/{n_samples} failed: {e}")
        return outputs

    # ── Internal ──

    def _resolve_providers(self, provider_name: str | None) -> list[LLMProvider]:
        if provider_name:
            return [p for p in self.config.providers if p.name == provider_name]
        return sorted(self.config.providers, key=lambda p: p.priority)

    def _check_budget(
        self, provider: LLMProvider, system: str, prompt: str
    ) -> None:
        prompt_tokens = estimate_tokens(system) + estimate_tokens(prompt)
        budget = provider.prompt_budget_tokens
        if prompt_tokens > budget:
            raise PromptTooLargeError(
                f"prompt={prompt_tokens} tokens > budget={budget} "
                f"(context={provider.context_window}, num_predict={provider.num_predict})"
            )

    def _call_provider(
        self,
        provider: LLMProvider,
        prompt: str,
        system: str,
        temperature: float,
        max_tokens: int,
        json_mode: bool = False,
    ) -> str:
        self.limiters[provider.name].acquire()

        is_groq_provider = _is_groq(provider)
        if is_groq_provider:
            _show_groq_patch_banner_once()
        pool = _get_groq_pool() if is_groq_provider else None

        # ── Groq JSON-mode prompt fix (v3: always-prepend) ──
        # Groq rejects json_mode calls with HTTP 400 when the prompt does
        # not contain a clear directive to produce JSON. Even if "json"
        # appears elsewhere (comments, identifier names), Groq may still
        # refuse. We therefore ALWAYS prepend a strong directive to the
        # system message when (a) groq provider, (b) json_mode requested,
        # (c) provider supports json_mode. This is idempotent if the
        # caller already has its own directive.
        if json_mode and is_groq_provider and provider.supports_json_mode:
            directive = (
                "You MUST respond with valid JSON only. "
                "No prose, no markdown, no explanations — JSON only."
            )
            system = f"{directive}\n\n{system}" if system else directive

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload: dict = {
            "model": provider.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if json_mode and provider.supports_json_mode:
            payload["response_format"] = {"type": "json_object"}

        if provider.is_ollama:
            payload["options"] = {
                "num_ctx": provider.context_window,
                "num_predict": max_tokens,
                "temperature": temperature,
            }

        url = provider.base_url.rstrip("/") + "/chat/completions"

        params = {}
        if "generativelanguage" in provider.base_url and provider.api_key:
            params["key"] = provider.api_key

        # ── Call loop (rotates keys if groq + pool enabled) ──
        max_attempts = pool.size() + 1 if pool else 1
        last_err: Exception | None = None

        for attempt in range(max_attempts):
            # Headers: copy provider defaults, then override Authorization
            # with a pool-provided key when rotation is active.
            headers = dict(provider.headers)
            rotated_key = None
            if pool:
                rotated_key = pool.get()
                if rotated_key is None:
                    break
                headers["Authorization"] = f"Bearer {rotated_key}"

            try:
                response = self.http.post(
                    url, headers=headers, json=payload, params=params,
                )
            except Exception as exc:
                transport = _require_httpx()
                if not isinstance(exc, (transport.TimeoutException, transport.ConnectError)):
                    raise
                # Transport-level failure — try next key (no penalty) if pool,
                # otherwise bubble up.
                if pool:
                    last_err = exc
                    continue
                raise

            status = response.status_code

            # 429 rate limit — with pool, penalize and rotate
            if status == 429 and pool and rotated_key:
                try:
                    err_body = response.json()
                    err_msg = err_body.get("error", {}).get("message", "")
                except Exception:
                    err_msg = response.text[:200]
                m = _RETRY_AFTER_RE.search(err_msg)
                retry_s = float(m.group(1)) if m else 60.0
                # Cap cooldown at 120s so a long wait doesn't block the whole run
                pool.penalize(rotated_key, seconds=min(retry_s + 1.0, 120.0))
                last_err = RuntimeError(
                    f"groq 429 on key (rotated): {err_msg[:180]}"
                )
                continue

            # Auth failures — penalize long and rotate
            if status in (401, 403) and pool and rotated_key:
                pool.penalize(rotated_key, seconds=3600)
                last_err = RuntimeError(
                    f"groq auth failed (HTTP {status}) on rotated key"
                )
                continue

            # Any other HTTP error — don't rotate, bubble up for fallback provider
            if status >= 400:
                try:
                    err_body = response.json()
                    err_msg = err_body.get("error", {}).get(
                        "message", response.text[:200]
                    )
                except Exception:
                    err_msg = response.text[:200]
                raise RuntimeError(
                    f"{provider.name} returned HTTP {status}: {err_msg}"
                )

            # ── Success path ──
            try:
                data = response.json()
            except Exception as e:
                raise ValueError(
                    f"{provider.name} returned non-JSON response: {response.text[:200]}"
                ) from e

            choices = data.get("choices", [])
            if not choices:
                raise ValueError(f"Empty choices array from {provider.name}")

            content = choices[0].get("message", {}).get("content", "")
            if not content:
                raise ValueError(f"Empty content from {provider.name}")

            finish_reason = choices[0].get("finish_reason", "")
            if finish_reason == "length":
                logger.warning(
                    f"[{provider.name}] Output hit max_tokens={max_tokens}. "
                    f"Output may be truncated. Consider raising num_predict or chunking."
                )

            logger.debug(
                f"[{provider.name}] in≈{estimate_tokens(prompt)}t out={len(content)}c "
                f"reason={finish_reason}"
            )
            return content

        # Exhausted all pool keys
        raise RuntimeError(
            f"All {pool.size() if pool else 1} keys exhausted for "
            f"{provider.name}. Last: {last_err}"
        )

    # ── Lifecycle ──

    def close(self) -> None:
        self.http.close()

    def __enter__(self) -> "LLMClient":
        return self

    def __exit__(self, *args) -> None:
        self.close()
