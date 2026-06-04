# BELIEF — Key Pool Patch v3 (JSON fix strengthened)

## Why v3

v2's JSON fix was too cautious: it only injected a directive when the word
"json" was absent from the prompt. But Groq rejects with HTTP 400 even
when "json" appears as part of code comments, function names, or doc
strings — it requires an explicit *instruction* to produce JSON, not just
the word appearing somewhere.

v3 always prepends the directive for groq json_mode calls. This is
idempotent and safe.

## Changes vs v2

- **JSON directive always prepended for groq + json_mode** (not conditional)
- **Info log on first groq call** ("llm_client v3 active: groq json_mode
  auto-prefix + key rotation") so you can visually confirm the patch is
  loaded
- **Key pool discovery log bumped to INFO** (was DEBUG) so the "1 key
  found, rotation disabled" or "N keys, rotation enabled" message shows
  up in normal runs

## Install

Same as v2 — backup and unzip:

```bash
cd /mnt/c/Users/tatam/Desktop/BELIEF_V2/belief_v4
# Only backup if you haven't already
[ -f belief/llm_client.py.bak ] || cp belief/llm_client.py belief/llm_client.py.bak
unzip -o ~/Downloads/belief_v4_keypool_v3.zip
```

## Verify the patch is actually loaded

These three greps should all print >= 1:

```bash
grep -c "You MUST respond with valid JSON only" belief/llm_client.py
grep -c "llm_client v3 active" belief/llm_client.py
grep -c "GroqKeyPool" belief/llm_client.py
```

Then at the next run, you should see a banner very early in the log:

```
llm_client v3 active: groq json_mode auto-prefix + key rotation
Groq key rotation enabled: N keys available       <-- if N >= 2
```

Or, if you only exported 1 key:

```
Groq key pool found 1 key — rotation disabled (add GROQ_API_KEY_2/_3/... to enable)
```

## Also worth knowing (not patched here)

### Separate error: JustificationCategory.C3_DOCUMENTED

The log line

    [observe] Base orchestrator failed:
    type object 'JustificationCategory' has no attribute 'C3_DOCUMENTED'

is a pre-existing bug in your `orchestrator.py` — an enum value is
referenced but not declared in `belief/models.py` (or wherever
`JustificationCategory` lives). Grep for it:

```bash
grep -rn "C3_DOCUMENTED\|JustificationCategory" belief/ --include='*.py' | head -40
```

The observer failing means the LLM-based extraction is effectively
bypassed, which is why you're only getting bandit verdicts. Fix this
separately — either add the missing enum member, or wrap the reference in
a try/except to degrade gracefully.

### TPM limit still tight

Even with the JSON fix, 12000 TPM on llama-3.3-70b-versatile is barely
enough for 1-2 belief extractions per minute when prompts reach 10k
tokens. Two mitigations:

1. **Switch model** to `llama-3.1-8b-instant` (30000 TPM, 2.5x more)
2. **Trim prompts** in extractor.py to ~2000 tokens per function

Key rotation helps you survive a burst, but the real fix is smaller
prompts.
