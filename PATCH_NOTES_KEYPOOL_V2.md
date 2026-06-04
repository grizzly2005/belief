# BELIEF — Key Pool Patch v2 (drop-in integration)

## What changed vs v1

v1 gave you the pool as a standalone module and asked you to integrate it
by hand in `llm_client.py`. v2 ships the patched `llm_client.py` directly,
so you just unzip and run.

## Contents

```
belief/
├── llm_client.py          <-- PATCHED (overwrites existing)
├── llm_key_pool.py        <-- new module (no conflict)
└── test_llm_key_pool.py   <-- local test, zero API calls
.env.example               <-- template for your keys
PATCH_NOTES_KEYPOOL_V2.md  <-- this file
```

## What's fixed in llm_client.py

### Fix 1 — Groq HTTP 400 "Failed to generate JSON"

Groq enforces a rule: when you use `response_format={"type": "json_object"}`,
the system or user prompt MUST contain the literal word "JSON" somewhere,
otherwise the API returns 400. Your previous `extractor.py` prompts don't
always include it, which is why your first attempt on every function was
failing before even hitting the rate limit.

The patched `_call_provider` now auto-injects a short directive in the
system prompt whenever (a) the provider is groq, (b) json_mode is on, and
(c) neither the system nor user prompt already mentions "json". Transparent
to callers — no change needed in `extractor.py`.

### Fix 2 — Automatic key rotation for groq

If `belief/llm_key_pool.py` is importable and you have at least 2
`GROQ_API_KEY*` env vars, the patched `_call_provider` automatically
rotates on HTTP 429 (rate limit) and 401/403 (auth). Each 429 parses the
`Retry-After` from Groq's error message ("Please try again in 41.73s") and
cools down that specific key for the right duration, capped at 120s so a
single slow key doesn't block the whole run.

Non-groq providers (ollama, gemini, openrouter, etc.) are untouched and
behave exactly as before.

If the pool can't initialize (no keys, or only 1 key), the client silently
falls back to single-key mode and logs it at DEBUG level.

## Install

Back up your current `llm_client.py` first:

```bash
cd /mnt/c/Users/tatam/Desktop/BELIEF_V2/belief_v4
cp belief/llm_client.py belief/llm_client.py.bak
unzip -o ~/Downloads/belief_v4_keypool_v2.zip
```

## Put your keys somewhere

Option A — `.env` file (recommended, loads automatically):

```bash
cp .env.example .env
nano .env
# fill in GROQ_API_KEY, GROQ_API_KEY_2, ... (up to _10)
echo ".env" >> .gitignore
source .venv/bin/activate
pip install python-dotenv
```

Then add once to `belief/__init__.py` (or `belief/__main__.py`) at the
top:

```python
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
```

Option B — shell export (simpler, per-session):

```bash
export GROQ_API_KEY="gsk_aaa..."
export GROQ_API_KEY_2="gsk_bbb..."
export GROQ_API_KEY_3="gsk_ccc..."
export GROQ_API_KEY_4="gsk_ddd..."
```

## Verify

```bash
source .venv/bin/activate

# 1) Pool sanity check (no API calls)
python3 -m belief.test_llm_key_pool
# Expected: "Discovered N keys", round-robin demo, [All tests passed]

# 2) Tiny real run — should no longer crash on HTTP 400, and should
#    rotate keys when one hits 429
python3 -m belief cognitive ../target_flaskjwt/flask_jwt_extended \
    --budget 120 --max-goals 3 \
    --bridges bandit
```

In the log you want to see (first run only, once per process):

```
Groq key rotation enabled: N keys available
```

And on 429s:

```
GroqKeyPool: penalizing gsk_xxx...abcd for 42s
```

## A note on TPM limits (independent concern)

Your log showed requests of 9000-10000 tokens each. That's huge for
extracting beliefs from a single function. With Groq free tier at 12000
TPM on `llama-3.3-70b-versatile`, one such call consumes ~80% of your
budget for the entire minute.

Two easy mitigations, independent of this patch:

1. **Switch to `llama-3.1-8b-instant`** — 30000 TPM (2.5x), still very
   capable for structured belief extraction. Change the model name in
   your `config.py` or wherever providers are declared.

2. **Trim `extractor.py` prompts** — check what context you bundle with
   each function. If you're sending the whole file, switch to function
   body + 1-2 lines of caller context. Target 2000-3000 tokens/call max.

Key rotation (this patch) mitigates the symptom. Smaller prompts fix the
cause.

## ToS reminder

Multi-account key rotation may violate Groq's ToS. Use at your own
discretion, and remove the pool before publishing the project publicly.
For production or serious benchmarking, pay for Dev Tier ($50/mo gets you
30000 TPM on the 70B model with sane concurrency).
