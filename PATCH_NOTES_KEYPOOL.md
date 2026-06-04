# BELIEF — Key Pool Patch

## What's in this patch

- `belief/llm_key_pool.py` — the rotation pool (new file, standalone module)
- `belief/test_llm_key_pool.py` — local sanity check, makes zero API calls
- `.env.example` — template for your keys (copy to `.env`)

## Install

Unzip into your BELIEF project root. The patch adds **new files only** — it
does not overwrite anything existing. After unzip:

```
belief_v4/
├── belief/
│   ├── llm_key_pool.py        <-- NEW
│   ├── test_llm_key_pool.py   <-- NEW
│   ├── llm_client.py          <-- edit manually, see below
│   └── ...
├── .env.example               <-- NEW (copy to .env)
└── ...
```

## Where to put your keys

Copy `.env.example` to `.env` at the project root:

```bash
cd /mnt/c/Users/tatam/Desktop/BELIEF_V2/belief_v4
cp .env.example .env
nano .env   # paste your actual keys
```

Add `.env` to `.gitignore` immediately:

```bash
grep -q "^\.env$" .gitignore 2>/dev/null || echo ".env" >> .gitignore
```

If your project doesn't already load `.env` somewhere, add this at the top
of `belief/__init__.py` or `belief/__main__.py`:

```python
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # fall back to real env vars
```

And `pip install python-dotenv` once.

**Alternative (no .env file):** just export in your shell:

```bash
export GROQ_API_KEY="gsk_aaa..."
export GROQ_API_KEY_2="gsk_bbb..."
export GROQ_API_KEY_3="gsk_ccc..."
export GROQ_API_KEY_4="gsk_ddd..."
```

## Wiring the pool into llm_client.py

This depends on how your current Groq call is written. Find the function in
`belief/llm_client.py` that does the actual HTTP call to Groq (usually
called `call_groq`, `_groq_call`, `GroqProvider.generate`, or similar). You
need to make 3 small changes:

### Change 1 — imports (top of file)

```python
from belief.llm_key_pool import GroqKeyPool, classify_error, retry_after_from_error

_groq_pool = GroqKeyPool()
```

### Change 2 — replace the "read API key once" with pool.get()

**Before** (typical shape):

```python
def call_groq(prompt, model=..., ...):
    api_key = os.getenv("GROQ_API_KEY")
    headers = {"Authorization": f"Bearer {api_key}"}
    resp = httpx.post(GROQ_URL, headers=headers, json={...})
    resp.raise_for_status()
    return resp.json()
```

**After**:

```python
def call_groq(prompt, model=..., ...):
    last_err = None
    for _ in range(_groq_pool.size() + 1):
        key = _groq_pool.get()
        headers = {"Authorization": f"Bearer {key}"}
        try:
            resp = httpx.post(GROQ_URL, headers=headers, json={...})
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            kind = classify_error(e)
            if kind == "rate_limit":
                _groq_pool.penalize(key, retry_after_from_error(e, 60))
                last_err = e
                continue
            if kind == "auth":
                _groq_pool.penalize(key, 3600)
                last_err = e
                continue
            if kind == "server":
                last_err = e
                continue
            raise
    raise RuntimeError(
        f"All {_groq_pool.size()} Groq keys exhausted. Last: {last_err}"
    )
```

### Change 3 — if you use the Groq SDK directly

If `llm_client.py` uses `groq.Groq(api_key=...)` instead of raw httpx:

```python
from groq import Groq

def call_groq(prompt, ...):
    last_err = None
    for _ in range(_groq_pool.size() + 1):
        key = _groq_pool.get()
        try:
            client = Groq(api_key=key)
            return client.chat.completions.create(...)
        except Exception as e:
            kind = classify_error(e)
            if kind == "rate_limit":
                _groq_pool.penalize(key, retry_after_from_error(e, 60))
            elif kind == "auth":
                _groq_pool.penalize(key, 3600)
            elif kind != "server":
                raise
            last_err = e
    raise RuntimeError(f"All Groq keys exhausted. Last: {last_err}")
```

## Verify it works

Before doing a real benchmark run, test the pool logic (no API calls):

```bash
cd /mnt/c/Users/tatam/Desktop/BELIEF_V2/belief_v4
source .venv/bin/activate
python3 -m belief.test_llm_key_pool
```

Expected output: "Discovered N key(s)", round-robin shown, penalization test
passes, `[All tests passed]`.

Then do a small real run to confirm Groq is actually reachable:

```bash
python3 -m belief cognitive ../target_flaskjwt/flask_jwt_extended \
    --budget 120 --max-goals 3 \
    --bridges bandit
```

Watch the logs — you should see no more `Provider ollama_local failed`
and no `Semantic conflict detection failed`.

## Operational tips

- **One call at a time per key** — if you parallelize, add a semaphore
  per key or you'll hit rate limits even faster.
- **Retry-After is respected** — the pool reads the header from 429
  responses and uses it as cooldown duration.
- **Keys are logged masked** — only first 6 and last 4 chars, safe to
  share logs for debugging.
- **Pool is thread-safe** — a `Lock` protects rotation and cooldown state.

## Publication / sharing warning

This rotation mechanism is a development-time convenience. Multi-account
usage to bypass free-tier quotas may violate Groq's Terms of Service.
Before publishing this project (GitHub, SSTIC, demo), remove
`llm_key_pool.py` and the multi-key logic from `llm_client.py`, or leave
only the 1-key fallback path. Consider moving to Groq's paid tier for any
serious benchmark or production workload.
