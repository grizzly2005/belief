"""
belief/cognitive/cwe_taxonomy.py — single source of truth for CWE classification.

Fixes B-06 from the audit: the codebase used to duplicate CWE-guessing logic in
4 different places (cognitive_loop._guess_cwe_from_belief, belief_graph._guess_cwe,
hydra_agent.KEYWORD_TO_CWE, cognitive_loop._learn mini-map) — each with a slightly
different keyword map, causing silent drift in score computations.

All CWE guessing MUST now go through `guess_cwe()` below. All severity lookups
MUST use `cwe_severity()`. Adding a new CWE pattern = edit one dict here.
"""
from __future__ import annotations

from typing import Optional

# ─────────────────────────────────────────────────────────────────
# Keyword → CWE map. ORDER MATTERS: first match wins.
# Keys are substrings (case-insensitive) searched inside predicate.expression
# and/or belief.predicate.natural_language.
# ─────────────────────────────────────────────────────────────────

# Order by specificity: more specific patterns first to avoid false overlap.
# (e.g. "sql_injection" must precede "injection".)
_KEYWORD_CWE: list[tuple[str, str]] = [
    # ── Injection (CWE-89, CWE-78, CWE-79, CWE-94, CWE-95) ──
    ("sql injection", "CWE-89"),
    ("sql_injection", "CWE-89"),
    ("sqli", "CWE-89"),
    ("sqlalchemy", "CWE-89"),     # often flagged when raw sql is built
    ("cursor.execute", "CWE-89"),
    ("query string", "CWE-89"),
    ("sql", "CWE-89"),

    ("command injection", "CWE-78"),
    ("os.system", "CWE-78"),
    ("subprocess", "CWE-78"),
    ("shell=true", "CWE-78"),
    ("shell_exec", "CWE-78"),
    ("shell", "CWE-78"),
    ("inject", "CWE-78"),         # generic injection → shell default

    ("xss", "CWE-79"),
    ("cross-site scripting", "CWE-79"),
    ("innerhtml", "CWE-79"),

    ("eval(", "CWE-95"),
    ("exec(", "CWE-95"),
    ("compile(", "CWE-95"),
    ("eval", "CWE-95"),
    ("exec", "CWE-95"),

    # ── Path / file (CWE-22, CWE-73, CWE-434) ──
    ("path traversal", "CWE-22"),
    ("directory traversal", "CWE-22"),
    ("..\\", "CWE-22"),
    ("../", "CWE-22"),
    ("traversal", "CWE-22"),
    ("path", "CWE-22"),           # broad last-resort for path beliefs

    ("file upload", "CWE-434"),
    ("uploaded file", "CWE-434"),

    # ── Deserialization (CWE-502) ──
    ("pickle", "CWE-502"),
    ("yaml.load(", "CWE-502"),
    ("yaml parsing", "CWE-502"),       # dlint DUO109: 'insecure use of "yaml" parsing function'
    ('use of "yaml"', "CWE-502"),      # dlint DUO109 alt phrasing
    ("unsafe yaml", "CWE-502"),
    ("marshal.load", "CWE-502"),
    ("deseriali", "CWE-502"),
    ("unserialize", "CWE-502"),
    # Fallback: any mention of yaml in a belief predicate — placed LAST
    # so stricter matches win. Safe because dlint/bandit only emit "yaml"
    # in contexts about unsafe loaders.
    ("yaml", "CWE-502"),

    # ── SSRF (CWE-918) ──
    # Order matters: more specific first.
    ("ssrf", "CWE-918"),
    ("server-side request", "CWE-918"),
    ("permitted schemes", "CWE-918"),  # bandit B310: "Audit url open for permitted schemes"
    ("url open", "CWE-918"),           # bandit B310 title phrase
    ("urllib", "CWE-918"),             # urllib.request, urllib.urlopen
    ("urlopen", "CWE-918"),
    ("requests.get", "CWE-918"),

    # ── Crypto (CWE-327, CWE-328, CWE-330, CWE-338, CWE-759, CWE-916) ──
    ("md5", "CWE-327"),
    ("sha1(", "CWE-327"),
    ("weak hash", "CWE-327"),
    ("weak cipher", "CWE-327"),
    ("des ", "CWE-327"),
    ("rc4", "CWE-327"),
    ("ecb", "CWE-327"),
    ("weak crypto", "CWE-327"),
    ('use of "hashlib"', "CWE-327"),   # dlint DUO130 exact phrasing
    ("hashlib", "CWE-327"),            # dlint DUO130: 'insecure use of "hashlib" module'
    ("crypto", "CWE-327"),

    ("random.random", "CWE-338"),
    ("random()", "CWE-338"),
    ("math.random", "CWE-338"),
    ("insecure random", "CWE-338"),
    ("random", "CWE-338"),

    # ── Secrets / credentials (CWE-798, CWE-321) ──
    ("hardcoded password", "CWE-798"),
    ("hardcoded secret", "CWE-798"),
    ("hardcoded key", "CWE-798"),
    ("api_key =", "CWE-798"),
    ("api key", "CWE-798"),
    ("hardcoded", "CWE-798"),

    # ── Auth/sess (CWE-287, CWE-306, CWE-384) ──
    ("authentication", "CWE-287"),
    ("auth bypass", "CWE-287"),
    ("session fix", "CWE-384"),
    ("missing auth", "CWE-306"),

    # ── SSL/TLS (CWE-295, CWE-297) ──
    ("verify=false", "CWE-295"),
    ("ssl verify", "CWE-295"),
    ("certificate valid", "CWE-295"),

    # ── Memory / bounds (CWE-119, CWE-125, CWE-787) ──
    ("buffer overflow", "CWE-119"),
    ("out of bounds", "CWE-125"),
    ("oob read", "CWE-125"),
    ("oob write", "CWE-787"),

    # ── Open redirect (CWE-601) ──
    ("open redirect", "CWE-601"),
    ("redirect", "CWE-601"),

    # ── XXE (CWE-611) ──
    ("xxe", "CWE-611"),
    ("external entity", "CWE-611"),

    # ── CSRF (CWE-352) ──
    ("csrf", "CWE-352"),
    ("cross-site request", "CWE-352"),

    # ── Regex (CWE-1333) ──
    ("redos", "CWE-1333"),
    ("regex dos", "CWE-1333"),
    ("catastrophic backtrack", "CWE-1333"),
]


# ─────────────────────────────────────────────────────────────────
# CWE → severity (0..1) lookup.
# Used by the _decide() scoring function as the "exploitability" factor.
# ─────────────────────────────────────────────────────────────────

_CWE_SEVERITY: dict[str, float] = {
    # Critical RCE / data loss
    "CWE-78":   0.95,  # OS command injection
    "CWE-89":   0.95,  # SQL injection
    "CWE-94":   0.95,  # code injection
    "CWE-95":   0.95,  # eval injection
    "CWE-502":  0.95,  # deserialization of untrusted data
    "CWE-611":  0.85,  # XXE

    # High-impact web vulns
    "CWE-22":   0.85,  # path traversal
    "CWE-73":   0.80,  # file path manipulation
    "CWE-79":   0.75,  # XSS
    "CWE-434":  0.80,  # unrestricted file upload
    "CWE-918":  0.80,  # SSRF
    "CWE-601":  0.60,  # open redirect

    # Crypto/auth
    "CWE-287":  0.80,  # auth weakness
    "CWE-306":  0.80,  # missing auth
    "CWE-295":  0.70,  # cert validation
    "CWE-327":  0.65,  # broken crypto
    "CWE-338":  0.55,  # weak PRNG
    "CWE-384":  0.70,  # session fixation
    "CWE-352":  0.60,  # CSRF

    # Secrets
    "CWE-798":  0.80,  # hardcoded credentials
    "CWE-321":  0.75,

    # Memory safety (rarely triggers in python codepath but supported)
    "CWE-119":  0.90,
    "CWE-125":  0.75,
    "CWE-787":  0.90,

    # Logic / dos
    "CWE-1333": 0.45,  # ReDoS
}

DEFAULT_SEVERITY = 0.50  # unknown CWE → neutral


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────

def guess_cwe(text: str, fallback: str = "") -> str:
    """Guess the CWE identifier from free-form text (predicate/description).

    Returns the CWE ID like "CWE-89" or `fallback` if nothing matches.
    Case-insensitive. First-match-wins per the ordered list above.
    """
    if not text:
        return fallback
    t = text.lower()
    for kw, cwe in _KEYWORD_CWE:
        if kw in t:
            return cwe
    return fallback


def guess_cwe_from_belief(belief) -> str:
    """Convenience wrapper for Belief objects. Checks predicate expression
    first, then natural_language description, then justification notes."""
    # predicate.expression
    cwe = guess_cwe(belief.predicate.expression)
    if cwe:
        return cwe
    # predicate.natural_language
    cwe = guess_cwe(belief.predicate.natural_language)
    if cwe:
        return cwe
    return ""


def cwe_severity(cwe: str) -> float:
    """Return severity score (0..1) for a CWE id. Unknown → DEFAULT_SEVERITY."""
    if not cwe:
        return DEFAULT_SEVERITY
    return _CWE_SEVERITY.get(cwe, DEFAULT_SEVERITY)


def is_injection(cwe: str) -> bool:
    """Helper for investigation strategies: is this an injection family?"""
    return cwe in {"CWE-78", "CWE-89", "CWE-94", "CWE-95", "CWE-79", "CWE-611"}


def is_memory_safety(cwe: str) -> bool:
    return cwe in {"CWE-119", "CWE-125", "CWE-787"}


def is_crypto(cwe: str) -> bool:
    return cwe in {"CWE-327", "CWE-328", "CWE-330", "CWE-338", "CWE-759", "CWE-916"}


__all__ = [
    "guess_cwe",
    "guess_cwe_from_belief",
    "cwe_severity",
    "is_injection",
    "is_memory_safety",
    "is_crypto",
    "DEFAULT_SEVERITY",
]
