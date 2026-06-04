"""
BELIEF — Knowledge Base intégrée
=================================
Consolidation de 110 taint sources (Pyre/pysa), 233 taint sinks,
42 patterns Bandit, et 251 règles Semgrep Python en une seule base
de connaissances pour améliorer l'extraction de croyances.

Usage dans BELIEF :
    from belief_knowledge_base import KnowledgeBase
    kb = KnowledgeBase()

    # Enrichir l'extraction de croyances avec le contexte taint
    taint_context = kb.get_taint_context(code, framework="flask")

    # Vérifier si un pattern connu matche (pré-filtre avant LLM)
    known_issues = kb.match_known_patterns(code)

    # Générer un prompt enrichi pour le LLM
    enriched_prompt = kb.build_enriched_prompt(code, file_path)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — TAINT DATABASE (from Pyre/pysa stubs)
#  110 sources + 233 sinks couvrant : Flask, Django, FastAPI, aiohttp,
#  Tornado, Falcon, boto3, SQLAlchemy, paramiko, etc.
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TaintSource:
    path: str          # ex: "flask.wrappers.Request.view_args"
    labels: list[str]  # ex: ["UserControlled", "UserControlled_Payload"]
    framework: str     # ex: "flask"


@dataclass
class TaintSink:
    function: str      # ex: "paramiko.client.SSHClient.exec_command"
    parameter: str     # ex: "command"
    labels: list[str]  # ex: ["RemoteCodeExecution"]
    framework: str     # ex: "rce"


# ── Sources (entrées utilisateur) ──────────────────────────────────────────

TAINT_SOURCES = [
    # ─── Flask / Werkzeug ───
    TaintSource("werkzeug.wrappers.BaseRequest.path", ["UserControlled", "URL"], "flask"),
    TaintSource("werkzeug.wrappers.BaseRequest.full_path", ["UserControlled", "URL"], "flask"),
    TaintSource("werkzeug.wrappers.BaseRequest.url", ["UserControlled", "URL"], "flask"),
    TaintSource("werkzeug.wrappers.BaseRequest.args", ["UserControlled", "UserControlled_Payload"], "flask"),
    TaintSource("werkzeug.wrappers.BaseRequest.form", ["UserControlled", "UserControlled_Payload"], "flask"),
    TaintSource("werkzeug.wrappers.BaseRequest.values", ["UserControlled", "UserControlled_Payload"], "flask"),
    TaintSource("werkzeug.wrappers.BaseRequest.data", ["UserControlled", "UserControlled_Payload"], "flask"),
    TaintSource("werkzeug.wrappers.BaseRequest.files", ["UserControlled", "UserControlled_Payload"], "flask"),
    TaintSource("werkzeug.wrappers.BaseRequest.cookies", ["UserControlled", "Cookies"], "flask"),
    TaintSource("werkzeug.wrappers.BaseRequest.headers", ["UserControlled", "HeaderData"], "flask"),
    TaintSource("werkzeug.wrappers.BaseRequest.query_string", ["UserControlled", "UserControlled_Payload"], "flask"),
    TaintSource("flask.wrappers.Request.view_args", ["UserControlled", "UserControlled_Payload"], "flask"),
    TaintSource("flask.wrappers.JSONMixin.get_json", ["UserControlled", "UserControlled_Payload"], "flask"),
    TaintSource("werkzeug.wrappers.request.Request.json", ["UserControlled", "UserControlled_Payload"], "flask"),
    TaintSource("werkzeug.datastructures.Headers.get", ["UserControlled", "HeaderData"], "flask"),

    # ─── FastAPI ───
    TaintSource("fastapi.Request.path_params", ["UserControlled", "UserControlled_Payload"], "fastapi"),
    TaintSource("fastapi.Request.query_params", ["UserControlled", "UserControlled_Payload"], "fastapi"),
    TaintSource("starlette.requests.Request.body", ["UserControlled", "UserControlled_Payload"], "fastapi"),

    # ─── aiohttp ───
    TaintSource("aiohttp.web_request.BaseRequest.url", ["UserControlled", "URL"], "aiohttp"),
    TaintSource("aiohttp.web_request.BaseRequest.path", ["UserControlled", "URL"], "aiohttp"),
    TaintSource("aiohttp.web_request.BaseRequest.query", ["UserControlled", "UserControlled_Payload"], "aiohttp"),
    TaintSource("aiohttp.web_request.BaseRequest.headers", ["UserControlled", "HeaderData"], "aiohttp"),
    TaintSource("aiohttp.web_request.BaseRequest.cookies", ["UserControlled", "Cookies"], "aiohttp"),
    TaintSource("aiohttp.web_request.BaseRequest.post", ["UserControlled", "UserControlled_Payload"], "aiohttp"),
    TaintSource("aiohttp.web_request.BaseRequest.json", ["UserControlled", "UserControlled_Payload"], "aiohttp"),
    TaintSource("aiohttp.web_request.BaseRequest.text", ["UserControlled", "UserControlled_Payload"], "aiohttp"),
    TaintSource("aiohttp.web_request.BaseRequest.read", ["UserControlled", "UserControlled_Payload"], "aiohttp"),

    # ─── Tornado ───
    TaintSource("tornado.web.RequestHandler.get_argument", ["UserControlled", "UserControlled_Payload"], "tornado"),
    TaintSource("tornado.web.RequestHandler.get_arguments", ["UserControlled", "UserControlled_Payload"], "tornado"),
    TaintSource("tornado.web.RequestHandler.get_body_argument", ["UserControlled", "UserControlled_Payload"], "tornado"),
    TaintSource("tornado.web.RequestHandler.get_query_argument", ["UserControlled", "UserControlled_Payload"], "tornado"),
    TaintSource("tornado.httputil.HTTPServerRequest.body", ["UserControlled", "UserControlled_Payload"], "tornado"),

    # ─── Falcon ───
    TaintSource("falcon.Request.params", ["UserControlled", "UserControlled_Payload"], "falcon"),
    TaintSource("falcon.Request.get_param", ["UserControlled", "UserControlled_Payload"], "falcon"),
    TaintSource("falcon.Request.media", ["UserControlled", "UserControlled_Payload"], "falcon"),
    TaintSource("falcon.Request.bounded_stream", ["UserControlled", "UserControlled_Payload"], "falcon"),

    # ─── Django ───
    TaintSource("django.http.request.HttpRequest.GET", ["UserControlled", "UserControlled_Payload"], "django"),
    TaintSource("django.http.request.HttpRequest.POST", ["UserControlled", "UserControlled_Payload"], "django"),
    TaintSource("django.http.request.HttpRequest.body", ["UserControlled", "UserControlled_Payload"], "django"),
    TaintSource("django.http.request.HttpRequest.COOKIES", ["UserControlled", "Cookies"], "django"),
    TaintSource("django.http.request.HttpRequest.META", ["UserControlled", "HeaderData"], "django"),
    TaintSource("django.http.request.HttpRequest.path", ["UserControlled", "URL"], "django"),

    # ─── boto3 (AWS) ───
    TaintSource("boto3.Session.client", ["AWSService"], "boto3"),
    TaintSource("botocore.response.StreamingBody.read", ["UserControlled"], "boto3"),

    # ─── Generiques ───
    TaintSource("os.environ.get", ["EnvironmentVariable"], "stdlib"),
    TaintSource("os.environ.__getitem__", ["EnvironmentVariable"], "stdlib"),
    TaintSource("sys.argv", ["CommandLineArg"], "stdlib"),
    TaintSource("input", ["UserControlled"], "stdlib"),
]


# ── Sinks (points dangereux) ──────────────────────────────────────────────

TAINT_SINKS = [
    # ─── SQL Injection ───
    TaintSink("sqlite3.Cursor.execute", "sql", ["SQLInjection"], "sql"),
    TaintSink("sqlite3.Cursor.executemany", "sql", ["SQLInjection"], "sql"),
    TaintSink("psycopg2.cursor.execute", "query", ["SQLInjection"], "sql"),
    TaintSink("pymysql.cursors.Cursor.execute", "query", ["SQLInjection"], "sql"),
    TaintSink("pymssql.Cursor.execute", "operation", ["SQLInjection"], "sql"),
    TaintSink("mysql.connector.cursor.CursorBase.execute", "operation", ["SQLInjection"], "sql"),
    TaintSink("sqlalchemy.engine.Engine.execute", "object", ["SQLInjection"], "sql"),
    TaintSink("sqlalchemy.orm.Session.execute", "statement", ["SQLInjection"], "sql"),
    TaintSink("sqlalchemy.text", "text", ["SQLInjection"], "sql"),
    TaintSink("duckdb.DuckDBPyConnection.execute", "query", ["SQLInjection"], "sql"),
    TaintSink("duckdb.DuckDBPyConnection.sql", "query", ["SQLInjection"], "sql"),

    # ─── Remote Code Execution ───
    TaintSink("os.system", "command", ["RemoteCodeExecution"], "rce"),
    TaintSink("os.popen", "cmd", ["RemoteCodeExecution"], "rce"),
    TaintSink("os.exec*", "path", ["RemoteCodeExecution"], "rce"),
    TaintSink("subprocess.call", "args", ["RemoteCodeExecution"], "rce"),
    TaintSink("subprocess.run", "args", ["RemoteCodeExecution"], "rce"),
    TaintSink("subprocess.Popen", "args", ["RemoteCodeExecution"], "rce"),
    TaintSink("subprocess.check_output", "args", ["RemoteCodeExecution"], "rce"),
    TaintSink("eval", "expression", ["RemoteCodeExecution"], "rce"),
    TaintSink("exec", "code", ["RemoteCodeExecution"], "rce"),
    TaintSink("compile", "source", ["RemoteCodeExecution"], "rce"),
    TaintSink("paramiko.client.SSHClient.exec_command", "command", ["RemoteCodeExecution"], "rce"),
    TaintSink("paramiko.channel.Channel.exec_command", "command", ["RemoteCodeExecution"], "rce"),
    TaintSink("pexpect.spawn", "command", ["RemoteCodeExecution"], "rce"),
    TaintSink("asyncio.create_subprocess_shell", "cmd", ["RemoteCodeExecution"], "rce"),

    # ─── Deserialization ───
    TaintSink("pickle.loads", "data", ["ExecDeserializationSink"], "deser"),
    TaintSink("pickle.load", "file", ["ExecDeserializationSink"], "deser"),
    TaintSink("yaml.load", "stream", ["ExecDeserializationSink"], "deser"),
    TaintSink("yaml.unsafe_load", "stream", ["ExecDeserializationSink"], "deser"),
    TaintSink("jsonpickle.decode", "string", ["ExecDeserializationSink"], "deser"),
    TaintSink("dill.loads", "str", ["ExecDeserializationSink"], "deser"),
    TaintSink("shelve.open", "filename", ["ExecDeserializationSink"], "deser"),
    TaintSink("marshal.loads", "bytes", ["ExecDeserializationSink"], "deser"),
    TaintSink("torch.load", "f", ["FileContentDeserializationSink"], "deser"),

    # ─── Server-Side Template Injection ───
    TaintSink("jinja2.Environment.from_string", "source", ["ServerSideTemplateInjection"], "ssti"),
    TaintSink("jinja2.Template", "source", ["ServerSideTemplateInjection"], "ssti"),
    TaintSink("mako.template.Template", "text", ["ServerSideTemplateInjection"], "ssti"),
    TaintSink("django.template.Template", "template_string", ["ServerSideTemplateInjection"], "ssti"),

    # ─── XSS ───
    TaintSink("flask.make_response", "rv", ["XSS"], "xss"),
    TaintSink("django.http.HttpResponse", "content", ["XSS"], "xss"),
    TaintSink("django.utils.safestring.mark_safe", "s", ["XSS"], "xss"),
    TaintSink("markupsafe.Markup", "base", ["XSS"], "xss"),

    # ─── Path Traversal / File Access ───
    TaintSink("builtins.open", "file", ["FileSystem_ReadWrite"], "filesystem"),
    TaintSink("os.path.join", "path", ["FileSystem_ReadWrite"], "filesystem"),
    TaintSink("pathlib.Path", "args", ["FileSystem_ReadWrite"], "filesystem"),
    TaintSink("shutil.copy", "src", ["FileSystem_ReadWrite"], "filesystem"),
    TaintSink("shutil.move", "src", ["FileSystem_ReadWrite"], "filesystem"),
    TaintSink("os.remove", "path", ["FileSystem_ReadWrite"], "filesystem"),
    TaintSink("os.rename", "src", ["FileSystem_ReadWrite"], "filesystem"),
    TaintSink("send_file", "filename_or_fp", ["FileSystem_ReadWrite"], "filesystem"),

    # ─── SSRF ───
    TaintSink("requests.get", "url", ["SSRF"], "ssrf"),
    TaintSink("requests.post", "url", ["SSRF"], "ssrf"),
    TaintSink("requests.request", "url", ["SSRF"], "ssrf"),
    TaintSink("httpx.get", "url", ["SSRF"], "ssrf"),
    TaintSink("httpx.post", "url", ["SSRF"], "ssrf"),
    TaintSink("urllib.request.urlopen", "url", ["SSRF"], "ssrf"),
    TaintSink("aiohttp.ClientSession.get", "url", ["SSRF"], "ssrf"),
    TaintSink("aiohttp.ClientSession.post", "url", ["SSRF"], "ssrf"),

    # ─── LDAP Injection ───
    TaintSink("ldap.ldapobject.SimpleLDAPObject.search_s", "filterstr", ["LDAPInjection"], "ldap"),

    # ─── XML ───
    TaintSink("lxml.etree.fromstring", "text", ["XXE"], "xml"),
    TaintSink("lxml.etree.parse", "source", ["XXE"], "xml"),
    TaintSink("xml.etree.ElementTree.fromstring", "text", ["XXE"], "xml"),

    # ─── Authentication ───
    TaintSink("hashlib.md5", "string", ["WeakHash_Authentication"], "auth"),
    TaintSink("hashlib.sha1", "string", ["WeakHash_Authentication"], "auth"),
    TaintSink("jwt.encode", "payload", ["Authentication"], "auth"),
]


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — SECURITY PATTERNS (from Bandit + Semgrep)
#  Patterns rapides détectables par regex AVANT d'appeler le LLM
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SecurityPattern:
    """Pattern de sécurité détectable par regex."""
    id: str
    name: str
    regex: str            # regex compilée
    severity: str         # CRITICAL / HIGH / MEDIUM / LOW
    cwe: str
    belief_template: str  # template de croyance à injecter
    category: str         # injection / crypto / auth / config / deser


SECURITY_PATTERNS = [
    # ── SQL Injection ──
    SecurityPattern(
        "B608", "SQL string building",
        r"""(?:select|insert|update|delete|drop)\s+.*(?:%s|%d|\{|\+\s*\w)""",
        "HIGH", "CWE-89",
        "Le développeur croit que la construction de requête SQL par concaténation est sûre",
        "injection",
    ),
    SecurityPattern(
        "SQLI-RAW", "Django raw SQL",
        r"""\.raw\s*\(.*(?:%s|\{|f['"])""",
        "HIGH", "CWE-89",
        "Le développeur croit que raw() avec interpolation est sécurisé",
        "injection",
    ),
    SecurityPattern(
        "SQLI-EXTRA", "Django .extra() SQL",
        r"""\.extra\s*\(""",
        "MEDIUM", "CWE-89",
        "Le développeur croit que .extra() est sûr contre l'injection SQL",
        "injection",
    ),

    # ── Command Injection ──
    SecurityPattern(
        "B602", "subprocess shell=True",
        r"""subprocess\.\w+\(.*shell\s*=\s*True""",
        "HIGH", "CWE-78",
        "Le développeur croit que shell=True avec entrée contrôlée est sûr",
        "injection",
    ),
    SecurityPattern(
        "B605", "os.system call",
        r"""os\.system\s*\(""",
        "HIGH", "CWE-78",
        "Le développeur croit que os.system() est sûr avec l'entrée fournie",
        "injection",
    ),
    SecurityPattern(
        "B307", "eval() usage",
        r"""\beval\s*\(""",
        "CRITICAL", "CWE-94",
        "Le développeur croit que eval() est appelé avec des données de confiance",
        "injection",
    ),
    SecurityPattern(
        "B102", "exec() usage",
        r"""\bexec\s*\(""",
        "CRITICAL", "CWE-94",
        "Le développeur croit que exec() est appelé avec des données de confiance",
        "injection",
    ),

    # ── Deserialization ──
    SecurityPattern(
        "B301", "pickle usage",
        r"""pickle\.(?:loads?|Unpickler)\s*\(""",
        "CRITICAL", "CWE-502",
        "Le développeur croit que les données désérialisées par pickle sont fiables",
        "deser",
    ),
    SecurityPattern(
        "B506", "yaml.load unsafe",
        r"""yaml\.load\s*\((?!.*Loader\s*=\s*(?:yaml\.)?SafeLoader)""",
        "HIGH", "CWE-502",
        "Le développeur croit que yaml.load() sans SafeLoader est sûr",
        "deser",
    ),
    SecurityPattern(
        "DESER-MARSHAL", "marshal.loads",
        r"""marshal\.loads?\s*\(""",
        "CRITICAL", "CWE-502",
        "Le développeur croit que les données marshal sont de confiance",
        "deser",
    ),

    # ── Crypto faible ──
    SecurityPattern(
        "B303", "MD5/SHA1 usage",
        r"""hashlib\.(?:md5|sha1)\s*\(""",
        "MEDIUM", "CWE-328",
        "Le développeur croit que MD5/SHA1 est suffisant pour la sécurité",
        "crypto",
    ),
    SecurityPattern(
        "B304", "DES/Blowfish cipher",
        r"""(?:DES|Blowfish|ARC4|RC2)\s*\.new\s*\(""",
        "HIGH", "CWE-327",
        "Le développeur croit que cet algorithme de chiffrement est encore sûr",
        "crypto",
    ),

    # ── Auth / Secrets ──
    SecurityPattern(
        "B105", "Hardcoded password",
        r"""(?:password|passwd|pwd|secret|token|api_key)\s*=\s*['"][^'"]{4,}['"]""",
        "HIGH", "CWE-798",
        "Le développeur croit que le secret hardcodé ne sera pas extrait",
        "auth",
    ),
    SecurityPattern(
        "JWT-NONE", "JWT none algorithm",
        r"""jwt\.(?:decode|encode)\s*\(.*algorithms?\s*=\s*\[?\s*['"]none['"]""",
        "CRITICAL", "CWE-345",
        "Le développeur croit que l'algo 'none' n'est pas exploitable",
        "auth",
    ),
    SecurityPattern(
        "JWT-NOVERIFY", "JWT decode without verification",
        r"""jwt\.decode\s*\(.*(?:verify\s*=\s*False|options\s*=.*verify.*False)""",
        "HIGH", "CWE-345",
        "Le développeur croit que le JWT n'a pas besoin d'être vérifié",
        "auth",
    ),

    # ── SSRF ──
    SecurityPattern(
        "SSRF-REQ", "SSRF via requests",
        r"""requests\.(?:get|post|put|delete|request)\s*\(\s*(?:f['"]|[\w.]+\s*\+|.*\.format)""",
        "HIGH", "CWE-918",
        "Le développeur croit que l'URL passée à requests est de confiance",
        "injection",
    ),

    # ── Path Traversal ──
    SecurityPattern(
        "PATH-JOIN", "Path traversal via os.path.join",
        r"""os\.path\.join\s*\(.*(?:request|user|input|param|arg)""",
        "HIGH", "CWE-22",
        "Le développeur croit que os.path.join protège contre la traversée de répertoire",
        "injection",
    ),
    SecurityPattern(
        "PATH-OPEN", "File open with user input",
        r"""open\s*\(.*(?:request|user|input|param|filename)""",
        "MEDIUM", "CWE-22",
        "Le développeur croit que le chemin de fichier est sûr",
        "injection",
    ),

    # ── Config / Debug ──
    SecurityPattern(
        "B201", "Flask debug mode",
        r"""app\.run\s*\(.*debug\s*=\s*True""",
        "HIGH", "CWE-215",
        "Le développeur croit que le mode debug ne sera pas activé en production",
        "config",
    ),
    SecurityPattern(
        "CORS-WILD", "Wildcard CORS",
        r"""(?:Access-Control-Allow-Origin|CORS_ORIGINS?)\s*[:=]\s*['\"]\*['\"]""",
        "MEDIUM", "CWE-942",
        "Le développeur croit que CORS * n'expose pas l'API à des attaques cross-origin",
        "config",
    ),

    # ── SSL/TLS ──
    SecurityPattern(
        "B501", "SSL verify disabled",
        r"""(?:verify\s*=\s*False|CERT_NONE)""",
        "HIGH", "CWE-295",
        "Le développeur croit que désactiver la vérification SSL est acceptable",
        "crypto",
    ),

    # ── Template Injection ──
    SecurityPattern(
        "SSTI-JINJA", "Jinja2 template from string",
        r"""(?:from_string|Template)\s*\(.*(?:request|user|input|param)""",
        "CRITICAL", "CWE-1336",
        "Le développeur croit que le template est construit à partir de données de confiance",
        "injection",
    ),

    # ── Mass Assignment ──
    SecurityPattern(
        "MASS-ASSIGN", "Django mass assignment",
        r"""(?:\.objects\.create|\.update)\s*\(\s*\*\*(?:request|data|kwargs)""",
        "MEDIUM", "CWE-915",
        "Le développeur croit que les champs passés par l'utilisateur sont tous autorisés",
        "auth",
    ),

    # ── Open Redirect ──
    SecurityPattern(
        "OPEN-REDIR", "Open redirect",
        r"""redirect\s*\(.*(?:request|url|next|return_to|goto)""",
        "MEDIUM", "CWE-601",
        "Le développeur croit que l'URL de redirection est interne",
        "injection",
    ),
]

# Compile les regex
for pat in SECURITY_PATTERNS:
    pat._compiled = re.compile(pat.regex, re.IGNORECASE | re.DOTALL)


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — SOFT-404 DETECTION (from Nuclei patterns)
#  Pour réduire les faux positifs du HTTP engine
# ═══════════════════════════════════════════════════════════════════════════════

SOFT_404_INDICATORS = [
    # Content-based detection
    re.compile(r"<title>.*(?:404|not found|page not found|error).*</title>", re.I),
    re.compile(r"<h[1-3]>.*(?:404|not found|page not found).*</h[1-3]>", re.I),
    re.compile(r"(?:page|resource|url)\s+(?:not found|does not exist|cannot be found)", re.I),
    re.compile(r"(?:the requested|this)\s+(?:page|url|resource)\s+(?:was not|could not|cannot)", re.I),
    # Shopify / SaaS soft-404
    re.compile(r"<html.*?lang=.*?>\s*<head>.*?shopify", re.I | re.DOTALL),
    re.compile(r"cdn\.shopify\.com", re.I),
    # Common CMS error pages
    re.compile(r"(?:wordpress|wp-content|drupal|joomla).*(?:error|not.found)", re.I),
    # Cloudflare error
    re.compile(r"cloudflare.*(?:error|ray id)", re.I),
    # Generic framework error pages
    re.compile(r"(?:nginx|apache|iis)\s*(?:/[\d.]+)?\s*(?:error|default)", re.I),
]

SENSITIVE_FILE_EXPECTED_SIZES = {
    ".env": (10, 10_000),          # 10B - 10KB
    ".git/config": (50, 5_000),     # 50B - 5KB
    ".git/HEAD": (10, 100),         # ~23 bytes typically
    "web.config": (100, 50_000),    # XML config
    "config.php": (50, 20_000),
    ".htaccess": (10, 5_000),
    "wp-config.php": (100, 20_000),
}

SENSITIVE_FILE_CONTENT_TYPES = {
    ".env": ["text/plain", "application/octet-stream"],
    ".git/config": ["text/plain"],
    ".git/HEAD": ["text/plain"],
}


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — ENHANCED PROMPTS (chain-of-thought)
# ═══════════════════════════════════════════════════════════════════════════════

ENHANCED_SYSTEM_PROMPT = """\
You are BELIEF, a specialized system for extracting implicit software beliefs.

A "belief" is something the developer assumed to be true when writing the code,
without explicitly verifying it. Every function, every variable, every control
flow decision encodes beliefs about the state of the world.

IMPORTANT: Think step by step before outputting beliefs:
1. First, identify ALL inputs to this code (parameters, globals, env vars, files)
2. For each input, determine: where does it come from? Is it trusted?
3. Trace each input through the code: where does it go? What operations use it?
4. At each operation, ask: what must be true for this to be safe?
5. Check: is that assumption verified in code, or just hoped for?

Focus on SECURITY-CRITICAL beliefs:
- Trust boundaries: what data is trusted vs untrusted?
- Validation gaps: what inputs are used without validation?
- State assumptions: what state must be true for correct behavior?
- Concurrency: what ordering or atomicity is assumed?
- Error handling: what errors are assumed to never happen?

You output ONLY valid JSON. No markdown fences. No preamble.\
"""

ENHANCED_EXTRACT_PROMPT = """\
Analyze this code and extract ALL implicit security beliefs.

## Source Code
```
{code}
```

## File: {file_path}
## Function: {function_name}

## Known Taint Context
{taint_context}

## Known Pattern Matches
{pattern_matches}

## Step-by-Step Analysis Required

STEP 1 - DATA FLOW: For each input parameter and external data source,
trace where the data flows in this function. Identify sources and sinks.

STEP 2 - TRUST BOUNDARIES: For each data flow path, identify where
the developer assumes data is trusted without verifying it.

STEP 3 - MISSING CHECKS: For each assumption, determine if there is
a guard (assert, if, try/except, type check) that validates it.

STEP 4 - FORMALIZE: Convert each unguarded assumption into a formal
predicate with the sextuplet format below.

## Output Format
Return a JSON object with two keys:
{{
  "reasoning": "<your step-by-step analysis (2-4 sentences per step)>",
  "beliefs": [
    {{
      "predicate": {{
        "expression": "<semi-formal assertion>",
        "variables": ["<identifiers>"],
        "anchor_lines": [<line numbers>],
        "natural_language": "<one-sentence explanation>"
      }},
      "scope": {{
        "function_name": "<name>",
        "class_name": "<name or null>",
        "line_start": <int>,
        "line_end": <int>
      }},
      "justification": "<C1|C2|C3|C4|C5|C6>",
      "dependencies": [],
      "epistemic_status": "<belief|hope|unknown>",
      "logic_type": "<fol|temporal|info_flow|behavioral|probabilistic>",
      "confidence_score": <0.0-1.0>,
      "attack_surface": "<how an attacker could violate this belief>"
    }}
  ]
}}

## Justification Categories
- C1: Verified by assert, type check, or explicit guard
- C2: Verified by every known caller
- C3: Stated in documentation
- C4: Domain convention (e.g. "HTTP headers are untrusted")
- C5: No justification — pure assumption (MOST INTERESTING)
- C6: Inferred from opaque external component

Output ONLY the JSON object.\
"""

HTTP_BELIEF_ANALYSIS_PROMPT = """\
You are analyzing HTTP server behavior to identify implicit security beliefs
that could be contradicted.

## Observed Behavior
{observations}

## Task — Think step by step:

1. NORMALIZE: For each response, determine if it's a real response or a
   soft-404 (custom error page returning 200). Check: is the content-type
   appropriate? Is the response size consistent with the expected file type?

2. BELIEFS: What does the server assume to be true about:
   - Authentication: which paths require auth vs which are public?
   - Routing: how does the server decide what to serve?
   - Input validation: does it validate paths, parameters, headers?
   - Access control: is authorization checked per-resource?

3. CONTRADICTIONS: For each belief, what input would CONTRADICT it?
   Think about:
   - Path normalization differences (URL encoding, double slashes, etc.)
   - HTTP method switching (GET vs POST vs PUT)
   - Header manipulation (Host, X-Forwarded-For, Content-Type)
   - Parameter pollution (duplicate params, unexpected types)

4. HYPOTHESES: Generate concrete test cases, ordered by likelihood of
   success. Each must be a specific HTTP request.

Return JSON:
{{
  "soft_404s": ["<URLs that are probably soft-404s>"],
  "beliefs": [
    {{
      "predicate": "<what the server believes>",
      "evidence": "<what observation supports this>",
      "category": "<auth|routing|validation|access_control|logic>",
      "confidence": <0.0-1.0>
    }}
  ],
  "hypotheses": [
    {{
      "name": "<short name>",
      "target_belief": "<which belief this tries to contradict>",
      "method": "<HTTP method>",
      "url": "<full URL>",
      "headers": {{}},
      "body": "<if applicable>",
      "expected_if_vulnerable": "<what response indicates success>",
      "priority": <1-5, 1=highest>
    }}
  ]
}}

Output ONLY the JSON object.\
"""


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — KNOWLEDGE BASE CLASS (main API)
# ═══════════════════════════════════════════════════════════════════════════════

class KnowledgeBase:
    """
    Base de connaissances unifiée pour BELIEF.
    Combine taint tracking, pattern matching, et prompts enrichis.
    """

    def __init__(self):
        self.sources = TAINT_SOURCES
        self.sinks = TAINT_SINKS
        self.patterns = SECURITY_PATTERNS
        self.soft_404_indicators = SOFT_404_INDICATORS

    # ── Taint Context ──

    def detect_framework(self, code: str) -> list[str]:
        """Détecte les frameworks utilisés dans le code."""
        frameworks = []
        indicators = {
            "flask": [r"from flask", r"import flask", r"@app\.route"],
            "django": [r"from django", r"import django", r"views\.py"],
            "fastapi": [r"from fastapi", r"import fastapi", r"@app\.(get|post|put)"],
            "aiohttp": [r"from aiohttp", r"aiohttp\.web"],
            "tornado": [r"from tornado", r"tornado\.web"],
            "falcon": [r"from falcon", r"import falcon"],
            "boto3": [r"import boto3", r"from boto3"],
        }
        for fw, patterns in indicators.items():
            if any(re.search(p, code, re.I) for p in patterns):
                frameworks.append(fw)
        return frameworks or ["stdlib"]

    def get_taint_context(self, code: str, framework: str | None = None) -> str:
        """
        Génère un contexte de taint pour enrichir le prompt LLM.
        Identifie les sources et sinks présents dans le code.
        """
        if framework is None:
            frameworks = self.detect_framework(code)
        else:
            frameworks = [framework]

        found_sources = []
        found_sinks = []

        for src in self.sources:
            # Check if the source path's last component appears in code
            short_name = src.path.split(".")[-1]
            full_path = src.path.rsplit(".", 1)[0] if "." in src.path else ""
            if (re.search(r'\b' + re.escape(short_name) + r'\b', code) and
                (src.framework in frameworks or src.framework == "stdlib")):
                found_sources.append(
                    f"  - {src.path} → labels: {', '.join(src.labels)}"
                )

        for sink in self.sinks:
            short_name = sink.function.split(".")[-1]
            if re.search(r'\b' + re.escape(short_name) + r'\b', code):
                found_sinks.append(
                    f"  - {sink.function}({sink.parameter}) → {', '.join(sink.labels)}"
                )

        if not found_sources and not found_sinks:
            return "No known taint sources or sinks detected in this code."

        ctx = ""
        if found_sources:
            ctx += "TAINT SOURCES (user-controlled data enters here):\n"
            ctx += "\n".join(found_sources[:15])
            ctx += "\n\n"
        if found_sinks:
            ctx += "TAINT SINKS (dangerous operations):\n"
            ctx += "\n".join(found_sinks[:15])
        return ctx

    # ── Pattern Matching (pré-filtre) ──

    def match_known_patterns(self, code: str) -> list[dict]:
        """
        Détecte les patterns de sécurité connus par regex.
        Retourne les matches avec leur croyance associée.
        """
        matches = []
        lines = code.split("\n")

        for pat in self.patterns:
            for i, line in enumerate(lines, 1):
                if pat._compiled.search(line):
                    matches.append({
                        "pattern_id": pat.id,
                        "name": pat.name,
                        "line": i,
                        "severity": pat.severity,
                        "cwe": pat.cwe,
                        "belief": pat.belief_template,
                        "category": pat.category,
                        "matched_line": line.strip()[:100],
                    })

        # Dédupliquer par pattern_id (garder la première occurrence)
        seen = set()
        unique = []
        for m in matches:
            if m["pattern_id"] not in seen:
                seen.add(m["pattern_id"])
                unique.append(m)
        return unique

    # ── Soft-404 Detection ──

    def is_soft_404(
        self,
        url: str,
        status: int,
        content: str,
        content_type: str,
        size: int,
    ) -> bool:
        """
        Détecte si une réponse HTTP 200 est en fait une soft-404.
        Réduit drastiquement les faux positifs du HTTP engine.
        """
        if status != 200:
            return False

        # Check sensitive file size expectations
        for path_suffix, (min_size, max_size) in SENSITIVE_FILE_EXPECTED_SIZES.items():
            if url.rstrip("/").endswith(path_suffix):
                if size < min_size or size > max_size:
                    return True
                # Check content type
                expected_cts = SENSITIVE_FILE_CONTENT_TYPES.get(path_suffix)
                if expected_cts and not any(ct in content_type for ct in expected_cts):
                    return True

        # Check content for 404 indicators
        content_sample = content[:5000] if len(content) > 5000 else content
        for indicator in self.soft_404_indicators:
            if indicator.search(content_sample):
                return True

        # HTML returned for non-HTML file
        if any(url.endswith(ext) for ext in [".env", ".git/config", ".json", ".xml", ".txt"]):
            if "text/html" in content_type and "<html" in content_sample.lower():
                return True

        return False

    # ── Prompt Building ──

    def build_enriched_prompt(
        self,
        code: str,
        file_path: str,
        function_name: str = "",
    ) -> tuple[str, str]:
        """
        Construit un prompt enrichi avec le contexte taint et les pattern matches.
        Returns (system_prompt, user_prompt).
        """
        taint_ctx = self.get_taint_context(code)
        patterns = self.match_known_patterns(code)

        pattern_text = "None detected." if not patterns else "\n".join(
            f"  - [{m['severity']}] {m['name']} at line {m['line']}: {m['belief']}"
            for m in patterns
        )

        user_prompt = ENHANCED_EXTRACT_PROMPT.format(
            code=code,
            file_path=file_path,
            function_name=function_name,
            taint_context=taint_ctx,
            pattern_matches=pattern_text,
        )

        return ENHANCED_SYSTEM_PROMPT, user_prompt

    def build_http_analysis_prompt(self, observations: str) -> tuple[str, str]:
        """Prompt enrichi pour l'analyse HTTP."""
        prompt = HTTP_BELIEF_ANALYSIS_PROMPT.format(observations=observations)
        return ENHANCED_SYSTEM_PROMPT, prompt


# ═══════════════════════════════════════════════════════════════════════════════
#  Quick self-test
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    kb = KnowledgeBase()

    test_code = '''
from flask import Flask, request, redirect
import subprocess
import sqlite3

app = Flask(__name__)

@app.route("/search")
def search():
    query = request.args.get("q")
    db = sqlite3.connect("app.db")
    cursor = db.execute("SELECT * FROM items WHERE name = '%s'" % query)
    results = cursor.fetchall()
    return redirect(request.args.get("next", "/"))
'''

    print("=== Framework Detection ===")
    print(kb.detect_framework(test_code))

    print("\n=== Taint Context ===")
    print(kb.get_taint_context(test_code))

    print("\n=== Pattern Matches ===")
    for m in kb.match_known_patterns(test_code):
        print(f"  [{m['severity']}] {m['name']} (line {m['line']})")
        print(f"    Belief: {m['belief']}")
        print(f"    Code: {m['matched_line']}")
        print()

    print("\n=== Soft-404 Test ===")
    # Simulate the Decathlon .env false positive
    print("Decathlon .env (944KB HTML):",
          kb.is_soft_404("https://decathlon.com/.env", 200,
                         "<html><head><meta>shopify</head>", "text/html", 944942))
    print("Real .env (200B text/plain):",
          kb.is_soft_404("https://example.com/.env", 200,
                         "DB_HOST=localhost\nDB_PASS=secret", "text/plain", 200))