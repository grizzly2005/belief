"""
BELIEF — Semgrep Rules Database (auto-generated).

Contains 1364 security rules extracted from semgrep/semgrep-rules.
Each rule maps to a belief pattern with CWE classification.

Generated from: github.com/semgrep/semgrep-rules
"""

from __future__ import annotations


RULE_COUNT = 1364

# Indexed by CWE for fast lookup
RULES_BY_CWE: dict[str, list[dict]] = {}

# Indexed by language
RULES_BY_LANG: dict[str, list[dict]] = {}


def _build_indices():
    """Build lookup indices from embedded rules."""
    rules = _ALL_RULES
    for r in rules:
        cwe = r.get("cwe", "")
        lang = r.get("language", "unknown")
        if cwe:
            RULES_BY_CWE.setdefault(cwe, []).append(r)
        RULES_BY_LANG.setdefault(lang, []).append(r)


def get_rules_for_cwe(cwe: str) -> list[dict]:
    """Get all rules matching a CWE identifier."""
    if not RULES_BY_CWE:
        _build_indices()
    return RULES_BY_CWE.get(cwe, [])


def get_rules_for_language(language: str) -> list[dict]:
    """Get all security rules for a language."""
    if not RULES_BY_LANG:
        _build_indices()
    return RULES_BY_LANG.get(language, [])


def search_rules(query: str) -> list[dict]:
    """Search rules by keyword in ID or message."""
    if not RULES_BY_CWE:
        _build_indices()
    q = query.lower()
    return [r for r in _ALL_RULES if q in r.get("id", "").lower()
            or q in r.get("message", "").lower()]


def get_cwe_summary() -> dict[str, int]:
    """Get count of rules per CWE."""
    if not RULES_BY_CWE:
        _build_indices()
    return {cwe: len(rules) for cwe, rules in sorted(RULES_BY_CWE.items())}


def get_language_summary() -> dict[str, int]:
    """Get count of rules per language."""
    if not RULES_BY_LANG:
        _build_indices()
    return {lang: len(rules) for lang, rules in sorted(RULES_BY_LANG.items())}


_ALL_RULES = [
  {
    "id": "apex-csrf-constructor",
    "language": "apex",
    "severity": "ERROR",
    "cwe": "CWE-352",
    "message": "Having DML operations in Apex class constructor or initializers can have unexpected side effects: By just accessing a page, the DML statements would be executed and the database would be modified. Jus",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "apex-csrf-static-constructor",
    "language": "generic",
    "severity": "ERROR",
    "cwe": "CWE-352",
    "message": "Having DML operations in Apex class constructor or initializers can have unexpected side effects: By just accessing a page, the DML statements would be executed and the database would be modified. Jus",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dml-native-statements",
    "language": "apex",
    "severity": "WARNING",
    "cwe": "CWE-863",
    "message": "Native Salesforce DML operations execute in system context, ignoring the current user's permissions, field-level security, organization-wide defaults, position in the role hierarchy, and sharing rules",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A04:2021 - Insecure Design",
      "A01:2025 - Broken Access Control",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "bad-crypto",
    "language": "apex",
    "severity": "ERROR",
    "cwe": "CWE-321",
    "message": "The rule makes sure you are using randomly generated IVs and keys for Crypto calls. Hard-coding these values greatly compromises the security of encrypted data.",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-http-request",
    "language": "apex",
    "severity": "ERROR",
    "cwe": "CWE-319",
    "message": "The software transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "named-credentials-constant-match",
    "language": "apex",
    "severity": "ERROR",
    "cwe": "CWE-540",
    "message": "Named Credentials (and callout endpoints) should be used instead of hard-coding credentials. 1. Hard-coded credentials are hard to maintain when mixed in with application code. 2. It is particularly h",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "named-credentials-string-match",
    "language": "apex",
    "severity": "ERROR",
    "cwe": "CWE-540",
    "message": "Named Credentials (and callout endpoints) should be used instead of hard-coding credentials. 1. Hard-coded credentials are hard to maintain when mixed in with application code. 2. It is particularly h",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "soql-injection-unescaped-url-param",
    "language": "apex",
    "severity": "ERROR",
    "cwe": "CWE-943",
    "message": "If a dynamic query must be used,leverage nFORCE Query Builder. In other programming languages, the related flaw is known as SQL injection. Apex doesn't use SQL, but uses its own database query languag",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "soql-injection-unescaped-param",
    "language": "apex",
    "severity": "ERROR",
    "cwe": "CWE-943",
    "message": "If a dynamic query must be used,leverage nFORCE Query Builder. In other programming languages, the related flaw is known as SQL injection. Apex doesn't use SQL, but uses its own database query languag",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "specify-sharing-level",
    "language": "apex",
    "severity": "WARNING",
    "cwe": "CWE-284",
    "message": "Every Apex class should have an explicit sharing mode declared. Use the `with sharing` or `without sharing` keywords on a class to specify whether sharing rules must be enforced. Use the `inherited sh",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "system-debug",
    "language": "apex",
    "severity": "WARNING",
    "cwe": "CWE-489",
    "message": "In addition to debug statements potentially logging data excessively, debug statements also contribute to longer transactions and consume Apex CPU time even when debug logs are not being captured.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "curl-eval",
    "language": "bash",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Data is being eval'd from a `curl` command. An attacker with control of the server in the `curl` command could inject malicious code into the `eval`, resulting in a system comrpomise. Avoid eval'ing u",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "curl-pipe-bash",
    "language": "bash",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Data is being piped into `bash` from a `curl` command. An attacker with control of the server in the `curl` command could inject malicious code into the pipe, resulting in a system compromise. Avoid p",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ifs-tampering",
    "language": "bash",
    "severity": "WARNING",
    "cwe": "CWE-20",
    "message": "The special variable IFS affects how splitting takes place when expanding unquoted variables. Don't set it globally. Prefer a dedicated utility such as 'cut' or 'awk' if you need to split input data. ",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "double-free",
    "language": "c",
    "severity": "ERROR",
    "cwe": "CWE-415",
    "message": "Variable '$VAR' was freed twice. This can lead to undefined behavior.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A01:2017 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "function-use-after-free",
    "language": "c",
    "severity": "WARNING",
    "cwe": "CWE-416",
    "message": "Variable '$VAR' was passed to a function after being freed. This can lead to undefined behavior.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "info-leak-on-non-formated-string",
    "language": "c",
    "severity": "WARNING",
    "cwe": "CWE-532",
    "message": "Use %s, %d, %c... to format your variables, otherwise this could leak information.",
    "category": "security",
    "owasp": [
      "A09:2021 - Security Logging and Monitoring Failures",
      "A09:2025 - Security Logging & Alerting Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-use-gets-fn",
    "language": "c",
    "severity": "ERROR",
    "cwe": "CWE-676",
    "message": "Avoid 'gets()'. This function does not consider buffer boundaries and can lead to buffer overflows. Use 'fgets()' or 'gets_s()' instead.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-use-memset",
    "language": "c",
    "severity": "WARNING",
    "cwe": "CWE-14",
    "message": "When handling sensitive information in a buffer, it's important to ensure  that the data is securely erased before the buffer is deleted or reused.  While `memset()` is commonly used for this purpose,",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-use-printf-fn",
    "language": "c",
    "severity": "WARNING",
    "cwe": "CWE-134",
    "message": "Avoid using user-controlled format strings passed into 'sprintf', 'printf' and 'vsprintf'. These functions put you at risk of buffer overflow vulnerabilities through the use of format string exploits.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-use-scanf-fn",
    "language": "c",
    "severity": "WARNING",
    "cwe": "CWE-676",
    "message": "Avoid using 'scanf()'. This function, when used improperly, does not consider buffer boundaries and can lead to buffer overflows. Use 'fgets()' instead for reading input.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-use-strcat-fn",
    "language": "c",
    "severity": "WARNING",
    "cwe": "CWE-676",
    "message": "Finding triggers whenever there is a strcat or strncat used. This is an issue because strcat or strncat can lead to buffer overflow vulns. Fix this by using strcat_s instead.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-use-string-copy-fn",
    "language": "c",
    "severity": "WARNING",
    "cwe": "CWE-676",
    "message": "Finding triggers whenever there is a strcpy or strncpy used. This is an issue because strcpy does not affirm the size of the destination array and strncpy will not automatically NULL-terminate strings",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-use-strtok-fn",
    "language": "c",
    "severity": "WARNING",
    "cwe": "CWE-676",
    "message": "Avoid using 'strtok()'. This function directly modifies the first argument buffer, permanently erasing the delimiter character. Use 'strtok_r()' instead.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "random-fd-exhaustion",
    "language": "c",
    "severity": "WARNING",
    "cwe": "CWE-774",
    "message": "Call to 'read()' without error checking is susceptible to file descriptor exhaustion. Consider using the 'getrandom()' function.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "use-after-free",
    "language": "c",
    "severity": "WARNING",
    "cwe": "CWE-416",
    "message": "Variable '$VAR' was used after being freed. This can lead to undefined behavior.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "command-injection-shell-call",
    "language": "clojure",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "A call to clojure.java.shell has been found, this could lead to an RCE if the inputs are user-controllable. Please ensure their origin is validated and sanitized.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "documentbuilderfactory-xxe",
    "language": "clojure",
    "severity": "ERROR",
    "cwe": "CWE-611",
    "message": "DOCTYPE declarations are enabled for javax.xml.parsers.SAXParserFactory. Without prohibiting external entity declarations, this is vulnerable to XML external entity attacks. Disable this by setting th",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-of-md5",
    "language": "clojure",
    "severity": "WARNING",
    "cwe": "CWE-328",
    "message": "MD5 hash algorithm detected. This is not collision resistant and leads to easily-cracked password hashes. Replace with current recommended hashing algorithms.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-of-sha1",
    "language": "clojure",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Instead, use PBKDF2 for password hashing or SHA25",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "read-string-unsafe",
    "language": "clojure",
    "severity": "ERROR",
    "cwe": "CWE-502",
    "message": "The default core Clojure read-string method is dangerous and can lead to deserialization vulnerabilities. Use the edn/read-string instead.",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ldap-injection",
    "language": "csharp",
    "severity": "ERROR",
    "cwe": "CWE-90",
    "message": "LDAP queries are constructed dynamically on user-controlled input. This vulnerability in code could lead to an arbitrary LDAP query execution.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "mass-assignment",
    "language": "csharp",
    "severity": "WARNING",
    "cwe": "CWE-915",
    "message": "Mass assignment or Autobinding vulnerability in code allows an attacker to execute over-posting attacks, which could create a new parameter in the binding request and manipulate the underlying object ",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "misconfigured-lockout-option",
    "language": "csharp",
    "severity": "WARNING",
    "cwe": "CWE-307",
    "message": "A misconfigured lockout mechanism allows an attacker to execute brute-force attacks. Account lockout must be correctly configured and enabled to prevent these attacks.",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "missing-or-broken-authorization",
    "language": "csharp",
    "severity": "INFO",
    "cwe": "CWE-862",
    "message": "Anonymous access shouldn't be allowed unless explicit by design. Access control checks are missing and potentially can be bypassed. This finding violates the principle of least privilege or deny by de",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "open-directory-listing",
    "language": "csharp",
    "severity": "INFO",
    "cwe": "CWE-548",
    "message": "An open directory listing is potentially exposed, potentially revealing sensitive information to attackers.",
    "category": "security",
    "owasp": [
      "A06:2017 - Security Misconfiguration",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "razor-use-of-htmlstring",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-116",
    "message": "ASP.NET Core MVC provides an HtmlString class which isn't automatically encoded upon output. This should never be used in combination with untrusted input as this will expose an XSS vulnerability.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "xpath-injection",
    "language": "csharp",
    "severity": "ERROR",
    "cwe": "CWE-643",
    "message": "XPath queries are constructed dynamically on user-controlled input. This vulnerability in code could lead to an XPath Injection exploitation.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "mvc-missing-antiforgery",
    "language": "csharp",
    "severity": "WARNING",
    "cwe": "CWE-352",
    "message": "$METHOD is a state-changing MVC method that does not validate the antiforgery token or do strict content-type checking. State-changing controller methods should either enforce antiforgery tokens or do",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "net-webconfig-debug",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-11",
    "message": "ASP.NET applications built with `debug` set to true in production may leak debug information to attackers. Debug mode also affects performance and reliability. Set `debug` to `false` or remove it from",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "net-webconfig-trace-enabled",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-1323",
    "message": "OWASP guidance recommends disabling tracing for production applications to prevent accidental leakage of sensitive application information.",
    "category": "security",
    "owasp": "A05:2021 - Security Misconfiguration",
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "razor-template-injection",
    "language": "csharp",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "User-controllable string passed to Razor.Parse. This leads directly to code execution in the context of the process.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use_deprecated_cipher_algorithm",
    "language": "csharp",
    "severity": "ERROR",
    "cwe": "CWE-327",
    "message": "Usage of deprecated cipher algorithm detected. Use Aes or ChaCha20Poly1305 instead.",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use_ecb_mode",
    "language": "csharp",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Usage of the insecure ECB mode detected. You should use an authenticated encryption mode instead, which is implemented by the classes AesGcm or ChaCha20Poly1305.",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use_weak_rng_for_keygeneration",
    "language": "csharp",
    "severity": "ERROR",
    "cwe": "CWE-338",
    "message": "You are using an insecure random number generator (RNG) to create a cryptographic key. System.Random must never be used for cryptographic purposes. Use System.Security.Cryptography.RandomNumberGenerat",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use_weak_rsa_encryption_padding",
    "language": "csharp",
    "severity": "WARNING",
    "cwe": "CWE-780",
    "message": "You are using the outdated PKCS#1 v1.5 encryption padding for your RSA key. Use the OAEP padding instead.",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "web-config-insecure-cookie-settings",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-614",
    "message": "Cookie Secure flag is explicitly disabled. You should enforce this value to avoid accidentally presenting sensitive cookie values over plaintext HTTP connections.",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "jwt-tokenvalidationparameters-no-expiry-validation",
    "language": "csharp",
    "severity": "WARNING",
    "cwe": "CWE-613",
    "message": "The TokenValidationParameters.$LIFETIME is set to $FALSE, this means the JWT tokens lifetime is not validated. This can lead to an JWT token being used after it has expired, which has security implica",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "X509-subject-name-validation",
    "language": "csharp",
    "severity": "WARNING",
    "cwe": "CWE-295",
    "message": "Validating certificates based on subject name is bad practice. Use the X509Certificate2.Verify() method instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "X509Certificate2-privkey",
    "language": "C#",
    "severity": "WARNING",
    "cwe": "CWE-310",
    "message": "X509Certificate2.PrivateKey is obsolete. Use a method such as GetRSAPrivateKey() or GetECDsaPrivateKey(). Alternatively, use the CopyWithPrivateKey() method to create a new instance with a private key",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "unsigned-security-token",
    "language": "csharp",
    "severity": "ERROR",
    "cwe": "CWE-347",
    "message": "Accepting unsigned security tokens as valid security tokens allows an attacker to remove its signature and potentially forge an identity. As a fix, set RequireSignedTokens to be true.",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "unsafe-path-combine",
    "language": "csharp",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "String argument $A is used to read or write data from a file via Path.Combine without direct sanitization via Path.GetFileName. If the path is user-supplied data this can lead to path traversal.",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "http-listener-wildcard-bindings",
    "language": "C#",
    "severity": "WARNING",
    "cwe": "CWE-706",
    "message": "The top level wildcard bindings $PREFIX leaves your application open to security vulnerabilities and give attackers more control over where traffic is routed. If you must use wildcards, consider using",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "os-command-injection",
    "language": "csharp",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could mod",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-binaryformatter-deserialization",
    "language": "C#",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "The BinaryFormatter type is dangerous and is not recommended for data processing. Applications should stop using BinaryFormatter as soon as possible, even if they believe the data they're processing t",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "data-contract-resolver",
    "language": "C#",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "Only use DataContractResolver if you are completely sure of what information is being serialized. Malicious types can cause unexpected behavior.",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-fastjson-deserialization",
    "language": "C#",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "$type extension has the potential to be unsafe, so use it with common sense and known json sources and not public facing ones to be safe",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-fspickler-deserialization",
    "language": "C#",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "The FsPickler is dangerous and is not recommended for data processing. Default configuration tend to insecure deserialization vulnerability.",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-typefilterlevel-full",
    "language": "C#",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "Using a .NET remoting service can lead to RCE, even if you try to configure TypeFilterLevel. Recommended to switch from .NET Remoting to WCF https://docs.microsoft.com/en-us/dotnet/framework/wcf/migra",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-javascriptserializer-deserialization",
    "language": "C#",
    "severity": "ERROR",
    "cwe": "CWE-502",
    "message": "The SimpleTypeResolver class is insecure and should not be used. Using SimpleTypeResolver to deserialize JSON could allow the remote client to execute malicious code within the app and take control of",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-losformatter-deserialization",
    "language": "C#",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "The LosFormatter type is dangerous and is not recommended for data processing. Applications should stop using LosFormatter as soon as possible, even if they believe the data they're processing to be t",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-netdatacontract-deserialization",
    "language": "C#",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "The NetDataContractSerializer type is dangerous and is not recommended for data processing. Applications should stop using NetDataContractSerializer as soon as possible, even if they believe the data ",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-newtonsoft-deserialization",
    "language": "csharp",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "TypeNameHandling $TYPEHANDLER is unsafe and can lead to arbitrary code execution in the context of the process. Use a custom SerializationBinder whenever using a setting other than TypeNameHandling.No",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-soapformatter-deserialization",
    "language": "C#",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "The SoapFormatter type is dangerous and is not recommended for data processing. Applications should stop using SoapFormatter as soon as possible, even if they believe the data they're processing to be",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "memory-marshal-create-span",
    "language": "C#",
    "severity": "WARNING",
    "cwe": "CWE-125",
    "message": "MemoryMarshal.CreateSpan and MemoryMarshal.CreateReadOnlySpan should be used with caution, as the length argument is not checked.",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "missing-hsts-header",
    "language": "csharp",
    "severity": "WARNING",
    "cwe": "CWE-346",
    "message": "The HSTS HTTP response security header is missing, allowing interaction and communication to be sent over the insecure HTTP protocol.",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "open-redirect",
    "language": "csharp",
    "severity": "ERROR",
    "cwe": "CWE-601",
    "message": "A query string parameter may contain a URL value that could cause the web application to redirect the request to a malicious website controlled by an attacker. Make sure to sanitize this parameter suf",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "regular-expression-dos-infinite-timeout",
    "language": "C#",
    "severity": "WARNING",
    "cwe": "CWE-1333",
    "message": "Specifying the regex timeout leaves the system vulnerable to a regex-based Denial of Service (DoS) attack. Consider setting the timeout to a short amount of time like 2 or 3 seconds. If you are sure y",
    "category": "security",
    "owasp": "A01:2017 - Injection",
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "regular-expression-dos",
    "language": "C#",
    "severity": "WARNING",
    "cwe": "CWE-1333",
    "message": "When using `System.Text.RegularExpressions` to process untrusted input, pass a timeout.  A malicious user can provide input to `RegularExpressions` that abuses the backtracking behaviour of this regul",
    "category": "security",
    "owasp": "A01:2017 - Injection",
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "csharp-sqli",
    "language": "csharp",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements instead. You can obtain a Prepa",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ssrf",
    "language": "csharp",
    "severity": "ERROR",
    "cwe": "CWE-918",
    "message": "SSRF is an attack vector that abuses an application to interact with the internal/external network or the machine itself.",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ssrf",
    "language": "csharp",
    "severity": "ERROR",
    "cwe": "CWE-918",
    "message": "SSRF is an attack vector that abuses an application to interact with the internal/external network or the machine itself.",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ssrf",
    "language": "csharp",
    "severity": "ERROR",
    "cwe": "CWE-918",
    "message": "SSRF is an attack vector that abuses an application to interact with the internal/external network or the machine itself.",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ssrf",
    "language": "csharp",
    "severity": "ERROR",
    "cwe": "CWE-918",
    "message": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected d",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "stacktrace-disclosure",
    "language": "csharp",
    "severity": "WARNING",
    "cwe": "CWE-209",
    "message": "Stacktrace information is displayed in a non-Development environment. Accidentally disclosing sensitive stack trace information in a production environment aids an attacker in reconnaissance and infor",
    "category": "security",
    "owasp": [
      "A06:2017 - Security Misconfiguration",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "xmldocument-unsafe-parser-override",
    "language": "csharp",
    "severity": "WARNING",
    "cwe": "CWE-611",
    "message": "XmlReaderSettings found with DtdProcessing.Parse on an XmlReader handling a string argument from a public method. Enabling Document Type Definition (DTD) parsing may cause XML External Entity (XXE) in",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "xmlreadersettings-unsafe-parser-override",
    "language": "csharp",
    "severity": "WARNING",
    "cwe": "CWE-611",
    "message": "XmlReaderSettings found with DtdProcessing.Parse on an XmlReader handling a string argument from a public method. Enabling Document Type Definition (DTD) parsing may cause XML External Entity (XXE) in",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "xmltextreader-unsafe-defaults",
    "language": "csharp",
    "severity": "WARNING",
    "cwe": "CWE-611",
    "message": "XmlReaderSettings found with DtdProcessing.Parse on an XmlReader handling a string argument from a public method. Enabling Document Type Definition (DTD) parsing may cause XML External Entity (XXE) in",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "html-raw-json",
    "language": "generic",
    "severity": "ERROR",
    "cwe": "CWE-79",
    "message": "Unencoded JSON in HTML context is vulnerable to cross-site scripting, because `</script>` is not properly encoded.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dockerfile-pip-extra-index-url",
    "language": "dockerfile",
    "severity": "INFO",
    "cwe": "CWE-427",
    "message": "When `--extra-index-url` is used in a `pip install` command, this is usually meant to  install a package from a package index other than the public one.  However, if a package is added with the same n",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dockerfile-source-not-pinned",
    "language": "dockerfile",
    "severity": "INFO",
    "cwe": "",
    "message": "To ensure reproducible builds, pin Dockerfile `FROM` commands to a specific hash. You can find the hash by running `docker pull $IMAGE` and then  specify it with `$IMAGE:$VERSION@sha256:<hash goes her",
    "category": "best-practice",
    "owasp": [],
    "subcategory": []
  },
  {
    "id": "dockerfile-dockerd-socket-mount",
    "language": "dockerfile",
    "severity": "ERROR",
    "cwe": "CWE-862",
    "message": "The Dockerfile(image) mounts docker.sock to the container which may allow an attacker already inside of the container to escape container and execute arbitrary commands on the host machine.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "last-user-is-root",
    "language": "dockerfile",
    "severity": "ERROR",
    "cwe": "CWE-269",
    "message": "The last user in the container is 'root'. This is a security hazard because if an attacker gains control of the container they will have root access. Switch back to another user after running commands",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "missing-user-entrypoint",
    "language": "dockerfile",
    "severity": "ERROR",
    "cwe": "CWE-269",
    "message": "By not specifying a USER, a program in the container may run as 'root'. This is a security hazard. If an attacker can control a process running as root, they may have control over the container. Ensur",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "missing-user",
    "language": "dockerfile",
    "severity": "ERROR",
    "cwe": "CWE-250",
    "message": "By not specifying a USER, a program in the container may run as 'root'. This is a security hazard. If an attacker can control a process running as root, they may have control over the container. Ensur",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-sudo-in-dockerfile",
    "language": "dockerfile",
    "severity": "WARNING",
    "cwe": "CWE-250",
    "message": "Avoid using sudo in Dockerfiles. Running processes as a non-root user can help  reduce the potential impact of configuration errors and security vulnerabilities.",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "secret-in-build-arg",
    "language": "dockerfile",
    "severity": "WARNING",
    "cwe": "CWE-538",
    "message": "Docker build time arguments are not suited for secrets, because the argument values are saved with the image. Running `docker image history` on the image will show information on how the image was bui",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "secure-parameter-for-secrets",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-532",
    "message": "Mark sensitive parameters with the @secure() decorator. This avoids logging the value or displaying it in the Azure portal, Azure CLI, or Azure PowerShell.",
    "category": "security",
    "owasp": [
      "A09:2021 - Security Logging and Monitoring Failures",
      "A09:2025 - Security Logging & Alerting Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "changed-semgrepignore",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "",
    "message": "`$1` has been added to the .semgrepignore list of ignored paths. Someone from app-sec may want to audit these changes.",
    "category": "best-practice",
    "owasp": [],
    "subcategory": []
  },
  {
    "id": "bash_reverse_shell",
    "language": "generic",
    "severity": "ERROR",
    "cwe": "CWE-94",
    "message": "Semgrep found a bash reverse shell",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "build-gradle-password-hardcoded",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-798",
    "message": "A secret is hard-coded in the application. Secrets stored in source code, such as credentials, identifiers, and other types of sensitive data, can be leaked and used by internal or external malicious ",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "unquoted-attribute-var",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: \"{{ ex",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "var-in-href",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If usi",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "var-in-script-src",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a template variable used as the 'src' in a script tag. Although template variables are HTML escaped, HTML escaping does not always prevent malicious URLs from being injected and could results",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "var-in-script-tag",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a template variable used in a script tag. Although template variables are HTML escaped, HTML escaping does not always prevent cross-site scripting (XSS) attacks when used directly in JavaScri",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "alias-path-traversal",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "The alias in this location block is subject to a path traversal because the location path does not end in a path separator (e.g., '/'). To fix, add a path separator to the end of the path.",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dynamic-proxy-host",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-441",
    "message": "The host for this proxy URL is dynamically determined. This can be dangerous if the host can be injected by an attacker because it may forcibly alter destination of the proxy. Consider hardcoding acce",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dynamic-proxy-scheme",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-16",
    "message": "The protocol scheme for this proxy is dynamically determined. This can be dangerous if the scheme can be injected by an attacker because it may forcibly alter the connection scheme. Consider hardcodin",
    "category": "security",
    "owasp": [
      "A06:2017 - Security Misconfiguration",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "header-injection",
    "language": "generic",
    "severity": "ERROR",
    "cwe": "CWE-113",
    "message": "The $$VARIABLE path parameter is added as a header in the response. This could allow an attacker to inject a newline and add a new header into the response. This is called HTTP response splitting. To ",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "header-redefinition",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-16",
    "message": "The 'add_header' directive is called in a 'location' block after headers have been set at the server block. Calling 'add_header' in the location block will actually overwrite the headers defined in th",
    "category": "security",
    "owasp": [
      "A06:2017 - Security Misconfiguration",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-redirect",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Detected an insecure redirect in this nginx configuration. If no scheme is specified, nginx will forward the request with the incoming scheme. This could result in unencrypted communications. To fix t",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-ssl-version",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Detected use of an insecure SSL version. Secure SSL versions are TLSv1.2 and TLS1.3; older versions are known to be broken and are susceptible to attacks. Prefer use of TLSv1.2 or later.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "missing-internal",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-16",
    "message": "This location block contains a 'proxy_pass' directive but does not contain the 'internal' directive. The 'internal' directive restricts access to this location to internal requests. Without 'internal'",
    "category": "security",
    "owasp": [
      "A06:2017 - Security Misconfiguration",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "missing-ssl-version",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "This server configuration is missing the 'ssl_protocols' directive. By default, this server will use 'ssl_protocols TLSv1 TLSv1.1 TLSv1.2', and versions older than TLSv1.2 are known to be broken. Expl",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "possible-nginx-h2c-smuggling",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-444",
    "message": "Conditions for Nginx H2C smuggling identified. H2C smuggling allows upgrading HTTP/1.1 connections to lesser-known HTTP/2 over cleartext (h2c) connections which can allow a bypass of reverse proxy acc",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "request-host-used",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-290",
    "message": "'$http_host' and '$host' variables may contain a malicious value from attacker controlled 'Host' request header. Use an explicitly configured host value or a allow list for validation.",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-amazon-mws-auth-token",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Amazon MWS Auth Token detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-artifactory-password",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Artifactory token detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-artifactory-token",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Artifactory token detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-aws-access-key-id-value",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here. Instead, read this value from an environment variable or keep it in a separate, private file.",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-aws-account-id",
    "language": "generic",
    "severity": "INFO",
    "cwe": "CWE-798",
    "message": "AWS Account ID detected. While not considered sensitive information, it is important to use them and share them carefully. For that reason it would be preferrable avoiding to hardcoded it here. Instea",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-aws-appsync-graphql-key",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "AWS AppSync GraphQL Key detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-aws-secret-access-key",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "AWS Secret Access Key detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-aws-session-token",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "AWS Session Token detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-bcrypt-hash",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "bcrypt hash detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-codeclimate",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "CodeClimate detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-etc-shadow",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "linux shadow file detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-facebook-access-token",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Facebook Access Token detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-facebook-oauth",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Facebook OAuth detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-generic-api-key",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Generic API Key detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-generic-secret",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Generic Secret detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-github-token",
    "language": "generic",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "GitHub Token detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-google-api-key",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Google API Key Detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-google-cloud-api-key",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Google Cloud API Key detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-google-gcm-service-account",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Google (GCM) Service account detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-google-oauth-access-token",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Google OAuth Access Token detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-google-oauth-url",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Google OAuth url detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-heroku-api-key",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Heroku API Key detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-hockeyapp",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "HockeyApp detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-jwt-token",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-321",
    "message": "JWT token detected",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-kolide-api-key",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Kolide API Key detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-mailchimp-api-key",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "MailChimp API Key detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-mailgun-api-key",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Mailgun API Key detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-npm-registry-auth-token",
    "language": "generic",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "NPM registry authentication token detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-onfido-live-api-token",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Onfido live API Token detected",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-outlook-team",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Outlook Team detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-paypal-braintree-access-token",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "PayPal Braintree Access Token detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-pgp-private-key-block",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Something that looks like a PGP private key block is detected. This is a potential hardcoded secret that could be leaked if this code is committed. Instead, remove this code block from the commit.",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-picatic-api-key",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Picatic API Key detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-private-key",
    "language": "generic",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Private Key detected. This is a sensitive credential and should not be hardcoded here. Instead, store this in a separate, private file.",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-sauce-token",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Sauce Token detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-sendgrid-api-key",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "SendGrid API Key detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-slack-token",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Slack Token detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-slack-webhook",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Slack Webhook detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-snyk-api-key",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Snyk API Key detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-softlayer-api-key",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "SoftLayer API Key detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-sonarqube-docs-api-key",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "SonarQube Docs API Key detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-square-access-token",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Square Access Token detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-square-oauth-secret",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Square OAuth Secret detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-ssh-password",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "SSH Password detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-stripe-api-key",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Stripe API Key detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-stripe-restricted-api-key",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Stripe Restricted API Key detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-telegram-bot-api-key",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Telegram Bot API Key detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-twilio-api-key",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Twilio API Key detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detected-username-and-password-in-uri",
    "language": "generic",
    "severity": "ERROR",
    "cwe": "CWE-798",
    "message": "Username and password in URI detected",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "google-maps-apikeyleak",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-538",
    "message": "Detects potential Google Maps API keys in code",
    "category": "security",
    "owasp": [
      "A3:2017 Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "use-SRI-for-CDNs",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-346",
    "message": "Consuming CDNs without including a SubResource Integrity (SRI) can expose your application and its users to compromised code. SRIs allow you to consume specific versions of content where if even a sin",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "xss-from-unescaped-url-param",
    "language": "generic",
    "severity": "ERROR",
    "cwe": "CWE-79",
    "message": "To remediate this issue, ensure that all URL parameters are properly escaped before including them in scripts. Please update your code to use either the JSENCODE method to escape URL parameters or the",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "csp-header-attribute",
    "language": "generic",
    "severity": "INFO",
    "cwe": "CWE-79",
    "message": "Visualforce Pages must have the cspHeader attribute set to true. This attribute is available in API version 55 or higher.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "visualforce-page-api-version",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Visualforce Pages must use API version 55 or higher for required use of the cspHeader attribute set to true.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "database-sqli",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parame",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-sql-string",
    "language": "go",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injectio",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "handler-assignment-from-multiple-sources",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-289",
    "message": "Variable $VAR is assigned from two different sources: '$Y' and '$R'. Make sure this is intended, as this could cause logic bugs if they are treated as they are the same object.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "session-cookie-missing-httponly",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-1004",
    "message": "A session cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie which mitigates XSS attac",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "session-cookie-missing-secure",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-614",
    "message": "A session cookie was detected without setting the 'Secure' flag. The 'secure' flag for cookies prevents the client from transmitting the cookie over insecure channels such as HTTP. Set the 'Secure' fl",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "session-cookie-samesitenone",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-1275",
    "message": "Found SameSiteNoneMode setting in Gorilla session options. Consider setting SameSite to Lax, Strict or Default for enhanced security.",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "websocket-missing-origin-check",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-352",
    "message": "The Origin header in the HTTP WebSocket handshake is used to guarantee that the connection accepted by the WebSocket is from a trusted origin domain. Failure to enforce can lead to Cross Site Request ",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gorm-dangerous-method-usage",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected usage of dangerous method $METHOD which does not escape inputs (see link in references). If the argument is user-controlled, this can lead to SQL injection. When using $METHOD function, do no",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "grpc-client-insecure-connection",
    "language": "go",
    "severity": "ERROR",
    "cwe": "CWE-300",
    "message": "Found an insecure gRPC connection using 'grpc.WithInsecure()'. This creates a connection without encryption to a gRPC server. A malicious attacker could tamper with the gRPC message, which could compr",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "grpc-server-insecure-connection",
    "language": "go",
    "severity": "ERROR",
    "cwe": "CWE-300",
    "message": "Found an insecure gRPC server without 'grpc.Creds()' or options with credentials. This allows for a connection without encryption to this server. A malicious attacker could tamper with the gRPC messag",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "jwt-go-parse-unverified",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-345",
    "message": "Detected the decoding of a JWT token without a verify step. Don't use `ParseUnverified` unless you know what you're doing This method parses the token but doesn't validate the signature. It's only eve",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "jwt-go-none-algorithm",
    "language": "go",
    "severity": "ERROR",
    "cwe": "CWE-327",
    "message": "Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that wil",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "hardcoded-jwt-key",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-798",
    "message": "A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It i",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-module-used",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "The package `net/http/cgi` is on the import blocklist.  The package is vulnerable to httpoxy attacks (CVE-2015-5386). It is recommended to use `net/http` or a web framework to build a web application ",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-ssh-insecure-ignore-host-key",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-322",
    "message": "Disabled host key verification detected. This allows man-in-the-middle attacks. Use the 'golang.org/x/crypto/ssh/knownhosts' package to do host key verification. See https://skarlso.github.io/2019/02/",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "math-random-used",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-338",
    "message": "Do not use `math/rand`. Use `crypto/rand` instead.",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "missing-ssl-minversion",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "`MinVersion` is missing from this TLS configuration.  By default, as of Go 1.22, TLS 1.2 is currently used as the minimum. General purpose web applications should default to TLS 1.3 with all other pro",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "sha224-hash",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-328",
    "message": "This code uses a 224-bit hash function, which is deprecated or disallowed in some security policies. Consider updating to a stronger hash function such as SHA-384 or higher to ensure compliance and se",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "ssl-v3-is-insecure",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "SSLv3 is insecure because it has known vulnerabilities. Starting with go1.14, SSLv3 will be removed. Instead, use 'tls.VersionTLS13'.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tls-with-insecure-cipher",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Detected an insecure CipherSuite via the 'tls' module. This suite is considered weak. Use the function 'tls.CipherSuites()' to get a list of good cipher suites. See https://golang.org/pkg/crypto/tls/#",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-of-md5",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-328",
    "message": "Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-of-sha1",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-328",
    "message": "Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-of-DES",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Detected DES cipher algorithm which is insecure. The algorithm is considered weak and has been deprecated. Use AES instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-of-rc4",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Detected RC4 cipher algorithm which is insecure. The algorithm has many known vulnerabilities. Use AES instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-of-weak-rsa-key",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "RSA keys should be at least 2048 bits",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-command-write",
    "language": "go",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected non-static command inside Write. Audit the input to '$CW.Write'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malic",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-exec-cmd",
    "language": "go",
    "severity": "ERROR",
    "cwe": "CWE-94",
    "message": "Detected non-static command inside exec.Cmd. Audit the input to 'exec.Cmd'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a mal",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-exec-command",
    "language": "go",
    "severity": "ERROR",
    "cwe": "CWE-94",
    "message": "Detected non-static command inside Command. Audit the input to 'exec.Command'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a ",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-syscall-exec",
    "language": "go",
    "severity": "ERROR",
    "cwe": "CWE-94",
    "message": "Detected non-static command inside Exec. Audit the input to 'syscall.Exec'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a mal",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "string-formatted-query",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "String-formatted SQL query detected. This could lead to SQL injection if the string is not sanitized properly. Audit this call to ensure the SQL is not manipulable by external data.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "md5-used-as-password",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function ",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "avoid-bind-to-all-interfaces",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-200",
    "message": "Detected a network listener listening on 0.0.0.0 or an empty string. This could unexpectedly expose the server publicly as it binds to all available interfaces. Instead, specify another IP address tha",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "cookie-missing-httponly",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-1004",
    "message": "A session cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie which mitigates XSS attac",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "cookie-missing-secure",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-614",
    "message": "A session cookie was detected without setting the 'Secure' flag. The 'secure' flag for cookies prevents the client from transmitting the cookie over insecure channels such as HTTP. Set the 'Secure' fl",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dynamic-httptrace-clienttrace",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-913",
    "message": "Detected a potentially dynamic ClientTrace. This occurred because semgrep could not find a static definition for '$TRACE'. Dynamic ClientTraces are dangerous because they deserialize function code to ",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "formatted-template-string",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Found a formatted template string passed to 'template.HTML()'. 'template.HTML()' does not escape contents. Be absolutely sure there is no user-controlled data in this template. If user data can reach ",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "fs-directory-listing",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-548",
    "message": "Detected usage of 'http.FileServer' as handler: this allows directory listing and an attacker could navigate through directories looking for sensitive files. Be sure to disable directory listing or re",
    "category": "security",
    "owasp": [
      "A06:2017 - Security Misconfiguration",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pprof-debug-exposure",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-489",
    "message": "The profiling 'pprof' endpoint is automatically exposed on /debug/pprof. This could leak information about the server. Instead, use `import \"net/http/pprof\"`. See https://www.farsightsecurity.com/blog",
    "category": "security",
    "owasp": "A06:2017 - Security Misconfiguration",
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "unescaped-data-in-htmlattr",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Found a formatted template string passed to 'template. HTMLAttr()'. 'template.HTMLAttr()' does not escape contents. Be absolutely sure there is no user-controlled data in this template or validate and",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "unescaped-data-in-js",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Found a formatted template string passed to 'template.JS()'. 'template.JS()' does not escape contents. Be absolutely sure there is no user-controlled data in this template.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "unescaped-data-in-url",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Found a formatted template string passed to 'template.URL()'. 'template.URL()' does not escape contents, and this could result in XSS (cross-site scripting) and therefore confidential data being stole",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "use-tls",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Found an HTTP server without TLS. Use 'http.ListenAndServeTLS' instead. See https://golang.org/pkg/net/http/#ListenAndServeTLS for more information.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "wip-xss-using-responsewriter-and-printf",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Found data going from url query parameters into formatted data written to ResponseWriter. This could be XSS and should not be done. If you must do this, ensure your data is sanitized or escaped.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "reflect-makefunc",
    "language": "go",
    "severity": "ERROR",
    "cwe": "CWE-913",
    "message": "'reflect.MakeFunc' detected. This will sidestep protections that are normally afforded by Go's type system. Audit this call and be sure that user input cannot be used to affect the code generated by M",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gosql-sqli",
    "language": "go",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Detected string concatenation with a non-literal variable in a \"database/sql\" Go SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pg-orm-sqli",
    "language": "go",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Detected string concatenation with a non-literal variable in a go-pg ORM SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prev",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pg-sqli",
    "language": "go",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Detected string concatenation with a non-literal variable in a go-pg SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent ",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pgx-sqli",
    "language": "go",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Detected string concatenation with a non-literal variable in a pgx Go SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "unsafe-reflect-by-name",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-470",
    "message": "If an attacker can supply values that the application then uses to determine which method or field to invoke, the potential exists for the attacker to create control flow paths through the application",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "use-of-unsafe-block",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-242",
    "message": "Using the unsafe package in Go gives you low-level memory management and many of the strengths of the C language, but also steps around the type safety of Go and can lead to buffer overflows and possi",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "import-text-template",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "When working with web applications that involve rendering user-generated  content, it's important to properly escape any HTML content to prevent  Cross-Site Scripting (XSS) attacks. In Go, the `text/t",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-direct-write-to-responsewriter",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected directly writing or similar in 'http.ResponseWriter.write()'. This bypasses HTML escaping that prevents cross-site scripting vulnerabilities. Instead, use the 'html/template' package and rend",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-fprintf-to-responsewriter",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected 'Fprintf' or similar writing to 'http.ResponseWriter'. This bypasses HTML escaping that prevents cross-site scripting vulnerabilities. Instead, use the 'html/template' package to render data ",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-interpolation-in-tag",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected template variable interpolation in an HTML tag. This is potentially vulnerable to cross-site scripting (XSS) attacks because a malicious actor has control over HTML but without the need to us",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-interpolation-js-template-string",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected template variable interpolation in a JavaScript template string. This is potentially vulnerable to cross-site scripting (XSS) attacks because a malicious actor has control over JavaScript but",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-io-writestring-to-responsewriter",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected 'io.WriteString()' writing directly to 'http.ResponseWriter'. This bypasses HTML escaping that prevents cross-site scripting vulnerabilities. Instead, use the 'html/template' package to rende",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-printf-in-responsewriter",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected 'printf' or similar in 'http.ResponseWriter.write()'. This bypasses HTML escaping that prevents cross-site scripting vulnerabilities. Instead, use the 'html/template' package to render data t",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "unsafe-template-type",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Semgrep could not determine that the argument to 'template.HTML()' is a constant. 'template.HTML()' and similar does not escape contents. Be absolutely sure there is no user-controlled data in this te",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "parsing-external-entities-enabled",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-611",
    "message": "Detected enabling of \"XMLParseNoEnt\", which allows parsing of external entities and can lead to XXE if user controlled data is parsed by the library. Instead, do not enable \"XMLParseNoEnt\" or be sure ",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "bad-tmp-file-creation",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-377",
    "message": "File creation in shared tmp directory without using `io.CreateTemp`.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "potential-dos-via-decompression-bomb",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-400",
    "message": "Detected a possible denial-of-service via a zip bomb attack. By limiting the max bytes read, you can mitigate this attack. `io.CopyN()` can specify a size. ",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "go-unsafe-deserialization-interface",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "Deserializing into `interface{}` allows arbitrary data structures and types, which can lead to security vulnerabilities (CWE-502). Use a concrete struct type instead.",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "filepath-clean-misuse",
    "language": "go",
    "severity": "ERROR",
    "cwe": "CWE-22",
    "message": "`Clean` is not intended to sanitize against path traversal attacks. This function is for finding the shortest path name equivalent to the given input. Using `Clean` to sanitize file reads may expose t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "open-redirect",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-601",
    "message": "An HTTP redirect was found to be crafted from user-input `$REQUEST`. This can lead to open redirect vulnerabilities, potentially allowing attackers to redirect users to malicious web sites. It is reco",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "raw-html-format",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-sql-string",
    "language": "go",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "User data flows into this manually-constructed SQL string. User data can be safely inserted into SQL strings using prepared statements or an object-relational mapper (ORM). Manually-constructed SQL st",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-url-host",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "A request was found to be crafted from user-input `$REQUEST`. This can lead to Server-Side Request Forgery (SSRF) vulnerabilities, potentially exposing sensitive data. It is recommend where possible t",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "reverseproxy-director",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-115",
    "message": "ReverseProxy can remove headers added by Director. Consider using ReverseProxy.Rewrite instead of ReverseProxy.Director.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "shared-url-struct-mutation",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-436",
    "message": "Shared URL struct may have been accidentally mutated. Ensure that this behavior is intended.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "path-traversal-inside-zip-extraction",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "File traversal when extracting zip archive",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-execution",
    "language": "go",
    "severity": "ERROR",
    "cwe": "CWE-94",
    "message": "Detected non-static script inside otto VM. Audit the input to 'VM.Run'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicio",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "go-insecure-templates",
    "language": "go",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "usage of insecure template types. They are documented as a security risk. See https://golang.org/pkg/html/template/#HTML.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "go-ssti",
    "language": "go",
    "severity": "ERROR",
    "cwe": "CWE-1336",
    "message": "A server-side template injection occurs when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side. When using \"html/templ",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "eval-detected",
    "language": "html",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected the use of eval(...). This can introduce  a Cross-Site-Scripting (XSS) vulnerability if this  comes from user-provided input. Follow OWASP best  practices to ensure you handle XSS within a Ja",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-document-method",
    "language": "html",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected the use of an inner/outerHTML assignment.  This can introduce a Cross-Site-Scripting (XSS) vulnerability if this  comes from user-provided input. If you have to use a dangerous web API,  cons",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "missing-integrity",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-353",
    "message": "This tag is missing an 'integrity' subresource integrity attribute. The 'integrity' attribute allows for the browser to verify that externally hosted files (for example from a CDN) are delivered witho",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "plaintext-http-link",
    "language": "html",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "This link points to a plaintext HTTP URL. Prefer an encrypted HTTPS URL if possible.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "manifest-usesCleartextTraffic-true",
    "language": "generic",
    "severity": "INFO",
    "cwe": "",
    "message": "The Android manifest is configured to allow non-encrypted connections. Evaluate if this is necessary for your app, and disable it if appropriate. This flag is ignored on Android 7 (API 24) and above i",
    "category": "best-practice",
    "owasp": [],
    "subcategory": []
  },
  {
    "id": "manifest-usesCleartextTraffic-ignored-by-nsc",
    "language": "generic",
    "severity": "INFO",
    "cwe": "",
    "message": "Manifest uses both `android:usesCleartextTraffic` and Network Security Config. The `usesCleartextTraffic` directive is ignored on Android 7 (API 24) and above if a Network Security Config is present.",
    "category": "best-practice",
    "owasp": [],
    "subcategory": []
  },
  {
    "id": "exported_activity",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-926",
    "message": "The application exports an activity. Any application on the device can launch the exported activity which may compromise the integrity of your application or its data.  Ensure that any exported activi",
    "category": "security",
    "owasp": [
      "A5:2021 Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-sql-string",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injectio",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-sqli",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use parameterized SQL queries or properly sani",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "java-jwt-decode-without-verify",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-345",
    "message": "Detected the decoding of a JWT token without a verify step. JWT tokens must be verified before use, otherwise the token's integrity is unknown. This means a malicious actor could forge a JWT token wit",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "java-jwt-hardcoded-secret",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-798",
    "message": "A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It i",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "java-jwt-none-alg",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-327",
    "message": "Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that wil",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-resteasy-deserialization",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "When a Restful webservice endpoint is configured to use wildcard mediaType {*/*} as a value for the @Consumes annotation, an attacker could abuse the SerializableProvider by sending a HTTP Request wit",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "default-resteasy-provider-abuse",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "When a Restful webservice endpoint isn't configured with a @Consumes annotation, an attacker could abuse the SerializableProvider by sending a HTTP Request with a Content-Type of application/x-java-se",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "jax-rs-path-traversal",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled var",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "seam-log-injection",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-95",
    "message": "Seam Logging API support an expression language to introduce bean property to log messages. The expression language can also be the source to unwanted code execution. In this context, an expression is",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "find-sql-string-concatenation",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "In $METHOD, $X is used to construct a SQL query via string concatenation.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "jjwt-none-alg",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-327",
    "message": "Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that wil",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "anonymous-ldap-bind",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-287",
    "message": "Detected anonymous LDAP bind. This permits anonymous users to execute LDAP statements. Consider enforcing authentication for LDAP. See https://docs.oracle.com/javase/tutorial/jndi/ldap/auth_mechs.html",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "bad-hexa-conversion",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-704",
    "message": "'Integer.toHexString()' strips leading zeroes from each byte if read byte-by-byte. This mistake weakens the hash value computed since it introduces more collisions. Use 'String.format(\"%02X\", ...)' in",
    "category": "security",
    "owasp": "A03:2017 - Sensitive Data Exposure",
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "blowfish-insufficient-key-size",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Using less than 128 bits for Blowfish is considered insecure. Use 128 bits or more, or switch to use AES instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "cbc-padding-oracle",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Using CBC with PKCS5Padding is susceptible to padding oracle attacks. A malicious actor could discern the difference between plaintext with valid or invalid padding. Further, CBC mode does not include",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "command-injection-formatted-runtime-call",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "A formatted or concatenated string was detected as input to a java.lang.Runtime call. This is dangerous if a variable is controlled by user input and could result in a command injection. Ensure your v",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "command-injection-process-builder",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "A formatted or concatenated string was detected as input to a ProcessBuilder call. This is dangerous if a variable is controlled by user input and could result in a command injection. Ensure your vari",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "cookie-missing-httponly",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-1004",
    "message": "A cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie. Set the 'HttpOnly' flag by calli",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "cookie-missing-secure-flag",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-614",
    "message": "A cookie was detected without setting the 'secure' flag. The 'secure' flag for cookies prevents the client from transmitting the cookie over insecure channels such as HTTP. Set the 'secure' flag by ca",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "crlf-injection-logs",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-93",
    "message": "When data from an untrusted source is put into a logger and not neutralized correctly, an attacker could forge log entries or include malicious content.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "des-is-deprecated",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "DES is considered deprecated. AES is the recommended cipher. Upgrade to use AES. See https://www.nist.gov/news-events/news/2005/06/nist-withdraws-outdated-data-encryption-standard for more information",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "desede-is-deprecated",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Triple DES (3DES or DESede) is considered deprecated. AES is the recommended cipher. Upgrade to use AES.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "ecb-cipher",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Cipher in ECB mode is detected. ECB mode produces the same output for the same input each time which allows an attacker to intercept and replay the data. Further, ECB mode does not provide any integri",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "gcm-detection",
    "language": "java",
    "severity": "INFO",
    "cwe": "CWE-323",
    "message": "GCM detected, please check that IV/nonce is not reused, an Initialization Vector (IV) is a nonce used to randomize the encryption, so that even if multiple messages with identical plaintext are encryp",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcm-nonce-reuse",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-323",
    "message": "GCM IV/nonce is reused: encryption can be totally useless",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "no-null-cipher",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "NullCipher was detected. This will not encrypt anything; the cipher text will be the same as the plain text. Use a valid, secure cipher: Cipher.getInstance(\"AES/CBC/PKCS7PADDING\"). See https://owasp.o",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "no-static-initialization-vector",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-329",
    "message": "Initialization Vectors (IVs) for block ciphers should be randomly generated each time they are used. Using a static IV means the same plaintext encrypts to the same ciphertext every time, weakening th",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "rsa-no-padding",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Using RSA without OAEP mode weakens the encryption.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "avoid-implementing-custom-digests",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Cryptographic algorithms are notoriously difficult to get right. By implementing a custom message digest, you risk introducing security issues into your program. Use one of the many sound message dige",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "defaulthttpclient-is-deprecated",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "DefaultHttpClient is deprecated. Further, it does not support connections using TLS1.2, which makes using DefaultHttpClient a security hazard. Use HttpClientBuilder instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-hostname-verifier",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-295",
    "message": "Insecure HostnameVerifier implementation detected. This will accept any SSL certificate with any hostname, which creates the possibility for man-in-the-middle attacks.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-trust-manager",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-295",
    "message": "Detected empty trust manager implementations. This is dangerous because it accepts any certificate, enabling man-in-the-middle attacks. Consider using a KeyStore and TrustManagerFactory instead. See h",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "unencrypted-socket",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Detected use of a Java socket that is not encrypted. As a result, the traffic could be read by an attacker intercepting the network traffic. Use an SSLSocket created by 'SSLSocketFactory' or 'SSLServe",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-of-aes-ecb",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Use of AES with ECB mode detected. ECB doesn't provide message confidentiality and  is not semantically secure so should not be used. Instead, use a strong, secure cipher: Cipher.getInstance(\"AES/CBC/",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-of-blowfish",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Use of Blowfish was detected. Blowfish uses a 64-bit block size that  makes it vulnerable to birthday attacks, and is therefore considered non-compliant.  Instead, use a strong, secure cipher: Cipher.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-of-default-aes",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Use of AES with no settings detected. By default, java.crypto.Cipher uses ECB mode. ECB doesn't  provide message confidentiality and is not semantically secure so should not be used. Instead, use a st",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-of-md5-digest-utils",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-328",
    "message": "Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use HMAC instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-of-md5",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-328",
    "message": "Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use HMAC instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-of-rc2",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Use of RC2 was detected. RC2 is vulnerable to related-key attacks, and is therefore considered non-compliant. Instead, use a strong, secure cipher: Cipher.getInstance(\"AES/CBC/PKCS7PADDING\"). See http",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-of-rc4",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Use of RC4 was detected. RC4 is vulnerable to several attacks, including stream cipher attacks and bit flipping attacks. Instead, use a strong, secure cipher: Cipher.getInstance(\"AES/CBC/PKCS7PADDING\"",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-of-sha1",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-328",
    "message": "Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Instead, use PBKDF2 for password hashing or SHA25",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-of-sha224",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-328",
    "message": "This code uses a 224-bit hash function, which is deprecated or disallowed in some security policies. Consider updating to a stronger hash function such as SHA-384 or higher to ensure compliance and se",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "weak-random",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-330",
    "message": "Detected use of the functions `Math.random()` or `java.util.Random()`. These are both not cryptographically strong random number generators (RNGs). If you are using these RNGs to create passwords or s",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "use-of-weak-rsa-key",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "RSA keys should be at least 2048 bits based on NIST recommendation.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-groovy-shell",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "el-injection",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "An expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "formatted-sql-string",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) in",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "http-response-splitting",
    "language": "java",
    "severity": "INFO",
    "cwe": "CWE-113",
    "message": "Older Java application servers are vulnerable to HTTP response splitting, which may occur if an HTTP request can be injected with CRLF characters. This finding is reported for completeness; it is reco",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-smtp-connection",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-297",
    "message": "Insecure SMTP connection detected. This connection will trust any SSL certificate. Enable certificate verification by setting 'email.setSSLCheckServerIdentity(true)'.",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "java-reverse-shell",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-78",
    "message": "Semgrep found potential reverse shell behavior",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "jdbc-sql-formatted-string",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Possible JDBC injection detected. Use the parameterized query feature available in queryForObject instead of concatenating or formatting strings: 'jdbc.queryForObject(\"select * from table where name =",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ldap-entry-poisoning",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-90",
    "message": "An object-returning LDAP search will allow attackers to control the LDAP response. This could lead to Remote Code Execution.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ldap-injection",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-90",
    "message": "Detected non-constant data passed into an LDAP query. If this data can be controlled by an external user, this is an LDAP injection. Ensure data passed to an LDAP query is not controllable; or properl",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "md5-used-as-password",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function ",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "object-deserialization",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "Found object deserialization using ObjectInputStream. Deserializing entire Java objects is dangerous because malicious actors can create Java object streams with unintended consequences. Ensure that t",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ognl-injection",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "A expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "overly-permissive-file-permission",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-276",
    "message": "Detected file permissions that are overly permissive (read, write, and execute). It is generally a bad practices to set overly permissive file permission such as read+write+exec for all users. If the ",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "permissive-cors",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-183",
    "message": "https://find-sec-bugs.github.io/bugs.htm#PERMISSIVE_CORS Permissive CORS policy will allow a malicious application to communicate with the victim application in an inappropriate way, leading to spoofi",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "script-engine-injection",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "Detected potential code injection using ScriptEngine. Ensure user-controlled data cannot enter '.eval()', otherwise, this is a code injection vulnerability.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "hibernate-sqli",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) in",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "jdbc-sqli",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) in",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "jdo-sqli",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) in",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "jpa-sqli",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) in",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "tainted-sql-from-http-request",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected input from a HTTPServletRequest going into a SQL sink or statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use parameterized SQL querie",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "turbine-sqli",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) in",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "vertx-sqli",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) in",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "tainted-cmd-from-http-request",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected input from a HTTPServletRequest going into a 'ProcessBuilder' or 'exec' command. This could lead to command injection if variables passed into the exec commands are not properly sanitized. In",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-env-from-http-request",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-454",
    "message": "Detected input from a HTTPServletRequest going into the environment variables of an 'exec' command.  Instead, call the command with user-supplied arguments by using the overloaded method with one Stri",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-ldapi-from-http-request",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-90",
    "message": "Detected input from a HTTPServletRequest going into an LDAP query. This could lead to LDAP injection if the input is not properly sanitized, which could result in attackers modifying objects in the LD",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-session-from-http-request",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-501",
    "message": "Detected input from a HTTPServletRequest going into a session command, like `setAttribute`. User input into such a command could lead to an attacker inputting malicious code into your session paramete",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-xpath-from-http-request",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-643",
    "message": "Detected input from a HTTPServletRequest going into a XPath evaluate or compile command. This could lead to xpath injection if variables passed into the evaluate or compile commands are not properly s",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "unsafe-reflection",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-470",
    "message": "If an attacker can supply values that the application then uses to determine which class to instantiate or which method to invoke, the potential exists for the attacker to create control flow paths th",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "unvalidated-redirect",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-601",
    "message": "Application redirects to a destination URL specified by a user-supplied parameter that is not validated. This could direct users to malicious locations. Consider using an allowlist to validate URLs.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "url-rewriting",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-200",
    "message": "URL rewriting has significant security risks. Since session ID appears in the URL, it may be easily seen by third parties.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "weak-ssl-context",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "An insecure SSL context was detected. TLS versions 1.0, 1.1, and all SSL versions are considered weak encryption and are deprecated. Use SSLContext.getInstance(\"TLSv1.2\") for the best security.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "xml-decoder",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-611",
    "message": "XMLDecoder should not be used to parse untrusted data. Deserializing user input can lead to arbitrary code execution. Use an alternative and explicitly disable external entities. See https://cheatshee",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "autoescape-disabled",
    "language": "regex",
    "severity": "WARNING",
    "cwe": "CWE-150",
    "message": "Detected an element with disabled HTML escaping. If external data can reach this, this is a cross-site scripting (XSS) vulnerability. Ensure no external data can reach here, or remove 'escape=false' f",
    "category": "security",
    "owasp": "A07:2017 - Cross-Site Scripting (XSS)",
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-scriptlets",
    "language": "regex",
    "severity": "WARNING",
    "cwe": "CWE-116",
    "message": "JSP scriptlet detected. Scriptlets are difficult to use securely and are considered bad practice. See https://stackoverflow.com/a/3180202. Instead, consider migrating to JSF or using the Expression La",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "use-escapexml",
    "language": "regex",
    "severity": "WARNING",
    "cwe": "CWE-116",
    "message": "Detected an Expression Language segment that does not escape output. This is dangerous because if any data in this expression can be controlled externally, it is a cross-site scripting vulnerability. ",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "use-jstl-escaping",
    "language": "regex",
    "severity": "WARNING",
    "cwe": "CWE-116",
    "message": "Detected an Expression Language segment in a tag that does not escape output. This is dangerous because if any data in this expression can be controlled externally, it is a cross-site scripting vulner",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-direct-response-writer",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a request with potential user-input going into a OutputStream or Writer object. This bypasses any view or template environments, including HTML escaping, which may expose this application to ",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "xssrequestwrapper-is-insecure",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "It looks like you're using an implementation of XSSRequestWrapper from dzone. (https://www.javacodegeeks.com/2012/07/anti-cross-site-scripting-xss-filter.html) The XSS filtering in this code is not se",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "documentbuilderfactory-disallow-doctype-decl-false",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-611",
    "message": "DOCTYPE declarations are enabled for $DBFACTORY. Without prohibiting external entity declarations, this is vulnerable to XML external entity attacks. Disable this by setting the feature \"http://apache",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "documentbuilderfactory-disallow-doctype-decl-missing",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-611",
    "message": "DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature \"http://apache.org/xml/features/disallow-doctyp",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "documentbuilderfactory-external-general-entities-true",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-611",
    "message": "External entities are allowed for $DBFACTORY. This is vulnerable to XML external entity attacks. Disable this by setting the feature \"http://xml.org/sax/features/external-general-entities\" to false.",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "documentbuilderfactory-external-parameter-entities-true",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-611",
    "message": "External entities are allowed for $DBFACTORY. This is vulnerable to XML external entity attacks. Disable this by setting the feature \"http://xml.org/sax/features/external-parameter-entities\" to false.",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "saxparserfactory-disallow-doctype-decl-missing",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-611",
    "message": "DOCTYPE declarations are enabled for this SAXParserFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature `http://apache.org/xml/features/disallow-doctype-decl",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "transformerfactory-dtds-not-disabled",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-611",
    "message": "DOCTYPE declarations are enabled for this TransformerFactory. This is vulnerable to XML external entity attacks. Disable this by setting the attributes \"accessExternalDTD\" and \"accessExternalStyleshee",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "do-privileged-use",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-269",
    "message": "Marking code as privileged enables a piece of trusted code to temporarily enable access to more resources than are available directly to the code that called it. Be very careful in your use of the pri",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "httpservlet-path-traversal",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-22",
    "message": "Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled var",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-jms-deserialization",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "JMS Object messages depend on Java Serialization for marshalling/unmarshalling of the message payload when ObjectMessage.getObject() is called. Deserialization of untrusted data can lead to security f",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "jackson-unsafe-deserialization",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "When using Jackson to marshall/unmarshall JSON to Java objects, enabling default typing is dangerous and can lead to RCE. If an attacker can control `$JSON` it might be possible to provide a malicious",
    "category": "security",
    "owasp": [
      "A8:2017 Insecure Deserialization",
      "A8:2021 Software and Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "java-pattern-from-string-parameter",
    "language": "java",
    "severity": "INFO",
    "cwe": "CWE-1333",
    "message": "A regular expression is being used directly from a String method parameter. This could be a Regular Expression Denial of Service (ReDoS) vulnerability if the parameter is user-controlled and not prope",
    "category": "security",
    "owasp": [
      "A03:2021 Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "servletresponse-writer-xss",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-79",
    "message": "Cross-site scripting detected in HttpServletResponse writer with variable '$VAR'. User input was detected going directly from the HttpServletRequest into output. Ensure your data is properly encoded u",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-snakeyaml-constructor",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "Used SnakeYAML org.yaml.snakeyaml.Yaml() constructor with no arguments, which is vulnerable to deserialization attacks. Use the one-argument Yaml(...) constructor instead, with SafeConstructor or a cu",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "xmlinputfactory-external-entities-enabled",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-611",
    "message": "XML external entities are enabled for this XMLInputFactory. This is vulnerable to XML external entity attacks. Disable external entities by setting \"javax.xml.stream.isSupportingExternalEntities\" to f",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "xmlinputfactory-possible-xxe",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-611",
    "message": "XML external entities are not explicitly disabled for this XMLInputFactory. This could be vulnerable to XML external entity vulnerabilities. Explicitly disable external entities by setting \"javax.xml.",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "mongodb-nosqli",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-943",
    "message": "Detected non-constant data passed into a NoSQL query using the 'where' evaluation operator. If this data can be controlled by an external user, this is a NoSQL injection. Ensure data passed to the NoS",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "server-dangerous-class-deserialization",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "Using a non-primitive class with Java RMI may be an insecure deserialization vulnerability. Depending on the underlying implementation. This object could be manipulated by a malicious actor allowing t",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "server-dangerous-object-deserialization",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-502",
    "message": "Using an arbitrary object ('$PARAMTYPE $PARAM') with Java RMI is an insecure deserialization vulnerability. This object can be manipulated by a malicious actor allowing them to execute code on your sy",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "cookie-issecure-false",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Default session middleware settings: `setSecure` not set to true. This ensures that the cookie is sent only over HTTPS to prevent cross-site scripting attacks.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "cookie-setSecure",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Default session middleware settings: `setSecure` not set to true. This ensures that the cookie is sent only over HTTPS to prevent cross-site scripting attacks.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "security-constraint-http-method",
    "language": "xml",
    "severity": "WARNING",
    "cwe": "CWE-863",
    "message": "The tag \"http-method\" is used to specify on which HTTP methods the java web security constraint apply. The target security constraints could be bypassed if a non listed HTTP method is used. Inverse th",
    "category": "security",
    "owasp": [
      "A05:2021 Security Misconfiguration",
      "A01:2021 Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "spel-injection",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "A Spring expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "spring-actuator-fully-enabled-yaml",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-200",
    "message": "Spring Boot Actuator is fully enabled. This exposes sensitive endpoints such as /actuator/env, /actuator/logfile, /actuator/heapdump and others. Unless you have Spring Security enabled or another mean",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "spring-actuator-fully-enabled",
    "language": "generic",
    "severity": "ERROR",
    "cwe": "CWE-200",
    "message": "Spring Boot Actuator is fully enabled. This exposes sensitive endpoints such as /actuator/env, /actuator/logfile, /actuator/heapdump and others. Unless you have Spring Security enabled or another mean",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "spring-actuator-dangerous-endpoints-enabled-yaml",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-200",
    "message": "Spring Boot Actuator \"$ACTUATOR\" is enabled. Depending on the actuator, this can pose a significant security risk. Please double-check if the actuator is needed and properly secured.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "spring-actuator-dangerous-endpoints-enabled",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-200",
    "message": "Spring Boot Actuators \"$...ACTUATORS\" are enabled. Depending on the actuators, this can pose a significant security risk. Please double-check if the actuators are needed and properly secured.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "spring-csrf-disabled",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-352",
    "message": "CSRF protection is disabled for this configuration. This is a security risk.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "spring-jsp-eval",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "A Spring expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "spring-sqli",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected a string argument from a public method contract in a raw SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statement",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "spring-unvalidated-redirect",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-601",
    "message": "Application redirects a user to a destination URL specified by a user supplied parameter that is not validated.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-file-path",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-23",
    "message": "Detected user input controlling a file path. An attacker could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled v",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-html-string",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-79",
    "message": "Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-sql-string",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "User data flows into this manually-constructed SQL string. User data can be safely inserted into SQL strings using prepared statements or an object-relational mapper (ORM). Manually-constructed SQL st",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-system-command",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected user input entering a method which executes a system command. This could result in a command injection vulnerability, which allows an attacker to inject an arbitrary system command onto the s",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-url-host",
    "language": "java",
    "severity": "ERROR",
    "cwe": "CWE-918",
    "message": "User data flows into the host portion of this manually-constructed URL. This could allow an attacker to send data to their own server, potentially exposing sensitive data such as cookies or authorizat",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "unrestricted-request-mapping",
    "language": "java",
    "severity": "WARNING",
    "cwe": "CWE-352",
    "message": "Detected a method annotated with 'RequestMapping' that does not specify the HTTP method. CSRF protections are not enabled for GET, HEAD, TRACE, or OPTIONS, and by default all HTTP methods are allowed ",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ajv-allerrors-true",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-400",
    "message": "By setting `allErrors: true` in `Ajv` library, all error objects will be allocated without limit. This allows the attacker to produce a huge number of errors which can lead to denial of service. Do no",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detect-angular-element-methods",
    "language": "javascript",
    "severity": "INFO",
    "cwe": "CWE-79",
    "message": "Use of angular.element can lead to XSS if user-input is treated as part of the HTML element within `$SINK`. It is recommended to contextually output encode user-input, before inserting into `$SINK`. I",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "detect-angular-element-taint",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Use of angular.element can lead to XSS if user-input is treated as part of the HTML element within `$SINK`. It is recommended to contextually output encode user-input, before inserting into `$SINK`. I",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "detect-angular-open-redirect",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-79",
    "message": "Use of $window.location.href can lead to open-redirect if user input is used for redirection.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detect-angular-resource-loading",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "$sceDelegateProvider allowlisting can introduce security issues if wildcards are used.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detect-angular-sce-disabled",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-79",
    "message": "$sceProvider is set to false. Disabling Strict Contextual escaping (SCE) in an AngularJS application could provide additional attack surface for XSS vulnerabilities.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "detect-angular-trust-as-css-method",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "The use of $sce.trustAsCss can be dangerous if unsanitized user input flows through this API.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detect-angular-trust-as-html-method",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "The use of $sce.trustAsHtml can be dangerous if unsanitized user input flows through this API.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detect-angular-trust-as-js-method",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "The use of $sce.trustAsJs can be dangerous if unsanitized user input flows through this API.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detect-angular-trust-as-method",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "The use of $sce.trustAs can be dangerous if unsanitized user input flows through this API.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "detect-angular-trust-as-resourceurl-method",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "The use of $sce.trustAsResourceUrl can be dangerous if unsanitized user input flows through this API.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detect-angular-trust-as-url-method",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "The use of $sce.trustAsUrl can be dangerous if unsanitized user input flows through this API.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detect-angular-translateprovider-translations-method",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "The use of $translateProvider.translations method can be dangerous if user input is provided to this API.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "apollo-axios-ssrf",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "User-controllable argument $DATAVAL to $METHOD passed to Axios via internal handler $INNERFUNC. This could be a server-side request forgery. A user could call a restricted API or leak internal headers",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "unsafe-argon2-config",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-916",
    "message": "Prefer Argon2id where possible. Per RFC9016, section 4 IETF recommends selecting Argon2id unless you can guarantee an adversary has no direct access to the computing environment.",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "detect-replaceall-sanitization",
    "language": "javascript",
    "severity": "INFO",
    "cwe": "CWE-79",
    "message": "Detected a call to `$FUNC()` in an attempt to HTML escape the string `$STR`. Manually sanitizing input through a manually built list can be circumvented in many situations, and it's better to use a we",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detect-child-process",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Allowing spawning arbitrary programs or running shell processes with arbitrary arguments may end up in a command injection vulnerability. Try to avoid non-literal values for the command string. If it ",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dynamodb-request-object",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-943",
    "message": "Detected DynamoDB query params that are tainted by `$EVENT` object. This could lead to NoSQL injection if the variable is user-controlled and not properly sanitized. Explicitly assign query params ins",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "knex-sqli",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parame",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "mysql-sqli",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parame",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pg-sqli",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parame",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "sequelize-sqli",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parame",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-eval",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "The `eval()` function evaluates JavaScript code represented as a string. Executing JavaScript from a string is an enormous security risk. It is far too easy for a bad actor to run arbitrary code when ",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-html-response",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected user input flowing into an HTML response. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnera",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-html-string",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-sql-string",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injectio",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "vm-runincontext-injection",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-94",
    "message": "The `vm` module enables compiling and running code within V8 Virtual Machine contexts. The `vm` module is not a security mechanism. Do not use it to run untrusted code. If code passed to `vm` function",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tofastproperties-code-execution",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "Potential arbitrary code execution, whatever is provided to `toFastProperties` is sent straight to eval()",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dom-based-xss",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-79",
    "message": "Detected possible DOM-based XSS. This occurs because a portion of the URL is being used to construct an element added directly to the page. For example, a malicious actor could send someone a link lik",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "eval-detected",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evalu",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-document-method",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-79",
    "message": "User controlled data in methods like `innerHTML`, `outerHTML` or `document.write` is an anti-pattern that can lead to XSS vulnerabilities",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-innerhtml",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-79",
    "message": "User controlled data in a `$EL.innerHTML` is an anti-pattern that can lead to XSS vulnerabilities",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insufficient-postmessage-origin-validation",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-345",
    "message": "No validation of origin is done by the addEventListener API. It may be possible to exploit this flaw to perform Cross Origin attacks such as Cross-Site Scripting(XSS).",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "js-open-redirect-from-function",
    "language": "javascript",
    "severity": "INFO",
    "cwe": "CWE-601",
    "message": "The application accepts potentially user-controlled input `$PROP` which can control the location of the current window context. This can lead two types of vulnerabilities open-redirection and Cross-Si",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "js-open-redirect",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-601",
    "message": "The application accepts potentially user-controlled input `$PROP` which can control the location of the current window context. This can lead two types of vulnerabilities open-redirection and Cross-Si",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "raw-html-concat",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "User controlled data in a HTML string may result in XSS",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "raw-html-join",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "User controlled data in a HTML string may result in XSS",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "wildcard-postmessage-configuration",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-345",
    "message": "The target origin of the window.postMessage() API is set to \"*\". This could allow for information disclosure due to the possibility of any origin allowed to receive the message.",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "chrome-remote-interface-compilescript-injection",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "If unverified user data can reach the `compileScript` method it can result in Server-Side Request Forgery vulnerabilities",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "deno-dangerous-run",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected non-literal calls to Deno.run(). This could lead to a command injection vulnerability.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-check-csurf-middleware-usage",
    "language": "javascript",
    "severity": "INFO",
    "cwe": "CWE-352",
    "message": "A CSRF middleware was not detected in your express application. Ensure you are either using one such as `csurf` or `csrf` (see rule references) and/or you are properly doing CSRF validation in your ro",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "express-check-directory-listing",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-548",
    "message": "Directory listing/indexing is enabled, which may lead to disclosure of sensitive directories and files. It is recommended to disable directory listing unless it is a public resource. If you need direc",
    "category": "security",
    "owasp": [
      "A06:2017 - Security Misconfiguration",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-cookie-session-default-name",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-522",
    "message": "Don\u2019t use the default session cookie name Using the default session cookie name can open your app to attacks. The security issue posed is similar to X-Powered-By: a potential attacker can use it to fi",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-cookie-session-no-secure",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-522",
    "message": "Default session middleware settings: `secure` not set. It ensures the browser only sends the cookie over HTTPS.",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-cookie-session-no-httponly",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-522",
    "message": "Default session middleware settings: `httpOnly` not set. It ensures the cookie is sent only over HTTP(S), not client JavaScript, helping to protect against cross-site scripting attacks.",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-cookie-session-no-domain",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-522",
    "message": "Default session middleware settings: `domain` not set. It indicates the domain of the cookie; use it to compare against the domain of the server in which the URL is being requested. If they match, the",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-cookie-session-no-path",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-522",
    "message": "Default session middleware settings: `path` not set. It indicates the path of the cookie; use it to compare against the request path. If this and domain match, then send the cookie in the request.",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-cookie-session-no-expires",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-522",
    "message": "Default session middleware settings: `expires` not set. Use it to set expiration date for persistent cookies.",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-detect-notevil-usage",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-1104",
    "message": "Detected usage of the `notevil` package, which is unmaintained and has vulnerabilities. Using any sort of `eval()` functionality can be very dangerous, but if you must, the `eval` package is an up to ",
    "category": "security",
    "owasp": [
      "A06:2021 - Vulnerable and Outdated Components",
      "A03:2025 - Software Supply Chain Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "express-jwt-not-revoked",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-522",
    "message": "No token revoking configured for `express-jwt`. A leaked token could still be used and unable to be revoked. Consider using function as the `isRevoked` option.",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-libxml-noent",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-611",
    "message": "The libxml library processes user-input with the `noent` attribute is set to `true` which can lead to being vulnerable to XML External Entities (XXE) type attacks. It is recommended to set `noent` to ",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-libxml-vm-noent",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-611",
    "message": "Detected use of parseXml() function with the `noent` field set to `true`. This can lead to an XML External Entities (XXE) attack if untrusted data is passed into it.",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "express-open-redirect",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-601",
    "message": "The application redirects to a URL specified by user-supplied input `$REQ` that is not validated. This could redirect users to malicious locations. Consider using an allow-list approach to validate UR",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-path-join-resolve-traversal",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "Possible writing outside of the destination, make sure that the target path is nested in the intended destination",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-res-sendfile",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-73",
    "message": "The application processes user-input, this is passed to res.sendFile which can allow an attacker to arbitrarily read files on the system through path traversal. It is recommended to perform input vali",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-session-hardcoded-secret",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-798",
    "message": "A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It i",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-ssrf",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "The following request $REQUEST.$METHOD() was found to be crafted from user-input `$REQ` which can lead to Server-Side Request Forgery (SSRF) vulnerabilities. It is recommended where possible to not al",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-third-party-object-deserialization",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "The following function call $SER.$FUNC accepts user controlled data which can result in Remote Code Execution (RCE) through Object Deserialization. It is recommended to use secure data processing alte",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-xml2json-xxe-event",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-611",
    "message": "Xml Parser is used inside Request Event. Make sure that unverified user data can not reach the XML Parser, as it can result in XML External or Internal Entity (XXE) Processing vulnerabilities",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "unknown-value-in-redirect",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-601",
    "message": "It looks like '$UNK' is read from user input and it is used to as a redirect. Ensure '$UNK' is not externally controlled, otherwise this is an open redirect.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "remote-property-injection",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-522",
    "message": "Bracket object notation with user input is present, this might allow an attacker to access all properties of the object and even it's prototype. Use literal values for object properties.",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "res-render-injection",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-706",
    "message": "User controllable data `$REQ` enters `$RES.render(...)` this can lead to the loading of other HTML/templating pages that they may not be authorized to render. An attacker may attempt to use directory ",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "direct-response-write",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected directly writing to a Response object from user-defined input. This bypasses any HTML escaping and may expose your application to a Cross-Site-scripting (XSS) vulnerability. Instead, use 'res",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "template-explicit-unescape",
    "language": "regex",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected an explicit unescape in an EJS template, using '<%- ... %>' If external data can reach these locations, your application is exposed to a cross-site scripting (XSS) vulnerability. Use '<%= ...",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "var-in-href",
    "language": "regex",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If usi",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "var-in-script-src",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a template variable used as the 'src' in a script tag. Although template variables are HTML escaped, HTML escaping does not always prevent malicious URLs from being injected and could results",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "var-in-script-tag",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a template variable used in a script tag. Although template variables are HTML escaped, HTML escaping does not always prevent cross-site scripting (XSS) attacks when used directly in JavaScri",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "escape-function-overwrite",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "The Mustache escape function is being overwritten. This could bypass HTML escaping safety measures built into the rendering engine, exposing your application to cross-site scripting (XSS) vulnerabilit",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "template-explicit-unescape",
    "language": "regex",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected an explicit unescape in a Mustache template, using triple braces '{{{...}}}' or ampersand '&'. If external data can reach these locations, your application is exposed to a cross-site scriptin",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "var-in-script-tag",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a template variable used in a script tag. Although template variables are HTML escaped, HTML escaping does not always prevent cross-site scripting (XSS) attacks when used directly in JavaScri",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "template-and-attributes",
    "language": "regex",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a unescaped variables using '&attributes'. If external data can reach these locations, your application is exposed to a cross-site scripting (XSS) vulnerability. If you must do this, ensure n",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "template-explicit-unescape",
    "language": "regex",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected an explicit unescape in a Pug template, using either '!=' or '!{...}'. If external data can reach these locations, your application is exposed to a cross-site scripting (XSS) vulnerability. I",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "var-in-href",
    "language": "regex",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If usi",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "var-in-script-tag",
    "language": "regex",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a template variable used in a script tag. Although template variables are HTML escaped, HTML escaping does not always prevent cross-site scripting (XSS) attacks when used directly in JavaScri",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "cors-misconfiguration",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-346",
    "message": "By letting user input control CORS parameters, there is a risk that software does not properly verify that the source of data or communication is valid. Use literal values for CORS settings.",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-data-exfiltration",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-915",
    "message": "Depending on the context, user control data in `Object.assign` can cause web response to include data that it should not have or can lead to a mass assignment vulnerability.",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "express-expat-xxe",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-611",
    "message": "Make sure that unverified user data can not reach the XML Parser, as it can result in XML External or Internal Entity (XXE) Processing vulnerabilities.",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-insecure-template-usage",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-1336",
    "message": "User data from `$REQ` is being compiled into the template, which can lead to a Server Side Template Injection (SSTI) vulnerability.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A01:2017 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-jwt-hardcoded-secret",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-798",
    "message": "A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It i",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "express-phantom-injection",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-918",
    "message": "If unverified user data can reach the `phantom` methods it can result in Server-Side Request Forgery vulnerabilities",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-puppeteer-injection",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-918",
    "message": "If unverified user data can reach the `puppeteer` methods it can result in Server-Side Request Forgery vulnerabilities",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-sandbox-code-injection",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-94",
    "message": "Make sure that unverified user data can not reach `sandbox`.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-vm-injection",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-94",
    "message": "Make sure that unverified user data can not reach `$VM`.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-vm2-injection",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "Make sure that unverified user data can not reach `vm2`.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-wkhtmltoimage-injection",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-918",
    "message": "If unverified user data can reach the `phantom` methods it can result in Server-Side Request Forgery vulnerabilities",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-wkhtmltopdf-injection",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-918",
    "message": "If unverified user data can reach the `wkhtmltopdf` methods it can result in Server-Side Request Forgery vulnerabilities",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "express-xml2json-xxe",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-611",
    "message": "Make sure that unverified user data can not reach the XML Parser, as it can result in XML External or Internal Entity (XXE) Processing vulnerabilities",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "raw-html-format",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "User data flows into the host portion of this manually-constructed HTML. This can introduce a Cross-Site-Scripting (XSS) vulnerability if this comes from user-provided input. Consider using a sanitiza",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-sql-string",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injectio",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "require-request",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-706",
    "message": "If an attacker controls the x in require(x) then they can cause code to load that was not intended to run on the server.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "x-frame-options-misconfiguration",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-451",
    "message": "By letting user input control `X-Frame-Options` header, there is a risk that software does not properly verify whether or not a browser should be allowed to render a page in an `iframe`.",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-createnodesfrommarkup",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "User controlled data in a `createNodesFromMarkup` is an anti-pattern that can lead to XSS vulnerabilities",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "grpc-nodejs-insecure-connection",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-502",
    "message": "Found an insecure gRPC connection. This creates a connection without encryption to a gRPC client/server. A malicious attacker could tamper with the gRPC message, which could compromise the machine.",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "intercom-settings-user-identifier-without-user-hash",
    "language": "js",
    "severity": "WARNING",
    "cwe": "CWE-287",
    "message": "Found an initialization of the Intercom Messenger that identifies a User, but does not specify a `user_hash`. This configuration allows users to impersonate one another. See the Intercom Identity Veri",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "jose-exposed-data",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-522",
    "message": "The object is passed strictly to jose.JWT.sign(...) Make sure that sensitive information is not exposed through JWT token payload.",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "hardcoded-jwt-secret",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-798",
    "message": "A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It i",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "jwt-none-alg",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-327",
    "message": "Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that wil",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "jquery-insecure-method",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "User controlled data in a jQuery's `.$METHOD(...)` is an anti-pattern that can lead to XSS vulnerabilities",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "jquery-insecure-selector",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "User controlled data in a `$(...)` is an anti-pattern that can lead to XSS vulnerabilities",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "prohibit-jquery-html",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "JQuery's `html` function is susceptible to Cross Site Scripting (XSS) attacks. If you're just passing text, consider `text` instead. Otherwise, use a function that escapes HTML such as edX's `HtmlUtil",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "jwt-decode-without-verify",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-345",
    "message": "Detected the decoding of a JWT token without a verify step. JWT tokens must be verified before use, otherwise the token's integrity is unknown. This means a malicious actor could forge a JWT token wit",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "jwt-exposed-data",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-522",
    "message": "The object is passed strictly to jsonwebtoken.sign(...) Make sure that sensitive information is not exposed through JWT token payload.",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "hardcoded-jwt-secret",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-798",
    "message": "A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It i",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "jwt-none-alg",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-327",
    "message": "Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that wil",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "jwt-simple-noverify",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-287",
    "message": "Detected the decoding of a JWT token without a verify step. JWT tokens must be verified before use, otherwise the token's integrity is unknown. This means a malicious actor could forge a JWT token wit",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A07:2021 - Identification and Authentication Failures",
      "A02:2025 - Security Misconfiguration",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "code-string-concat",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-95",
    "message": "Found data from an Express or Next web request flowing to `eval`. If this data is user-controllable this can lead to execution of arbitrary system commands in the context of your application process. ",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-spawn-shell",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected non-literal calls to $EXEC(). This could lead to a command injection vulnerability.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "detect-non-literal-fs-filename",
    "language": "typescript",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "Detected that function argument `$ARG` has entered the fs module. An attacker could potentially control the location of this file, to include going backwards in the directory with '../'. To address th",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "detect-non-literal-regexp",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-1333",
    "message": "RegExp() called with a `$ARG` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A06:2017 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "detect-non-literal-require",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Detected the use of require(variable). Calling require with a non-literal argument might allow an attacker to load and run arbitrary code, or access arbitrary files.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "detect-redos",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-1333",
    "message": "Detected the use of a regular expression `$REDOS` which appears to be vulnerable to a Regular expression Denial-of-Service (ReDoS). For this reason, it is recommended to review the regex and ensure it",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A06:2017 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "hardcoded-hmac-key",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-798",
    "message": "Detected a hardcoded hmac key. Avoid hardcoding secrets and consider using an alternate option such as reading the secret from a config file or using an environment variable.",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "incomplete-sanitization",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-116",
    "message": "`$STR.replace` method will only replace the first occurrence when used with a string argument ($CHAR). If this method is used for escaping of dangerous data then there is a possibility for a bypass. T",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "md5-used-as-password",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function ",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "path-join-resolve-traversal",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "Detected possible user input going into a `path.join` or `path.resolve` function. This could possibly lead to a path traversal vulnerability,  where the attacker can access arbitrary files stored in t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "prototype-pollution-assignment",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-915",
    "message": "Possibility of prototype polluting assignment detected. By adding or modifying attributes of an object prototype, it is possible to create attributes that exist on every object, or replace critical at",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "prototype-pollution-loop",
    "language": "typescript",
    "severity": "WARNING",
    "cwe": "CWE-915",
    "message": "Possibility of prototype polluting function detected. By adding or modifying attributes of an object prototype, it is possible to create attributes that exist on every object, or replace critical attr",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "spawn-shell-true",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Found '$SPAWN' with '{shell: $SHELL}'. This is dangerous because this call will spawn the command using a shell process. Doing so propagates current shell settings and variables, which makes it much e",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "node-knex-sqli",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected SQL statement that is tainted by `$REQ` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, it is recomm",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "node-mssql-sqli",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected string concatenation with a non-literal variable in a `mssql` JS SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to pre",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "node-mysql-sqli",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected a `$IMPORT` SQL statement that comes from a function argument. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injec",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "node-postgres-sqli",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-915",
    "message": "Detected string concatenation with a non-literal variable in a node-postgres JS SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order ",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "unknown-value-with-script-tag",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Cannot determine what '$UNK' is and it is used with a '<script>' tag. This could be susceptible to cross-site scripting (XSS). Ensure '$UNK' is not externally controlled, or sanitize this data.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "unsafe-dynamic-method",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "Using non-static data to retrieve and run functions from the object is dangerous. If the data is user-controlled, it may allow executing arbitrary code.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "unsafe-formatstring",
    "language": "javascript",
    "severity": "INFO",
    "cwe": "CWE-134",
    "message": "Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use co",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detect-buffer-noassert",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-119",
    "message": "Detected usage of noassert in Buffer API, which allows the offset the be beyond the end of the buffer. This could result in writing or reading beyond the end of the buffer.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detect-child-process",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected calls to child_process from a function argument `$FUNC`. This could lead to a command injection if the input is user controllable. Try to avoid calls to child_process, and if it is needed ens",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detect-disable-mustache-escape",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-116",
    "message": "Markup escaping disabled. This can be used with some template engines to escape disabling of HTML entities, which can lead to XSS attacks.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detect-eval-with-expression",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Detected use of dynamic execution of JavaScript which may come from user-input, which can lead to Cross-Site-Scripting (XSS). Where possible avoid including user-input in functions which dynamically e",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "detect-insecure-websocket",
    "language": "regex",
    "severity": "ERROR",
    "cwe": "CWE-319",
    "message": "Insecure WebSocket Detected. WebSocket Secure (wss) should be used for all WebSocket connections.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detect-no-csrf-before-method-override",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-352",
    "message": "Detected use of express.csrf() middleware before express.methodOverride(). This can allow GET requests (which are not checked by csrf) to turn into POST requests later.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A05:2017 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detect-pseudoRandomBytes",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-338",
    "message": "Detected usage of crypto.pseudoRandomBytes, which does not produce secure random numbers.",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "html-in-template-string",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-116",
    "message": "This template literal looks like HTML and has interpolated variables. These variables are not HTML-encoded by default. If the variables contain HTML tags, these may be interpreted by the browser, resu",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-object-assign",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-601",
    "message": "Depending on the context, user control data in `Object.assign` can cause web response to include data that it should not have or can lead to a mass assignment vulnerability.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "spawn-git-clone",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Git allows shell commands to be specified in ext URLs for remote repositories. For example, git clone 'ext::sh -c whoami% >&2' will execute the whoami command to try to connect to a remote repository.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "monaco-hover-htmlsupport",
    "language": "typescript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "If user input reaches `HoverProvider` while `supportHml` is set to `true` it may introduce an XSS vulnerability. Do not produce HTML for hovers with dynamically generated input.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aead-no-final",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-310",
    "message": "The 'final' call of a Decipher object checks the authentication tag in a mode for authenticated encryption. Failing to call 'final' will invalidate all integrity guarantees of the released ciphertext.",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "create-de-cipher-no-iv",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-1204",
    "message": "The deprecated functions 'createCipher' and 'createDecipher' generate the same initialization vector every time. For counter modes such as CTR, GCM, or CCM this leads to break of both confidentiality ",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "gcm-no-tag-length",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-310",
    "message": "The call to 'createDecipheriv' with the Galois Counter Mode (GCM) mode of operation is missing an expected authentication tag length. If the expected authentication tag length is not specified or othe",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "expat-xxe",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-611",
    "message": "If unverified user data can reach the XML Parser it can result in XML External or Internal Entity (XXE) Processing vulnerabilities",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "hardcoded-passport-secret",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-798",
    "message": "A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It i",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "phantom-injection",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "If unverified user data can reach the `phantom` page methods it can result in Server-Side Request Forgery vulnerabilities",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "playwright-addinitscript-code-injection",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "If unverified user data can reach the `addInitScript` method it can result in Server-Side Request Forgery vulnerabilities",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "playwright-evaluate-arg-injection",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "If unverified user data can reach the `evaluate` method it can result in Server-Side Request Forgery vulnerabilities",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "playwright-evaluate-code-injection",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "If unverified user data can reach the `evaluate` method it can result in Server-Side Request Forgery vulnerabilities",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "playwright-exposed-chrome-devtools",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "Remote debugging protocol does not perform any authentication, so exposing it too widely can be a security risk.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "playwright-goto-injection",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "If unverified user data can reach the `goto` method it can result in Server-Side Request Forgery vulnerabilities",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "playwright-setcontent-injection",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "If unverified user data can reach the `setContent` method it can result in Server-Side Request Forgery vulnerabilities",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "puppeteer-evaluate-arg-injection",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "If unverified user data can reach the `evaluate` method it can result in Server-Side Request Forgery vulnerabilities",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "puppeteer-evaluate-code-injection",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "If unverified user data can reach the `evaluate` method it can result in Server-Side Request Forgery vulnerabilities",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "puppeteer-exposed-chrome-devtools",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "Remote debugging protocol does not perform any authentication, so exposing it too widely can be a security risk.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "puppeteer-goto-injection",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "If unverified user data can reach the `goto` method it can result in Server-Side Request Forgery vulnerabilities",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "puppeteer-setcontent-injection",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "If unverified user data can reach the `setContent` method it can result in Server-Side Request Forgery vulnerabilities",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "sandbox-code-injection",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "Make sure that unverified user data can not reach `sandbox`.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "sax-xxe",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-611",
    "message": "Use of 'ondoctype' in 'sax' library detected. By default, 'sax' won't do anything with custom DTD entity definitions. If you're implementing a custom DTD entity definition, be sure not to introduce XM",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "sequelize-enforce-tls",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "If TLS is disabled on server side (Postgresql server), Sequelize establishes connection without TLS and no error will be thrown. To prevent MITN (Man In The Middle) attack, TLS must be enforce by Sequ",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "express-sequelize-injection",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it i",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "sequelize-raw-query",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. Data replacement or data binding should be used. See https://sequelize.org/master/manual",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "sequelize-tls-disabled-cert-validation",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-94",
    "message": "Set \"rejectUnauthorized\" to false is a convenient way to resolve certificate error. But this method is unsafe because it disables the server certificate verification, making the Node app open to MITM ",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "sequelize-weak-tls-version",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "TLS1.0 and TLS1.1 are deprecated and should not be used anymore. By default, NodeJS used TLSv1.2. So, TLS min version must not be downgrade to TLS1.0 or TLS1.1. Enforce TLS1.3 is highly recommended Th",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "unsafe-serialize-javascript",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-80",
    "message": "`serialize-javascript` used with `unsafe` parameter, this could be vulnerable to XSS.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "shelljs-exec-injection",
    "language": "javascript",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "If unverified user data can reach the `exec` method it can result in Remote Code Execution",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "multiargs-code-execution",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "Potential arbitrary code execution, piped to eval",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "vm2-code-injection",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "Make sure that unverified user data can not reach `vm2`.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "vm2-context-injection",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "Make sure that unverified user data can not reach `vm2`.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-v-html",
    "language": "regex",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Dynamically rendering arbitrary HTML on your website can be very dangerous because it can easily lead to XSS vulnerabilities. Only use HTML interpolation on trusted content and never on user-provided ",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "wkhtmltoimage-injection",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "If unverified user data can reach the `wkhtmltoimage` it can result in Server-Side Request Forgery vulnerabilities",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "wkhtmltopdf-injection",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "If unverified user data can reach the `wkhtmltopdf` it can result in Server-Side Request Forgery vulnerabilities",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "xml2json-xxe",
    "language": "javascript",
    "severity": "WARNING",
    "cwe": "CWE-611",
    "message": "If unverified user data can reach the XML Parser it can result in XML External or Internal Entity (XXE) Processing vulnerabilities",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "public-s3-bucket",
    "language": "json",
    "severity": "WARNING",
    "cwe": "CWE-264",
    "message": "Detected public S3 bucket. This policy allows anyone to have some kind of access to the bucket. The exact level of access and types of actions allowed will depend on the configuration of bucket policy",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "public-s3-policy-statement",
    "language": "json",
    "severity": "WARNING",
    "cwe": "CWE-264",
    "message": "Detected public S3 bucket policy. This policy allows anyone to access certain properties of or items in the bucket. Do not do this unless you will never have sensitive data inside the bucket.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "wildcard-assume-role",
    "language": "json",
    "severity": "ERROR",
    "cwe": "CWE-250",
    "message": "Detected wildcard access granted to sts:AssumeRole. This means anyone with your AWS account ID and the name of the role can assume the role. Instead, limit to a specific identity in your account, like",
    "category": "security",
    "owasp": [
      "A06:2017 - Security Misconfiguration",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "build-gradle-password-hardcoded",
    "language": "kotlin",
    "severity": "WARNING",
    "cwe": "CWE-798",
    "message": "A secret is hard-coded in the application. Secrets stored in source code, such as credentials, identifiers, and other types of sensitive data, can be leaked and used by internal or external malicious ",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "anonymous-ldap-bind",
    "language": "kt",
    "severity": "WARNING",
    "cwe": "CWE-287",
    "message": "Detected anonymous LDAP bind. This permits anonymous users to execute LDAP statements. Consider enforcing authentication for LDAP. See https://docs.oracle.com/javase/tutorial/jndi/ldap/auth_mechs.html",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "bad-hexa-conversion",
    "language": "kt",
    "severity": "WARNING",
    "cwe": "CWE-704",
    "message": "'Integer.toHexString()' strips leading zeroes from each byte if read byte-by-byte. This mistake weakens the hash value computed since it introduces more collisions. Use 'String.format(\"%02X\", ...)' in",
    "category": "security",
    "owasp": "A03:2017 - Sensitive Data Exposure",
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "command-injection-formatted-runtime-call",
    "language": "kt",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "A formatted or concatenated string was detected as input to a java.lang.Runtime call. This is dangerous if a variable is controlled by user input and could result in a command injection. Ensure your v",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "cookie-missing-httponly",
    "language": "kt",
    "severity": "WARNING",
    "cwe": "CWE-1004",
    "message": "A cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie. Set the 'HttpOnly' flag by calli",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "cookie-missing-secure-flag",
    "language": "kt",
    "severity": "WARNING",
    "cwe": "CWE-614",
    "message": "A cookie was detected without setting the 'secure' flag. The 'secure' flag for cookies prevents the client from transmitting the cookie over insecure channels such as HTTP. Set the 'secure' flag by ca",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "defaulthttpclient-is-deprecated",
    "language": "kt",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "DefaultHttpClient is deprecated. Further, it does not support connections using TLS1.2, which makes using DefaultHttpClient a security hazard. Use SystemDefaultHttpClient instead, which supports TLS1.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ecb-cipher",
    "language": "kt",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Cipher in ECB mode is detected. ECB mode produces the same output for the same input each time which allows an attacker to intercept and replay the data. Further, ECB mode does not provide any integri",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "gcm-detection",
    "language": "kt",
    "severity": "INFO",
    "cwe": "CWE-323",
    "message": "GCM detected, please check that IV/nonce is not reused, an Initialization Vector (IV) is a nonce used to randomize the encryption, so that even if multiple messages with identical plaintext are encryp",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-null-cipher",
    "language": "kt",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "NullCipher was detected. This will not encrypt anything; the cipher text will be the same as the plain text. Use a valid, secure cipher: Cipher.getInstance(\"AES/CBC/PKCS7PADDING\"). See https://owasp.o",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "unencrypted-socket",
    "language": "kt",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "This socket is not encrypted. The traffic could be read by an attacker intercepting the network traffic. Use an SSLSocket created by 'SSLSocketFactory' or 'SSLServerSocketFactory' instead",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "use-of-md5",
    "language": "kt",
    "severity": "WARNING",
    "cwe": "CWE-328",
    "message": "Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-of-sha1",
    "language": "kt",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-of-weak-rsa-key",
    "language": "kt",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "RSA keys should be at least 2048 bits based on NIST recommendation.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ocamllint-digest",
    "language": "ocaml",
    "severity": "WARNING",
    "cwe": "",
    "message": "Digest uses MD5 and should not be used for security purposes. Consider using SHA256 instead.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ocamllint-exec",
    "language": "ocaml",
    "severity": "WARNING",
    "cwe": "",
    "message": "Executing external programs might lead to comand or argument injection vulnerabilities.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ocamllint-filenameconcat",
    "language": "ocaml",
    "severity": "WARNING",
    "cwe": "",
    "message": "When attacker supplied data is passed to Filename.concat directory traversal attacks might be possible.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ocamllint-hashtable-dos",
    "language": "ocaml",
    "severity": "WARNING",
    "cwe": "",
    "message": "Creating a Hashtbl without the optional random number parameter makes it prone to DoS attacks when attackers are able to fill the table with malicious content. Hashtbl.randomize or the R flag in the O",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ocamllint-marshal",
    "language": "ocaml",
    "severity": "WARNING",
    "cwe": "",
    "message": "Marshaling is currently not type-safe and can lead to insecure behaviour when untrusted data is marshalled. Marshalling can lead to out-of-bound reads as well.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "ocamllint-tempfile",
    "language": "ocaml",
    "severity": "WARNING",
    "cwe": "",
    "message": "Filename.temp_file might lead to race conditions, since the file could be altered or replaced by a symlink before being opened.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ocamllint-unsafe",
    "language": "ocaml",
    "severity": "WARNING",
    "cwe": "",
    "message": "Unsafe functions do not perform boundary checks or have other side effects, use with care.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "doctrine-dbal-dangerous-query",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected string concatenation with a non-literal variable in a Doctrine DBAL query method. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to p",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "doctrine-orm-dangerous-query",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "`$QUERY` Detected string concatenation with a non-literal variable in a Doctrine QueryBuilder method. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "assert-use",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-95",
    "message": "Calling assert with user input is equivalent to eval'ing.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "assert-use-audit",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-95",
    "message": "Calling assert with user input is equivalent to eval'ing.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "openssl-decrypt-validate",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-252",
    "message": "The function `openssl_decrypt` returns either a string of the decrypted data on success or `false` on failure. If the failure case is not handled, this could lead to undefined behavior in your applica",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "sha224-hash",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-328",
    "message": "This code uses a 224-bit hash function, which is deprecated or disallowed in some security policies. Consider updating to a stronger hash function such as SHA-384 or higher to ensure compliance and se",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "backticks-use",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-94",
    "message": "Backticks use may lead to command injection vulnerabilities.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "base-convert-loses-precision",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-190",
    "message": "The function base_convert uses 64-bit numbers internally, and does not correctly convert large numbers. It is not suitable for random tokens such as those used for session tokens or CSRF tokens.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "curl-ssl-verifypeer-off",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-319",
    "message": "SSL verification is disabled but should not be (currently CURLOPT_SSL_VERIFYPEER= $IS_VERIFIED)",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "extract-user-data",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-502",
    "message": "Do not call 'extract()' on user-controllable data. If you must, then you must also provide the EXTR_SKIP flag to prevent overwriting existing variables.",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "eval-use",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Evaluating non-constant commands. This can lead to command injection.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "exec-use",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-94",
    "message": "Executing non-constant commands. This can lead to command injection.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "file-inclusion",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-98",
    "message": "Detected non-constant file inclusion. This can lead to local file inclusion (LFI) or remote file inclusion (RFI) if user input reaches this statement. LFI and RFI could lead to sensitive files being o",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ftp-use",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-319",
    "message": "FTP allows for unencrypted file transfers. Consider using an encrypted alternative.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "echoed-request",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-79",
    "message": "`Echo`ing user input risks cross-site scripting vulnerability. You should use `htmlentities()` when showing data to users.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "printed-request",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-79",
    "message": "`Printing user input risks cross-site scripting vulnerability. You should use `htmlentities()` when showing data to users.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-callable",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "Callable based on user input risks remote code execution.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-exec",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-78",
    "message": "User input is passed to a function that executes a shell command. This can lead to remote code execution.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-filename",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "File name based on user input risks server-side request forgery.",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-object-instantiation",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-470",
    "message": "<- A new object is created where the class name is based on user input. This could lead to remote code execution, as it allows to instantiate any class in the application.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-session",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-284",
    "message": "Session key based on user input risks session poisoning. The user can determine the key used for the session, and thus write any session variable. Session variables are typically trusted to be set onl",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-sql-string",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "User data flows into this manually-constructed SQL string. User data can be safely inserted into SQL strings using prepared statements or an object-relational mapper (ORM). Manually-constructed SQL st",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-url-host",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "User data flows into the host portion of this manually-constructed URL. This could allow an attacker to send data to their own server, potentially exposing sensitive data such as cookies or authorizat",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "ldap-bind-without-password",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-287",
    "message": "Detected anonymous LDAP bind. This permits anonymous users to execute LDAP statements. Consider enforcing authentication for LDAP.",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "mb-ereg-replace-eval",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-94",
    "message": "Calling mb_ereg_replace with user input in the options can lead to arbitrary code execution. The eval modifier (`e`) evaluates the replacement argument as code.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "mcrypt-use",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-676",
    "message": "Mcrypt functionality has been deprecated and/or removed in recent PHP versions. Consider using Sodium or OpenSSL.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "md5-loose-equality",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-697",
    "message": "Make sure comparisons involving md5 values are strict (use `===` not `==`) to avoid type juggling issues",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "md5-used-as-password",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function ",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "openssl-cbc-static-iv",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-329",
    "message": "Static IV used with AES in CBC mode. Static IVs enable chosen-plaintext attacks against encrypted data.",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "php-permissive-cors",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-346",
    "message": "Access-Control-Allow-Origin response header is set to \"*\". This will disable CORS Same Origin Policy restrictions.",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "php-ssrf",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-918",
    "message": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected d",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "phpinfo-use",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-200",
    "message": "The 'phpinfo' function may reveal sensitive information about your environment.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "redirect-to-request-uri",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-601",
    "message": "Redirecting to the current request URL may redirect to another domain, if the current path starts with two slashes.  E.g. in https://www.example.com//attacker.com, the value of REQUEST_URI is //attack",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-exec",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-94",
    "message": "Executing non-constant commands. This can lead to command injection. You should use `escapeshellarg()` when using command.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "unlink-use",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "Using user input when deleting files with `unlink()` is potentially dangerous. A malicious actor could use this to modify or access files they have no right to.",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "unserialize-use",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "Calling `unserialize()` with user input in the pattern can lead to arbitrary code execution. Consider using JSON or structured data approaches (e.g. Google Protocol Buffers).",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "weak-crypto",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-328",
    "message": "Detected usage of weak crypto function. Consider using stronger alternatives.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "laravel-active-debug-code",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-489",
    "message": "Found an instance setting the APP_DEBUG environment variable to true. In your production environment, this should always be false. Otherwise, you risk exposing sensitive configuration values to potent",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "laravel-api-route-sql-injection",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "HTTP method [$METHOD] to Laravel route $ROUTE_NAME is vulnerable to SQL injection via string concatenation or unsafe interpolation.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "laravel-blade-form-missing-csrf",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-352",
    "message": "Detected a form executing a state-changing HTTP method `$METHOD` to route definition `$...ROUTE` without a Laravel CSRF decorator or explicit CSRF token implementation. If this form modifies sensitive",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "laravel-cookie-http-only",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-1004",
    "message": "Found a configuration file where the HttpOnly attribute is not set to true. Setting `http_only` to true makes sure that your cookies are inaccessible from Javascript, which mitigates XSS attacks. Inst",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "laravel-cookie-long-timeout",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-1004",
    "message": "Found a configuration file where the lifetime attribute is over 30 minutes.",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "laravel-cookie-null-domain",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-200",
    "message": "Found a configuration file where the domain attribute is not set to null. It is recommended (unless you are using sub-domain route registrations) to set this attribute to null so that only the same or",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "laravel-cookie-same-site",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-1275",
    "message": "Found a configuration file where the same_site attribute is not set to 'lax' or 'strict'. Setting 'same_site' to 'lax' or 'strict' restricts cookies to a first-party or same-site context, which will p",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "laravel-cookie-secure-set",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-614",
    "message": "Found a configuration file where the secure attribute is not set to 'true'. Setting 'secure' to 'true' prevents the client from transmitting the cookie over unencrypted channels and therefore prevents",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "laravel-dangerous-model-construction",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-915",
    "message": "Setting `$guarded` to an empty array allows mass assignment to every property in a Laravel model. This explicitly overrides Eloquent's safe-by-default mass assignment protections.",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "laravel-sql-injection",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected a SQL query based on user input. This could lead to SQL injection, which could potentially result in sensitive data being exfiltrated by attackers. Instead, use parameterized queries and prep",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "laravel-unsafe-validator",
    "language": "php",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Found a request argument passed to an `ignore()` definition in a Rule constraint. This can lead to SQL injection.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "symfony-csrf-protection-disabled",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-352",
    "message": "CSRF protection is disabled for this configuration. This is a security risk. Make sure that it is safe or consider setting `csrf_protection` property to `true`.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "symfony-non-literal-redirect",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-601",
    "message": "The `redirect()` method does not check its destination in any way. If you redirect to a URL provided by end-users, your application may be open to the unvalidated redirects security vulnerability. Con",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "symfony-permissive-cors",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-346",
    "message": "Access-Control-Allow-Origin response header is set to \"*\". This will disable CORS Same Origin Policy restrictions.",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "wp-ajax-no-auth-and-auth-hooks-audit",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-285",
    "message": "These hooks allow the developer to handle the custom AJAX endpoints.\"wp_ajax_$action\" hook get fires for any authenticated user and \"wp_ajax_nopriv_$action\" hook get fires for non-authenticated users.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "wp-authorisation-checks-audit",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-285",
    "message": "These are some of the patterns used for authorisation. Look properly if the authorisation is proper or not.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "wp-code-execution-audit",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "These functions can lead to code injection if the data inside them is user-controlled. Don't use the input directly or validate the data properly before passing it to these functions.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "wp-command-execution-audit",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-78",
    "message": "These functions can lead to command execution if the data inside them is user-controlled. Don't use the input directly or validate the data properly before passing it to these functions.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "wp-csrf-audit",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-352",
    "message": "Passing false or 0 as the third argument to this function will not cause the script to die, making the check useless.",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "wp-file-download-audit",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-73",
    "message": "These functions can be used to read to content of the files if the data inside is user-controlled. Don't use the input directly or validate the data properly before passing it to these functions.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "wp-file-inclusion-audit",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "These functions can lead to Local File Inclusion (LFI) or Remote File Inclusion (RFI) if the data inside is user-controlled. Validate the data properly before passing it to these functions.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A08:2021 - Software and Data Integrity Failures",
      "A01:2025 - Broken Access Control",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "wp-file-manipulation-audit",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "These functions can be used to delete the files if the data inside the functions are user controlled. Use these functions carefully.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A08:2021 - Software and Data Integrity Failures",
      "A01:2025 - Broken Access Control",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "wp-open-redirect-audit",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-601",
    "message": "This function can be used to redirect to user supplied URLs. If user input is not sanitised or validated, this could lead to Open Redirect vulnerabilities. Use \"wp_safe_redirect()\" to prevent this kin",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "wp-php-object-injection-audit",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "If the data used inside the patterns are directly used without proper sanitization, then this could lead to PHP Object Injection. Do not use these function with user-supplied input, use JSON functions",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "wp-sql-injection-audit",
    "language": "php",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected unsafe API methods. This could lead to SQL Injection if the used variable in the functions are user controlled and not properly escaped or sanitized. In order to prevent SQL Injection, use sa",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "wp-ssrf-audit",
    "language": "php",
    "severity": "WARNING",
    "cwe": "",
    "message": "Detected usage of vulnerable functions with user input, which could lead to SSRF vulnerabilities.",
    "category": "security",
    "owasp": "A10:2021 - Server-Side Request Forgery (SSRF)",
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "formatted-string-bashoperator",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Found a formatted string in BashOperator: $CMD. This could be vulnerable to injection. Be extra sure your variables are not controllable by external sources.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-asyncio-create-exec",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected 'create_subprocess_exec' function with argument tainted by `event` object. If this data can be controlled by a malicious actor, it may be an instance of command injection. Audit the use of th",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-asyncio-exec",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected subprocess function '$LOOP.subprocess_exec' with argument tainted by `event` object. If this data can be controlled by a malicious actor, it may be an instance of command injection. Audit the",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-asyncio-shell",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected asyncio subprocess function with argument tainted by `event` object. If this data can be controlled by a malicious actor, it may be an instance of command injection. Audit the use of this cal",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-spawn-process",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected `os` function with argument tainted by `event` object. This is dangerous if external data can reach this function call because it allows a malicious actor to execute commands. Ensure no exter",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-subprocess-use",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected subprocess function with argument tainted by an `event` object.  If this data can be controlled by a malicious actor, it may be an instance of command injection. The default option for `shell",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-system-call",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected `os` function with argument tainted by `event` object. This is dangerous if external data can reach this function call because it allows a malicious actor to execute commands. Use the 'subpro",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dynamodb-filter-injection",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-943",
    "message": "Detected DynamoDB query filter that is tainted by `$EVENT` object. This could lead to NoSQL injection if the variable is user-controlled and not properly sanitized. Explicitly assign query params inst",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "mysql-sqli",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected SQL statement that is tainted by `event` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use paramet",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "psycopg-sqli",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected SQL statement that is tainted by `event` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use paramet",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pymssql-sqli",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected SQL statement that is tainted by `event` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use paramet",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pymysql-sqli",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected SQL statement that is tainted by `event` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use paramet",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "sqlalchemy-sqli",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected SQL statement that is tainted by `event` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use paramet",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-code-exec",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Detected the use of `exec/eval`.This can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure eva",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-html-response",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected user input flowing into an HTML response. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnera",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-html-string",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-pickle-deserialization",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "Avoid using `pickle`, which is known to lead to code execution vulnerabilities. When unpickling, the serialized data could be manipulated to run arbitrary code. Instead, consider serializing the relev",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-sql-string",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injectio",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "hardcoded-token",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-798",
    "message": "A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It i",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "empty-aes-key",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Potential empty AES encryption key. Using an empty key in AES encryption can result in weak encryption and may allow attackers to easily decrypt sensitive data. Ensure that a strong, non-empty key is ",
    "category": "security",
    "owasp": "A6:2017 misconfiguration",
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-cipher-algorithm-arc4",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "ARC4 (Alleged RC4) is a stream cipher with serious weaknesses in its initial stream output.  Its use is strongly discouraged. ARC4 does not use mode constructions. Use a strong symmetric cipher such a",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-cipher-algorithm-blowfish",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Blowfish is a block cipher developed by Bruce Schneier. It is known to be susceptible to attacks when using weak keys.  The author has recommended that users of Blowfish move to newer algorithms such ",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-cipher-algorithm-idea",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "IDEA (International Data Encryption Algorithm) is a block cipher created in 1991.  It is an optional component of the OpenPGP standard. This cipher is susceptible to attacks when using weak keys.  It ",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-cipher-mode-ecb",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "ECB (Electronic Code Book) is the simplest mode of operation for block ciphers.  Each block of data is encrypted in the same way.  This means identical plaintext blocks will always result in identical",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-hash-algorithm-md5",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-hash-algorithm-sha1",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insufficient-dsa-key-size",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Detected an insufficient key size for DSA. NIST recommends a key size of 2048 or higher.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insufficient-ec-key-size",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Detected an insufficient curve size for EC. NIST recommends a key size of 224 or higher. For example, use 'ec.SECP256R1'.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insufficient-rsa-key-size",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Detected an insufficient key size for RSA. NIST recommends a key size of 2048 or higher.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "crypto-mode-without-authentication",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-327",
    "message": "An encryption mode of operation is being used without proper message authentication. This can potentially result in the encrypted content to be decrypted by an attacker. Consider instead use an AEAD m",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "require-encryption",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Initializing a security context for Dask (`distributed`) without \"require_encryption\" keyword argument may silently fail to provide security.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "avoid-insecure-deserialization",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-502",
    "message": "Avoid using insecure deserialization library, backed by `pickle`, `_pickle`, `cpickle`, `dill`, `shelve`, or `yaml`, which are known to lead to remote code execution vulnerabilities.",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "avoid-mark-safe",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "'mark_safe()' is used to mark a string as \"safe\" for HTML output. This disables escaping and could therefore subject the content to XSS attacks. Use 'django.utils.html.format_html()' to build HTML for",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-csrf-exempt",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-352",
    "message": "Detected usage of @csrf_exempt, which indicates that there is no CSRF token set for this route. This could lead to an attacker manipulating the user's account and exfiltration of private data. Instead",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "custom-expression-as-sql",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected a Custom Expression ''$EXPRESSION'' calling ''as_sql(...).'' This could lead to SQL injection, which can result in attackers exfiltrating sensitive data. Instead, ensure no user input enters ",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "missing-throttle-config",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-770",
    "message": "Django REST framework configuration is missing default rate- limiting options. This could inadvertently allow resource starvation or Denial of Service (DoS) attacks. Add 'DEFAULT_THROTTLE_CLASSES' and",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A06:2017 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "extends-custom-expression",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Found extension of custom expression: $CLASS. Extending expressions in this way could inadvertently lead to a SQL injection vulnerability, which can result in attackers exfiltrating sensitive data. In",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-query-set-extra",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "QuerySet.extra' does not provide safeguards against SQL injection and requires very careful use. SQL injection can lead to critical data being stolen by attackers. Instead of using '.extra', use the D",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-raw-sql",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected the use of 'RawSQL' or 'raw' indicating the execution of a non-parameterized SQL query. This could lead to a SQL injection and therefore protected information could be leaked. Instead, use Dj",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "django-secure-set-cookie",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-614",
    "message": "Django cookies should be handled securely by setting secure=True, httponly=True, and samesite='Lax' in response.set_cookie(...). If your situation calls for different settings, explicitly disable the ",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "debug-template-tag",
    "language": "regex",
    "severity": "WARNING",
    "cwe": "CWE-489",
    "message": "Detected a debug template tag in a Django template. This dumps debugging information to the page when debug mode is enabled. Showing debug information to users is dangerous because it may reveal infor",
    "category": "security",
    "owasp": "A06:2017 - Security Misconfiguration",
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "unvalidated-password",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-521",
    "message": "The password on '$MODEL' is being set without validating the password. Call django.contrib.auth.password_validation.validate_password() with validation functions before setting the password. See https",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "class-extends-safestring",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Found a class extending 'SafeString', 'SafeText' or 'SafeData'. These classes are for bypassing the escaping engine built in to Django and should not be used directly. Improper use of this class expos",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "context-autoescape-off",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a Context with autoescape disabled. If you are rendering any web pages, this exposes your application to cross-site scripting (XSS) vulnerabilities. Remove 'autoescape: False' or set it to 'T",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "direct-use-of-httpresponse",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected data rendered directly to the end user via 'HttpResponse' or a similar object. This bypasses Django's built-in cross-site scripting (XSS) defenses and could result in an XSS vulnerability. Us",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "filter-with-is-safe",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected Django filters flagged with 'is_safe'. 'is_safe' tells Django not to apply escaping on the value returned by this filter (although the input is escaped). Used improperly, 'is_safe' could expo",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "formathtml-fstring-parameter",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Passing a formatted string as first parameter to `format_html` disables the proper encoding of variables. Any HTML in the first parameter is not encoded. Using a formatted string as first parameter ob",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "global-autoescape-off",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Autoescape is globally disbaled for this Django application. If you are rendering any web pages, this exposes your application to cross-site scripting (XSS) vulnerabilities. Remove 'autoescape: False'",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "html-magic-method",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "The `__html__` method indicates to the Django template engine that the value is 'safe' for rendering. This means that normal HTML escaping will not be applied to the return value. This exposes your ap",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "html-safe",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "`html_safe()` add the `__html__` magic method to the provided class. The `__html__` method indicates to the Django template engine that the value is 'safe' for rendering. This means that normal HTML e",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "template-autoescape-off",
    "language": "regex",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a template block where autoescaping is explicitly disabled with '{% autoescape off %}'. This allows rendering of raw HTML in this segment. Turn autoescaping on to prevent cross-site scripting",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "template-blocktranslate-no-escape",
    "language": "generic",
    "severity": "INFO",
    "cwe": "CWE-79",
    "message": "Translated strings will not be escaped when rendered in a template. This leads to a vulnerability where translators could include malicious script tags in their translations. Consider using `force_esc",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "template-translate-as-no-escape",
    "language": "generic",
    "severity": "INFO",
    "cwe": "CWE-79",
    "message": "Translated strings will not be escaped when rendered in a template. This leads to a vulnerability where translators could include malicious script tags in their translations. Consider using `force_esc",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "template-var-unescaped-with-safeseq",
    "language": "regex",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a template variable where autoescaping is explicitly disabled with '| safeseq' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwise this ",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "django-no-csrf-token",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "",
    "message": "Manually-created forms in django templates should specify a csrf_token to prevent CSRF attacks.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "django-using-request-post-after-is-valid",
    "language": "python",
    "severity": "WARNING",
    "cwe": "",
    "message": "Use $FORM.cleaned_data[] instead of request.POST[] after form.is_valid() has been executed to only access sanitized data",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "globals-as-template-context",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-96",
    "message": "Using 'globals()' as a context to 'render(...)' is extremely dangerous. This exposes Python functions to the template that were not meant to be exposed. An attacker could use these functions to execut",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "hashids-with-django-secret",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-327",
    "message": "The Django secret key is used as salt in HashIDs. The HashID mechanism is not secure. By observing sufficient HashIDs, the salt used to construct them can be recovered. This means the Django secret ke",
    "category": "security",
    "owasp": [
      "A02:2021 \u2013 Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "globals-misuse-code-execution",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-96",
    "message": "Found request data as an index to 'globals()'. This is extremely dangerous because it allows an attacker to execute arbitrary code on the system. Refactor your code not to use 'globals()'.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "user-eval-format-string",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Found user data in a call to 'eval'. This is extremely dangerous because it can enable an attacker to execute remote code. See https://owasp.org/www-community/attacks/Code_Injection for more informati",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "user-eval",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Found user data in a call to 'eval'. This is extremely dangerous because it can enable an attacker to execute arbitrary remote code on the system. Instead, refactor your code to not use 'eval' and ins",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "user-exec-format-string",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Found user data in a call to 'exec'. This is extremely dangerous because it can enable an attacker to execute arbitrary remote code on the system. Instead, refactor your code to not use 'eval' and ins",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "user-exec",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Found user data in a call to 'exec'. This is extremely dangerous because it can enable an attacker to execute arbitrary remote code on the system. Instead, refactor your code to not use 'eval' and ins",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "command-injection-os-system",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Request data detected in os.system. This could be vulnerable to a command injection and should be avoided. If this must be done, use the 'subprocess' module instead and pass the arguments as a list. S",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "subprocess-injection",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected user input entering a `subprocess` call unsafely. This could result in a command injection vulnerability. An attacker could use this vulnerability to execute arbitrary commands on the host, w",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "csv-writer-injection",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-1236",
    "message": "Detected user input into a generated CSV file using the built-in `csv` module. If user data is used to generate the data in this file, it is possible that an attacker could inject a formula when the C",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "xss-html-email-body",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-74",
    "message": "Found request data in an EmailMessage that is set to use HTML. This is dangerous because HTML emails are susceptible to XSS. An attacker could inject data into this HTML email, causing XSS.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "xss-send-mail-html-message",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-74",
    "message": "Found request data in 'send_mail(...)' that uses 'html_message'. This is dangerous because HTML emails are susceptible to XSS. An attacker could inject data into this HTML email, causing XSS.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "mass-assignment",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-915",
    "message": "Mass assignment detected. This can result in assignment to model fields that are unintended and can be exploited by an attacker. Instead of using '**request.$W', assign each field you want to edit ind",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "open-redirect",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-601",
    "message": "Data from request ($DATA) is passed to redirect(). This is an open redirect and could be exploited. Ensure you are redirecting to safe URLs by using django.utils.http.is_safe_url(). See https://cwe.mi",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "path-traversal-file-name",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "Data from request is passed to a file name `$FILE`. This is a path traversal vulnerability, which can lead to sensitive data being leaked. To mitigate, consider using os.path.abspath or os.path.realpa",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "path-traversal-join",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "Data from request is passed to os.path.join() and to open(). This is a path traversal vulnerability, which can lead to sensitive data being leaked. To mitigate, consider using os.path.abspath or os.pa",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "path-traversal-open",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "Found request data in a call to 'open'. Ensure the request data is validated or sanitized, otherwise it could result in path traversal attacks and therefore sensitive data being leaked. To mitigate, c",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "raw-html-format",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "reflected-data-httpresponse",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Found user-controlled request data passed into HttpResponse. This could be vulnerable to XSS, leading to attackers gaining access to user cookies and protected information. Ensure that the request dat",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "reflected-data-httpresponsebadrequest",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Found user-controlled request data passed into a HttpResponseBadRequest. This could be vulnerable to XSS, leading to attackers gaining access to user cookies and protected information. Ensure that the",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "request-data-fileresponse",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "Found user-controlled request data being passed into a file open, which is them passed as an argument into the FileResponse. This is dangerous because an attacker could specify an arbitrary file to re",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "request-data-write",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-93",
    "message": "Found user-controlled request data passed into '.write(...)'. This could be dangerous if a malicious actor is able to control data into sensitive files. For example, a malicious actor could force roll",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "sql-injection-using-extra-where",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "User-controlled data from a request is passed to 'extra()'. This could lead to a SQL injection and therefore protected information could be leaked. Instead, use parameterized queries or escape the use",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "sql-injection-using-rawsql",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "User-controlled data from request is passed to 'RawSQL()'. This could lead to a SQL injection and therefore protected information could be leaked. Instead, use parameterized queries or escape the user",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "sql-injection-db-cursor-execute",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "User-controlled data from a request is passed to 'execute()'. This could lead to a SQL injection and therefore protected information could be leaked. Instead, use django's QuerySets, which are built w",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "sql-injection-using-raw",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Data that is possible user-controlled from a python request is passed to `raw()`. This could lead to SQL injection and attackers gaining access to protected information. Instead, use django's QuerySet",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "ssrf-injection-requests",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-918",
    "message": "Data from request object is passed to a new server-side request. This could lead to a server-side request forgery (SSRF). To mitigate, ensure that schemes and hosts are validated against an allowlist,",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "ssrf-injection-urllib",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-918",
    "message": "Data from request object is passed to a new server-side request. This could lead to a server-side request forgery (SSRF), which could result in attackers gaining access to private organization data. T",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-sql-string",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-915",
    "message": "Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injectio",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "tainted-url-host",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "User data flows into the host portion of this manually-constructed URL. This could allow an attacker to send data to their own server, potentially exposing sensitive data such as cookies or authorizat",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "locals-as-template-context",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-96",
    "message": "Using 'locals()' as a context to 'render(...)' is extremely dangerous. This exposes Python functions to the template that were not meant to be exposed. An attacker could use these functions to execute",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "nan-injection",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-704",
    "message": "Found user input going directly into typecast for bool(), float(), or complex(). This allows an attacker to inject Python's not-a-number (NaN) into the typecast. This results in undefind behavior, par",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "password-empty-string",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-521",
    "message": "'$VAR' is the empty string and is being used to set the password on '$MODEL'. If you meant to set an unusable password, set the password to None or call 'set_unusable_password()'.",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-none-for-password-default",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-521",
    "message": "'$VAR' is using the empty string as its default and is being used to set the password on '$MODEL'. If you meant to set an unusable password, set the default value to 'None' or call 'set_unusable_passw",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "docker-arbitrary-container-run",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-250",
    "message": "If unverified user data can reach the `run` or `create` method it can result in running arbitrary container.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "wildcard-cors",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-942",
    "message": "CORS policy allows any origin (using wildcard '*'). This is insecure and should be avoided.",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "avoid_app_run_with_bad_host",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-668",
    "message": "Running flask app with host 0.0.0.0 could expose the server publicly.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "avoid_using_app_run_directly",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-668",
    "message": "top-level app.run(...) is ignored by flask. Consider putting app.run(...) behind a guard, like inside a function",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "debug-enabled",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-489",
    "message": "Detected Flask app with debug=True. Do not deploy to production with this flag enabled as it will leak sensitive information. Instead, consider using Flask configuration variables or setting 'debug' u",
    "category": "security",
    "owasp": "A06:2017 - Security Misconfiguration",
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "directly-returned-format-string",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected Flask route directly returning a formatted string. This is subject to cross-site scripting if user input can reach the string. Consider using the template engine instead and rendering pages w",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "flask-cors-misconfiguration",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-942",
    "message": "Setting 'support_credentials=True' together with 'origin=\"*\"' is a CORS misconfiguration that can allow third party origins to read sensitive data. Using this configuration, flask_cors will dynamicall",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "flask-url-for-external-true",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-673",
    "message": "Function `flask.url_for` with `_external=True` argument will generate URLs using the `Host` header of the HTTP request, which may lead to security risks such as Host header injection",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid_hardcoded_config_TESTING",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-489",
    "message": "Hardcoded variable `TESTING` detected. Use environment variables or config files instead",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid_hardcoded_config_SECRET_KEY",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-489",
    "message": "Hardcoded variable `SECRET_KEY` detected. Use environment variables or config files instead",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid_hardcoded_config_ENV",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-489",
    "message": "Hardcoded variable `ENV` detected. Set this by using FLASK_ENV environment variable",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid_hardcoded_config_DEBUG",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-489",
    "message": "Hardcoded variable `DEBUG` detected. Set this by using FLASK_DEBUG environment variable",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "host-header-injection-python",
    "language": "python",
    "severity": "INFO",
    "cwe": "CWE-20",
    "message": "The `flask.request.host` is used to construct an HTTP request.  This can lead to host header injection issues. Vulnerabilities  that generally occur due to this issue are authentication bypasses,  pas",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "render-template-string",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-96",
    "message": "Found a template created with string formatting. This is susceptible to server-side template injection and cross-site scripting attacks.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "secure-set-cookie",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-614",
    "message": "Found a Flask cookie with insecurely configured properties.  By default the secure, httponly and samesite ar configured insecurely. cookies should be handled securely by setting `secure=True`, `httpon",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "flask-wtf-csrf-disabled",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-352",
    "message": "Setting 'WTF_CSRF_ENABLED' to 'False' explicitly disables CSRF protection.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "make-response-with-unknown-content",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Be careful with `flask.make_response()`. If this response is rendered onto a webpage, this could create a cross-site scripting (XSS) vulnerability. `flask.make_response()` will not autoescape HTML. If",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-template-string",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-96",
    "message": "Found a template created with string formatting. This is susceptible to server-side template injection and cross-site scripting attacks.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "flask-api-method-string-format",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-134",
    "message": "Method $METHOD in API controller $CLASS provides user arg $ARG to requests method $REQMETHOD",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "hashids-with-flask-secret",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-327",
    "message": "The Flask secret key is used as salt in HashIDs. The HashID mechanism is not secure. By observing sufficient HashIDs, the salt used to construct them can be recovered. This means the Flask secret key ",
    "category": "security",
    "owasp": [
      "A02:2021 \u2013 Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "csv-writer-injection",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-1236",
    "message": "Detected user input into a generated CSV file using the built-in `csv` module. If user data is used to generate the data in this file, it is possible that an attacker could inject a formula when the C",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "nan-injection",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-704",
    "message": "Found user input going directly into typecast for bool(), float(), or complex(). This allows an attacker to inject Python's not-a-number (NaN) into the typecast. This results in undefind behavior, par",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "os-system-injection",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "User data detected in os.system. This could be vulnerable to a command injection and should be avoided. If this must be done, use the 'subprocess' module instead and pass the arguments as a list.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "path-traversal-open",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-22",
    "message": "Found request data in a call to 'open'. Ensure the request data is validated or sanitized, otherwise it could result in path traversal attacks.",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "raw-html-format",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "ssrf-requests",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-918",
    "message": "Data from request object is passed to a new server-side request. This could lead to a server-side request forgery (SSRF). To mitigate, ensure that schemes and hosts are validated against an allowlist,",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "subprocess-injection",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected user input entering a `subprocess` call unsafely. This could result in a command injection vulnerability. An attacker could use this vulnerability to execute arbitrary commands on the host, w",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-sql-string",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-704",
    "message": "Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injectio",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-url-host",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "User data flows into the host portion of this manually-constructed URL. This could allow an attacker to send data to their own server, potentially exposing sensitive data such as cookies or authorizat",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "eval-injection",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-95",
    "message": "Detected user data flowing into eval. This is code injection and should be avoided.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "exec-injection",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-95",
    "message": "Detected user data flowing into exec. This is code injection and should be avoided.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-deserialization",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-502",
    "message": "Detected the use of an insecure deserialization library in a Flask route. These libraries are prone to code execution vulnerabilities. Ensure user data does not enter this function. To fix this, try t",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "open-redirect",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-601",
    "message": "Data from request is passed to redirect(). This is an open redirect and could be exploited. Consider using 'url_for()' to generate links to known locations. If you must use a URL to unknown pages, con",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid_send_file_without_path_sanitization",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-73",
    "message": "Detected a user-controlled `filename` that could flow to `flask.send_file()` function. This could lead to an attacker reading arbitrary file from the system, leaking private information. Make sure to ",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "unescaped-template-extension",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Flask does not automatically escape Jinja templates unless they have .html, .htm, .xml, or .xhtml extensions. This could lead to XSS attacks. Use .html, .htm, .xml, or .xhtml for your template extensi",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "response-contains-unsanitized-input",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Flask response reflects unsanitized user input. This could lead to a cross-site scripting vulnerability (https://owasp.org/www-community/attacks/xss/) in which an attacker causes arbitrary code to be ",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "direct-use-of-jinja2",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected direct use of jinja2. If not done properly, this may bypass HTML escaping which opens up the application to cross-site scripting (XSS) vulnerabilities. Prefer using the Flask method 'render_t",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "explicit-unescape-with-markup",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected explicitly unescaped content using 'Markup()'. This permits the unescaped data to include unescaped HTML which could result in cross-site scripting. Ensure this data is not externally control",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "template-autoescape-off",
    "language": "regex",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a segment of a Flask template where autoescaping is explicitly disabled with '{% autoescape off %}'. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, o",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "template-unescaped-with-safe",
    "language": "regex",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a segment of a Flask template where autoescaping is explicitly disabled with '| safe' filter. This allows rendering of raw HTML in this segment. Ensure no user data is rendered here, otherwis",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "template-unquoted-attribute-var",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: \"{{ $.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "incorrect-autoescape-disabled",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-116",
    "message": "Detected a Jinja2 environment with 'autoescaping' disabled. This is dangerous if you are rendering to a browser because this allows for cross-site scripting (XSS) attacks. If you are in a web context,",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "missing-autoescape-disabled",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-116",
    "message": "Detected a Jinja2 environment without autoescaping. Jinja2 does not autoescape by default. This is dangerous if you are rendering to a browser because this allows for cross-site scripting (XSS) attack",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "jwt-python-exposed-data",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-522",
    "message": "The object is passed strictly to jwt.encode(...) Make sure that sensitive information is not exposed through JWT token payload.",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "jwt-python-exposed-credentials",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-522",
    "message": "Password is exposed through JWT token payload. This is not encrypted and the password could be compromised. Do not store passwords in JWT tokens.",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "jwt-python-hardcoded-secret",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-522",
    "message": "Hardcoded JWT secret or private key is used. This is a Insufficiently Protected Credentials weakness: https://cwe.mitre.org/data/definitions/522.html Consider using an appropriate security mechanism t",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "jwt-python-none-alg",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-327",
    "message": "Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that wil",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "unverified-jwt-decode",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-287",
    "message": "Detected JWT token decoded with 'verify=False'. This bypasses any integrity checks for the token which means the token could be tampered with by malicious actors. Ensure that the JWT token is verified",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "multiprocessing-recv",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "The Connection.recv() method automatically unpickles the data it receives, which can be a security risk unless you can trust the process which sent the message. Therefore, unless the connection object",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-annotations-usage",
    "language": "python",
    "severity": "INFO",
    "cwe": "CWE-95",
    "message": "Annotations passed to `typing.get_type_hints` are evaluated in `globals` and `locals` namespaces. Make sure that no arbitrary value can be written as the annotation and passed to `typing.get_type_hint",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-asyncio-create-exec-audit",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected 'create_subprocess_exec' function without a static string. If this data can be controlled by a malicious actor, it may be an instance of command injection. Audit the use of this call to ensur",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-asyncio-create-exec-tainted-env-args",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected 'create_subprocess_exec' function with user controlled data. You may consider using 'shlex.escape()'.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-asyncio-exec-audit",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected subprocess function '$LOOP.subprocess_exec' without a static string. If this data can be controlled by a malicious actor, it may be an instance of command injection. Audit the use of this cal",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-asyncio-exec-tainted-env-args",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected subprocess function '$LOOP.subprocess_exec' with user controlled data. You may consider using 'shlex.escape()'.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-asyncio-shell-audit",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected asyncio subprocess function without a static string. If this data can be controlled by a malicious actor, it may be an instance of command injection. Audit the use of this call to ensure it i",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-asyncio-shell-tainted-env-args",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected asyncio subprocess function with user controlled data. You may consider using 'shlex.escape()'.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-interactive-code-run-audit",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Found dynamic content inside InteractiveConsole/InteractiveInterpreter method. This is dangerous if external data can reach this function call because it allows a malicious actor to run arbitrary Pyth",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-interactive-code-run-tainted-env-args",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Found user controlled data inside InteractiveConsole/InteractiveInterpreter method. This is dangerous if external data can reach this function call because it allows a malicious actor to run arbitrary",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-os-exec-audit",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Found dynamic content when spawning a process. This is dangerous if external data can reach this function call because it allows a malicious actor to execute commands. Ensure no external data reaches ",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-os-exec-tainted-env-args",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Found user controlled content when spawning a process. This is dangerous because it allows a malicious actor to execute commands.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-spawn-process-audit",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Found dynamic content when spawning a process. This is dangerous if external data can reach this function call because it allows a malicious actor to execute commands. Ensure no external data reaches ",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-spawn-process-tainted-env-args",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Found user controlled content when spawning a process. This is dangerous because it allows a malicious actor to execute commands.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-subinterpreters-run-string-audit",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Found dynamic content in `run_string`. This is dangerous if external data can reach this function call because it allows a malicious actor to run arbitrary Python code. Ensure no external data reaches",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-subinterpreters-run-string-tainted-env-args",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Found user controlled content in `run_string`. This is dangerous because it allows a malicious actor to run arbitrary Python code.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-subprocess-use-audit",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected subprocess function '$FUNC' without a static string. If this data can be controlled by a malicious actor, it may be an instance of command injection. Audit the use of this call to ensure it i",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-subprocess-use-tainted-env-args",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected subprocess function '$FUNC' with user controlled data. A malicious actor could leverage this to perform command injection. You may consider using 'shlex.quote()'.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-system-call-audit",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Found dynamic content used in a system call. This is dangerous if external data can reach this function call because it allows a malicious actor to execute commands. Use the 'subprocess' module instea",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-system-call-tainted-env-args",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Found user-controlled data used in a system call. This could allow a malicious actor to execute commands. Use the 'subprocess' module instead, which is easier to use without accidentally exposing a co",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-testcapi-run-in-subinterp-audit",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Found dynamic content in `run_in_subinterp`. This is dangerous if external data can reach this function call because it allows a malicious actor to run arbitrary Python code. Ensure no external data r",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-testcapi-run-in-subinterp-tainted-env-args",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Found user controlled content in `run_in_subinterp`. This is dangerous because it allows a malicious actor to run arbitrary Python code.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dynamic-urllib-use-detected",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-939",
    "message": "Detected a dynamic value being used with urllib. urllib supports 'file://' schemes, so a dynamic value controlled by a malicious actor may allow them to read arbitrary files. Audit uses of urllib call",
    "category": "security",
    "owasp": "A01:2017 - Injection",
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "eval-detected",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evalu",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "exec-detected",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Detected the use of exec(). exec() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evalu",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "formatted-sql-query",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected possible formatted SQL query. Use parameterized queries instead.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "hardcoded-password-default-argument",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-798",
    "message": "Hardcoded password is used as a default argument to '$FUNC'. This could be dangerous if a real password is not supplied.",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "httpsconnection-detected",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-295",
    "message": "The HTTPSConnection API has changed frequently with minor releases of Python. Ensure you are using the API for your version of Python securely. For example, Python 3 versions prior to 3.4.3 will not v",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-file-permissions",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-276",
    "message": "These permissions `$BITS` are widely permissive and grant access to more people than may be necessary. A good default is `0o644` which gives read and write access to yourself and read access to everyo",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-ftp-tls",
    "language": "python",
    "severity": "INFO",
    "cwe": "CWE-319",
    "message": "The 'FTP' class sends information unencrypted. Consider using the 'FTP_TLS' class instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "request-session-http-in-with-context",
    "language": "python",
    "severity": "INFO",
    "cwe": "CWE-319",
    "message": "Detected a request using 'http://'. This request will be unencrypted. Use 'https://' instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "request-session-with-http",
    "language": "python",
    "severity": "INFO",
    "cwe": "CWE-319",
    "message": "Detected a request using 'http://'. This request will be unencrypted. Use 'https://' instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "request-with-http",
    "language": "python",
    "severity": "INFO",
    "cwe": "CWE-319",
    "message": "Detected a request using 'http://'. This request will be unencrypted, and attackers could listen into traffic on the network and be able to obtain sensitive information. Use 'https://' instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-set-ciphers",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "The 'ssl' module disables insecure cipher suites by default. Therefore, use of 'set_ciphers()' should only be used when you have very specialized requirements. Otherwise, you risk lowering the securit",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-openerdirector-open-ftp",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Detected an unsecured transmission channel. 'OpenerDirector.open(...)' is being used with 'ftp://'. Information sent over this connection will be unencrypted. Consider using SFTP instead. urllib does ",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-openerdirector-open",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Detected an unsecured transmission channel. 'OpenerDirector.open(...)' is being used with 'http://'. Use 'https://' instead to secure the channel.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-request-object-ftp",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Detected a 'urllib.request.Request()' object using an insecure transport protocol, 'ftp://'. This connection will not be encrypted. Consider using SFTP instead. urllib does not support SFTP natively, ",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-request-object",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Detected a 'urllib.request.Request()' object using an insecure transport protocol, 'http://'. This connection will not be encrypted. Use 'https://' instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-urlopen-ftp",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Detected 'urllib.urlopen()' using 'ftp://'. This request will not be encrypted. Consider using SFTP instead. urllib does not support SFTP, so consider switching to a library which supports SFTP.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-urlopen",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Detected 'urllib.urlopen()' using 'http://'. This request will not be encrypted. Use 'https://' instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-urlopener-open-ftp",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Detected an insecure transmission channel. 'URLopener.open(...)' is being used with 'ftp://'. Use SFTP instead. urllib does not support SFTP, so consider using a library which supports SFTP.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-urlopener-open",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Detected an unsecured transmission channel. 'URLopener.open(...)' is being used with 'http://'. Use 'https://' instead to secure the channel.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-urlopener-retrieve-ftp",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Detected an insecure transmission channel. 'URLopener.retrieve(...)' is being used with 'ftp://'. Use SFTP instead. urllib does not support SFTP, so consider using a library which supports SFTP.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-urlopener-retrieve",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Detected an unsecured transmission channel. 'URLopener.retrieve(...)' is being used with 'http://'. Use 'https://' instead to secure the channel.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-urlretrieve-ftp",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Detected 'urllib.urlretrieve()' using 'ftp://'. This request will not be encrypted. Use SFTP instead. urllib does not support SFTP, so consider switching to a library which supports SFTP.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-urlretrieve",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Detected 'urllib.urlretrieve()' using 'http://'. This request will not be encrypted. Use 'https://' instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "listen-eval",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Because portions of the logging configuration are passed through eval(), use of this function may open its users to a security risk. While the function only binds to a socket on localhost, and so does",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "python-logger-credential-disclosure",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-532",
    "message": "Detected a python logger call with a potential hardcoded secret $FORMAT_STRING being logged. This may lead to secret credentials being exposed. Make sure that the logger is not logging  sensitive info",
    "category": "security",
    "owasp": [
      "A09:2021 - Security Logging and Monitoring Failures",
      "A09:2025 - Security Logging & Alerting Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "mako-templates-detected",
    "language": "python",
    "severity": "INFO",
    "cwe": "CWE-79",
    "message": "Mako templates do not provide a global HTML escaping mechanism. This means you must escape all sensitive data in your templates using '| u' for URL escaping or '| h' for HTML escaping. If you are usin",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "marshal-usage",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "The marshal module is not intended to be secure against erroneous or maliciously constructed data. Never unmarshal data received from an untrusted or unauthenticated source. See more details: https://",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "md5-used-as-password",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function ",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "avoid-bind-to-all-interfaces",
    "language": "python",
    "severity": "INFO",
    "cwe": "CWE-200",
    "message": "Running `socket.bind` to 0.0.0.0, or empty string could unexpectedly expose the server publicly as it binds to all available interfaces. Consider instead getting correct address from an environment va",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "disabled-cert-validation",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-295",
    "message": "certificate verification explicitly disabled, insecure connections possible",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "http-not-https-connection",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-319",
    "message": "Detected HTTPConnectionPool. This will transmit data in cleartext. It is recommended to use HTTPSConnectionPool instead for to encrypt communications.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "non-literal-import",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-706",
    "message": "Untrusted user input in `importlib.import_module()` function allows an attacker to load arbitrary code. Avoid dynamic values in `importlib.import_module()` or use a whitelist to prevent running untrus",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "paramiko-exec-command",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Unverified SSL context detected. This will permit insecure connections without verifying SSL certificates. Use 'ssl.create_default_context()' instead.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "paramiko-implicit-trust-host-key",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-322",
    "message": "Detected a paramiko host key policy that implicitly trusts a server's host key. Host keys should be verified to ensure the connection is not to a malicious server. Use RejectPolicy or a custom subclas",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "python-reverse-shell",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-553",
    "message": "Semgrep found a Python reverse shell using $BINPATH to $IP at $PORT",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "regex_dos",
    "language": "python",
    "severity": "WARNING",
    "cwe": "",
    "message": "Detected usage of re.compile with an inefficient regular expression. This can lead to regular expression denial of service, which can result in service down time. Instead, check all regexes or use saf",
    "category": "security",
    "owasp": "A06:2017 - Security Misconfiguration",
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "sha224-hash",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "This code uses a 224-bit hash function, which is deprecated or disallowed in some security policies. Consider updating to a stronger hash function such as SHA-384 or higher to ensure compliance and se",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aiopg-sqli",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected string concatenation with a non-literal variable in an aiopg Python SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to ",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "asyncpg-sqli",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected string concatenation with a non-literal variable in a asyncpg Python SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "pg8000-sqli",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected string concatenation with a non-literal variable in a pg8000 Python SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to ",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "psycopg-sqli",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected string concatenation with a non-literal variable in a psycopg2 Python SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order t",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ssl-wrap-socket-is-deprecated",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "'ssl.wrap_socket()' is deprecated. This function creates an insecure socket without server name indication or hostname matching. Instead, create an SSL context using 'ssl.SSLContext()' and use that to",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "subprocess-list-passed-as-string",
    "language": "python",
    "severity": "WARNING",
    "cwe": "",
    "message": "Detected `\" \".join(...)` being passed to `subprocess.run`. This can lead to argument splitting issues and potential security vulnerabilities. Instead, pass the list directly to `subprocess.run` to pre",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "subprocess-shell-true",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Found 'subprocess' function '$FUNC' with 'shell=True'. This is dangerous because this call will spawn the command using a shell process. Doing so propagates current shell settings and variables, which",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "secure default"
    ]
  },
  {
    "id": "system-wildcard-detected",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-155",
    "message": "Detected use of the wildcard character in a system call that spawns a shell. This subjects the wildcard to normal shell expansion, which can have unintended consequences if there exist any non-standar",
    "category": "security",
    "owasp": "A01:2017 - Injection",
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "telnetlib",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Telnet does not encrypt communications. Use SSH instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "weak-ssl-version",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "An insecure SSL version was detected. TLS versions 1.0, 1.1, and all SSL versions are considered weak encryption and are deprecated. Use 'ssl.PROTOCOL_TLSv1_2' or higher.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-interactive-code-run",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Found user controlled data inside InteractiveConsole/InteractiveInterpreter method. This is dangerous if external data can reach this function call because it allows a malicious actor to run arbitrary",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-globals-use",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-96",
    "message": "Found non static data as an index to 'globals()'. This is extremely dangerous because it allows an attacker to execute arbitrary code on the system. Refactor your code not to use 'globals()'.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-os-exec",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Found user controlled content when spawning a process. This is dangerous because it allows a malicious actor to execute commands.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-spawn-process",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Found user controlled content when spawning a process. This is dangerous because it allows a malicious actor to execute commands.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-subinterpreters-run-string",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Found user controlled content in `run_string`. This is dangerous because it allows a malicious actor to run arbitrary Python code.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-subprocess-use",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected subprocess function '$FUNC' with user controlled data. A malicious actor could leverage this to perform command injection. You may consider using 'shlex.escape()'.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-system-call",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Found user-controlled data used in a system call. This could allow a malicious actor to execute commands. Use the 'subprocess' module instead, which is easier to use without accidentally exposing a co",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-testcapi-run-in-subinterp",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-95",
    "message": "Found user controlled content in `run_in_subinterp`. This is dangerous because it allows a malicious actor to run arbitrary Python code.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "avoid-jsonpickle",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "Avoid using `jsonpickle`, which is known to lead to code execution vulnerabilities. When unpickling, the serialized data could be manipulated to run arbitrary code. Instead, consider serializing the r",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-pyyaml-load",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-502",
    "message": "Detected a possible YAML deserialization vulnerability. `yaml.unsafe_load`, `yaml.Loader`, `yaml.CLoader`, and `yaml.UnsafeLoader` are all known to be unsafe methods of deserializing YAML. An attacker",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-unsafe-ruamel",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-502",
    "message": "Avoid using unsafe `ruamel.yaml.YAML()`. `ruamel.yaml.YAML` can create arbitrary Python objects. A malicious actor could exploit this to run arbitrary code. Use `YAML(typ='rt')` or `YAML(typ='safe')` ",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-pickle",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "Avoid using `pickle`, which is known to lead to code execution vulnerabilities. When unpickling, the serialized data could be manipulated to run arbitrary code. Instead, consider serializing the relev",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-cPickle",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "Avoid using `cPickle`, which is known to lead to code execution vulnerabilities. When unpickling, the serialized data could be manipulated to run arbitrary code. Instead, consider serializing the rele",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-dill",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "Avoid using `dill`, which uses `pickle`, which is known to lead to code execution vulnerabilities. When unpickling, the serialized data could be manipulated to run arbitrary code. Instead, consider se",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-shelve",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "Avoid using `shelve`, which uses `pickle`, which is known to lead to code execution vulnerabilities. When unpickling, the serialized data could be manipulated to run arbitrary code. Instead, consider ",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-hash-algorithm-md5",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-hash-algorithm-sha1",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-hash-function",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Detected use of an insecure MD4 or MD5 hash function. These functions have known vulnerabilities and are considered deprecated. Consider using 'SHA256' or a similar function instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-uuid-version",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-330",
    "message": "Using UUID version 1 for UUID generation can lead to predictable UUIDs based on system information (e.g., MAC address, timestamp). This may lead to security risks such as the sandwich attack. Consider",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "unverified-ssl-context",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-295",
    "message": "Unverified SSL context detected. This will permit insecure connections without verifying SSL certificates. Use 'ssl.create_default_context' instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "use-defused-xml-parse",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-611",
    "message": "The native Python `xml` library is vulnerable to XML External Entity (XXE) attacks.  These attacks can leak confidential data and \"XML bombs\" can cause denial of service. Do not use this library to pa",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "use-defused-xml",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-611",
    "message": "The Python documentation recommends using `defusedxml` instead of `xml` because the native Python `xml` library is vulnerable to XML External Entity (XXE) attacks. These attacks can leak confidential ",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "use-defused-xmlrpc",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-776",
    "message": "Detected use of xmlrpc. xmlrpc is not inherently safe from vulnerabilities. Use defusedxml.xmlrpc instead.",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "use-defusedcsv",
    "language": "python",
    "severity": "INFO",
    "cwe": "CWE-1236",
    "message": "Detected the generation of a CSV file using the built-in `csv` module. If user data is used to generate the data in this file, it is possible that an attacker could inject a formula when the CSV is im",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-cipher-algorithm-blowfish",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Detected Blowfish cipher algorithm which is considered insecure. This algorithm is not cryptographically secure and can be reversed easily. Use secure stream ciphers such as ChaCha20, XChaCha20 and Sa",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-cipher-algorithm-des",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Detected DES cipher or Triple DES algorithm which is considered insecure. This algorithm is not cryptographically secure and can be reversed easily. Use a secure symmetric cipher from the cryptodome p",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-cipher-algorithm-rc2",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Detected RC2 cipher algorithm which is considered insecure. This algorithm is not cryptographically secure and can be reversed easily. Use secure stream ciphers such as ChaCha20, XChaCha20 and Salsa20",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-cipher-algorithm-rc4",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Detected ARC4 cipher algorithm which is considered insecure. This algorithm is not cryptographically secure and can be reversed easily. Use secure stream ciphers such as ChaCha20, XChaCha20 and Salsa2",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-cipher-algorithm-xor",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Detected XOR cipher algorithm which is considered insecure. This algorithm is not cryptographically secure and can be reversed easily. Use AES instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-hash-algorithm-md2",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Detected MD2 hash algorithm which is considered insecure. MD2 is not collision resistant and is therefore not suitable as a cryptographic signature.  Use a modern hash algorithm from the SHA-2, SHA-3,",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-hash-algorithm-md4",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Detected MD4 hash algorithm which is considered insecure. MD4 is not collision resistant and is therefore not suitable as a cryptographic signature. Use a modern hash algorithm from the SHA-2, SHA-3, ",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-hash-algorithm-md5",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature.  Use a modern hash algorithm from the SHA-2, SHA-3,",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-hash-algorithm-sha1",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insufficient-dsa-key-size",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Detected an insufficient key size for DSA. NIST recommends a key size of 2048 or higher.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insufficient-rsa-key-size",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Detected an insufficient key size for RSA. NIST recommends a key size of 3072 or higher.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "crypto-mode-without-authentication",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-327",
    "message": "An encryption mode of operation is being used without proper message authentication. This can potentially result in the encrypted content to be decrypted by an attacker. Consider instead use an AEAD m",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "mongo-client-bad-auth",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-477",
    "message": "Warning MONGODB-CR was deprecated with the release of MongoDB 3.6 and is no longer supported by MongoDB 4.0 (see https://api.mongodb.com/python/current/examples/authentication.html for details).",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pyramid-authtkt-cookie-httponly-unsafe-default",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-1004",
    "message": "Found a Pyramid Authentication Ticket cookie without the httponly option correctly set. Pyramid cookies should be handled securely by setting httponly=True. If this parameter is not properly set, your",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pyramid-authtkt-cookie-httponly-unsafe-value",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-1004",
    "message": "Found a Pyramid Authentication Ticket cookie without the httponly option correctly set. Pyramid cookies should be handled securely by setting httponly=True. If this parameter is not properly set, your",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pyramid-authtkt-cookie-samesite",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-1275",
    "message": "Found a Pyramid Authentication Ticket without the samesite option correctly set. Pyramid cookies should be handled securely by setting samesite='Lax'. If this parameter is not properly set, your cooki",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pyramid-authtkt-cookie-secure-unsafe-default",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-614",
    "message": "Found a Pyramid Authentication Ticket cookie using an unsafe default for the secure option. Pyramid cookies should be handled securely by setting secure=True. If this parameter is not properly set, yo",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pyramid-authtkt-cookie-secure-unsafe-value",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-614",
    "message": "Found a Pyramid Authentication Ticket cookie without the secure option correctly set. Pyramid cookies should be handled securely by setting secure=True. If this parameter is not properly set, your coo",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pyramid-csrf-check-disabled",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-352",
    "message": "CSRF protection is disabled for this view. This is a security risk.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "pyramid-csrf-origin-check-disabled-globally",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-352",
    "message": "Automatic check of the referrer for cross-site request forgery tokens has been explicitly disabled globally, which might leave views unprotected when an unsafe CSRF storage policy is used. Use 'pyrami",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pyramid-csrf-origin-check-disabled",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-352",
    "message": "Origin check for the CSRF token is disabled for this view. This might represent a security risk if the CSRF storage policy is not known to be secure.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pyramid-set-cookie-httponly-unsafe-default",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-1004",
    "message": "Found a Pyramid cookie using an unsafe default for the httponly option. Pyramid cookies should be handled securely by setting httponly=True in response.set_cookie(...). If this parameter is not proper",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pyramid-set-cookie-httponly-unsafe-value",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-1004",
    "message": "Found a Pyramid cookie without the httponly option correctly set. Pyramid cookies should be handled securely by setting httponly=True in response.set_cookie(...). If this parameter is not properly set",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pyramid-set-cookie-samesite-unsafe-default",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-1275",
    "message": "Found a Pyramid cookie using an unsafe value for the samesite option. Pyramid cookies should be handled securely by setting samesite='Lax' in response.set_cookie(...). If this parameter is not properl",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pyramid-set-cookie-samesite-unsafe-value",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-1275",
    "message": "Found a Pyramid cookie without the samesite option correctly set. Pyramid cookies should be handled securely by setting samesite='Lax' in response.set_cookie(...). If this parameter is not properly se",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pyramid-set-cookie-secure-unsafe-default",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-614",
    "message": "Found a Pyramid cookie using an unsafe default for the secure option. Pyramid cookies should be handled securely by setting secure=True in response.set_cookie(...). If this parameter is not properly s",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pyramid-set-cookie-secure-unsafe-value",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-614",
    "message": "Found a Pyramid cookie without the secure option correctly set. Pyramid cookies should be handled securely by setting secure=True in response.set_cookie(...). If this parameter is not properly set, yo",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pyramid-csrf-check-disabled-globally",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-352",
    "message": "Automatic check of cross-site request forgery tokens has been explicitly disabled globally, which might leave views unprotected. Use 'pyramid.config.Configurator.set_default_csrf_options(require_csrf=",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pyramid-direct-use-of-response",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-79",
    "message": "Detected data rendered directly to the end user via 'Response'. This bypasses Pyramid's built-in cross-site scripting (XSS) defenses and could result in an XSS vulnerability. Use Pyramid's template en",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pyramid-sqlalchemy-sql-injection",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Distinct, Having, Group_by, Order_by, and Filter in SQLAlchemy can cause sql injections if the developer inputs raw SQL into the before-mentioned clauses. This pattern captures relevant cases in which",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "disabled-cert-validation",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-295",
    "message": "Certificate verification has been explicitly disabled. This permits insecure connections to insecure servers. Re-enable certification validation.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-auth-over-http",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-523",
    "message": "Authentication detected over HTTP. HTTP does not provide any encryption or protection for these authentication credentials. This may expose these credentials to unauthorized parties. Use 'https://' in",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "string-concat",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Detected string concatenation or formatting in a call to a command via 'sh'. This could be a command injection vulnerability if the data is user-controlled. Instead, use a list and append the argument",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-sqlalchemy-text",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "sqlalchemy.text passes the constructed SQL statement to the database mostly unchanged. This means that the usual SQL injection protections are not applied and this function is vulnerable to SQL inject",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "sqlalchemy-execute-raw-query",
    "language": "python",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy prov",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "sqlalchemy-sql-injection",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Distinct, Having, Group_by, Order_by, and Filter in SQLAlchemy can cause sql injections if the developer inputs raw SQL into the before-mentioned clauses. This pattern captures relevant cases in which",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "twiml-injection",
    "language": "python",
    "severity": "WARNING",
    "cwe": "CWE-91",
    "message": "Using non-constant TwiML (Twilio Markup Language) argument when creating a Twilio conversation could allow the injection of additional TwiML commands",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "activerecord-sqli",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected SQL statement that is tainted by `event` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use paramet",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "mysql2-sqli",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected SQL statement that is tainted by `event` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use paramet",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pg-sqli",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected SQL statement that is tainted by `event` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use paramet",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "sequel-sqli",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected SQL statement that is tainted by `event` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use paramet",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-deserialization",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-502",
    "message": "Deserialization of a string tainted by `event` object found. Objects in Ruby can be serialized into strings, then later loaded from strings. However, uses of `load` can cause remote code execution. Lo",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-sql-string",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injectio",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "ruby-jwt-decode-without-verify",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-345",
    "message": "Detected the decoding of a JWT token without a verify step. JWT tokens must be verified before use, otherwise the token's integrity is unknown. This means a malicious actor could forge a JWT token wit",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ruby-jwt-exposed-data",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-522",
    "message": "The object is passed strictly to jsonwebtoken.sign(...) Make sure that sensitive information is not exposed through JWT token payload.",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ruby-jwt-exposed-credentials",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-522",
    "message": "Password is exposed through JWT token payload. This is not encrypted and the password could be compromised. Do not store passwords in JWT tokens.",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ruby-jwt-hardcoded-secret",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-522",
    "message": "Hardcoded JWT secret or private key is used. This is a Insufficiently Protected Credentials weakness: https://cwe.mitre.org/data/definitions/522.html Consider using an appropriate security mechanism t",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ruby-jwt-none-alg",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-327",
    "message": "Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that wil",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "sha224-hash",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-328",
    "message": "This code uses a 224-bit hash function, which is deprecated or disallowed in some security policies. Consider updating to a stronger hash function such as SHA-384 or higher to ensure compliance and se",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "bad-deserialization-env",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-502",
    "message": "Checks for unsafe deserialization. Objects in Ruby can be serialized into strings, then later loaded from strings. However, uses of load and object_load can cause remote code execution. Loading user i",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "bad-deserialization-yaml",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-502",
    "message": "Unsafe deserialization from YAML. Objects in Ruby can be serialized into strings, then later loaded from strings. However, uses of load and object_load can cause remote code execution. Loading user in",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "bad-deserialization",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-502",
    "message": "Checks for unsafe deserialization. Objects in Ruby can be serialized into strings, then later loaded from strings. However, uses of load and object_load can cause remote code execution. Loading user i",
    "category": "security",
    "owasp": [
      "A08:2017 - Insecure Deserialization",
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "cookie-serialization",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-94",
    "message": "Checks if code allows cookies to be deserialized using Marshal. If the attacker can craft a valid cookie, this could lead to remote code execution. The hybrid check is just to warn users to migrate to",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "create-with",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-915",
    "message": "Checks for strong parameter bypass through usage of create_with. Create_with bypasses strong parameter protection, which could allow attackers to set arbitrary attributes on models. To fix this vulner",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-exec",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "Detected non-static command inside $EXEC. Audit the input to '$EXEC'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-open",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "Detected non-static command inside 'open'. Audit the input to 'open'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-open3-pipeline",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "Detected non-static command inside $PIPE. Audit the input to '$PIPE'. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-subshell",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "Detected non-static command inside `...`. If unverified user data can reach this call site, this is a code injection vulnerability. A malicious actor can inject a malicious script to execute arbitrary",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-syscall",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "'syscall' is essentially unsafe and unportable. The DL (https://apidock.com/ruby/Fiddle) library is preferred for safer and a bit more portable programming.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "divide-by-zero",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-369",
    "message": "Detected a possible ZeroDivisionError.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "file-disclosure",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-22",
    "message": "Special requests can determine whether a file exists on a filesystem that's outside the Rails app's root directory. To fix this, set config.serve_static_assets = false.",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "filter-skipping",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-1021",
    "message": "Checks for use of action in Ruby routes. This can cause Rails to render an arbitrary view if an attacker creates an URL accurately. Affects 3.0 applications. Can avoid the vulnerability by providing a",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "force-ssl-false",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-311",
    "message": "Checks for configuration setting of force_ssl to false. Force_ssl forces usage of HTTPS, which could lead to network interception of unencrypted application traffic. To fix, set config.force_ssl = tru",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "hardcoded-http-auth-in-controller",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-798",
    "message": "Detected hardcoded password used in basic authentication in a controller class. Including this password in version control could expose this credential. Consider refactoring to use environment variabl",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "hardcoded-secret-rsa-passphrase",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-798",
    "message": "Found the use of an hardcoded passphrase for RSA. The passphrase can be easily discovered, and therefore should not be stored in source-code. It is recommended to remove the passphrase from source-cod",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insufficient-rsa-key-size",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "The RSA key size $SIZE is insufficent by NIST standards. It is recommended to use a key length of 2048 or higher.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "json-entity-escape",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Checks if HTML escaping is globally disabled for JSON output. This could lead to XSS.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "mass-assignment-protection-disabled",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-915",
    "message": "Mass assignment protection disabled for '$MODEL'. This could permit assignment to sensitive model fields without intention. Instead, use 'attr_accessible' for the model or disable mass assigment using",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "md5-used-as-password",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-327",
    "message": "It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Instead, use a suitable password hashing ",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "missing-csrf-protection",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-352",
    "message": "Detected controller which does not enable cross-site request forgery protections using 'protect_from_forgery'. Add 'protect_from_forgery :with => :exception' to your controller class.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "model-attr-accessible",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-915",
    "message": "Checks for dangerous permitted attributes that can lead to mass assignment vulnerabilities. Query parameters allowed using permit and attr_accessible are checked for allowance of dangerous attributes ",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "model-attributes-attr-accessible",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-915",
    "message": "Checks for models that do not use attr_accessible. This means there is no limiting of which variables can be manipulated through mass assignment. For newer Rails applications, parameters should be all",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ruby-eval",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "Use of eval with user-controllable input detected. This can lead  to attackers running arbitrary code. Ensure external data does not  reach here, otherwise this is a security vulnerability. Consider  ",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "bad-send",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-94",
    "message": "Checks for unsafe use of Object#send, try, __send__, and public_send. These only account for unsafe use of a method, not target. This can lead to arbitrary calling of exit, along with arbitrary code e",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ssl-mode-no-verify",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-295",
    "message": "Detected SSL that will accept an unverified connection. This makes the connections susceptible to man-in-the-middle attacks. Use 'OpenSSL::SSL::VERIFY_PEER' instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "mass-assignment-vuln",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-915",
    "message": "Checks for calls to without_protection during mass assignment (which allows record creation from hash values). This can lead to users bypassing permissions protections. For Rails 4 and higher, mass pr",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "weak-hashes-md5",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-328",
    "message": "Should not use md5 to generate hashes. md5 is proven to be vulnerable through the use of brute-force attacks. Could also result in collisions, leading to potential collision attacks. Use SHA256 or oth",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "weak-hashes-sha1",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-328",
    "message": "Should not use SHA1 to generate hashes. There is a proven SHA1 hash collision by Google, which could lead to vulnerabilities. Use SHA256, SHA3 or other hashing functions instead.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "avoid-logging-everything",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-532",
    "message": "Avoid logging `params` and `params.inspect` as this bypasses Rails filter_parameters and may inadvertently log sensitive data. Instead, reference specific fields to ensure only expected data is logged",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-session-manipulation",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-276",
    "message": "This gets data from session using user inputs. A malicious user may be able to retrieve information from your session that you didn't intend them to. Do not use user input as a session key.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "avoid-tainted-file-access",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "Using user input when accessing files is potentially dangerous. A malicious actor could use this to modify or access files they have no right to.",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "avoid-tainted-ftp-call",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "Using user input when accessing files is potentially dangerous. A malicious actor could use this to modify or access files they have no right to.",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "avoid-tainted-http-request",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "Using user input when accessing files is potentially dangerous. A malicious actor could use this to modify or access files they have no right to.",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "avoid-tainted-shell-call",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Using user input when accessing files is potentially dangerous. A malicious actor could use this to modify or access files they have no right to.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "detailed-exceptions",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-200",
    "message": "Found that the setting for providing detailed exception reports in Rails is set to true. This can lead to information exposure, where sensitive system or internal information is displayed to the end u",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "rails-skip-forgery-protection",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-352",
    "message": "This call turns off CSRF protection allowing CSRF attacks against the application",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ruby-pg-sqli",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Detected string concatenation with a non-literal variable in a pg Ruby SQL statement. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to preven",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "avoid-content-tag",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "'content_tag()' bypasses HTML escaping for some portion of the content. If external data can reach here, this exposes your application to cross-site scripting (XSS) attacks. Ensure no external data re",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-default-routes",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-276",
    "message": "Default routes are enabled in this routes file. This means any public method on a controller can be called as an action. It is very easy to accidentally expose a method you didn't mean to. Instead, re",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-html-safe",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "'html_safe()' does not make the supplied string safe. 'html_safe()' bypasses HTML escaping. If external data can reach here, this exposes your application to cross-site scripting (XSS) attacks. Ensure",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-link-to",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "This code includes user input in `link_to`. In Rails 2.x, the body of `link_to` is not escaped. This means that user input which reaches the body will be executed when the HTML is rendered. Even in ot",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "avoid-raw",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "'raw()' bypasses HTML escaping. If external data can reach here, this exposes your application to cross-site scripting (XSS) attacks. If you must do this, construct individual strings and mark them as",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-redirect",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-601",
    "message": "When a redirect uses user input, a malicious user can spoof a website under a trusted URL or access restricted parts of a site. When using user-supplied values, sanitize the value before using it for ",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "avoid-render-dynamic-path",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "Avoid rendering user input. It may be possible for a malicious user to input a path that lets them access a template they shouldn't. To prevent this, check dynamic template paths against a predefined ",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "avoid-render-inline",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "'render inline: ...' renders an entire ERB template inline and is dangerous. If external data can reach here, this exposes your application to server-side template injection (SSTI) or cross-site scrip",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-render-text",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "'render text: ...' actually sets the content-type to 'text/html'. If external data can reach here, this exposes your application to cross-site scripting (XSS) attacks. Instead, use 'render plain: ...'",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "manual-template-creation",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected manual creation of an ERB template. Manual creation of templates may expose your application to server-side template injection (SSTI) or cross-site scripting (XSS) attacks if user input is us",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "alias-for-html-safe",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "The syntax `<%== ... %>` is an alias for `html_safe`. This means the content inside these tags will be rendered as raw HTML. This may expose your application to cross-site scripting. If you need raw H",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-content-tag",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "'content_tag' exhibits unintuitive escaping behavior and may accidentally expose your application to cross-site scripting. If using Rails 2, only attribute values are escaped. If using Rails 3, conten",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-html-safe",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "'html_safe' renders raw HTML. This means that normal HTML escaping is bypassed. If user data can be controlled here, this exposes your application to cross-site scripting (XSS). If you need to do this",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "avoid-raw",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "'raw' renders raw HTML, as the name implies. This means that normal HTML escaping is bypassed. If user data can be controlled here, this exposes your application to cross-site scripting (XSS). If you ",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-link-to",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a template variable used in 'link_to'. This will generate dynamic data in the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scri",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "unquoted-attribute",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a unquoted template variable as an attribute. If unquoted, a malicious actor could inject custom JavaScript handlers. To fix this, add quotes around the template expression, like this: \"<%= e",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "var-in-href",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If usi",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "var-in-script-tag",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a template variable used in a script tag. Although template variables are HTML escaped, HTML escaping does not always prevent cross-site scripting (XSS) attacks when used directly in JavaScri",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "libxml-backend",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-611",
    "message": "This application is using LibXML as the XML backend. LibXML can be vulnerable to XML External Entities (XXE) vulnerabilities. Use the built-in Rails XML parser, REXML, instead.",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "xml-external-entities-enabled",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-611",
    "message": "This application is explicitly enabling external entities enabling an attacker to inject malicious XML to exploit an XML External Entities (XXE) vulnerability. This could let the attacker cause a deni",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "check-before-filter",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-284",
    "message": "Disabled-by-default Rails controller checks make it much easier to introduce access control mistakes. Prefer an allowlist approach with `:only => [...]` rather than `except: => [...]`",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "check-cookie-store-session-security-attributes",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-1004",
    "message": "Found a Rails `cookie_store` session configuration setting the `$KEY` attribute to `false`. If using a cookie-based session store, the HttpOnly and Secure flags should be set.",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "check-dynamic-render-local-file-include",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "Found request parameters in a call to `render` in a dynamic context. This can allow end users to request arbitrary local files which may result in leaking sensitive information persisted on disk.",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "check-http-verb-confusion",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-650",
    "message": "Found an improperly constructed control flow block with `request.get?`. Rails will route HEAD requests as GET requests but they will fail the `request.get?` check, potentially causing unexpected behav",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "check-permit-attributes-high",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-915",
    "message": "Calling `permit` on security-critical properties like `$ATTRIBUTE` may leave your application vulnerable to mass assignment.",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "check-permit-attributes-medium",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-915",
    "message": "Calling `permit` on security-critical properties like `$ATTRIBUTE` may leave your application vulnerable to mass assignment.",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "check-rails-secret-yaml",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-540",
    "message": "$VALUE Found a string literal assignment to a production Rails session secret in `secrets.yaml`. Do not commit secret values to source control! Any user in possession of this value may falsify arbitra",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "check-rails-session-secret-handling",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-540",
    "message": "Found a string literal assignment to a Rails session secret `$KEY`. Do not commit secret values to source control! Any user in possession of this value may falsify arbitrary session data in your appli",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "check-redirect-to",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-601",
    "message": "Found potentially unsafe handling of redirect behavior $X. Do not pass `params` to `redirect_to` without the `:only_path => true` hash value.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "check-regex-dos",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-1333",
    "message": "Found a potentially user-controllable argument in the construction of a regular expressions. This may result in excessive resource consumption when applied to certain inputs, or when the user is allow",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "check-render-local-file-include",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "Found request parameters in a call to `render`. This can allow end users to request arbitrary local files which may result in leaking sensitive information persisted on disk. Where possible, avoid let",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "check-reverse-tabnabbing",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-1022",
    "message": "Setting an anchor target of `_blank` without the `noopener` or `noreferrer` attribute allows reverse tabnabbing on Internet Explorer, Opera, and Android Webview.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "check-secrets",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-200",
    "message": "Found a Brakeman-style secret - a variable with the name password/secret/api_key/rest_auth_site_key and a non-empty string literal value.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "check-send-file",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-73",
    "message": "Allowing user input to `send_file` allows a malicious user to potentially read arbitrary files from the server. Avoid accepting user input in `send_file` or normalize with `File.basename(...)`",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "check-sql",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Found potential SQL injection due to unsafe SQL query construction via $X. Where possible, prefer parameterized queries.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "check-unsafe-reflection-methods",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-94",
    "message": "Found user-controllable input to a reflection method. This may allow a user to alter program behavior and potentially execute arbitrary instructions in the context of the process. Do not provide arbit",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "check-unsafe-reflection",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-94",
    "message": "Found user-controllable input to Ruby reflection functionality. This allows a remote user to influence runtime behavior, up to and including arbitrary remote code execution. Do not provide user-contro",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "check-unscoped-find",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-639",
    "message": "Found an unscoped `find(...)` with user-controllable input. If the ActiveRecord model being searched against is sensitive, this may lead to Insecure Direct Object Reference (IDOR) behavior and allow u",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "check-validation-regex",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-185",
    "message": "$V Found an incorrectly-bounded regex passed to `validates_format_of` or `validate ... format => ...`. Ruby regex behavior is multiline by default and lines should be terminated by `\\A` for beginning ",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "raw-html-format",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-sql-string",
    "language": "ruby",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injectio",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-url-host",
    "language": "ruby",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "User data flows into the host portion of this manually-constructed URL. This could allow an attacker to send data to their own server, potentially exposing sensitive data such as cookies or authorizat",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "jwt-scala-hardcode",
    "language": "scala",
    "severity": "WARNING",
    "cwe": "CWE-522",
    "message": "Hardcoded JWT secret or private key is used. This is a Insufficiently Protected Credentials weakness: https://cwe.mitre.org/data/definitions/522.html Consider using an appropriate security mechanism t",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "dangerous-seq-run",
    "language": "scala",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Found dynamic content used for the external process. This is dangerous if arbitrary data can reach this function call because it allows a malicious actor to execute commands. Ensure your variables are",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dangerous-shell-run",
    "language": "scala",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Found dynamic content used for the external process. This is dangerous if arbitrary data can reach this function call because it allows a malicious actor to execute commands. Ensure your variables are",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "dispatch-ssrf",
    "language": "scala",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "A parameter being passed directly into `url` most likely lead to SSRF. This could allow an attacker to send data to their own server, potentially exposing sensitive data sent with this request. They c",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "documentbuilder-dtd-enabled",
    "language": "scala",
    "severity": "WARNING",
    "cwe": "CWE-611",
    "message": "Document Builder being instantiated without calling the `setFeature` functions that are generally used for disabling entity processing. User controlled data in XML Document builder can result in XML I",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "insecure-random",
    "language": "scala",
    "severity": "WARNING",
    "cwe": "CWE-330",
    "message": "Flags the use of a predictable random value from `scala.util.Random`. This can lead to vulnerabilities when used in security contexts, such as in a CSRF token, password reset token, or any other secre",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "io-source-ssrf",
    "language": "scala",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "A parameter being passed directly into `fromURL` most likely lead to SSRF. This could allow an attacker to send data to their own server, potentially exposing sensitive data sent with this request. Th",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "path-traversal-fromfile",
    "language": "scala",
    "severity": "WARNING",
    "cwe": "CWE-22",
    "message": "Flags cases of possible path traversal. If an unfiltered parameter is passed into 'fromFile', file from an arbitrary filesystem location could be read. This could lead to sensitive data exposure and o",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "rsa-padding-set",
    "language": "scala",
    "severity": "WARNING",
    "cwe": "CWE-780",
    "message": "Usage of RSA without OAEP (Optimal Asymmetric Encryption Padding) may weaken encryption. This could lead to sensitive data exposure. Instead, use RSA with `OAEPWithMD5AndMGF1Padding` instead.",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "sax-dtd-enabled",
    "language": "scala",
    "severity": "WARNING",
    "cwe": "CWE-611",
    "message": "XML processor being instantiated without calling the `setFeature` functions that are generally used for disabling entity processing. User controlled data in XML Parsers can result in XML Internal Enti",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "scala-dangerous-process-run",
    "language": "scala",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Found dynamic content used for the external process. This is dangerous if arbitrary data can reach this function call because it allows a malicious actor to execute commands. Use `Seq(...)` for dynami",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "scalac-debug",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-489",
    "message": "Scala applications built with `debug` set to true in production may leak debug information to attackers. Debug mode also affects performance and reliability. Remove it from configuration.",
    "category": "security",
    "owasp": "A05:2021 - Security Misconfiguration",
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "scalaj-http-ssrf",
    "language": "scala",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "A parameter being passed directly into `Http` can likely lead to SSRF. This could allow an attacker to send data to their own server, potentially exposing sensitive data sent with this request. They c",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "scalajs-eval",
    "language": "scala",
    "severity": "WARNING",
    "cwe": "CWE-94",
    "message": "`eval()` function evaluates JavaScript code represented as a string. Executing JavaScript from a string is an enormous security risk. It is far too easy for a bad actor to run arbitrary code when you ",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-sql-string",
    "language": "scala",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "User data flows into this manually-constructed SQL string. User data can be safely inserted into SQL strings using prepared statements or an object-relational mapper (ORM). Manually-constructed SQL st",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "xmlinputfactory-dtd-enabled",
    "language": "scala",
    "severity": "WARNING",
    "cwe": "CWE-611",
    "message": "XMLInputFactory being instantiated without calling the setProperty functions that are generally used for disabling entity processing. User controlled data in XML Document builder can result in XML Int",
    "category": "security",
    "owasp": [
      "A04:2017 - XML External Entities (XXE)",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "conf-csrf-headers-bypass",
    "language": "generic",
    "severity": "ERROR",
    "cwe": "CWE-352",
    "message": "Possibly bypassable CSRF configuration found. CSRF is an attack that forces an end user to execute unwanted actions on a web application in which they\u2019re currently authenticated. Make sure that Conten",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "conf-insecure-cookie-settings",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-614",
    "message": "Session cookie `Secure` flag is explicitly disabled. The `secure` flag for cookies prevents the client from transmitting the cookie over insecure channels such as HTTP. Set the `Secure` flag by settin",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-html-response",
    "language": "scala",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a request with potential user-input going into an `Ok()` response. This bypasses any view or template environments, including HTML escaping, which may expose this application to cross-site sc",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-slick-sqli",
    "language": "scala",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Detected a tainted SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Avoid using using user input for generating SQL strings.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tainted-sql-from-http-request",
    "language": "scala",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "User data flows into this manually-constructed SQL string. User data can be safely inserted into SQL strings using prepared statements or an object-relational mapper (ORM). Manually-constructed SQL st",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "twirl-html-var",
    "language": "generic",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Raw html content controlled by a variable detected. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulner",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "webservice-ssrf",
    "language": "scala",
    "severity": "WARNING",
    "cwe": "CWE-918",
    "message": "A parameter being passed directly into `WSClient` most likely lead to SSRF. This could allow an attacker to send data to their own server, potentially exposing sensitive data sent with this request. T",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "scala-jwt-hardcoded-secret",
    "language": "scala",
    "severity": "ERROR",
    "cwe": "CWE-522",
    "message": "Hardcoded JWT secret or private key is used. This is a Insufficiently Protected Credentials weakness: https://cwe.mitre.org/data/definitions/522.html Consider using an appropriate security mechanism t",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "scala-slick-overrideSql-literal",
    "language": "scala",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Avoid using non literal values in `overrideSql(...)`.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "scala-slick-sql-non-literal",
    "language": "scala",
    "severity": "ERROR",
    "cwe": "CWE-89",
    "message": "Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Avoid using `#$variable` and use `$variable` in `sql\"...\"",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "accessible-selfdestruct",
    "language": "solidity",
    "severity": "ERROR",
    "cwe": "",
    "message": "Contract can be destructed by anyone in $FUNC",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "arbitrary-low-level-call",
    "language": "solidity",
    "severity": "ERROR",
    "cwe": "",
    "message": "An attacker may perform call() to an arbitrary address with controlled calldata",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "arbitrary-send-erc20",
    "language": "solidity",
    "severity": "WARNING",
    "cwe": "CWE-285",
    "message": "msg.sender is not being used when calling erc20.transferFrom. Example - Alice approves this contract to spend her ERC20 tokens. Bob can call function 'a' and specify Alice's address as the from parame",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "balancer-readonly-reentrancy-getpooltokens",
    "language": "solidity",
    "severity": "ERROR",
    "cwe": "",
    "message": "$VAULT.getPoolTokens() call on a Balancer pool is not protected from the read-only reentrancy.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "balancer-readonly-reentrancy-getrate",
    "language": "solidity",
    "severity": "ERROR",
    "cwe": "",
    "message": "$VAR.getRate() call on a Balancer pool is not protected from the read-only reentrancy.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "basic-arithmetic-underflow",
    "language": "solidity",
    "severity": "INFO",
    "cwe": "",
    "message": "Possible arithmetic underflow",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "basic-oracle-manipulation",
    "language": "solidity",
    "severity": "INFO",
    "cwe": "",
    "message": "Price oracle can be manipulated via flashloan",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "compound-borrowfresh-reentrancy",
    "language": "solidity",
    "severity": "WARNING",
    "cwe": "",
    "message": "Function borrowFresh() in Compound performs state update after doTransferOut()",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "compound-sweeptoken-not-restricted",
    "language": "solidity",
    "severity": "WARNING",
    "cwe": "",
    "message": "Function sweepToken is allowed to be called by anyone",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "curve-readonly-reentrancy",
    "language": "solidity",
    "severity": "ERROR",
    "cwe": "",
    "message": "$POOL.get_virtual_price() call on a Curve pool is not protected from the read-only reentrancy.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "delegatecall-to-arbitrary-address",
    "language": "solidity",
    "severity": "ERROR",
    "cwe": "",
    "message": "An attacker may perform delegatecall() to an arbitrary address.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "encode-packed-collision",
    "language": "solidity",
    "severity": "ERROR",
    "cwe": "",
    "message": "abi.encodePacked hash collision with variable length arguments in $F()",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "erc20-public-burn",
    "language": "solidity",
    "severity": "ERROR",
    "cwe": "",
    "message": "Anyone can burn tokens of other accounts",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "erc20-public-transfer",
    "language": "solidity",
    "severity": "WARNING",
    "cwe": "",
    "message": "Custom ERC20 implementation exposes _transfer() as public",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "erc677-reentrancy",
    "language": "solidity",
    "severity": "WARNING",
    "cwe": "",
    "message": "ERC677 callAfterTransfer() reentrancy",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "erc721-arbitrary-transferfrom",
    "language": "solidity",
    "severity": "WARNING",
    "cwe": "",
    "message": "Custom ERC721 implementation lacks access control checks in _transfer()",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "erc721-reentrancy",
    "language": "solidity",
    "severity": "WARNING",
    "cwe": "",
    "message": "ERC721 onERC721Received() reentrancy",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "erc777-reentrancy",
    "language": "solidity",
    "severity": "WARNING",
    "cwe": "",
    "message": "ERC777 tokensReceived() reentrancy",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "gearbox-tokens-path-confusion",
    "language": "solidity",
    "severity": "WARNING",
    "cwe": "",
    "message": "UniswapV3 adapter implemented incorrect extraction of path parameters",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "incorrect-use-of-blockhash",
    "language": "solidity",
    "severity": "ERROR",
    "cwe": "",
    "message": "blockhash(block.number) and blockhash(block.number + N) always returns 0.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "keeper-network-oracle-manipulation",
    "language": "solidity",
    "severity": "WARNING",
    "cwe": "",
    "message": "Keep3rV2.current() call has high data freshness, but it has low security,  an exploiter simply needs to manipulate 2 data points to be able to impact the feed.",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "missing-self-transfer-check-ercx",
    "language": "solidity",
    "severity": "ERROR",
    "cwe": "",
    "message": "Missing check for 'from' and 'to' being the same before updating balances could lead to incorrect balance manipulation on self-transfers. Include a check to ensure 'from' and 'to' are not the same bef",
    "category": "security",
    "owasp": [
      "A7:2021 Identification and Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "msg-value-multicall",
    "language": "solidity",
    "severity": "ERROR",
    "cwe": "",
    "message": "$F with constant msg.value can be called multiple times",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "no-bidi-characters",
    "language": "solidity",
    "severity": "WARNING",
    "cwe": "",
    "message": "The code must not contain any of Unicode Direction Control Characters",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-slippage-check",
    "language": "solidity",
    "severity": "ERROR",
    "cwe": "",
    "message": "No slippage check in a Uniswap v2/v3 trade",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "openzeppelin-ecdsa-recover-malleable",
    "language": "solidity",
    "severity": "WARNING",
    "cwe": "",
    "message": "Potential signature malleability in $F",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "oracle-price-update-not-restricted",
    "language": "solidity",
    "severity": "ERROR",
    "cwe": "",
    "message": "Oracle price data can be submitted by anyone",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "proxy-storage-collision",
    "language": "solidity",
    "severity": "WARNING",
    "cwe": "",
    "message": "Proxy declares a state var that may override a storage slot of the implementation",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "redacted-cartel-custom-approval-bug",
    "language": "solidity",
    "severity": "ERROR",
    "cwe": "",
    "message": "transferFrom() can steal allowance of other accounts",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "rigoblock-missing-access-control",
    "language": "solidity",
    "severity": "ERROR",
    "cwe": "",
    "message": "setMultipleAllowances() is missing onlyOwner modifier",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "sense-missing-oracle-access-control",
    "language": "solidity",
    "severity": "ERROR",
    "cwe": "",
    "message": "Oracle update is not restricted in $F()",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "superfluid-ctx-injection",
    "language": "solidity",
    "severity": "ERROR",
    "cwe": "",
    "message": "A specially crafted calldata may be used to impersonate other accounts",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "tecra-coin-burnfrom-bug",
    "language": "solidity",
    "severity": "ERROR",
    "cwe": "",
    "message": "Parameter \"from\" is checked at incorrect position in \"_allowances\" mapping",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "uniswap-callback-not-protected",
    "language": "solidity",
    "severity": "WARNING",
    "cwe": "",
    "message": "Uniswap callback is not protected",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "unrestricted-transferownership",
    "language": "solidity",
    "severity": "ERROR",
    "cwe": "",
    "message": "Unrestricted transferOwnership",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "swift-potential-sqlite-injection",
    "language": "swift",
    "severity": "WARNING",
    "cwe": "CWE-89",
    "message": "Potential Client-side SQL injection which has different impacts depending on the SQL use-case. The impact may include the circumvention of local authentication mechanisms, obtaining of sensitive data ",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-athena-client-can-disable-workgroup-encryption",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-311",
    "message": "The Athena workgroup configuration can be overriden by client-side settings. The client can make changes to disable encryption settings. Enforce the configuration to prevent client overrides.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-athena-database-unencrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-311",
    "message": "The Athena database is unencrypted at rest. These databases are generally derived from data in S3 buckets and should have the same level of at rest protection. The AWS KMS encryption key protects data",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-athena-workgroup-unencrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-311",
    "message": "The AWS Athena Work Group is unencrypted. The AWS KMS encryption key protects backups in the work group. To create your own, create a aws_kms_key resource or use the ARN string of a key in your accoun",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-backup-vault-unencrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "The AWS Backup vault is unencrypted. The AWS KMS encryption key protects backups in the Backup vault. To create your own, create a aws_kms_key resource or use the ARN string of a key in your account.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-insecure-cloudfront-distribution-tls-version",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Detected an AWS CloudFront Distribution with an insecure TLS version. TLS versions less than 1.2 are considered insecure because they can be broken. To fix this, set your `minimum_protocol_version` to",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-cloudtrail-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure CloudTrail logs are encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-cloudwatch-log-group-no-retention",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "The AWS CloudWatch Log Group has no retention. Missing retention in log groups can cause losing important event information.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-cloudwatch-log-group-unencrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-732",
    "message": "By default, AWS CloudWatch Log Group is encrypted using AWS-managed keys. However, for added security, it's recommended to configure your own AWS KMS encryption key to protect your log group in CloudW",
    "category": "security",
    "owasp": [
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-codebuild-artifacts-unencrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-311",
    "message": "The CodeBuild project artifacts are unencrypted. All artifacts produced by your CodeBuild project pipeline should be encrypted to prevent them from being read if compromised.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-codebuild-project-artifacts-unencrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "The AWS CodeBuild Project Artifacts are unencrypted. The AWS KMS encryption key protects artifacts in the CodeBuild Projects. To create your own, create a aws_kms_key resource or use the ARN string of",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-codebuild-project-unencrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "The AWS CodeBuild Project is unencrypted. The AWS KMS encryption key protects projects in the CodeBuild. To create your own, create a aws_kms_key resource or use the ARN string of a key in your accoun",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-config-aggregator-not-all-regions",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-778",
    "message": "The AWS configuration aggregator does not aggregate all AWS Config region. This may result in unmonitored configuration in regions that are thought to be unused. Configure the aggregator with all_regi",
    "category": "security",
    "owasp": [
      "A09:2021 - Security Logging and Monitoring Failures",
      "A09:2025 - Security Logging & Alerting Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-db-instance-no-logging",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-311",
    "message": "Database instance has no logging. Missing logs can cause missing important event information.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-docdb-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure DocDB is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-documentdb-auditing-disabled",
    "language": "hcl",
    "severity": "INFO",
    "cwe": "CWE-778",
    "message": "Auditing is not enabled for DocumentDB. To ensure that you are able to accurately audit the usage of your DocumentDB cluster, you should enable auditing and export logs to CloudWatch.",
    "category": "security",
    "owasp": [
      "A09:2021 - Security Logging and Monitoring Failures",
      "A09:2025 - Security Logging & Alerting Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-documentdb-storage-unencrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-311",
    "message": "The AWS DocumentDB cluster is unencrypted. The data could be read if the underlying disks are compromised. You should enable storage encryption.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-dynamodb-point-in-time-recovery-disabled",
    "language": "hcl",
    "severity": "INFO",
    "cwe": "CWE-221",
    "message": "Point-in-time recovery is not enabled for the DynamoDB table. DynamoDB tables should be protected against accidental or malicious write/delete actions. By enabling point-in-time-recovery you can resto",
    "category": "security",
    "owasp": [
      "A09:2021 \u2013 Security Logging and Monitoring Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-dynamodb-table-unencrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "By default, AWS DynamoDB Table is encrypted using AWS-managed keys. However, for added security, it's recommended to configure your own AWS KMS encryption key to protect your data in the DynamoDB tabl",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-ebs-snapshot-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure EBS Snapshot is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-ebs-unencrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "The AWS EBS is unencrypted. The AWS EBS encryption protects data in the EBS.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-ebs-volume-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure EBS Volume is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-ebs-volume-unencrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-311",
    "message": "The AWS EBS volume is unencrypted. The volume, the disk I/O and any derived snapshots could be read if compromised. Volumes should be encrypted to ensure sensitive data is stored securely.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-ec2-has-public-ip",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "EC2 instances should not have a public IP address attached in order to block public access to the instances. To fix this, set your `associate_public_ip_address` to `\"false\"`.",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-ec2-launch-configuration-ebs-block-device-unencrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-311",
    "message": "The AWS launch configuration EBS block device is unencrypted. The block device could be read if compromised. Block devices should be encrypted to ensure sensitive data is held securely at rest.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-ec2-launch-template-metadata-service-v1-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1390",
    "message": "The EC2 launch template has Instance Metadata Service Version 1 (IMDSv1) enabled. IMDSv2 introduced session authentication tokens which improve security when talking to IMDS. You should either disable",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-ec2-security-group-allows-public-ingress",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "The security group rule allows ingress from public internet. Opening up ports to the public internet is potentially dangerous. You should restrict access to IP addresses or ranges that explicitly requ",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-ec2-security-group-rule-missing-description",
    "language": "hcl",
    "severity": "INFO",
    "cwe": "CWE-223",
    "message": "The AWS security group rule is missing a description, or its description is empty or the default value.  Security groups rules should include a meaningful description in order to simplify auditing, de",
    "category": "security",
    "owasp": [
      "A09:2021 - Security Logging and Monitoring Failures",
      "A09:2025 - Security Logging & Alerting Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-ecr-image-scanning-disabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-223",
    "message": "The ECR repository has image scans disabled. Repository image scans should be enabled to ensure vulnerable software can be discovered and remediated as soon as possible.",
    "category": "security",
    "owasp": [
      "A09:2021 - Security Logging and Monitoring Failures",
      "A09:2025 - Security Logging & Alerting Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-ecr-mutable-image-tags",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-345",
    "message": "The ECR repository allows tag mutability. Image tags could be overwritten with compromised images. ECR images should be set to IMMUTABLE to prevent code injection through image mutation. This can be d",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software or Data Integrity Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-ecr-repository-wildcard-principal",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-732",
    "message": "Detected wildcard access granted in your ECR repository policy principal. This grants access to all users, including anonymous users (public access). Instead, limit principals, actions and resources t",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-efs-filesystem-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure EFS filesystem is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-elasticsearch-insecure-tls-version",
    "language": "terraform",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Detected an AWS Elasticsearch domain using an insecure version of TLS. To fix this, set \"tls_security_policy\" equal to \"Policy-Min-TLS-1-2-2019-07\".",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-elasticsearch-nodetonode-encryption-not-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Ensure all Elasticsearch has node-to-node encryption enabled.\t",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-elb-access-logs-not-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "ELB has no logging. Missing logs can cause missing important event information.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-emr-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure EMR is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-fsx-lustre-filesystem-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-200",
    "message": "Ensure FSX Lustre file system is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-fsx-lustre-filesystem-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-311",
    "message": "Ensure FSX Lustre file system is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-fsx-ontapfs-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure FSX ONTAP file system is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-fsx-windows-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure FSX Windows file system is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-glacier-vault-any-principal",
    "language": "hcl",
    "severity": "ERROR",
    "cwe": "CWE-732",
    "message": "Detected wildcard access granted to Glacier Vault. This means anyone within your AWS account ID can perform actions on Glacier resources. Instead, limit to a specific identity in your account, like th",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-iam-admin-policy-ssoadmin",
    "language": "hcl",
    "severity": "ERROR",
    "cwe": "CWE-732",
    "message": "Detected admin access granted in your policy. This means anyone with this policy can perform administrative actions. Instead, limit actions and resources to what you need according to least privilege.",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-iam-admin-policy",
    "language": "hcl",
    "severity": "ERROR",
    "cwe": "CWE-732",
    "message": "Detected admin access granted in your policy. This means anyone with this policy can perform administrative actions. Instead, limit actions and resources to what you need according to least privilege.",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-imagebuilder-component-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure ImageBuilder component is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-insecure-api-gateway-tls-version",
    "language": "terraform",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Detected AWS API Gateway to be using an insecure version of TLS. To fix this issue make sure to set \"security_policy\" equal to \"TLS_1_2\".",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-insecure-redshift-ssl-configuration",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Detected an AWS Redshift configuration with a SSL disabled. To fix this, set your `require_ssl` to `\"true\"`.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-kinesis-stream-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure Kinesis stream is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-kinesis-stream-unencrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-311",
    "message": "The AWS Kinesis stream does not encrypt data at rest. The data could be read if the Kinesis stream storage layer is compromised. Enable Kinesis stream server-side encryption.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-kinesis-video-stream-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure Kinesis video stream is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-kms-key-wildcard-principal",
    "language": "hcl",
    "severity": "ERROR",
    "cwe": "CWE-732",
    "message": "Detected wildcard access granted in your KMS key. This means anyone with this policy can perform administrative actions over the keys. Instead, limit principals, actions and resources to what you need",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-kms-no-rotation",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "The AWS KMS has no rotation. Missing rotation can cause leaked key to be used by attackers. To fix this, set a `enable_key_rotation`.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-lambda-environment-credentials",
    "language": "hcl",
    "severity": "ERROR",
    "cwe": "CWE-326",
    "message": "A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It i",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-lambda-environment-unencrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "By default, the AWS Lambda Environment is encrypted using AWS-managed keys. However, for added security, it's recommended to configure your own AWS KMS encryption key to protect your environment varia",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-lambda-permission-unrestricted-source-arn",
    "language": "hcl",
    "severity": "ERROR",
    "cwe": "CWE-732",
    "message": "The AWS Lambda permission has an AWS service principal but does not specify a source ARN. If you grant permission to a service principal without specifying the source, other accounts could potentially",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-lambda-x-ray-tracing-not-active",
    "language": "hcl",
    "severity": "INFO",
    "cwe": "CWE-778",
    "message": "The AWS Lambda function does not have active X-Ray tracing enabled. X-Ray tracing enables end-to-end debugging and analysis of all function activity. This makes it easier to trace the flow of logs and",
    "category": "security",
    "owasp": [
      "A09:2021 Security Logging and Monitoring Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-network-acl-allows-all-ports",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ingress and/or egress is allowed for all ports in the network ACL rule. Ensure access to specific required ports is allowed, and nothing else.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-network-acl-allows-public-ingress",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "The network ACL rule allows ingress from public internet. Opening up ACLs to the public internet is potentially dangerous. You should restrict access to IP addresses or ranges that explicitly require ",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-opensearchserverless-encrypted-with-cmk",
    "language": "terraform",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure opensearch serverless is encrypted at rest using AWS KMS (Key Management Service) CMK (Customer Managed Keys). CMKs give you control over the encryption key in terms of access and rotation.",
    "category": "security",
    "owasp": [
      "A2:2021 Cryptographic Failures",
      "A5:2021 Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-provider-static-credentials",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-798",
    "message": "A hard-coded credential was detected. It is not recommended to store credentials in source-code, as this risks secrets being leaked and used by either an internal or external malicious adversary. It i",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-provisioner-exec",
    "language": "terraform",
    "severity": "WARNING",
    "cwe": "CWE-77",
    "message": "Provisioners are a tool of last resort and should be avoided where possible. Provisioner behavior cannot be mapped by Terraform as part of a plan, and execute arbitrary shell commands by design.",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A01:2017 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-rds-backup-no-retention",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "The AWS RDS has no retention. Missing retention can cause losing important event information. To fix this, set a `backup_retention_period`.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-redshift-cluster-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure AWS Redshift cluster is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-s3-bucket-object-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure S3 bucket object is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-s3-object-copy-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure S3 object copies are encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-sagemaker-domain-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure AWS Sagemaker domains are encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-secretsmanager-secret-unencrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "By default, AWS SecretManager secrets are encrypted using AWS-managed keys. However, for added security, it's recommended to configure your own AWS KMS encryption key to protect your secrets in the Se",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-sns-topic-unencrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-311",
    "message": "The AWS SNS topic is unencrypted. The SNS topic messages could be read if compromised. The AWS KMS encryption key protects topic contents. To create your own, create a aws_kms_key resource or use the ",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-sqs-queue-policy-wildcard-action",
    "language": "hcl",
    "severity": "INFO",
    "cwe": "CWE-732",
    "message": "Wildcard used in your SQS queue policy action. SQS queue policies should always grant least privilege - that is, only grant the permissions required to perform a specific task. Implementing least priv",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-sqs-queue-policy-wildcard-principal",
    "language": "hcl",
    "severity": "ERROR",
    "cwe": "CWE-732",
    "message": "Wildcard used in your SQS queue policy principal. This grants access to all users, including anonymous users (public access). Unless you explicitly require anyone on the internet to be able to read or",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "aws-sqs-queue-unencrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-311",
    "message": "The AWS SQS queue contents are unencrypted. The data could be read if compromised. Enable server-side encryption for your queue using SQS-managed encryption keys (SSE-SQS), or using your own AWS KMS k",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-ssm-document-logging-issues",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "The AWS SSM logs are unencrypted or disabled. Please enable logs and use AWS KMS encryption key to protect SSM logs. To create your own, create a aws_kms_key resource or use the ARN string of a key in",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-subnet-has-public-ip-address",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Resources in the AWS subnet are assigned a public IP address. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your appl",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-timestream-database-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure Timestream database is encrypted at rest using KMS CMKs. CMKs gives you control over the encryption key in terms of access and rotation.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-transfer-server-is-public",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Transfer Server endpoint type should not have public or null configured in order to block public access. To fix this, set your `endpoint_type` to `\"VPC\"`.",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-workspaces-root-volume-unencrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "The AWS Workspace root volume is unencrypted. The AWS KMS encryption key protects root volume. To create your own, create a aws_kms_key resource or use the ARN string of a key in your account.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "aws-workspaces-user-volume-unencrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "The AWS Workspace user volume is unencrypted. The AWS KMS encryption key protects user volume. To create your own, create a aws_kms_key resource or use the ARN string of a key in your account.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "insecure-load-balancer-tls-version",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Detected an AWS load balancer with an insecure TLS version. TLS versions less than 1.2 are considered insecure because they can be broken. To fix this, set your `ssl_policy` to `\"ELBSecurityPolicy-TLS",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "missing-athena-workgroup-encryption",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "The AWS Athena Workgroup is unencrypted. Encryption protects query results in your workgroup. To enable, add: `encryption_configuration { encryption_option = \"SSE_KMS\" kms_key_arn =  aws_kms_key.examp",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "unrestricted-github-oidc-policy",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "`$POLICY` is missing a `condition` block which scopes users of this policy to specific GitHub repositories. Without this, `$POLICY` is open to all users on GitHub. Add a `condition` block on the varia",
    "category": "security",
    "owasp": [
      "A05:2017 - Sensitive Data Exposure",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "wildcard-assume-role",
    "language": "hcl",
    "severity": "ERROR",
    "cwe": "CWE-250",
    "message": "Detected wildcard access granted to sts:AssumeRole. This means anyone with your AWS account ID and the name of the role can assume the role. Instead, limit to a specific identity in your account, like",
    "category": "security",
    "owasp": [
      "A06:2017 - Security Misconfiguration",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "azure-securitycenter-contact-emails",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "",
    "message": "Ensure that Security contact emails is set",
    "category": "best-practice",
    "owasp": [],
    "subcategory": []
  },
  {
    "id": "azure-securitycenter-contact-phone",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "",
    "message": "Ensure that Security contact Phone number is set",
    "category": "best-practice",
    "owasp": [],
    "subcategory": []
  },
  {
    "id": "azure-securitycenter-email-alert-admins",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "",
    "message": "Ensure that Send email notification for high severity alerts is set to On",
    "category": "best-practice",
    "owasp": [],
    "subcategory": []
  },
  {
    "id": "azure-securitycenter-standard-pricing",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "",
    "message": "Ensure that standard pricing tier is selected",
    "category": "best-practice",
    "owasp": [],
    "subcategory": []
  },
  {
    "id": "azure-aks-apiserver-auth-ip-ranges",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure AKS has an API Server Authorized IP Ranges enabled\t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-aks-private-clusters-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that AKS enables private clusters\t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-aks-uses-disk-encryptionset",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure that AKS uses disk encryption set",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-apiservices-use-virtualnetwork",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that API management services use virtual networks",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "appservice-account-identity-registered",
    "language": "hcl",
    "severity": "INFO",
    "cwe": "CWE-287",
    "message": "Registering the identity used by an App with AD allows it to interact with other services without using username and password. Set the `identity` block in your appservice.",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "appservice-authentication-enabled",
    "language": "hcl",
    "severity": "ERROR",
    "cwe": "CWE-287",
    "message": "Enabling authentication ensures that all communications in the application are authenticated. The `auth_settings` block needs to be filled out with the appropriate auth backend settings",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "appservice-enable-http2",
    "language": "hcl",
    "severity": "INFO",
    "cwe": "CWE-444",
    "message": "Use the latest version of HTTP to ensure you are benefiting from security fixes. Add `http2_enabled = true` to your appservice resource block",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "appservice-enable-https-only",
    "language": "hcl",
    "severity": "ERROR",
    "cwe": "CWE-319",
    "message": "By default, clients can connect to App Service by using both HTTP or HTTPS. HTTP should be disabled enabling the HTTPS Only setting.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "appservice-require-client-cert",
    "language": "hcl",
    "severity": "INFO",
    "cwe": "CWE-295",
    "message": "Detected an AppService that was not configured to use a client certificate. Add `client_cert_enabled = true` in your resource block.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "appservice-use-secure-tls-policy",
    "language": "hcl",
    "severity": "ERROR",
    "cwe": "CWE-326",
    "message": "Detected an AppService that was not configured to use TLS 1.2. Add `site_config.min_tls_version = \"1.2\"` in your resource block.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "azure-appservice-auth",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure App Service Authentication is set on Azure App Service",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-appservice-client-certificate",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Ensure the web app has Client Certificates",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-appservice-detailed-errormessages-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-778",
    "message": "Ensure that App service enables detailed error messages",
    "category": "security",
    "owasp": [
      "A10:2017 - Insufficient Logging & Monitoring",
      "A09:2021 - Security Logging and Monitoring Failures",
      "A09:2025 - Security Logging & Alerting Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "azure-appservice-disallowed-cors",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-942",
    "message": "Ensure that CORS disallows every resource to access app services",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-appservice-enabled-failed-request",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-778",
    "message": "Ensure that App service enables failed request tracing",
    "category": "security",
    "owasp": [
      "A10:2017 - Insufficient Logging & Monitoring",
      "A09:2021 - Security Logging and Monitoring Failures",
      "A09:2025 - Security Logging & Alerting Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-appservice-http-logging-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-778",
    "message": "Ensure that App service enables HTTP logging",
    "category": "security",
    "owasp": [
      "A10:2017 - Insufficient Logging & Monitoring",
      "A09:2021 - Security Logging and Monitoring Failures",
      "A09:2025 - Security Logging & Alerting Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-appservice-https-only",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service Slot",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "azure-appservice-identity",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure App Service Authentication is set on Azure App Service",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-appservice-identityprovider-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Managed identity provider is enabled for app services",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-appservice-min-tls-version",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Ensure web app is using the latest version of TLS encryption",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-automation-encrypted",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure that Automation account variables are encrypted",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-batchaccount-uses-keyvault-encrpytion",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure that Azure Batch account uses key vault to encrypt data",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-cognitiveservices-disables-public-network",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Cognitive Services accounts disable public network access",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-containergroup-deployed-into-virtualnetwork",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Azure Container group is deployed into virtual network",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-cosmosdb-accounts-restricted-access",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Cosmos DB accounts have restricted access",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-cosmosdb-disable-access-key-write",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Cosmos DB accounts have access key write capability disabled",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-cosmosdb-disables-public-network",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Azure Cosmos DB disables public network access",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-cosmosdb-have-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure that Cosmos DB accounts have customer-managed keys to encrypt data at rest",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-customrole-definition-subscription-owner",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that no custom subscription owner roles are created",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-dataexplorer-double-encryption-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure that Azure Data Explorer uses double encryption",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-dataexplorer-uses-disk-encryption",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure that Azure Data Explorer uses disk encryption",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-datafactory-no-public-network-access",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Azure Data factory public network access is disabled",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-datafactory-uses-git-repository",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Azure Data Factory uses Git repository for source control",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-datalake-store-encryption",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure that Data Lake Store accounts enables encryption",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-eventgrid-domain-network-access",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Azure Event Grid Domain public network access is disabled",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-functionapp-disallow-cors",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-942",
    "message": "ensure that CORS disallows all resources to access Function app",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-functionapps-enable-auth",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that function apps enables Authentication",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-instance-extensions",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Virtual Machine Extensions are not Installed",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-iot-no-public-network-access",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Azure IoT Hub disables public network access",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-key-backedby-hsm",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure that key vault key is backed by HSM",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-key-no-expiration-date",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure that the expiration date is set on all keys",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "azure-managed-disk-encryption-set",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure that managed disks use a specific set of disk encryption sets for the customer-managed key encryption",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-managed-disk-encryption",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure Azure managed disk has encryption enabled",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-mariadb-public-access-disabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure public network access enabled is set to False for MariaDB servers",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-monitor-log-profile-retention-days",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "",
    "message": "Ensure that Activity Log Retention is set 365 days or greater",
    "category": "best-practice",
    "owasp": [],
    "subcategory": []
  },
  {
    "id": "azure-mssql-service-mintls-version",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Ensure MSSQL is using the latest version of TLS encryption",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "azure-mysql-encryption-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure that MySQL server enables infrastructure encryption",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "azure-mysql-mintls-version",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Ensure MySQL is using the latest version of TLS encryption",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "azure-mysql-public-access-disabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure public network access enabled is set to False for MySQL servers",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-network-watcher-flowlog-period",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "",
    "message": "Ensure that Network Security Group Flow Log retention period is 90 days or greater",
    "category": "best-practice",
    "owasp": [],
    "subcategory": []
  },
  {
    "id": "azure-postgresql-encryption-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure that PostgreSQL server enables infrastructure encryption",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-postgresql-min-tls-version",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Ensure PostgreSQL is using the latest version of TLS encryption",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-postgresql-server-public-access-disabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure public network access enabled is set to False for PostgreSQL servers",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-redis-cache-enable-non-ssl-port",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Ensure that only SSL are enabled for Cache for Redis",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-redis-cache-public-network-access-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Azure Cache for Redis disables public network access",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-remote-debugging-not-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that remote debugging is not enabled for app services",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-scale-set-password",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Virtual machine does not enable password authentication",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-search-publicnetwork-access-disabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Azure Cognitive Search disables public network access",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-service-fabric-cluster-protection-level",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure that Service Fabric use three levels of protection available",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-sqlserver-no-public-access",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure no SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-sqlserver-public-access-disabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that SQL server disables public network access",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-storage-account-disable-public-access",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure default network access rule for Storage Accounts is set to deny",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-storage-account-minimum-tlsversion",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Ensure Storage Account is using the latest version of TLS encryption",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-storage-blob-service-container-private-access",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Public access level is set to Private for blob containers",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-storage-sync-public-access-disabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Azure File Sync disables public network access",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "azure-vmencryption-at-host-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure that Virtual machine scale sets have encryption at host enabled",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "functionapp-authentication-enabled",
    "language": "hcl",
    "severity": "INFO",
    "cwe": "CWE-287",
    "message": "Enabling authentication ensures that all communications in the application are authenticated. The `auth_settings` block needs to be filled out with the appropriate auth backend settings",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "functionapp-enable-http2",
    "language": "hcl",
    "severity": "INFO",
    "cwe": "CWE-444",
    "message": "Use the latest version of HTTP to ensure you are benefiting from security fixes. Add `http2_enabled = true` to your function app resource block",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "keyvault-content-type-for-secret",
    "language": "hcl",
    "severity": "INFO",
    "cwe": "",
    "message": "Key vault Secret should have a content type set",
    "category": "correctness",
    "owasp": [],
    "subcategory": []
  },
  {
    "id": "keyvault-ensure-key-expires",
    "language": "hcl",
    "severity": "INFO",
    "cwe": "CWE-262",
    "message": "Ensure that the expiration date is set on all keys",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "keyvault-ensure-secret-expires",
    "language": "hcl",
    "severity": "INFO",
    "cwe": "CWE-262",
    "message": "Ensure that the expiration date is set on all secrets",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "keyvault-purge-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-693",
    "message": "Key vault should have purge protection enabled",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "keyvault-specify-network-acl",
    "language": "hcl",
    "severity": "ERROR",
    "cwe": "CWE-1220",
    "message": "Network ACLs allow you to reduce your exposure to risk by limiting what can access your key vault. The default action of the Network ACL should be set to deny for when IPs are not matched. Azure servi",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "storage-allow-microsoft-service-bypass",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Some Microsoft services that interact with storage accounts operate from networks that can't be granted access through network rules. To help this type of service work as intended, allow the set of tr",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "storage-default-action-deny",
    "language": "hcl",
    "severity": "ERROR",
    "cwe": "CWE-16",
    "message": "Detected a Storage that was not configured to deny action by default. Add `default_action = \"Deny\"` in your resource block.",
    "category": "security",
    "owasp": [
      "A06:2017 - Security Misconfiguration",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "storage-enforce-https",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Detected a Storage that was not configured to deny action by default. Add `enable_https_traffic_only = true` in your resource block.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "storage-queue-services-logging",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-778",
    "message": "Storage Analytics logs detailed information about successful and failed requests to a storage service. This information can be used to monitor individual requests and to diagnose issues with a storage",
    "category": "security",
    "owasp": [
      "A10:2017 - Insufficient Logging & Monitoring",
      "A09:2021 - Security Logging and Monitoring Failures",
      "A09:2025 - Security Logging & Alerting Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "storage-use-secure-tls-policy",
    "language": "hcl",
    "severity": "ERROR",
    "cwe": "CWE-326",
    "message": "Azure Storage currently supports three versions of the TLS protocol: 1.0, 1.1, and 1.2. Azure Storage uses TLS 1.2 on public HTTPS endpoints, but TLS 1.0 and TLS 1.1 are still supported for backward c",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "gcp-artifact-registry-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure Artifact Registry Repositories are encrypted with Customer Supplied Encryption Keys (CSEK)",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-artifact-registry-private-repo-iam-binding",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Artifact Registry repositories are not anonymously or publicly accessible\t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-artifact-registry-private-repo-iam-member",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Artifact Registry repositories are not anonymously or publicly accessible\t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-bigquery-dataset-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure that BigQuery datasets are not anonymously or publicly accessible\t",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-bigquery-private-table-iam-binding",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that BigQuery Tables are not anonymously or publicly accessible\t\t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-bigquery-private-table-iam-member",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that BigQuery Tables are not anonymously or publicly accessible\t\t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-bigquery-table-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure Big Query Tables are encrypted with Customer Supplied Encryption Keys (CSEK)\t",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-bigtable-instance-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure Big Table Instances are encrypted with Customer Supplied Encryption Keys (CSEK)\t",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-build-workers-private",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Cloud build workers are private\t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-cloud-storage-logging",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-778",
    "message": "Ensure bucket logs access.",
    "category": "security",
    "owasp": [
      "A10:2017 - Insufficient Logging & Monitoring",
      "A09:2021 - Security Logging and Monitoring Failures",
      "A09:2025 - Security Logging & Alerting Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "gcp-compute-boot-disk-encryption",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-311",
    "message": "Ensure VM disks for critical VMs are encrypted with Customer Supplied Encryption Keys (CSEK)",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-compute-disk-encryption",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-311",
    "message": "Ensure VM disks for critical VMs are encrypted with Customer Supplied Encryption Keys (CSEK)",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-compute-firewall-unrestricted-ingress-20",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Google compute firewall ingress does not allow unrestricted FTP access",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-compute-firewall-unrestricted-ingress-21",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Google compute firewall ingress does not allow unrestricted FTP access",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-compute-firewall-unrestricted-ingress-22",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Google compute firewall ingress does not allow unrestricted SSH access",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-compute-firewall-unrestricted-ingress-3306",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Google compute firewall ingress does not allow unrestricted MySQL access",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-compute-firewall-unrestricted-ingress-3389",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Google compute firewall ingress does not allow unrestricted RDP access",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-compute-firewall-unrestricted-ingress-80",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Google compute firewall ingress does not allow unrestricted HTTP access",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-compute-ip-forward",
    "language": "hcl",
    "severity": "INFO",
    "cwe": "CWE-1220",
    "message": "Ensure that IP forwarding is not enabled on Instances. This lets the instance act as a traffic router and receive traffic not intended for it, which may route traffic through unintended passages.\t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-compute-os-login",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that no instance in the project overrides the project setting for enabling OSLogin (OSLogin needs to be enabled in project metadata for all instances)\t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-compute-project-os-login",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure oslogin is enabled for a Project\t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-compute-public-ip",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Compute instances do not have public IP addresses\t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-compute-serial-ports",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure 'Enable connecting to serial ports' is not enabled for VM Instance\t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-compute-ssl-policy",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-compute-template-ip-forward",
    "language": "hcl",
    "severity": "INFO",
    "cwe": "CWE-1220",
    "message": "Ensure that IP forwarding is not enabled on Instances. This lets the instance act as a traffic router and receive traffic not intended for it, which may route traffic through unintended passages.",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-compute-template-public-ip",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Compute instances do not have public IP addresses\t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-dataflow-job-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure data flow jobs are encrypted with Customer Supplied Encryption Keys (CSEK)",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-dataflow-private-job",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Dataflow jobs are private",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-datafusion-private-instance",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Data fusion instances are private",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-datafusion-stack-driver-logging",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Datafusion has stack driver logging enabled.",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-datafusion-stack-driver-monitoring",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Ensure Datafusion has stack driver monitoring enabled.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-dataproc-cluster-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure Dataproc cluster is encrypted with Customer Supplied Encryption Keys (CSEK)\t",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-dataproc-cluster-public-ip",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Dataproc Clusters do not have public IPs",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-dataproc-private-cluster-iam-binding",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Dataproc clusters are not anonymously or publicly accessible",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-dataproc-private-cluster-iam-member",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Dataproc clusters are not anonymously or publicly accessible",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-dns-key-specs-rsasha1",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Ensure that RSASHA1 is not used for the zone-signing and key-signing keys in Cloud DNS DNSSEC\t",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "gcp-folder-impersonation-roles-iam-binding",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure no roles that enable to impersonate and manage all service accounts are used at a folder level\t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-folder-impersonation-roles-iam-member",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure no roles that enable to impersonate and manage all service accounts are used at a folder level\t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-folder-member-default-service-account-iam-binding",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Default Service account is not used at a folder level",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-folder-member-default-service-account-iam-member",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Default Service account is not used at a folder level",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-gke-basic-auth",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure GKE basic auth is disabled\t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-gke-client-certificate-disabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure client certificate authentication to Kubernetes Engine Clusters is disabled",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-gke-cluster-logging",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure logging is set to Enabled on Kubernetes Engine Clusters",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-gke-enabled-vpc-flow-logs",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Enable VPC Flow Logs and Intranode Visibility",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-gke-ensure-integrity-monitoring",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Integrity Monitoring for Shielded GKE Nodes is Enabled",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-gke-kubernetes-rbac-google-groups",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Manage Kubernetes RBAC users with Google Groups for GKE",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-gke-legacy-auth-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Legacy Authorization is set to Disabled on Kubernetes Engine Clusters",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-gke-legacy-instance-metadata-disabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure legacy Compute Engine instance metadata APIs are Disabled",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-gke-master-authz-networks-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure master authorized networks is set to enabled in GKE clusters",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-gke-monitoring-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure monitoring is set to Enabled on Kubernetes Engine Clusters",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-gke-network-policy-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Network Policy is enabled on Kubernetes Engine Clusters",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-gke-nodepool-integrity-monitoring",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Integrity Monitoring for Shielded GKE Nodes is Enabled",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-gke-pod-security-policy-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure PodSecurityPolicy controller is enabled on the Kubernetes Engine Clusters",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-gke-private-cluster-config",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Kubernetes Cluster is created with Private cluster enabled",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-gke-public-control-plane",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure GKE Control Plane is not public",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-gke-secure-boot-for-shielded-nodes",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "",
    "message": "Ensure Secure Boot for Shielded GKE Nodes is Enabled\t",
    "category": "best-practice",
    "owasp": [],
    "subcategory": []
  },
  {
    "id": "gcp-insecure-load-balancer-tls-version",
    "language": "terraform",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Detected GCP Load Balancer to be using an insecure version of TLS. To fix this set your \"min_tls_version\" to \"TLS_1_2\"",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-kms-prevent-destroy",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure KMS keys are protected from deletion",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-memory-store-for-redis-auth-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Memorystore for Redis has AUTH enabled",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-memory-store-for-redis-intransit-encryption",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Memorystore for Redis uses intransit encryption",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-org-impersonation-roles-iam-binding",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure no roles that enable to impersonate and manage all service accounts are used at an organization level\t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-org-impersonation-roles-iam-member",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure no roles that enable to impersonate and manage all service accounts are used at an organization level\t",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-org-member-default-service-account-iam-binding",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure default service account is not used at an organization level",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-org-member-default-service-account-iam-member",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure default service account is not used at an organization level",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-project-default-network",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that the default network does not exist in a project. Set auto_create_network to `false`.",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-project-member-default-service-account-iam-binding",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Default Service account is not used at a project level",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-project-member-default-service-account-iam-member",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Default Service account is not used at a project level",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-project-service-account-user-iam-binding",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-project-service-account-user-iam-member",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-pubsub-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure PubSub Topics are encrypted with Customer Supplied Encryption Keys (CSEK)",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-pubsub-private-topic-iam-binding",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Pub/Sub Topics are not anonymously or publicly accessible",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-pubsub-private-topic-iam-member",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Pub/Sub Topics are not anonymously or publicly accessible",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-run-private-service-iam-binding",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that GCP Cloud Run services are not anonymously or publicly accessible",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-run-private-service-iam-member",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that GCP Cloud Run services are not anonymously or publicly accessible",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-spanner-database-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure Spanner Database is encrypted with Customer Supplied Encryption Keys (CSEK)",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-sql-database-require-ssl",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Ensure all Cloud SQL database instance requires all incoming connections to use SSL",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "gcp-sql-database-ssl-insecure-value-postgres-mysql",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Ensure all Cloud SQL database instance require incoming connections to use SSL. To enable this for PostgresSQL and MySQL, use `ssl_mode=\"TRUSTED_CLIENT_CERTIFICATE_REQUIRED\"`.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "gcp-sql-database-ssl-insecure-value-sqlserver",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-326",
    "message": "Ensure all Cloud SQL database instance require incoming connections to use SSL. For SQL Server, `ssl_mode=\"ENCRYPTED_ONLY\"` is the most secure value that is supported.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "gcp-sql-public-database",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Cloud SQL database Instances are not open to the world",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "gcp-sqlserver-no-public-ip",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Cloud SQL database does not have public IP",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-storage-bucket-not-public-iam-binding",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Container Registry repositories are not anonymously or publicly accessible",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-storage-bucket-not-public-iam-member",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Container Registry repositories are not anonymously or publicly accessible",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-storage-bucket-uniform-access",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that Cloud Storage buckets have uniform bucket-level access enabled. Setting `uniform_bucket_level_access` to `true` ensures that access is managed uniformly at the bucket level, which improves",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-sub-network-logging-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-sub-network-private-google-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure that private_ip_google_access is enabled for Subnet",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-vertexai-dataset-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure Vertex AI datasets uses a CMK (Customer Manager Key)",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-vertexai-metadata-store-encrypted-with-cmk",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-320",
    "message": "Ensure Vertex AI Metadata Store uses a CMK (Customer Manager Key)",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "gcp-vertexai-private-instance",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "Ensure Vertex AI instances are private",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "ec2-imdsv1-optional",
    "language": "hcl",
    "severity": "ERROR",
    "cwe": "CWE-918",
    "message": "AWS EC2 Instance allowing use of the IMDSv1",
    "category": "security",
    "owasp": [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "ecr-image-scan-on-push",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1104",
    "message": "The ECR Repository isn't configured to scan images on push",
    "category": "security",
    "owasp": [
      "A06:2021 - Vulnerable and Outdated Components",
      "A03:2025 - Software Supply Chain Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "eks-insufficient-control-plane-logging",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-778",
    "message": "Missing EKS control plane logging. It is recommended to enable at least Kubernetes API server component logs (\"api\") and audit logs (\"audit\") of the EKS control plane through the enabled_cluster_log_t",
    "category": "security",
    "owasp": [
      "A10:2017 - Insufficient Logging & Monitoring",
      "A09:2021 - Security Logging and Monitoring Failures",
      "A09:2025 - Security Logging & Alerting Failures"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "eks-public-endpoint-enabled",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-200",
    "message": "The vpc_config resource inside the eks cluster has not explicitly disabled public endpoint access",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "elastic-search-encryption-at-rest",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-311",
    "message": "Encryption at rest is not enabled for the elastic search domain resource",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-iam-admin-privileges",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-269",
    "message": "IAM policies that allow full \"*-*\" admin privileges violates the principle of least privilege. This allows an attacker to take full control over all AWS account resources. Instead, give each user more",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-iam-creds-exposure",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-200",
    "message": "Ensure IAM policies don't allow credentials exposure. Credentials exposure actions return credentials as part of the API response, and can possibly lead to leaking important credentials. Instead, use ",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-iam-data-exfiltration",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-200",
    "message": "Ensure that IAM policies don't allow data exfiltration actions that are not resource-constrained. This can allow the user to read sensitive data they don't need to read. Instead, make sure that the us",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-iam-priv-esc-funcs",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-250",
    "message": "Ensure that actions that can result in privilege escalation are not used. These actions could potentially result in an attacker gaining full administrator access of an AWS account. Try not to use thes",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-iam-priv-esc-other-users",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-269",
    "message": "Ensure that IAM policies with permissions on other users don't allow for privilege escalation. This can lead to an attacker gaining full administrator access of AWS accounts. Instead, specify which us",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-iam-priv-esc-roles",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-269",
    "message": "Ensure that groups of actions that include iam:PassRole and could result in privilege escalation are not all allowed for the same user. These actions could result in an attacker gaining full admin acc",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-iam-resource-exposure",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-200",
    "message": "Ensure IAM policies don't allow resource exposure. These actions can expose AWS resources to the public. For example `ecr:SetRepositoryPolicy` could let an attacker retrieve container images. Instead,",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-iam-star-actions",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-269",
    "message": "Ensure that no IAM policies allow \"*\" as a statement's actions. This allows all actions to be performed on the specified resources, and is a violation of the principle of least privilege. Instead, spe",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "rds-insecure-password-storage-in-source-code",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-522",
    "message": "RDS instance or cluster with hardcoded credentials in source code. It is recommended to pass the credentials at runtime, or generate random credentials using the random_password resource.",
    "category": "security",
    "owasp": [
      "A02:2017 - Broken Authentication",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "rds-public-access",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-1220",
    "message": "RDS instance accessible from the Internet detected.",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "all-origins-allowed",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-942",
    "message": "CORS rule on bucket permits any origin",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "s3-public-read-bucket",
    "language": "hcl",
    "severity": "WARNING",
    "cwe": "CWE-200",
    "message": "S3 bucket with public read access detected.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "s3-public-rw-bucket",
    "language": "hcl",
    "severity": "ERROR",
    "cwe": "CWE-200",
    "message": "S3 bucket with public read-write access detected.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "s3-unencrypted-bucket",
    "language": "hcl",
    "severity": "INFO",
    "cwe": "CWE-311",
    "message": "This rule has been deprecated, as all s3 buckets are encrypted by default with no way to disable it. See https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_si",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "angular-bypasssecuritytrust",
    "language": "typescript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected the use of `$TRUST`. This can introduce a Cross-Site-Scripting (XSS) vulnerability if this comes from user-provided input. If you have to use `$TRUST`, ensure it does not come from user-input",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "cors-regex-wildcard",
    "language": "ts",
    "severity": "WARNING",
    "cwe": "CWE-183",
    "message": "Unescaped '.' character in CORS domain regex $CORS: $PATTERN",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "nestjs-header-cors-any",
    "language": "typescript",
    "severity": "WARNING",
    "cwe": "CWE-183",
    "message": "Access-Control-Allow-Origin response header is set to \"*\". This will disable CORS Same Origin Policy restrictions.",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "nestjs-header-xss-disabled",
    "language": "typescript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "X-XSS-Protection header is set to 0. This will disable the browser's XSS Filter.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "nestjs-open-redirect",
    "language": "typescript",
    "severity": "WARNING",
    "cwe": "CWE-601",
    "message": "Untrusted user input in {url: ...} can result in Open Redirect vulnerability.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "react-dangerouslysetinnerhtml",
    "language": "typescript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detection of dangerouslySetInnerHTML from non-constant definition. This can inadvertently expose users to cross-site scripting (XSS) attacks if this comes from user-provided input. If you have to use ",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "react-href-var",
    "language": "typescript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detected a variable used in an anchor tag with the 'href' attribute. A malicious actor may be able to input the 'javascript:' URI, which could cause cross-site scripting (XSS). It is recommended to di",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "react-jwt-decoded-property",
    "language": "typescript",
    "severity": "INFO",
    "cwe": "CWE-922",
    "message": "Property decoded from JWT token without verifying and cannot be trustworthy.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "react-jwt-in-localstorage",
    "language": "typescript",
    "severity": "INFO",
    "cwe": "CWE-922",
    "message": "Storing JWT tokens in localStorage known to be a bad practice, consider moving your tokens from localStorage to a HTTP cookie.",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "react-unsanitized-method",
    "language": "typescript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detection of $HTML from non-constant definition. This can inadvertently expose users to cross-site scripting (XSS) attacks if this comes from user-provided input. If you have to use $HTML, consider us",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "react-unsanitized-property",
    "language": "typescript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Detection of $HTML from non-constant definition. This can inadvertently expose users to cross-site scripting (XSS) attacks if this comes from user-provided input. If you have to use $HTML, consider us",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "react-insecure-request",
    "language": "typescript",
    "severity": "ERROR",
    "cwe": "CWE-319",
    "message": "Unencrypted request over HTTP detected.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "react-markdown-insecure-html",
    "language": "typescript",
    "severity": "WARNING",
    "cwe": "CWE-79",
    "message": "Overwriting `transformLinkUri` or `transformImageUri` to something insecure, or turning `allowDangerousHtml` on, or turning `escapeHtml` off, will open the code up to XSS vectors.",
    "category": "security",
    "owasp": [
      "A07:2017 - Cross-Site Scripting (XSS)",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "argo-workflow-parameter-command-injection",
    "language": "yaml",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Using input or workflow parameters in here-scripts can lead to command injection or code injection. Convert the parameters to env variables instead.",
    "category": "security",
    "owasp": [
      "A03:2021 \u2013 Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "exposing-docker-socket-volume",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-250",
    "message": "Exposing host's Docker socket to containers via a volume. The owner of this socket is root. Giving someone access to it is equivalent to giving unrestricted root access to your host. Remove 'docker.so",
    "category": "security",
    "owasp": [
      "A06:2017 - Security Misconfiguration",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "no-new-privileges",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-732",
    "message": "Service '$SERVICE' allows for privilege escalation via setuid or setgid binaries. Add 'no-new-privileges:true' in 'security_opt' to prevent this.",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A06:2017 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "privileged-service",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-250",
    "message": "Service '$SERVICE' is running in privileged mode. This grants the container the equivalent of root capabilities on the host machine. This can lead to container escapes, privilege escalation, and other",
    "category": "security",
    "owasp": [
      "A06:2017 - Security Misconfiguration",
      "A05:2021 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "seccomp-confinement-disabled",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-284",
    "message": "Service '$SERVICE' is explicitly disabling seccomp confinement. This runs the service in an unrestricted state. Remove 'seccomp:unconfined' to prevent this.",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "selinux-separation-disabled",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-284",
    "message": "Service '$SERVICE' is explicitly disabling SELinux separation. This runs the service as an unconfined type. Remove 'label:disable' to prevent this.",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "writable-filesystem-service",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-732",
    "message": "Service '$SERVICE' is running with a writable root filesystem. This may allow malicious applications to download and run additional payloads, or modify container files. If an application inside a cont",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A06:2017 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "allowed-unsecure-commands",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-749",
    "message": "The environment variable `ACTIONS_ALLOW_UNSECURE_COMMANDS` grants this workflow permissions to use the `set-env` and `add-path` commands. There is a vulnerability in these commands that could result i",
    "category": "security",
    "owasp": "A06:2017 - Security Misconfiguration",
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "unsafe-add-mask-workflow-command",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-200",
    "message": "GitHub Actions provides the **'add-mask'** workflow command to mask sensitive data in the workflow logs. If **'add-mask'** is not used or if workflow commands have been stopped, sensitive data can lea",
    "category": "security",
    "owasp": "A06:2017 - Security Misconfiguration",
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "curl-eval",
    "language": "yaml",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Data is being eval'd from a `curl` command. An attacker with control of the server in the `curl` command could inject malicious code into the `eval`, resulting in a system comrpomise. Avoid eval'ing u",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "detect-shai-hulud-backdoor",
    "language": "yaml",
    "severity": "ERROR",
    "cwe": "CWE-509",
    "message": "The Shai-hulud backdoor creates a purposefully vulnerable github action with the name `discussion.yaml`.",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "github-actions-mutable-action-tag",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-1357",
    "message": "GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks \u2014 as seen in the trivy-action and kics-gi",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software and Data Integrity Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "github-script-injection",
    "language": "yaml",
    "severity": "ERROR",
    "cwe": "CWE-94",
    "message": "Using variable interpolation `${{...}}` with `github` context data in a `actions/github-script`'s `script:` step could allow an attacker to inject their own code into the runner. This would allow them",
    "category": "security",
    "owasp": [
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "pull-request-target-code-checkout",
    "language": "yaml",
    "severity": "ERROR",
    "cwe": "CWE-829",
    "message": "This GitHub Actions workflow file uses `pull_request_target` and checks out code from the incoming pull request. When using `pull_request_target`, the Action runs in the context of the target reposito",
    "category": "security",
    "owasp": [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025 - Software and Data Integrity Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "run-shell-injection",
    "language": "yaml",
    "severity": "ERROR",
    "cwe": "CWE-78",
    "message": "Using variable interpolation `${{...}}` with `github` context data in a `run:` step could allow an attacker to inject their own code into the runner. This would allow them to steal secrets and code. `",
    "category": "security",
    "owasp": [
      "A01:2017 - Injection",
      "A03:2021 - Injection",
      "A05:2025 - Injection"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "secrets-inherit",
    "language": "yaml",
    "severity": "ERROR",
    "cwe": "CWE-250",
    "message": "This workflow uses `secrets: inherit` to pass all of the calling workflow's secrets to a reusable workflow. This violates the principle of least privilege because the called workflow receives access t",
    "category": "security",
    "owasp": [
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "workflow-run-target-code-checkout",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "",
    "message": "This GitHub Actions workflow file uses `workflow_run` and checks out code from the incoming pull request. When using `workflow_run`, the Action runs in the context of the target repository, which incl",
    "category": "security",
    "owasp": "A01:2017 - Injection",
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "allow-privilege-escalation-no-securitycontext",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-732",
    "message": "In Kubernetes, each pod runs in its own isolated environment with its own set of security policies. However, certain container images may contain `setuid` or `setgid` binaries that could allow an atta",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A06:2017 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "allow-privilege-escalation-true",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-732",
    "message": "In Kubernetes, each pod runs in its own isolated environment with its own  set of security policies. However, certain container images may contain  `setuid` or `setgid` binaries that could allow an at",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A06:2017 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "allow-privilege-escalation",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-732",
    "message": "In Kubernetes, each pod runs in its own isolated environment with its own set of security policies. However, certain container images may contain `setuid` or `setgid` binaries that could allow an atta",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A06:2017 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "flask-debugging-enabled",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-489",
    "message": "Do not set FLASK_ENV to \"development\" since that sets `debug=True` in Flask. Use \"dev\" or a similar term instead.",
    "category": "security",
    "owasp": "A06:2017 - Security Misconfiguration",
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "exposing-docker-socket-hostpath",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-250",
    "message": "Exposing host's Docker socket to containers via a volume. The owner of this socket is root. Giving someone access to it is equivalent to giving unrestricted root access to your host. Remove 'docker.so",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "hostipc-pod",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-693",
    "message": "Pod is sharing the host IPC namespace. This allows container processes to communicate with processes on the host which reduces isolation and bypasses container protection models. Remove the 'hostIPC' ",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "hostnetwork-pod",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-406",
    "message": "Pod may use the node network namespace. This gives the pod access to the loopback device, services listening on localhost, and could be used to snoop on network activity of other pods on the same node",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "hostpid-pod",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-269",
    "message": "Pod is sharing the host process ID namespace. When paired with ptrace this can be used to escalate privileges outside of the container. Remove the 'hostPID' key to disable this functionality.",
    "category": "security",
    "owasp": [
      "A04:2021 - Insecure Design",
      "A06:2025 - Insecure Design"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "",
    "language": "unknown",
    "severity": "WARNING",
    "cwe": "",
    "message": "",
    "category": "security",
    "owasp": [],
    "subcategory": []
  },
  {
    "id": "",
    "language": "unknown",
    "severity": "WARNING",
    "cwe": "",
    "message": "",
    "category": "security",
    "owasp": [],
    "subcategory": []
  },
  {
    "id": "",
    "language": "unknown",
    "severity": "WARNING",
    "cwe": "",
    "message": "",
    "category": "security",
    "owasp": [],
    "subcategory": []
  },
  {
    "id": "",
    "language": "unknown",
    "severity": "WARNING",
    "cwe": "",
    "message": "",
    "category": "security",
    "owasp": [],
    "subcategory": []
  },
  {
    "id": "",
    "language": "unknown",
    "severity": "WARNING",
    "cwe": "",
    "message": "",
    "category": "security",
    "owasp": [],
    "subcategory": []
  },
  {
    "id": "",
    "language": "unknown",
    "severity": "WARNING",
    "cwe": "",
    "message": "",
    "category": "security",
    "owasp": [],
    "subcategory": []
  },
  {
    "id": "legacy-api-clusterrole-excessive-permissions",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-269",
    "message": "Semgrep detected a Kubernetes core API ClusterRole with excessive permissions. Attaching excessive permissions to a ClusterRole associated with the core namespace allows the V1 API to perform arbitrar",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A06:2017 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "privileged-container",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-250",
    "message": "Container or pod is running in privileged mode. This grants the container the equivalent of root capabilities on the host machine. This can lead to container escapes, privilege escalation, and other s",
    "category": "security",
    "owasp": [],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "run-as-non-root-container-level-missing-security-context",
    "language": "yaml",
    "severity": "INFO",
    "cwe": "CWE-250",
    "message": "When running containers in Kubernetes, it's important to ensure that they are properly secured to prevent privilege escalation attacks. One potential vulnerability is when a container is allowed to ru",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A06:2017 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "run-as-non-root-container-level",
    "language": "yaml",
    "severity": "INFO",
    "cwe": "CWE-250",
    "message": "When running containers in Kubernetes, it's important to ensure that they are properly secured to prevent privilege escalation attacks. One potential vulnerability is when a container is allowed to ru",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A06:2017 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "run-as-non-root-security-context-pod-level",
    "language": "yaml",
    "severity": "INFO",
    "cwe": "CWE-250",
    "message": "When running containers in Kubernetes, it's important to ensure that they are properly secured to prevent privilege escalation attacks. One potential vulnerability is when a container is allowed to ru",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A06:2017 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "run-as-non-root-unsafe-value",
    "language": "yaml",
    "severity": "INFO",
    "cwe": "CWE-250",
    "message": "When running containers in Kubernetes, it's important to ensure that they  are properly secured to prevent privilege escalation attacks.  One potential vulnerability is when a container is allowed to ",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A06:2017 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "run-as-non-root",
    "language": "yaml",
    "severity": "INFO",
    "cwe": "CWE-250",
    "message": "When running containers in Kubernetes, it's important to ensure that they  are properly secured to prevent privilege escalation attacks.  One potential vulnerability is when a container is allowed to ",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A06:2017 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "seccomp-confinement-disabled",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-284",
    "message": "Container is explicitly disabling seccomp confinement. This runs the service in an unrestricted state. Remove 'seccompProfile: unconfined' to prevent this.",
    "category": "security",
    "owasp": [
      "A05:2017 - Broken Access Control",
      "A01:2021 - Broken Access Control",
      "A01:2025 - Broken Access Control"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "secrets-in-config-file",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-798",
    "message": "Secrets ($VALUE) should not be stored in infrastructure as code files. Use an alternative such as Bitnami Sealed Secrets or KSOPS to encrypt Kubernetes Secrets. ",
    "category": "security",
    "owasp": [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025 - Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "skip-tls-verify-cluster",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Cluster is disabling TLS certificate verification when communicating with the server. This makes your HTTPS connections insecure. Remove the 'insecure-skip-tls-verify: true' key to secure communicatio",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "skip-tls-verify-service",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-319",
    "message": "Service is disabling TLS certificate verification when communicating with the server. This makes your HTTPS connections insecure. Remove the 'insecureSkipTLSVerify: true' key to secure communication.",
    "category": "security",
    "owasp": [
      "A03:2017 - Sensitive Data Exposure",
      "A02:2021 - Cryptographic Failures",
      "A04:2025 - Cryptographic Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "writable-filesystem-container",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "CWE-732",
    "message": "Container $CONTAINER is running with a writable root filesystem. This may allow malicious applications to download and run additional payloads, or modify container files. If an application inside a co",
    "category": "security",
    "owasp": [
      "A05:2021 - Security Misconfiguration",
      "A06:2017 - Security Misconfiguration",
      "A02:2025 - Security Misconfiguration"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "api-key-in-query-parameter",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "",
    "message": "The $SECURITY_SCHEME security scheme passes an API key in a query parameter. API keys should not be passed as query parameters in security schemes.  Pass the API key in the header or body. If using a ",
    "category": "security",
    "owasp": [
      "A04:2021 Insecure Design",
      "A07:2021 Identification and Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  },
  {
    "id": "openai-consequential-action-false",
    "language": "yaml",
    "severity": "WARNING",
    "cwe": "",
    "message": "Found 'x-openai-isConsequential: false' in a state-changing HTTP method: $METHOD $PATH. This Action configuration will enable the 'Always Allow' option for state-changing HTTP methods, such as POST, P",
    "category": "security",
    "owasp": [
      "A04:2021 Insecure Design",
      "LLM08:2023 - Excessive Agency"
    ],
    "subcategory": [
      "audit"
    ]
  },
  {
    "id": "use-of-basic-authentication",
    "language": "yaml",
    "severity": "ERROR",
    "cwe": "",
    "message": "Basic authentication is considered weak and should be avoided.  Use a different authentication scheme, such of OAuth2, OpenID Connect, or mTLS.",
    "category": "security",
    "owasp": [
      "A04:2021 Insecure Design",
      "A07:2021 Identification and Authentication Failures"
    ],
    "subcategory": [
      "vuln"
    ]
  }
]