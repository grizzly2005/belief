"""
bandit_bridge — run Bandit on a project and convert findings to BELIEF sextuplets.

Bandit is a widely-used Python security linter. It matches ~100 patterns
(SQL injection, shell injection, hardcoded secrets, insecure hashing, etc.).

We use it as a PRE-FILTER in BELIEF: before sending code to the LLM,
Bandit flags syntactic danger points. The LLM then focuses on these
regions and extracts the SEMANTIC belief that is being violated.

Invocation model: subprocess (bandit -f json -r <path>).
Reason: keeps Bandit's ~20 dependencies out of BELIEF's env.

Mapping to BELIEF sextuplet:
  assumption   ← f"{test_name} should not match at {location}"
  anchor_point ← (file, line)
  justification_type ← C2_STATICALLY_VERIFIED_PROPERTY
  contextual_constraint ← bandit's test_id + severity + confidence
  trust_domain ← file's module
  logic_type   ← 'semantic' (pre-LLM, not Z3-translatable directly)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import BridgeResult

logger = logging.getLogger("belief.bridges.bandit")

# Cache under ~/.cache/belief/bridges/bandit/
_CACHE = Path.home() / ".cache" / "belief" / "bridges" / "bandit"
_CACHE.mkdir(parents=True, exist_ok=True)


def is_installed() -> bool:
    """Check that bandit binary is available."""
    return shutil.which("bandit") is not None


# Bandit test IDs that carry no triage signal for BELIEF.
#
# Two families qualify, and only these two:
#
#   * the whole B4xx "blacklist imports" family — an import is a module
#     reference, not a data flow. Bandit already reports the *use* of the same
#     dangerous API under a separate ID (B403 import_pickle vs B301 pickle,
#     B405-B411 import_xml_* vs B313-B320 xml_bad_*), so keeping the import
#     variant duplicates a finding BELIEF cannot anchor to a source or sink;
#   * three control-flow hygiene checks that describe style, not a weakness.
#
# Deliberately NOT informational: B603 and B607. They are noisy, but they are
# call sites with a real CWE-78 mapping, so dropping them would remove
# candidate sinks rather than noise.
BANDIT_INFORMATIONAL_TEST_IDS = frozenset({
    # Control-flow hygiene — no weakness on its own.
    "B101",  # assert_used
    "B110",  # try_except_pass
    "B112",  # try_except_continue
    # Blacklisted imports — reference only, never an anchored flow.
    "B401",  # import_telnetlib
    "B402",  # import_ftplib
    "B403",  # import_pickle
    "B404",  # import_subprocess
    "B405",  # import_xml_etree
    "B406",  # import_xml_sax
    "B407",  # import_xml_expat
    "B408",  # import_xml_minidom
    "B409",  # import_xml_pulldom
    "B410",  # import_lxml
    "B411",  # import_xmlrpclib
    "B412",  # import_httpoxy
    "B413",  # import_pycrypto
    "B414",  # import_pycryptodome
    "B415",  # import_pyghmi
})


def is_informational(finding: Dict[str, Any]) -> bool:
    """True when a Bandit finding is not relevant to BELIEF triage."""
    return str(finding.get("test_id", "")) in BANDIT_INFORMATIONAL_TEST_IDS


def _project_hash(project_path: str) -> str:
    """Stable hash of all .py files' mtimes+sizes. Invalidates cache on any change."""
    p = Path(project_path)
    sig_parts = []
    for f in sorted(p.rglob("*.py")):
        try:
            st = f.stat()
            sig_parts.append(f"{f.relative_to(p)}|{st.st_mtime}|{st.st_size}")
        except OSError:
            continue
    return hashlib.sha256("\n".join(sig_parts).encode()).hexdigest()[:16]


def _apply_informational_filter(
    result: BridgeResult,
    drop_informational: bool,
) -> None:
    """Record, and optionally remove, findings with no triage signal.

    The disk cache always holds Bandit's raw output, so the same cache entry
    stays correct under either setting.
    """
    dropped = [f for f in result.findings if is_informational(f)]
    result.metadata["informational_available"] = len(dropped)
    result.metadata["informational_dropped"] = len(dropped) if drop_informational else 0
    result.metadata["informational_test_ids"] = sorted(
        {str(f.get("test_id", "")) for f in dropped}
    )
    if drop_informational and dropped:
        result.findings = [f for f in result.findings if not is_informational(f)]
        logger.info(
            "bandit: dropped %d informational finding(s) (%s)",
            len(dropped),
            ", ".join(result.metadata["informational_test_ids"]),
        )


def run_bandit(
    project_path: str,
    *,
    severity: str = "low",   # low|medium|high (min level)
    confidence: str = "low",
    exclude: Optional[List[str]] = None,
    use_cache: bool = True,
    drop_informational: bool = True,
) -> BridgeResult:
    """Run bandit, return BridgeResult.

    Subprocess-based. Falls back gracefully if bandit isn't installed.

    `drop_informational` removes the test IDs listed in
    `BANDIT_INFORMATIONAL_TEST_IDS` before the findings reach triage. It is on
    by default: those IDs are import references and style checks that BELIEF
    cannot anchor to a source or a sink. Pass False to obtain Bandit's raw
    finding set — required when reproducing a measurement recorded before this
    filter existed.
    """
    t0 = time.time()
    result = BridgeResult(source="bandit")

    if not is_installed():
        result.errors.append(
            "bandit not installed. `pip install bandit` to enable this bridge."
        )
        result.elapsed_s = time.time() - t0
        return result

    project_path = os.path.abspath(project_path)
    if not os.path.isdir(project_path):
        result.errors.append(f"not a directory: {project_path}")
        result.elapsed_s = time.time() - t0
        return result

    # Cache check
    sig = _project_hash(project_path)
    cache_key = f"{sig}_{severity}_{confidence}.json"
    cache_file = _CACHE / cache_key
    if use_cache and cache_file.exists():
        try:
            data = json.loads(cache_file.read_text())
            result.findings = data.get("results", [])
            result.cache_hit = True
            _apply_informational_filter(result, drop_informational)
            result.elapsed_s = time.time() - t0
            logger.info(f"bandit cache hit: {len(result.findings)} findings")
            return result
        except Exception:
            pass

    # Build command
    cmd = [
        "bandit",
        "-f", "json",
        "-r", project_path,
        f"--severity-level={severity}",
        f"--confidence-level={confidence}",
        "-q",
    ]
    if exclude:
        cmd += ["-x", ",".join(exclude)]

    # Default excludes (tests, cache)
    cmd += ["-x", ",".join([
        os.path.join(project_path, "tests"),
        os.path.join(project_path, "test"),
        os.path.join(project_path, "__pycache__"),
    ])]

    try:
        # Bandit exits with code 1 when it finds issues → not an error for us
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )
        out = proc.stdout or "{}"
        data = json.loads(out)
        result.findings = data.get("results", [])
        if use_cache:
            cache_file.write_text(json.dumps({"results": result.findings}))
    except subprocess.TimeoutExpired:
        result.errors.append("bandit scan timed out after 300s")
    except json.JSONDecodeError as e:
        result.errors.append(f"bandit output not JSON: {e}; stderr={proc.stderr[:200]}")
    except Exception as e:
        result.errors.append(f"bandit subprocess failed: {type(e).__name__}: {e}")

    _apply_informational_filter(result, drop_informational)
    result.elapsed_s = time.time() - t0
    logger.info(f"bandit: {len(result.findings)} findings in {result.elapsed_s:.1f}s")
    return result


def to_belief(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a Bandit finding dict to BELIEF sextuplet fields as a dict.
    Extractor or orchestrator wraps this into a full Belief model.

    v4 hotfix #3.2: include bandit's issue_text in the assumption so the
    downstream CWE-guessing taxonomy can match on real vulnerability
    keywords (e.g. "Audit url open for permitted schemes" → CWE-918).
    Also propagate a `cwe` field derived from the bandit test_id, so the
    cognitive layer doesn't have to re-guess from text.
    """
    test_id = finding.get("test_id", "B???")
    test_name = finding.get("test_name", "unknown")
    issue_text = finding.get("issue_text", "")  # real description from bandit
    severity = finding.get("issue_severity", "LOW").upper()
    confidence = finding.get("issue_confidence", "LOW").upper()
    filename = finding.get("filename", "<unknown>")
    line = finding.get("line_number", 0)

    # Severity and evidentiary support are separate axes.  This bridge emits a
    # concrete static rule match, never a source-bound mechanical proof.
    justif = "C2_STATICALLY_VERIFIED_PROPERTY"

    # Trust domain = module path
    trust_domain = Path(filename).stem

    # v4 hotfix #3.2: map bandit test_id → CWE. This is deterministic and
    # skips the fragile text-keyword lookup. The CWE is authoritative from
    # bandit's own rule catalog.
    #
    # Source: https://bandit.readthedocs.io/en/latest/plugins/index.html
    _BANDIT_CODE_TO_CWE = {
        "B102": "CWE-95",   # exec
        "B103": "CWE-732",  # set_bad_file_permissions
        "B105": "CWE-798",  # hardcoded_password_string
        "B106": "CWE-798",  # hardcoded_password_funcarg
        "B107": "CWE-798",  # hardcoded_password_default
        "B108": "CWE-377",  # hardcoded_tmp_directory (treated as FP by us)
        "B301": "CWE-502",  # pickle (deserialization)
        "B302": "CWE-502",  # marshal
        "B303": "CWE-327",  # md5
        "B304": "CWE-327",  # weak ciphers (DES, RC4)
        "B305": "CWE-327",  # cipher modes (ECB)
        "B306": "CWE-377",  # mktemp_q
        "B307": "CWE-95",   # eval
        "B308": "CWE-79",   # mark_safe
        "B310": "CWE-918",  # urllib_urlopen — SSRF
        "B311": "CWE-338",  # random (insecure RNG)
        "B313": "CWE-611",  # xml_bad_cElementTree
        "B314": "CWE-611",  # xml_bad_ElementTree
        "B315": "CWE-611",  # xml_bad_expatreader
        "B316": "CWE-611",  # xml_bad_expatbuilder
        "B317": "CWE-611",  # xml_bad_sax
        "B318": "CWE-611",  # xml_bad_minidom
        "B319": "CWE-611",  # xml_bad_pulldom
        "B320": "CWE-611",  # xml_bad_etree
        "B321": "CWE-319",  # ftplib
        "B323": "CWE-295",  # unverified_context
        "B324": "CWE-327",  # hashlib weak hash (md5/sha1)
        "B501": "CWE-295",  # request_with_no_cert_validation
        "B502": "CWE-327",  # ssl_with_bad_version
        "B503": "CWE-327",  # ssl_with_bad_defaults
        "B504": "CWE-327",  # ssl_with_no_version
        "B505": "CWE-326",  # weak_cryptographic_key
        "B506": "CWE-502",  # yaml_load
        "B507": "CWE-295",  # ssh_no_host_key_verification
        "B601": "CWE-78",   # paramiko_calls
        "B602": "CWE-78",   # subprocess_popen_with_shell_equals_true
        "B603": "CWE-78",   # subprocess_without_shell_equals_true (noisy, kept: real sink)
        "B604": "CWE-78",   # any_other_function_with_shell_equals_true
        "B605": "CWE-78",   # start_process_with_a_shell
        "B606": "CWE-78",   # start_process_with_no_shell
        "B607": "CWE-78",   # start_process_with_partial_path
        "B608": "CWE-89",   # hardcoded_sql_expressions — SQL injection
        "B609": "CWE-78",   # linux_commands_wildcard_injection
        "B610": "CWE-89",   # django_extra_used
        "B611": "CWE-89",   # django_rawsql_used
        "B701": "CWE-94",   # jinja2_autoescape_false
        "B702": "CWE-94",   # use_of_mako_templates
        "B703": "CWE-79",   # django_mark_safe
    }
    cwe = _BANDIT_CODE_TO_CWE.get(test_id, "")

    # Assumption text: include issue_text so taxonomy keyword matching
    # remains a useful fallback even if our code→CWE table is missing entries.
    assumption = (f"Bandit {test_id}: {issue_text}"
                  if issue_text else
                  f"Bandit {test_id} ({test_name}) should not match here")

    return {
        "assumption": assumption,
        "anchor_file": filename,
        "anchor_line": line,
        "anchor_line_end": finding.get("line_range", [line, line])[-1],
        "justification_type": justif,
        "contextual_constraint": f"severity={severity}, confidence={confidence}, test_id={test_id}",
        "trust_domain": trust_domain,
        "logic_type": "semantic",
        "source": "bandit",
        "cwe": cwe,     # v4 hotfix #3.2: let belief_adapter propagate this to Belief.cwe
        # Labelled, not assumed absent: run_bandit(drop_informational=False)
        # and direct to_belief() callers both still reach this path.
        "informational": is_informational(finding),
        "raw": finding,
    }


def register(registry) -> None:
    """Called by bridges.__init__ auto-register."""
    registry.register("bandit", run_bandit)
