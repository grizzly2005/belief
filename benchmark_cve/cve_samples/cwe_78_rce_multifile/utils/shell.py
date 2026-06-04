"""Shell wrapper — the actual sink. The local belief is that `path`
is always a well-formed filesystem path (valid characters, no shell
metacharacters). Nothing in this module enforces that belief — it's an
assumed precondition that was never checked upstream.
"""
import subprocess


def convert_to_pdf(path):
    # VULN: shell=True + string interpolation. Locally detectable, but
    # the DANGER only emerges when `path` is user-controlled — which is
    # a fact about the WHOLE program, not this file.
    cmd = f"libreoffice --headless --convert-to pdf {path}"   # line 10
    subprocess.run(cmd, shell=True)
