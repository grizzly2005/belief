"""Business layer. Builds a PDF path and invokes the shell wrapper.
Locally this module has no obvious vuln — it just concatenates a directory
and a name. But the belief 'filename is safe for shell' is held here
without evidence.
"""
import os
from utils.shell import convert_to_pdf


def build_report(filename):
    # Local belief: `filename` is a user-friendly label (trusted enough)
    # Upstream reality: it's raw JSON input, not validated anywhere.
    out_dir = os.path.expanduser("~/reports")
    full_path = f"{out_dir}/{filename}"
    # Hands off to shell wrapper — carries the taint further
    convert_to_pdf(full_path)
    return full_path
