"""Storage layer. Locally looks fine: os.path.join is widely (mis)believed
to sanitize paths. It DOES NOT — it happily handles '../'.

The belief held here is: "os.path.join + base_dir prefix = safe".
This belief is FALSE, and it's the precondition on which the whole module
relies. BELIEF should detect this as an unjustified trust assumption
combined with untrusted input propagated from web.py.
"""
import os

BASE_DIR = "/var/data/uploads"


def read_file(fname):
    # Assumption: BASE_DIR + fname stays within BASE_DIR.
    # Reality: '../' in fname escapes BASE_DIR (CWE-22)
    full_path = os.path.join(BASE_DIR, fname)    # does NOT sanitize ../
    with open(full_path, "r") as f:              # line 13: VULN
        return f.read()
