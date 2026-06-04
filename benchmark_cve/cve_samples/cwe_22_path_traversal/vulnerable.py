"""CWE-22: path traversal via user-controlled path concatenation."""
import os

BASE = "/var/www/files/"

def serve(filename):
    # VULN line 8: no basename/abspath check; attacker can request ../../etc/passwd
    path = os.path.join(BASE, filename)
    return open(path).read()
