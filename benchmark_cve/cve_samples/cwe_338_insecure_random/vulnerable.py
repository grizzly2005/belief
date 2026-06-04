"""CWE-338: predictable random used for security token."""
import random

def session_token():
    # VULN line 6: random is predictable; use secrets.token_hex
    return str(random.random())
