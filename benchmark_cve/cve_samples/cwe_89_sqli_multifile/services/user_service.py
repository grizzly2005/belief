"""User service — the sink. Calls DB with untrusted string interpolation.
The belief `name is safe` is held here but CONTRADICTED by the belief
`name is untrusted` propagated from app.py through the call chain.
"""
from db.queries import run_query


def find_user(name):
    # DEVELOPER ASSUMPTION: name is a valid identifier (trusted)
    # REALITY: name comes straight from HTTP query string (tainted)
    # → Belief contradiction: local trust assumption vs. upstream taint
    if not name:
        return None

    # SINK: string interpolation into SQL — CWE-89
    query = f"SELECT * FROM users WHERE username = '{name}'"   # line 14: VULN
    return run_query(query)
