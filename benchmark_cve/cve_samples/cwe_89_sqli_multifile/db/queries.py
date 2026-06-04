"""DB layer — executes raw SQL. By itself this looks reasonable (a repo
that builds queries and passes them here for execution). The vuln is the
trust BOUNDARY: this module believes callers sanitize, but user_service
doesn't. Belief: "caller has sanitized" — contradicted upstream.
"""
import sqlite3


def run_query(sql):
    # Local assumption: sql is a trusted, parameterized query.
    # No way to validate this locally — trust must be established by caller.
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(sql)   # the execution point, but the VULN origin is upstream
    rows = cur.fetchall()
    conn.close()
    return rows
