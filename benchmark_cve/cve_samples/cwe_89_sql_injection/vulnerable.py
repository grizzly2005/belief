"""CWE-89: SQL injection via string formatting."""
import sqlite3

def find_user(conn, username):
    # VULN line 6: user input interpolated directly into SQL
    q = "SELECT * FROM users WHERE name = '%s'" % username
    return conn.execute(q).fetchall()
