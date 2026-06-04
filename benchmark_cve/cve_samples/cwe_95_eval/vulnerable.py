"""CWE-95: eval on user input → arbitrary Python."""

def calc(expr):
    # VULN line 5: eval on user-controlled expr = RCE
    return eval(expr)
