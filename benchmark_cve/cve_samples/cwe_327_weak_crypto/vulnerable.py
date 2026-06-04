"""CWE-327: Weak MD5 hash used for passwords."""
import hashlib

def store_password(pw):
    # VULN line 6: MD5 is broken, unsuitable for passwords
    return hashlib.md5(pw.encode()).hexdigest()
