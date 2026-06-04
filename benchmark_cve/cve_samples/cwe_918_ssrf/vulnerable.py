"""CWE-918: SSRF — unvalidated URL fetch."""
import urllib.request

def fetch(url):
    # VULN line 6: no url whitelist; attacker can hit internal services
    return urllib.request.urlopen(url).read()
