"""CWE-78: OS command injection via shell=True."""
import subprocess

def ping_host(host):
    # VULN line 6: user-controlled host passed to shell=True
    subprocess.call(f"ping -c 1 {host}", shell=True)
