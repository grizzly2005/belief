"""CVE-2017-18342: unsafe yaml.load enables arbitrary code execution."""
import yaml

def load_config(path):
    with open(path) as f:
        # VULN line 7: yaml.load without Loader is unsafe.
        # An attacker-controlled YAML file can execute arbitrary Python.
        return yaml.load(f.read())
