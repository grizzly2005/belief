"""Pickle deserialization of untrusted data."""
import pickle

def process(blob_path):
    with open(blob_path, "rb") as f:
        # VULN line 7: pickle.load on attacker-controlled path → RCE
        data = pickle.load(f)
    return data
