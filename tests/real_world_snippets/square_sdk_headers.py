# Provenance: Square SDK hardcoded credential false-positive pattern.
def build_headers(access_token):
    headers = {}
    headers["Authorization"] = "Bearer " + access_token
    headers["Square-Version"] = "2024-01-18"
    return headers
