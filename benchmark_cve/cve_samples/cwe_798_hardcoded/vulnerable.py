"""CWE-798: hardcoded credentials in source."""
# VULN line 3-4: hardcoded admin credentials
API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
ADMIN_PASSWORD = "SuperSecret123!"

def auth(user, pw):
    return user == "admin" and pw == ADMIN_PASSWORD
