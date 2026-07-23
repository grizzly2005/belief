import os
from pathlib import Path
from flask import request

ALLOWED_DIRECTORY = Path("/srv/public").resolve()

@app.get("/files/safe")
def download_safe_file():
    requested_path = request.args["path"]
    candidate = (ALLOWED_DIRECTORY / requested_path).resolve()
    if os.path.commonpath([str(ALLOWED_DIRECTORY), str(candidate)]) != str(ALLOWED_DIRECTORY):
        raise PermissionError("path escapes allowed directory")
    return open(candidate).read()
