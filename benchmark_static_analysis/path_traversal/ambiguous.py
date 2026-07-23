from flask import request

@app.get("/files/delegated")
def download_delegated_file():
    requested_path = request.args["path"]
    candidate = resolve_download_path(requested_path)
    return open(candidate).read()
