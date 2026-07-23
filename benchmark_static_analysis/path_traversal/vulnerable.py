from flask import request

@app.get("/files")
def download_file():
    path = request.args["path"]
    return open(path).read()
