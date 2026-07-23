import os
from flask import request

STATIC_INDEX = "/srv/public/index.html"

@app.get("/files/index")
def download_static_index():
    requested_label = request.args["path"]
    audit_label = os.path.basename(requested_label)
    return open(STATIC_INDEX).read(), {"X-Audit-Label": audit_label}
