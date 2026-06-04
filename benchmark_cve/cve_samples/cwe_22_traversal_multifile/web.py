"""Web entrypoint. Download endpoint takes a filename from query string."""
from flask import Flask, request
from storage.file_store import read_file

app = Flask(__name__)


@app.route("/download")
def download():
    # Taint source: filename from untrusted client
    fname = request.args.get("file", "default.txt")
    # Handler assumes storage layer will sanitize (it doesn't)
    content = read_file(fname)
    return {"content": content}
