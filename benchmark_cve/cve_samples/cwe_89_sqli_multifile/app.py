"""Entrypoint: HTTP route. User input originates here (untrusted)."""
from flask import Flask, request
from services.user_service import find_user

app = Flask(__name__)


@app.route("/user")
def get_user():
    # Taint source: query param from untrusted client
    name = request.args.get("name", "")
    # Passed through one layer — looks innocuous locally
    result = find_user(name)
    return {"user": result}


if __name__ == "__main__":
    app.run()
