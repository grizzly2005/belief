"""Synthetic mass-assignment candidate: direct copy of request JSON into model."""


def update_user_profile(request, user):
    for key, value in request.json.items():
        user[key] = value
    return {"status": "updated", "user_id": user.get("id")}
