"""Synthetic protected mass-assignment case: explicit safe field allowlist."""


SAFE_PROFILE_FIELDS = {"display_name", "timezone", "bio"}


def update_user_profile_allowlist(request, user):
    for key, value in request.json.items():
        if key in SAFE_PROFILE_FIELDS:
            user[key] = value
    return {"status": "updated", "user_id": user.get("id")}
