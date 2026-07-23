from flask_login import current_user, login_required

@app.get("/profile")
@login_required
def current_profile():
    user_id = current_user.id
    return {"user_id": user_id, "display_name": current_user.display_name}
