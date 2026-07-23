from flask_login import current_user, login_required

@app.get("/documents/<document_id>/safe")
@login_required
def read_owned_document(document_id):
    document = Document.query.filter_by(id=document_id, owner_id=current_user.id).first_or_404()
    return serialize_document(document)
