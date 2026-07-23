from flask_login import current_user, login_required

@app.get("/documents/<document_id>/delegated")
@login_required
def read_delegated_document(document_id):
    document = Document.query.filter_by(id=document_id).first_or_404()
    authorize_document_access(current_user, document)
    return serialize_document(document)
