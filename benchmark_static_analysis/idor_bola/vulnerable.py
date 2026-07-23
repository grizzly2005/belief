from flask_login import login_required

@app.get("/documents/<document_id>")
@login_required
def read_document(document_id):
    document = Document.query.filter_by(id=document_id).first_or_404()
    return serialize_document(document)
