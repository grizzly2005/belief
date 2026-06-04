# Provenance: SecureDrop 2.15.1 `source_app/main.py` source-scoped reply access pattern.
from flask import current_app, request, send_file

from securedrop.auth import login_required
from securedrop.models import Reply
from store import Storage


@login_required
def download_reply(logged_in_source):
    reply = Reply.query.filter_by(
        filename=request.form["reply_filename"],
        source_id=logged_in_source.db_record_id,
    ).one()
    reply_path = Storage.get_default().path(reply.filename)
    return send_file(open(reply_path, "rb"))
