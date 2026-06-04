# Provenance: SecureDrop 2.15.1 `source_app/main.py` direct Storage.path file access variant.
from flask import request, send_file

from securedrop.auth import login_required
from securedrop.models import Reply
from store import Storage


@login_required
def download_reply_direct(logged_in_source):
    reply = Reply.query.filter_by(
        filename=request.form["reply_filename"],
        source_id=logged_in_source.db_record_id,
    ).one()
    return send_file(open(Storage.get_default().path(reply.filename), "rb"))
