# Provenance: SecureDrop 2.15.1 `journalist_app/main.py` escaped Markup rendering pattern.
from markupsafe import Markup, escape

from securedrop.auth import admin_required


@admin_required
def format_source_name(display_name):
    return Markup("<b>{}</b>".format(escape(display_name)))
