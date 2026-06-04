# Provenance: SecureDrop 2.15.1 `store.py` storage path verification pattern.
import os
import re
import uuid

VALIDATE_FILENAME = re.compile(r"^[A-Za-z0-9_.-]+$")


class Storage:
    def __init__(self, root):
        self.root = os.path.realpath(root)

    def store_contains(self, path):
        path = os.path.realpath(path)
        return os.path.commonpath([self.root, path]) == self.root

    def verify(self, path):
        normalized = os.path.realpath(path)
        if not self.store_contains(normalized):
            raise ValueError("path outside store")
        return normalized

    def path(self, filename):
        candidate = os.path.realpath(os.path.join(self.root, filename))
        return self.verify(candidate)

    def make_filename(self, source_uuid, interaction_count):
        server_piece = uuid.uuid4().hex
        return f"{source_uuid}-{interaction_count}-{server_piece}.gpg"
