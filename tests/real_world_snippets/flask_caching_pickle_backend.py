# Provenance: Flask-Caching 1.10.1 backend pickle example.
import pickle


class FileSystemCache:
    def load_value(self, filename):
        with open(filename, "rb") as cache_file:
            payload = cache_file.read()
        return pickle.loads(payload)
