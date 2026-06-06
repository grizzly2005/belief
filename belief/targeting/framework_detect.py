"""Best-effort framework detection from local files."""

from __future__ import annotations

from pathlib import Path


def detect_frameworks(files: list[Path]) -> list[str]:
    frameworks = set()
    for path in files:
        if path.name in {"requirements.txt", "pyproject.toml", "Pipfile"} or path.suffix == ".py":
            text = _read_small(path).lower()
            if "fastapi" in text:
                frameworks.add("fastapi")
            if "flask" in text:
                frameworks.add("flask")
            if "django" in text:
                frameworks.add("django")
        if path.name == "package.json":
            text = _read_small(path).lower()
            for name in ("express", "next", "react", "vue", "angular"):
                if name in text:
                    frameworks.add(name)
    return sorted(frameworks)


def _read_small(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:20000]
    except OSError:
        return ""


__all__ = ["detect_frameworks"]
