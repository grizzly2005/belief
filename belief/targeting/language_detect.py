"""Lightweight local language detection."""

from __future__ import annotations

from pathlib import Path


LANGUAGE_EXTENSIONS = {
    "python": {".py"},
    "javascript": {".js", ".jsx"},
    "typescript": {".ts", ".tsx"},
    "go": {".go"},
    "java": {".java"},
    "ruby": {".rb"},
    "php": {".php"},
}

PACKAGE_FILES = {
    "pyproject.toml",
    "requirements.txt",
    "Pipfile",
    "poetry.lock",
    "package.json",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "composer.json",
}
LOCKFILES = {"poetry.lock", "Pipfile.lock", "yarn.lock", "pnpm-lock.yaml", "package-lock.json", "go.sum"}


def detect_languages(files: list[Path]) -> list[str]:
    languages = set()
    names = {path.name for path in files}
    if {"pyproject.toml", "requirements.txt", "Pipfile", "poetry.lock"} & names:
        languages.add("python")
    if {"package.json", "yarn.lock", "pnpm-lock.yaml", "package-lock.json"} & names:
        languages.add("javascript")
    if "go.mod" in names:
        languages.add("go")
    if {"pom.xml", "build.gradle"} & names:
        languages.add("java")
    if "Gemfile" in names:
        languages.add("ruby")
    if "composer.json" in names:
        languages.add("php")
    for path in files:
        for language, extensions in LANGUAGE_EXTENSIONS.items():
            if path.suffix.lower() in extensions:
                languages.add(language)
    return sorted(languages)


__all__ = ["LOCKFILES", "PACKAGE_FILES", "detect_languages"]
