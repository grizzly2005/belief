"""Local target classifier for BELIEF orchestration."""

from __future__ import annotations

from pathlib import Path

from belief.scope.matchers import is_url

from .artifact_detect import detect_artifacts
from .framework_detect import detect_frameworks
from .language_detect import LOCKFILES, PACKAGE_FILES, detect_languages
from .models import TargetProfile


def classify_target(target: str | Path) -> TargetProfile:
    target_text = str(target)
    if is_url(target_text):
        return TargetProfile(
            target=target_text,
            target_type="url",
            exists=False,
            recommended_flags=("web-passive",),
            safety_notes=("URL targets require explicit scope before network or dynamic tools.",),
        )

    path = Path(target_text)
    exists = path.exists()
    if not exists:
        return TargetProfile(
            target=target_text,
            target_type="missing",
            exists=False,
            safety_notes=("Target path does not exist.",),
        )

    files = _collect_files(path)
    artifacts = detect_artifacts(files)
    languages = detect_languages(files)
    frameworks = detect_frameworks(files)
    target_type = _target_type(path, artifacts, languages)
    package_files = _relative_names(files, path, PACKAGE_FILES)
    lockfiles = _relative_names(files, path, LOCKFILES)
    recommended_flags = _recommended_flags(target_type, languages, artifacts)
    safety_notes = ["Classification is local and does not execute target code."]
    if target_type in {"har_file", "burp_xml", "openapi_file", "pdx_json"}:
        safety_notes.append("Artifact should be imported passively.")

    return TargetProfile(
        target=target_text,
        target_type=target_type,
        exists=True,
        languages=tuple(languages),
        frameworks=tuple(frameworks),
        package_files=tuple(package_files),
        lockfiles=tuple(lockfiles),
        iac_files=tuple(_relative_paths(artifacts["iac_files"], path)),
        api_files=tuple(_relative_paths(artifacts["api_files"], path)),
        traffic_files=tuple(_relative_paths(artifacts["traffic_files"], path)),
        pdx_files=tuple(_relative_paths(artifacts["pdx_files"], path)),
        recommended_flags=tuple(recommended_flags),
        safety_notes=tuple(safety_notes),
    )


def _collect_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    ignored = {".git", "__pycache__", ".pytest_cache", "node_modules", "dist", "build", ".venv", "venv"}
    files: list[Path] = []
    for item in path.rglob("*"):
        if any(part in ignored for part in item.parts):
            continue
        if item.is_file():
            files.append(item)
    return sorted(files, key=lambda item: item.as_posix())


def _target_type(path: Path, artifacts: dict[str, list[str]], languages: list[str]) -> str:
    if path.is_file():
        suffix = path.suffix.lower()
        if artifacts["pdx_files"]:
            return "pdx_json"
        if artifacts["api_files"]:
            return "openapi_file"
        if suffix == ".har":
            return "har_file"
        if suffix == ".xml" and artifacts["traffic_files"]:
            return "burp_xml"
        if suffix == ".json":
            return "json_file"
        return "file"
    if "python" in languages:
        return "python_repo"
    if "go" in languages:
        return "go_repo"
    if "java" in languages:
        return "java_repo"
    if "ruby" in languages:
        return "ruby_repo"
    if "php" in languages:
        return "php_repo"
    if "javascript" in languages or "typescript" in languages:
        return "js_ts_repo"
    if artifacts["iac_files"]:
        return "iac_repo"
    return "local_directory"


def _relative_names(files: list[Path], root: Path, names: set[str]) -> list[str]:
    return sorted(_rel(path, root) for path in files if path.name in names)


def _relative_paths(paths: list[str], root: Path) -> list[str]:
    if root.is_file():
        return [Path(path).name for path in paths]
    root_posix = root.as_posix().rstrip("/") + "/"
    return sorted(path.removeprefix(root_posix) for path in paths)


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root if root.is_dir() else root.parent).as_posix()
    except ValueError:
        return path.as_posix()


def _recommended_flags(target_type: str, languages: list[str], artifacts: dict[str, list[str]]) -> list[str]:
    flags = {"auto"}
    if target_type.endswith("_repo") or target_type == "local_directory":
        flags.add("code")
    if "python" in languages:
        flags.add("sca")
    if artifacts["iac_files"]:
        flags.add("iac")
    if artifacts["api_files"]:
        flags.add("api")
    if artifacts["traffic_files"] or artifacts["pdx_files"]:
        flags.add("imported")
    return sorted(flags)


__all__ = ["classify_target"]
