from pathlib import Path

from belief.orchestration.output_layout import LAYOUT_DIRS, build_output_layout, ensure_output_layout


def test_output_layout_contains_expected_dirs(tmp_path):
    layout = build_output_layout(tmp_path / "run")

    assert set(LAYOUT_DIRS) <= set(layout)
    assert layout["metadata"].endswith("/metadata")


def test_ensure_output_layout_creates_dirs(tmp_path):
    layout = ensure_output_layout(tmp_path / "run")

    for path in layout.values():
        assert Path(path).exists()
