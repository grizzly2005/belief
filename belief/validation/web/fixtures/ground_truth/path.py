"""Independent normative scenarios for path-boundary fixtures."""

PATH_SCENARIOS = (
    {
        "scenario": "legitimate_path",
        "stimulus_kind": "literal",
        "stimulus": "public.txt",
        "baseline": True,
        "required": True,
    },
    {
        "scenario": "parent_segment",
        "stimulus_kind": "literal",
        "stimulus": "../outside/sentinel.txt",
        "baseline": False,
        "required": True,
    },
    {
        "scenario": "absolute_path",
        "stimulus_kind": "absolute_outside",
        "stimulus": "fixture/outside/sentinel.txt",
        "baseline": False,
        "required": True,
    },
    {
        "scenario": "normalized_equivalent",
        "stimulus_kind": "literal",
        "stimulus": "nested/../../outside/sentinel.txt",
        "baseline": False,
        "required": True,
    },
    {
        "scenario": "symlink_boundary",
        "stimulus_kind": "symlink",
        "stimulus": "linked-sentinel.txt",
        "baseline": False,
        "required": False,
    },
)
