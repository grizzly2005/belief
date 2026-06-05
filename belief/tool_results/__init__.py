"""Tool-result import, mapping, correlation, and reportability adapters."""

from .io import (
    normalized_tool_result_from_dict,
    normalized_tool_result_to_dict,
    read_many_normalized_tool_results,
    read_normalized_tool_result,
    write_normalized_tool_result,
)
from .models import TOOL_RESULT_SCHEMA_VERSION, ToolResultSchemaError
from .provenance import SignalProvenance

__all__ = [
    "TOOL_RESULT_SCHEMA_VERSION",
    "SignalProvenance",
    "ToolResultSchemaError",
    "normalized_tool_result_from_dict",
    "normalized_tool_result_to_dict",
    "read_many_normalized_tool_results",
    "read_normalized_tool_result",
    "write_normalized_tool_result",
]
