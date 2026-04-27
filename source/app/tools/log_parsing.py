"""Stateless log parsing helpers shared by PoC and verify stages.

These functions implement the PoC log contract:
    target_binary=...
    trigger_command=...
    execution_exit_code=<int>
    stdout_begin / stdout_end
    stderr_begin / stderr_end
"""

from __future__ import annotations

import re
from typing import Any


def extract_block(text: str, begin: str, end: str) -> str:
    """Extract content between two marker lines."""

    pattern = rf"{re.escape(begin)}\n(.*?)(?:\n{re.escape(end)})"
    match = re.search(pattern, text, re.DOTALL)
    if not match:
        return ""
    return match.group(1).strip()


def extract_execution_observation(execution_logs: str) -> dict[str, Any]:
    """Parse the PoC log contract into a structured observation."""

    stdout = extract_block(execution_logs, "stdout_begin", "stdout_end")
    stderr = extract_block(execution_logs, "stderr_begin", "stderr_end")
    exit_code = None
    match = re.search(r"execution_exit_code=(\d+)", execution_logs)
    if match:
        exit_code = int(match.group(1))
    crash_type = ""
    joined = f"{stdout}\n{stderr}".lower()
    for marker in ("segmentation fault", "assert", "abort", "heap-buffer-overflow", "stack-overflow"):
        if marker in joined:
            crash_type = marker
            break
    return {
        "observed_exit_code": exit_code,
        "observed_stdout": stdout,
        "observed_stderr": stderr,
        "observed_crash_type": crash_type,
    }


def match_patterns(haystack: str, patterns: list[str]) -> list[str]:
    """Return the subset of patterns that appear (case-insensitively) in the haystack."""

    lowered = haystack.lower()
    matches = [pattern for pattern in patterns if pattern and pattern.lower() in lowered]
    return sorted(set(matches))
