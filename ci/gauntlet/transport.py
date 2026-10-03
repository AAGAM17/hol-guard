"""Distinguish safe inference transport recovery from replaying a tool."""
from __future__ import annotations

from typing import Any


def reconcile_rounds(rounds: list[dict[str, Any]]) -> tuple[bool, int]:
    """Accept only completed rounds or identical, zero-byte HTTP retries.

    A failed partial stream cannot qualify. This function never retries a
    request and never excuses a repeated, blocked or failed host tool call.
    """
    if not rounds:
        return False, 0
    recovered = 0
    for index, row in enumerate(rounds):
        if row.get("status") == "completed":
            continue
        status = row.get("http_status")
        if (row.get("status") != "provider-error" or row.get("error_type") != "HTTPError"
                or row.get("delivered_bytes") != 0 or type(status) is not int
                or not (status == 429 or 500 <= status <= 599)
                or not isinstance(row.get("request_sha256"), str)):
            return False, recovered
        same_request_completed = False
        for retry in rounds[index + 1:]:
            if retry.get("request_sha256") != row["request_sha256"]:
                break
            if retry.get("status") == "completed":
                same_request_completed = True
                break
        if not same_request_completed:
            return False, recovered
        recovered += 1
    return True, recovered
