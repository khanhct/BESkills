"""
GitHub provider stub — PR review comments via GitHub API.

To be implemented: map threadContext to path, line, side, etc. using
Create a review comment for a pull request.
"""

from typing import Any


def post_threads(
    token: str,
    org: str,
    repository: str,
    pull_request_id: int,
    threads: list[dict[str, Any]],
    project: str | None = None,
) -> dict[str, Any]:
    """Not implemented. Use azure_devops for now."""
    return {
        "created": 0,
        "errors": [{"index": 0, "message": "GitHub provider is not implemented yet."}],
    }
