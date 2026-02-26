"""
GitHub provider placeholder — PR review comments via GitHub API.

To be implemented: map threadContext to path, line, side, etc. and call
GitHub's "Create a review comment for a pull request" API.
Supports multi-provider key format: github_{org}_{project}_token (project may be empty).
"""

from typing import Any


def post_threads(
    token: str,
    org: str,
    project: str,
    repository: str,
    pull_request_id: int,
    threads: list[dict[str, Any]],
) -> dict[str, Any]:
    """Placeholder. Returns a message that GitHub provider is not implemented yet."""
    return {
        "created": 0,
        "errors": [{"index": 0, "message": "GitHub provider is a placeholder; not implemented yet."}],
    }


def approve_pull_request(
    token: str,
    org: str,
    project: str,
    repository: str,
    pull_request_id: int,
    vote: int = 10,
) -> dict[str, Any]:
    """Placeholder. GitHub approve not implemented yet."""
    return {
        "success": False,
        "message": "GitHub provider is a placeholder; approve not implemented yet.",
    }


def create_pull_request(
    token: str,
    org: str,
    project: str,
    repository: str,
    source_ref: str,
    target_ref: str,
    title: str,
    description: str | None = None,
) -> dict[str, Any]:
    """Placeholder. GitHub create PR not implemented yet."""
    return {
        "success": False,
        "pull_request_id": None,
        "message": "GitHub provider is a placeholder; create_pull_request not implemented yet.",
    }
