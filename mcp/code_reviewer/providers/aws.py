"""
AWS CodeCommit provider stub — PR comments via PostCommentForPullRequest.

To be implemented: map repository to repo name, PR to pullRequestId.
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
        "errors": [{"index": 0, "message": "AWS CodeCommit provider is not implemented yet."}],
    }
