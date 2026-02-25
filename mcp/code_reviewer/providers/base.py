"""Abstract provider interface for posting PR review threads."""

from abc import ABC, abstractmethod
from typing import Any


class BaseProvider(ABC):
    """Interface for PR comment providers (Azure DevOps, GitHub, AWS)."""

    @abstractmethod
    def post_threads(
        self,
        org: str,
        repository: str,
        pull_request_id: int,
        threads: list[dict[str, Any]],
        project: str | None = None,
    ) -> dict[str, Any]:
        """
        Post comment threads to a pull request.

        Args:
            org: Organization name.
            repository: Repository name or ID.
            pull_request_id: Pull request number or ID.
            threads: List of thread objects (comments, status, threadContext).
            project: Optional project (Azure DevOps).

        Returns:
            Summary with created count and any errors.
        """
        ...
