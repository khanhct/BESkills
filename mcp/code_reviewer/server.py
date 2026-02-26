"""
PR Comment MCP Server — post review comments to PRs (Azure DevOps, GitHub, AWS).

Tools:
- post_pr_comments: Post a JSON array of comment threads to a PR (pr-comment-format.md).
- approve_pr: Approve a pull request (set reviewer vote). Azure: vote 10 = approved; GitHub placeholder.
- reject_pr: Reject a pull request (set reviewer vote to -10). Same headers as approve_pr; GitHub placeholder.
- create_pr: Create a pull request. Azure: source_branch, target_branch, title, description (optional); GitHub placeholder.

Header keys only (no fallbacks, no env, no tool params):
- Token: X-{provider}-{org}-{project}-token (e.g. X-azure-electrolux-T1-token)
- Reviewer ID (for approve_pr): X-{provider}-{org}-{project}-reviewer-id
If the required header is not sent, the tool returns an error.
"""
import argparse
import asyncio
import logging
from contextvars import ContextVar

import uvicorn
from mcp.server import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from providers.azure_devops import post_threads as azure_post_threads
from providers.azure_devops import approve_pull_request as azure_approve_pr
from providers.azure_devops import create_pull_request as azure_create_pr
from providers.github import post_threads as github_post_threads
from providers.github import approve_pull_request as github_approve_pr
from providers.github import create_pull_request as github_create_pr
from validation import validate_comments_body

logger = logging.getLogger(__name__)

# Set by middleware: all request headers with lowercase keys for lookup.
_request_headers: ContextVar[dict[str, str]] = ContextVar("request_headers", default={})


def _normalize_provider(provider: str) -> str:
    """Normalize provider: strip, lower, replace '-' with '_'. Only 'azure' and 'github' are supported."""
    if not provider or not str(provider).strip():
        return provider or ""
    return str(provider).strip().lower().replace("-", "_")


def _token_header_name(provider: str, org: str, project: str) -> str:
    """Header name for keyed token: X-{provider}-{org}-{project}-token (dashes in header)."""
    parts = [
        provider.replace("_", "-"),
        (org or "").replace("_", "-"),
        (project or "").replace("_", "-"),
    ]
    parts = [p for p in parts if p]
    return "X-" + "-".join(parts) + "-token"


def _key_to_token_header(key: str) -> str:
    """Canonical lowercase header name for token from key."""
    inner = key.replace("_token", "").replace("_", "-")
    return f"x-{inner}-token"


def _token_key(provider: str, org: str, project: str) -> str:
    """Internal lookup key: {provider}_{org}_{project}_token (no x- prefix)."""
    parts = [
        (provider or "").replace("-", "_").lower(),
        (org or "").replace("-", "_").lower(),
        (project or "").replace("-", "_").lower(),
    ]
    return "_".join(p for p in parts if p) + "_token"


def _key_to_reviewer_header(key: str) -> str:
    """Canonical lowercase header name for reviewer-id from key."""
    inner = key.replace("_token", "").replace("_", "-")
    return f"x-{inner}-reviewer-id"


def _no_token_msg(provider: str, org: str, project: str) -> str:
    header_name = _token_header_name(provider, org, project).lower()
    return (
        f"Missing token for {provider}/{org}/{project}. "
        f"Set header {header_name}."
    )


mcp = FastMCP(
    name="pr-comment",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
    instructions="Post PR review comments (post_pr_comments), approve PRs (approve_pr), reject PRs (reject_pr), or create PRs (create_pr). Token: header X-{provider}-{org}-{project}-token. Reviewer ID (approve_pr/reject_pr): header X-{provider}-{org}-{project}-reviewer-id. No fallbacks.",
)


def _effective_token(provider: str, org: str, project: str) -> tuple[str | None, str]:
    """Resolve token from header X-{provider}-{org}-{project}-token only. Returns (token, error_message)."""
    key = _token_key(provider, org, project)
    header_name = _key_to_token_header(key)
    headers = _request_headers.get()
    if isinstance(headers, dict):
        val = headers.get(header_name)
        if val and str(val).strip():
            return str(val).strip(), ""
    return None, _no_token_msg(provider, org, project)


def _effective_reviewer_id(provider: str, org: str, project: str) -> str | None:
    """Resolve reviewer ID from header X-{provider}-{org}-{project}-reviewer-id only."""
    key = _token_key(provider, org, project)
    header_name = _key_to_reviewer_header(key)
    headers = _request_headers.get()
    if isinstance(headers, dict):
        val = headers.get(header_name)
        if val and str(val).strip():
            return str(val).strip()
    return None


class TokenFromHeaderMiddleware(BaseHTTPMiddleware):
    """Store all request headers with lowercase keys for lookup by token/reviewer-id header names."""

    async def dispatch(self, request, call_next):
        headers = {name.lower().strip(): str(value).strip() for name, value in request.headers.items() if value and str(value).strip()}
        ctx = _request_headers.set(headers)
        try:
            return await call_next(request)
        finally:
            _request_headers.reset(ctx)


@mcp.tool(
    name="post_pr_comments",
    description="Post comment threads to a pull request. Required: provider, org, project, repository, pull_request_id, comments_body. Token from header X-{provider}-{org}-{project}-token. Providers: azure, github (placeholder).",
)
def post_pr_comments(
    provider: str,
    org: str,
    project: str,
    repository: str,
    pull_request_id: int,
    comments_body: str,
) -> str:
    """
    Post one or more comment threads to an existing pull request.

    Each thread is placed at a specific file and line range (right side of the diff).
    The comments_body must be a JSON array matching pr-comment-format (see references).

    Parameters:
        provider (str): Git provider. Use "azure" for Azure DevOps; "github" is placeholder.
        org (str): Organization or account name (e.g. electrolux for Azure DevOps).
        project (str): Project name within the organization (e.g. T1).
        repository (str): Repository name or ID.
        pull_request_id (int): The pull request number (integer ID).
        comments_body (str): JSON string: array of thread objects. Each thread has "comments" (one comment), "status": 1, and "threadContext" with "filePath" (leading slash), "rightFileStart", "rightFileEnd".

    Returns:
        str: Success message with count of created threads, or validation/API errors.

    Authentication:
        Token must be sent in request header: X-{provider}-{org}-{project}-token (e.g. x-azure-electrolux-t1-token).
    """
    provider = _normalize_provider(provider)
    resolved_token, no_token_msg = _effective_token(provider, org, project)
    if not resolved_token:
        return no_token_msg
    logger.info("post_pr_comments: token resolved for provider=%s org=%s project=%s", provider, org, project)
    threads, validation_errors = validate_comments_body(comments_body)
    if validation_errors:
        return "Validation failed:\n" + "\n".join(validation_errors)
    if not threads:
        return "No valid threads to post (empty array or all invalid)."
    if provider == "azure":
        result = azure_post_threads(
            token=resolved_token,
            org=org,
            project=project,
            repository=repository,
            pull_request_id=pull_request_id,
            threads=threads,
        )
    elif provider == "github":
        result = github_post_threads(
            token=resolved_token,
            org=org,
            project=project,
            repository=repository,
            pull_request_id=pull_request_id,
            threads=threads,
        )
    else:
        return f"Provider '{provider}' is not implemented. Use azure or github (placeholder)."
    created = result["created"]
    errors = result["errors"]
    msg = f"Created {created} thread(s)."
    if errors:
        msg += "\nErrors:\n" + "\n".join(f"  [{e['index']}] {e['message']}" for e in errors)
    return msg


@mcp.tool(
    name="approve_pr",
    description="Approve a pull request (set reviewer vote to approved). Required: provider, org, project, repository, pull_request_id. Token and reviewer ID from headers. Optional: vote (default 10=approved). Providers: azure, github (placeholder).",
)
def approve_pr(
    provider: str,
    org: str,
    project: str,
    repository: str,
    pull_request_id: int,
    vote: int = 10,
) -> str:
    """
    Approve a pull request by setting the current user's reviewer vote.

    For Azure DevOps, the reviewer is identified by the reviewer_id header; the PAT identifies the user.

    Parameters:
        provider (str): Git provider. Use "azure" for Azure DevOps; "github" is placeholder.
        org (str): Organization or account name.
        project (str): Project name within the organization.
        repository (str): Repository name or ID.
        pull_request_id (int): The pull request number (integer ID).
        vote (int): Reviewer vote. 10 = approved (default), 5 = approved with suggestions, 0 = no vote, -5 = waiting for author, -10 = rejected.

    Returns:
        str: Success message or error description.

    Authentication:
        Token: header X-{provider}-{org}-{project}-token.
        Reviewer ID (Azure): header X-{provider}-{org}-{project}-reviewer-id (your Azure DevOps identity GUID).
    """
    provider = _normalize_provider(provider)
    if provider == "azure":
        resolved_token, no_token_msg = _effective_token(provider, org, project)
        if not resolved_token:
            return no_token_msg
        resolved_reviewer_id = _effective_reviewer_id(provider, org, project)
        if not resolved_reviewer_id:
            header_name = _token_header_name(provider, org, project).replace("-token", "-reviewer-id").lower()
            return f"Missing reviewer_id for approve_pr. Set header {header_name}."
        logger.info("approve_pr: token and reviewer_id resolved for provider=%s org=%s project=%s", provider, org, project)
        result = azure_approve_pr(
            token=resolved_token,
            org=org,
            project=project,
            repository=repository,
            pull_request_id=pull_request_id,
            vote=vote,
            reviewer_id=resolved_reviewer_id,
        )
        return result["message"] if result.get("success") else f"Approve failed: {result.get('message', 'Unknown error')}"
    if provider == "github":
        resolved_token, no_token_msg = _effective_token(provider, org, project)
        if not resolved_token:
            return no_token_msg
        logger.info("approve_pr: token resolved for provider=%s org=%s project=%s", provider, org, project)
        result = github_approve_pr(
            token=resolved_token,
            org=org,
            project=project,
            repository=repository,
            pull_request_id=pull_request_id,
            vote=vote,
        )
        return result["message"]
    return f"Provider '{provider}' is not implemented. Use azure or github (placeholder)."


@mcp.tool(
    name="reject_pr",
    description="Reject a pull request (set reviewer vote to -10). Required: provider, org, project, repository, pull_request_id. Token and reviewer ID from headers (same as approve_pr). Providers: azure, github (placeholder).",
)
def reject_pr(
    provider: str,
    org: str,
    project: str,
    repository: str,
    pull_request_id: int,
) -> str:
    """
    Reject a pull request by setting the current user's reviewer vote to rejected (-10).

    Uses the same authentication as approve_pr (token and reviewer_id headers).

    Parameters:
        provider (str): Git provider. Use "azure" for Azure DevOps; "github" is placeholder.
        org (str): Organization or account name.
        project (str): Project name within the organization.
        repository (str): Repository name or ID.
        pull_request_id (int): The pull request number (integer ID).

    Returns:
        str: Success message or error description.

    Authentication:
        Token: header X-{provider}-{org}-{project}-token.
        Reviewer ID (Azure): header X-{provider}-{org}-{project}-reviewer-id.
    """
    provider = _normalize_provider(provider)
    if provider == "azure":
        resolved_token, no_token_msg = _effective_token(provider, org, project)
        if not resolved_token:
            return no_token_msg
        resolved_reviewer_id = _effective_reviewer_id(provider, org, project)
        if not resolved_reviewer_id:
            header_name = _token_header_name(provider, org, project).replace("-token", "-reviewer-id").lower()
            return f"Missing reviewer_id for reject_pr. Set header {header_name}."
        logger.info("reject_pr: token and reviewer_id resolved for provider=%s org=%s project=%s", provider, org, project)
        result = azure_approve_pr(
            token=resolved_token,
            org=org,
            project=project,
            repository=repository,
            pull_request_id=pull_request_id,
            vote=-10,
            reviewer_id=resolved_reviewer_id,
        )
        return result["message"] if result.get("success") else f"Reject failed: {result.get('message', 'Unknown error')}"
    if provider == "github":
        resolved_token, no_token_msg = _effective_token(provider, org, project)
        if not resolved_token:
            return no_token_msg
        result = github_approve_pr(
            token=resolved_token,
            org=org,
            project=project,
            repository=repository,
            pull_request_id=pull_request_id,
            vote=-10,
        )
        return result["message"]
    return f"Provider '{provider}' is not implemented. Use azure or github (placeholder)."


@mcp.tool(
    name="create_pr",
    description="Create a new pull request. Required: provider, org, project, repository, source_branch, target_branch, title. Optional: description. Token from header X-{provider}-{org}-{project}-token. Providers: azure, github (placeholder).",
)
def create_pr(
    provider: str,
    org: str,
    project: str,
    repository: str,
    source_branch: str,
    target_branch: str,
    title: str,
    description: str | None = None,
) -> str:
    """
    Create a new pull request from a source branch into a target branch.

    Branch names can be short (e.g. "main", "feature/xyz") or full refs (refs/heads/main); they are normalized automatically.

    Parameters:
        provider (str): Git provider. Use "azure" for Azure DevOps; "github" is placeholder.
        org (str): Organization or account name.
        project (str): Project name within the organization.
        repository (str): Repository name or ID.
        source_branch (str): Branch containing the changes (e.g. feature/xyz or refs/heads/feature/xyz).
        target_branch (str): Branch to merge into (e.g. main or refs/heads/main).
        title (str): Pull request title.
        description (str, optional): Pull request description/body. Can be empty or omitted.

    Returns:
        str: Success message including the new PR ID, or error description.

    Authentication:
        Token: header X-{provider}-{org}-{project}-token.
    """
    provider = _normalize_provider(provider)
    resolved_token, no_token_msg = _effective_token(provider, org, project)
    if not resolved_token:
        return no_token_msg
    if provider == "azure":
        result = azure_create_pr(
            token=resolved_token,
            org=org,
            project=project,
            repository=repository,
            source_ref=source_branch,
            target_ref=target_branch,
            title=title,
            description=description,
        )
        if result.get("success"):
            return result["message"]
        return f"Create PR failed: {result.get('message', 'Unknown error')}"
    if provider == "github":
        result = github_create_pr(
            token=resolved_token,
            org=org,
            project=project,
            repository=repository,
            source_ref=source_branch,
            target_ref=target_branch,
            title=title,
            description=description,
        )
        return result["message"]
    return f"Provider '{provider}' is not implemented. Use azure or github (placeholder)."


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request):
    return JSONResponse({"status": "ok"})


async def run_sse_with_cors():
    """Custom SSE transport with CORS and keyed token header support."""
    sse_app = mcp.sse_app()
    sse_app.add_middleware(TokenFromHeaderMiddleware)
    sse_app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    config = uvicorn.Config(
        sse_app,
        host=mcp.settings.host,
        port=mcp.settings.port,
        log_level=mcp.settings.log_level.lower(),
    )
    server = uvicorn.Server(config)
    await server.serve()


async def run_http_with_cors():
    """Custom HTTP transport with CORS and keyed token header support."""
    http_app = mcp.streamable_http_app()
    http_app.add_middleware(TokenFromHeaderMiddleware)
    http_app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    config = uvicorn.Config(
        http_app,
        host=mcp.settings.host,
        port=mcp.settings.port,
        log_level=mcp.settings.log_level.lower(),
    )
    server = uvicorn.Server(config)
    await server.serve()


async def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--transport",
        choices=["sse", "stdio", "http"],
        default="sse",
        help="Transport to use for communication with the client. (default: stdio)",
    )

    # HTTP transport options
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind the HTTP server to (default: 127.0.0.1)",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to bind the HTTP server to (default: 8000)",
    )

    parser.add_argument(
        "--path",
        default="/mcp",
        help="Path for the MCP HTTP endpoint (default: /mcp)",
    )

    parser.add_argument(
        "--log-level",
        default="info",
        choices=["debug", "info", "warning", "error"],
        help="Log level for the HTTP server (default: info)",
    )

    args = parser.parse_args()

    mcp.settings.host = args.host
    mcp.settings.port = args.port

    if args.transport == "stdio":
        await mcp.run_stdio_async()
    elif args.transport == "sse":
        await run_sse_with_cors()
    elif args.transport == "http":
        await run_http_with_cors()


def run() -> None:
    """Entry point for the console script (e.g. code-reviewer-mcp)."""
    try:
        asyncio.run(main())
    except Exception as e:
        raise


if __name__ == "__main__":
    run()
