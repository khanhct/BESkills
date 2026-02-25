"""
PR Comment MCP Server — post review comments to PRs (Azure DevOps, GitHub, AWS).

Tools:
- pr_comment_add_token: Store a PAT/token for a provider and org (optional project).
- pr_comment_post: Post a JSON array of comment threads to a PR (pr-comment-format.md).

Multi-user: pass user_id, or set X-User-Id header (SSE/HTTP), or USER_ID env (stdio). Else 'default'.
"""
import argparse
import asyncio
import os
from contextvars import ContextVar

import uvicorn
from mcp.server import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from providers import token_store
from providers.azure_devops import post_threads as azure_post_threads
from validation import validate_comments_body

# Set by middleware from X-User-Id header (SSE/HTTP). None when not set or stdio.
_current_user_id_from_header: ContextVar[str | None] = ContextVar(
    "current_user_id_from_header", default=None
)

mcp = FastMCP(
    name="pr-comment",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
    instructions="Post PR review comments to Azure DevOps (and later GitHub, AWS). Use add_token to store a PAT. Multi-user: pass user_id, or X-User-Id header (SSE/HTTP), or USER_ID env (stdio), then post_pr_comments to post comment threads.",
)


def _effective_user_id(user_id: str | None) -> str:
    """Resolve user_id: explicit arg, else X-User-Id header (SSE/HTTP), else USER_ID env, else 'default'."""
    if user_id and str(user_id).strip():
        return str(user_id).strip()
    from_header = _current_user_id_from_header.get()
    if from_header and str(from_header).strip():
        return str(from_header).strip()
    return os.environ.get("USER_ID", "default")


class XUserIdMiddleware(BaseHTTPMiddleware):
    """Set request-scoped user id from X-User-Id header for SSE/HTTP transports."""

    async def dispatch(self, request, call_next):
        raw = request.headers.get("X-User-Id")
        value = raw.strip() if raw and raw.strip() else None
        token = _current_user_id_from_header.set(value)
        try:
            return await call_next(request)
        finally:
            _current_user_id_from_header.reset(token)


@mcp.tool(
    name="add_token",
    description="Store a PAT/token for a provider and organization. Optional project for Azure DevOps; optional user_id for multi-user (else X-User-Id header or USER_ID env or 'default'). Supported providers: azure_devops, github, aws.",
)
def add_token(
    provider: str,  # The provider to store the token for (e.g., 'azure_devops', 'github', 'aws'). Case-sensitive.
    org: str,       # The organization or account name. For Azure DevOps, this is the organization.
    token: str,     # The personal access token (PAT) or secret to store.
    project: str | None = None,  # (Optional) The project within the organization. Required for some providers like Azure DevOps.
    user_id: str | None = None,  # (Optional) User identifier to scope the token. If omitted, X-User-Id header (SSE/HTTP) or USER_ID env is used, else 'default'.
) -> str:
    """
    Add or update token for the given provider, org, and optional project and user_id.

    Parameters:
        provider (str): The provider to store the token for (should be one of: 'azure_devops', 'github', 'aws').
        org (str): The organization or account name for which the token is stored.
        token (str): The personal access token (PAT) or authentication token value.
        project (str, optional): The project within the organization. This is required for Azure DevOps, but optional/ignored for other providers.
        user_id (str, optional): User identifier for multi-user isolation. Omit to use X-User-Id header (SSE/HTTP) or USER_ID env or 'default'.

    Returns:
        str: A result message indicating success or details of any error encountered.
    """
    try:
        effective_user = _effective_user_id(user_id)
        token_store.set_token(provider, org, token, project, user_id=effective_user)
        parts = [provider, org]
        if project:
            parts.append(project)
        msg = "Token stored for " + " / ".join(parts)
        if effective_user != "default":
            msg += f" (user: {effective_user})"
        return msg + "."
    except ValueError as e:
        return str(e)
    except OSError as e:
        return f"Failed to write credentials file: {e}"


@mcp.tool(
    name="post_pr_comments",
    description="Post comment threads to a pull request. Body must be JSON array per pr-comment-format (one comment per thread). Required: provider, org, project (for Azure), repository, pull_request_id, comments_body. Optional user_id (else X-User-Id header or USER_ID env or 'default').",
)
def post_pr_comments(
    provider: str,      # The provider to use for posting comments (e.g., 'azure_devops'). Case-sensitive.
    org: str,           # The organization or account name in the provider (for Azure DevOps: the organization name).
    project: str,       # The project within the organization (for Azure DevOps; may be ignored by other providers).
    repository: str,    # The name or identifier of the repository to post comments to.
    pull_request_id: int,   # The numeric ID of the pull request to comment on.
    comments_body: str,     # JSON string: array of thread objects as described in pr-comment-format.md; each includes comments and location.
    user_id: str | None = None,  # (Optional) User identifier whose token to use. If omitted, X-User-Id header (SSE/HTTP) or USER_ID env is used, else 'default'.
) -> str:
    """
    Post PR comments to the given repository and pull request.

    Parameters:
        provider (str): The provider to use for posting comments ('azure_devops', 'github', or 'aws').
        org (str): The organization or account name in the provider. For Azure DevOps, this is the organization name.
        project (str): The project name, required for Azure DevOps. Ignored for other providers.
        repository (str): The target repository name or identifier for the pull request.
        pull_request_id (int): The numeric ID of the pull request to post comments on.
        comments_body (str): JSON string representing an array of comment thread objects (see pr-comment-format.md for format).
        user_id (str, optional): User identifier for token lookup. Omit to use X-User-Id header (SSE/HTTP) or USER_ID env or 'default'.

    Returns:
        str: A summary of created threads and any errors encountered.
    """
    if provider != "azure_devops":
        return f"Provider '{provider}' is not implemented yet. Use azure_devops."
    effective_user = _effective_user_id(user_id)
    token = token_store.get_token(provider, org, project, user_id=effective_user)
    if not token:
        # Try org-level token without project
        token = token_store.get_token(provider, org, None, user_id=effective_user)
    if not token:
        return "No token found. Use add_token for this provider/org (and project if needed). Use the same user (user_id, X-User-Id header, or USER_ID env) when posting."
    threads, validation_errors = validate_comments_body(comments_body)
    if validation_errors:
        return "Validation failed:\n" + "\n".join(validation_errors)
    if not threads:
        return "No valid threads to post (empty array or all invalid)."
    result = azure_post_threads(
        token=token,
        org=org,
        project=project,
        repository=repository,
        pull_request_id=pull_request_id,
        threads=threads,
    )
    created = result["created"]
    errors = result["errors"]
    msg = f"Created {created} thread(s)."
    if errors:
        msg += "\nErrors:\n" + "\n".join(f"  [{e['index']}] {e['message']}" for e in errors)
    return msg


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request):
    return JSONResponse({"status": "ok"})


async def run_sse_with_cors():
    """Custom SSE transport with CORS and X-User-Id header support."""
    sse_app = mcp.sse_app()
    sse_app.add_middleware(XUserIdMiddleware)
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
    """Custom HTTP transport with CORS and X-User-Id header support."""
    http_app = mcp.streamable_http_app()
    http_app.add_middleware(XUserIdMiddleware)
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


if __name__ == "__main__":

    try:
        asyncio.run(main())
    except Exception as e:
        raise
