"""
PR Comment MCP Server — post review comments to PRs (Azure DevOps, GitHub, AWS).

Tools:
- post_pr_comments: Post a JSON array of comment threads to a PR (pr-comment-format.md).
- approve_pr: Approve a pull request (set reviewer vote). Azure DevOps: vote 10 = approved; GitHub placeholder.

Token is keyed by provider/org/project. Key format: {provider}_{org}_{project}_token.
Pass tokens via header X-{provider}-{org}-{project}-token (e.g. X-azure-devops-myorg-myproject-token),
or X-PR-Comment-Tokens JSON, or env PR_COMMENT_<KEY_UPPERCASED>, or optional token parameter.
Fallback: Authorization: Bearer / X-PR-Comment-Token / PR_COMMENT_TOKEN. No X-User-Id required.
"""
import argparse
import asyncio
import json
import os
from contextvars import ContextVar

import uvicorn
from mcp.server import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from providers.azure_devops import post_threads as azure_post_threads
from providers.azure_devops import approve_pull_request as azure_approve_pr
from providers.github import post_threads as github_post_threads
from providers.github import approve_pull_request as github_approve_pr
from validation import validate_comments_body

# Set by middleware: keyed tokens from X-PR-Comment-Tokens JSON (SSE/HTTP).
_tokens_from_header: ContextVar[dict[str, str]] = ContextVar(
    "tokens_from_header", default={}
)
# Set by middleware: single token from Authorization: Bearer or X-PR-Comment-Token (fallback).
_fallback_token_from_header: ContextVar[str | None] = ContextVar(
    "fallback_token_from_header", default=None
)

TOKEN_ENV_PREFIX = "PR_COMMENT_"


def _token_header_name(provider: str, org: str, project: str) -> str:
    """Header name for keyed token: X-{provider}-{org}-{project}-token (dashes in header)."""
    parts = [
        provider.replace("_", "-"),
        (org or "").replace("_", "-"),
        (project or "").replace("_", "-"),
    ]
    parts = [p for p in parts if p]
    return "X-" + "-".join(parts) + "-token"


def _header_name_to_key(header_name: str) -> str | None:
    """Convert header name X-{p}-{o}-{proj}-token to key {provider}_{org}_{project}_token."""
    n = header_name.lower().strip()
    if not n.startswith("x-") or not n.endswith("-token"):
        return None
    inner = n[2:-6]  # drop "x-" and "-token"
    if not inner:
        return None
    return inner.replace("-", "_") + "_token"


def _token_key(provider: str, org: str, project: str) -> str:
    """Key format: {provider}_{org}_{project}_token. Normalized to underscores for header lookup."""
    parts = [
        (provider or "").replace("-", "_"),
        (org or "").replace("-", "_"),
        (project or "").replace("-", "_"),
    ]
    return "_".join(p for p in parts if p) + "_token"


def _no_token_msg(provider: str, org: str, project: str) -> str:
    key = _token_key(provider, org, project)
    header_name = _token_header_name(provider, org, project)
    env_name = TOKEN_ENV_PREFIX + key.upper()
    return (
        f"No token provided for {provider}/{org}/{project}. "
        f"Set header {header_name}, or env {env_name}, "
        f"or fallback Authorization: Bearer / X-PR-Comment-Token / PR_COMMENT_TOKEN, or pass the token parameter."
    )


mcp = FastMCP(
    name="pr-comment",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
    instructions="Post PR review comments (post_pr_comments) or approve PRs (approve_pr) for Azure DevOps and GitHub (placeholder). Token key: {provider}_{org}_{project}_token. Pass via header X-{provider}-{org}-{project}-token (e.g. X-azure-devops-myorg-myproject-token) or env PR_COMMENT_<KEY_UPPERCASED>; fallback: Authorization: Bearer / X-PR-Comment-Token / PR_COMMENT_TOKEN.",
)


def _effective_token(provider: str, org: str, project: str, token_param: str | None) -> tuple[str | None, str]:
    """
    Resolve token: (1) token_param, (2) keyed header/env, (3) fallback header/env.
    Returns (token, error_message). If token is non-None, error_message is empty.
    """
    if token_param and str(token_param).strip():
        return str(token_param).strip(), ""
    key = _token_key(provider, org, project)
    # Keyed lookup from header (keys from headers are lowercased)
    tokens_dict = _tokens_from_header.get()
    if isinstance(tokens_dict, dict):
        lookup_key = key.lower()
        if lookup_key in tokens_dict:
            val = tokens_dict[lookup_key]
            if val and str(val).strip():
                return str(val).strip(), ""
    # Keyed env
    env_name = TOKEN_ENV_PREFIX + key.upper()
    env_val = os.environ.get(env_name)
    if env_val and str(env_val).strip():
        return str(env_val).strip(), ""
    # Fallback: single header
    fallback = _fallback_token_from_header.get()
    if fallback and str(fallback).strip():
        return str(fallback).strip(), ""
    # Fallback env
    fallback_env = os.environ.get("PR_COMMENT_TOKEN")
    if fallback_env and str(fallback_env).strip():
        return str(fallback_env).strip(), ""
    return None, _no_token_msg(provider, org, project)


class TokenFromHeaderMiddleware(BaseHTTPMiddleware):
    """Set request-scoped tokens from X-{provider}-{org}-{project}-token headers or X-PR-Comment-Tokens (JSON), or fallback Authorization: Bearer / X-PR-Comment-Token."""

    async def dispatch(self, request, call_next):
        tokens_dict: dict[str, str] = {}
        fallback: str | None = None
        # 1) Keyed headers: X-{provider}-{org}-{project}-token
        for name, value in request.headers.items():
            key = _header_name_to_key(name)
            if key and value and str(value).strip():
                tokens_dict[key] = str(value).strip()
        # 2) Optional: X-PR-Comment-Tokens JSON (overrides/adds to keyed headers)
        raw_json = request.headers.get("X-PR-Comment-Tokens")
        if raw_json and raw_json.strip():
            try:
                parsed = json.loads(raw_json)
                if isinstance(parsed, dict):
                    for k, v in parsed.items():
                        if v is not None and str(v).strip():
                            tokens_dict[k] = str(v).strip()
            except (json.JSONDecodeError, TypeError):
                pass
        # 3) Fallback single token (used when keyed lookup fails)
        auth = request.headers.get("Authorization")
        if auth and auth.startswith("Bearer "):
            fallback = auth[7:].strip()
        if not fallback:
            raw = request.headers.get("X-PR-Comment-Token")
            fallback = raw.strip() if raw and raw.strip() else None
        tok_ctx = _tokens_from_header.set(tokens_dict)
        fallback_ctx = _fallback_token_from_header.set(fallback)
        try:
            return await call_next(request)
        finally:
            _tokens_from_header.reset(tok_ctx)
            _fallback_token_from_header.reset(fallback_ctx)


@mcp.tool(
    name="post_pr_comments",
    description="Post comment threads to a pull request. Body must be JSON array per pr-comment-format (one comment per thread). Required: provider, org, project (for Azure; may be empty for GitHub), repository, pull_request_id, comments_body. Optional: token (else keyed header X-{provider}-{org}-{project}-token or env PR_COMMENT_<KEY> or fallback). Providers: azure_devops, github (placeholder).",
)
def post_pr_comments(
    provider: str,      # The provider to use for posting comments (e.g., 'azure_devops'). Case-sensitive.
    org: str,           # The organization or account name in the provider (for Azure DevOps: the organization name).
    project: str,       # The project within the organization (for Azure DevOps; may be ignored by other providers).
    repository: str,    # The name or identifier of the repository to post comments to.
    pull_request_id: int,   # The numeric ID of the pull request to comment on.
    comments_body: str,     # JSON string: array of thread objects as described in pr-comment-format.md; each includes comments and location.
    token: str | None = None,  # (Optional) PAT for this call. If omitted, use keyed header/env or fallback.
) -> str:
    """
    Post PR comments to the given repository and pull request.

    Parameters:
        provider (str): The provider to use for posting comments (e.g., 'azure_devops'). Case-sensitive.
        org (str): The organization or account name in the provider (for Azure DevOps, the organization name).
        project (str): The project within the organization (for Azure DevOps; may be ignored by other providers).
        repository (str): The name or identifier of the repository to post comments to.
        pull_request_id (int): The numeric ID of the pull request to comment on.
        comments_body (str): JSON string: array of thread objects as described in pr-comment-format.md; each includes comments and location.
        token (str, optional): Personal Access Token (PAT) for this call. If omitted, uses keyed header/env or fallback.

    Returns:
        str: Result message describing the actions taken (created threads, validation errors, or token errors).

    Token resolution:
      - Uses key {provider}_{org}_{project}_token from header X-{provider}-{org}-{project}-token or env PR_COMMENT_<KEY_UPPERCASED>
      - Fallback: Authorization: Bearer / X-PR-Comment-Token / PR_COMMENT_TOKEN
      - Or, use the explicit 'token' parameter to override
    """
    resolved_token, no_token_msg = _effective_token(provider, org, project, token)
    if not resolved_token:
        return no_token_msg
    threads, validation_errors = validate_comments_body(comments_body)
    if validation_errors:
        return "Validation failed:\n" + "\n".join(validation_errors)
    if not threads:
        return "No valid threads to post (empty array or all invalid)."
    if provider == "azure_devops":
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
        return f"Provider '{provider}' is not implemented. Use azure_devops or github (placeholder)."
    created = result["created"]
    errors = result["errors"]
    msg = f"Created {created} thread(s)."
    if errors:
        msg += "\nErrors:\n" + "\n".join(f"  [{e['index']}] {e['message']}" for e in errors)
    return msg


@mcp.tool(
    name="approve_pr",
    description="Approve a pull request (set reviewer vote for the authenticated user). Required: provider, org, project (may be empty for GitHub), repository, pull_request_id. Optional: vote (10=approved, 5=approved with suggestions, 0=no vote, -5=waiting for author, -10=rejected; default 10), token. Providers: azure_devops, github (placeholder). Same token header X-{provider}-{org}-{project}-token as post_pr_comments.",
)
def approve_pr(
    provider: str,
    org: str,
    project: str,
    repository: str,
    pull_request_id: int,
    vote: int = 10,
    token: str | None = None,
) -> str:
    """
    Approve a pull request. Uses the same token resolution as post_pr_comments.
    For Azure DevOps, gets the current user from ConnectionData and sets their vote on the PR.
    """
    if provider == "azure_devops":
        resolved_token, no_token_msg = _effective_token(provider, org, project, token)
        if not resolved_token:
            return no_token_msg
        result = azure_approve_pr(
            token=resolved_token,
            org=org,
            project=project,
            repository=repository,
            pull_request_id=pull_request_id,
            vote=vote,
        )
        return result["message"] if result.get("success") else f"Approve failed: {result.get('message', 'Unknown error')}"
    if provider == "github":
        resolved_token, no_token_msg = _effective_token(provider, org, project, token)
        if not resolved_token:
            return no_token_msg
        result = github_approve_pr(
            token=resolved_token,
            org=org,
            project=project,
            repository=repository,
            pull_request_id=pull_request_id,
            vote=vote,
        )
        return result["message"]
    return f"Provider '{provider}' is not implemented. Use azure_devops or github (placeholder)."


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
