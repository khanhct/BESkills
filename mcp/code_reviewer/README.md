# PR Comment MCP Server (code_reviewer)

Post pull request review comments from an MCP client (e.g. Cursor) to Azure DevOps (and later GitHub, AWS CodeCommit). Comment body format follows [pr-comment-format.md](../../code-review/references/pr-comment-format.md).

## Setup

From the repo root or from this folder:

```bash
cd mcp/code_reviewer
uv sync
```

This creates a virtual environment and installs dependencies from `pyproject.toml`. To use the system Python instead, run `uv sync --no-install-project` or install with pip: `uv pip install -e .`

## Running the server

**Development / test:**

```bash
cd mcp/code_reviewer
uv run fastmcp dev server.py
```

**Production (e.g. Cursor MCP):**

```bash
cd mcp/code_reviewer
uv run fastmcp run server.py
```

Or run the module directly:

```bash
cd mcp/code_reviewer
uv run python -m fastmcp run server.py
```

**Deploy with uvicorn (HTTP):**

```bash
cd mcp/code_reviewer
uv run python run.py
```

Or with uvicorn explicitly (custom host/port/reload):

```bash
cd mcp/code_reviewer
uv run uvicorn run:app --host 0.0.0.0 --port 8000
uv run uvicorn run:app --host 0.0.0.0 --port 8000 --reload   # development
```

## Environment

The server **does not store tokens**. Only keyed headers are supported (no env, no fallback).

| Header | Format | Example |
|--------|--------|---------|
| **Token** | `X-{provider}-{org}-{project}-token` | `X-azure-electrolux-T1-token: <PAT>` |
| **Reviewer ID** (for approve_pr) | `X-{provider}-{org}-{project}-reviewer-id` | `X-azure-electrolux-T1-reviewer-id: <GUID>` |

If the required header is not sent, the tool returns an error. Underscores in provider/org/project become dashes in the header.

## Cursor MCP configuration

Add the server to Cursor (Settings → MCP, or `.cursor/mcp.json` in the project).

**Option A — SSE (recommended for Cursor):** Run the server manually with SSE, then point Cursor at the URL.

1. Start the server:
   ```bash
   uv run python server.py --transport sse --host 127.0.0.1 --port 8080
   ```
2. In `mcp.json`, pass token and reviewer-id via keyed headers only:
   ```json
   {
     "mcpServers": {
       "code-review": {
         "url": "http://127.0.0.1:8080/sse",
         "headers": {
          "X-azure-electrolux-T1-token": "YOUR_AZURE_DEVOPS_PAT",
          "X-azure-electrolux-T1-reviewer-id": "YOUR_REVIEWER_ID_GUID"
         }
       }
     }
   }
   ```

**Option B — stdio with uv:** Not supported; token/reviewer-id must be passed via SSE/HTTP headers. Run the server with `--transport sse` and use Option A.

**Option C — stdio with system Python:** Same as Option B; use SSE + headers.

## Tools

### post_pr_comments

Post comment threads to a pull request. Token must be in header **`X-{provider}-{org}-{project}-token`** (e.g. `X-azure-electrolux-T1-token`). No fallbacks.

- **provider**: `azure` (Azure DevOps) or `github` (placeholder).
- **org**: Organization name.
- **project**: Project name (Azure DevOps).
- **repository**: Repository name or GUID.
- **pull_request_id**: PR number (integer).
- **comments_body**: JSON string — array of thread objects. Each thread must have exactly one comment, `status: 1`, and `threadContext` with `filePath` (leading `/`), `rightFileStart`, `rightFileEnd`. See [pr-comment-format.md](../../code-review/references/pr-comment-format.md).
- **token**: From header `X-{provider}-{org}-{project}-token` only (no param).

Example `comments_body`:

```json
[
  {
    "comments": [{ "parentCommentId": 0, "content": "Consider using a parameterized query here.", "commentType": 1 }],
    "status": 1,
    "threadContext": {
      "filePath": "/src/Services/UserService.cs",
      "rightFileStart": { "line": 45, "offset": 1 },
      "rightFileEnd": { "line": 45, "offset": 1 }
    }
  }
]
```

## Azure DevOps PAT

Create a [Personal Access Token](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens) with scope **Code (Read & Write)** or **Pull Request Threads (Read & Write)**. Pass it only via header **`X-azure-<org>-<project>-token`**. For approve_pr, also set **`X-azure-<org>-<project>-reviewer-id`** to your identity GUID. No env or fallback. The server does not store tokens.
